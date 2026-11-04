//! The `upgrade` control request.
//!
//! [`prepare`] runs while the system is up, before the request is acknowledged: it copies the
//! bundle into init's private staging directory, verifies it against the release key the
//! image ships and plans the writes, so a bad bundle is refused with nothing stopped.
//! [`run`] runs in [`super::shutdown::finish`] after every other process is gone: it prunes
//! the overlay (settings stay), locks init in memory, writes the partitions and returns so
//! the shutdown can reboot.

use std::fs;
use std::path::{Path, PathBuf};

use owr_board::Board;
use owr_common::paths::{RELEASE_KEY_FILE, RUN_DIR};
use owr_upgrade::{Version, WriteStep, apply, bundle, plan, release};
use rustix::mm::{MlockAllFlags, mlockall};

use super::console_log;
use super::mount_exec::resolve_device;
use crate::boot::factory_reset_marker;
use crate::control::UpgradeRequest;
use crate::mounts::{BootMode, DATA_MOUNT};

/// A verified upgrade, ready to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UpgradeJob {
    pub(super) version: String,
    image: PathBuf,
    steps: Vec<WriteStep>,
    /// The board's storage device; partition labels resolve on it only.
    disk: String,
    wipe_settings: bool,
}

fn staging_dir() -> PathBuf {
    Path::new(RUN_DIR).join("upgrade")
}

fn device_of(label: &str, disk: &str) -> Option<PathBuf> {
    resolve_device(&format!("PARTLABEL={label}"), Some(disk))
        .ok()
        .map(PathBuf::from)
}

/// Size in bytes of the partition labelled `label` (sysfs counts 512-byte sectors).
fn partition_size(label: &str, disk: &str) -> Option<u64> {
    let dev = device_of(label, disk)?;
    let name = dev.file_name()?.to_str()?.to_owned();
    let sectors: u64 = fs::read_to_string(format!("/sys/class/block/{name}/size"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    sectors.checked_mul(512)
}

/// Stage, verify and plan. The error is shown to whoever asked (API, CLI).
pub(super) fn prepare(
    req: &UpgradeRequest,
    board: Option<&Board>,
    mode: BootMode,
    persistent: bool,
) -> Result<UpgradeJob, String> {
    // The overlay must be the real data partition: pruning it is what keeps the old image's
    // files from shadowing the new one. In failsafe or an initramfs boot it is not mounted.
    if mode == BootMode::Failsafe || !persistent {
        return Err(
            "upgrades run from a normal boot with the data partition mounted; \
                    in failsafe or an initramfs boot use the bootloader's recovery"
                .into(),
        );
    }
    let board = board.ok_or("no board description loaded")?;
    let key_text =
        fs::read_to_string(RELEASE_KEY_FILE).map_err(|e| format!("{RELEASE_KEY_FILE}: {e}"))?;
    let pubkey = release::parse_pubkey(&key_text)
        .ok_or_else(|| format!("{RELEASE_KEY_FILE}: not a public key"))?;
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .ok_or("the running version is not MAJOR.MINOR.PATCH")?;
    let staged = staging_dir();
    let result = (|| {
        bundle::stage(Path::new(&req.dir), &staged, &board.board.id).map_err(|e| e.to_string())?;
        let expect = bundle::Expect {
            board_id: &board.board.id,
            profile: &board.openwrt.profile,
            current: &current,
        };
        let verified = bundle::verify(&staged, &pubkey, &expect, req.allow_downgrade)
            .map_err(|e| e.to_string())?;
        let steps = plan::write_plan(&board.storage, &verified.image).map_err(|e| e.to_string())?;
        let disk = board.storage.device.clone();
        plan::check_fit(&steps, |label| partition_size(label, &disk)).map_err(|e| e.to_string())?;
        Ok(UpgradeJob {
            version: verified.version.to_string(),
            image: verified.image_path,
            steps,
            disk,
            wipe_settings: req.wipe_settings,
        })
    })();
    if result.is_err() {
        // Free the RAM the staged image occupies.
        let _ = fs::remove_dir_all(&staged);
    }
    result
}

/// Write the upgrade. Called with every other process gone and the watchdog kept alive.
/// Nothing is written unless pruning, the settings choice and the memory lock all succeed;
/// returns whether the image was written completely.
pub(super) fn run(job: &UpgradeJob) -> bool {
    console_log(format_args!("upgrade to {}: preparing", job.version));
    match apply::prune_upper(&Path::new(DATA_MOUNT).join("upper")) {
        Ok(removed) => console_log(format_args!(
            "upgrade: removed {} entries of the old image from the overlay",
            removed.len()
        )),
        Err(e) => {
            console_log(format_args!(
                "upgrade aborted, nothing written: overlay prune: {e}"
            ));
            return false;
        }
    }
    if job.wipe_settings {
        if let Err(e) = fs::write(factory_reset_marker(), b"1\n") {
            console_log(format_args!(
                "upgrade aborted, nothing written: factory reset marker: {e}"
            ));
            return false;
        }
        console_log(format_args!(
            "upgrade: settings will be reset on first boot"
        ));
    }
    rustix::fs::sync();
    // init runs from the root filesystem about to be overwritten: keep every page of it in
    // RAM so nothing is read back from the partition mid-write.
    if let Err(e) = mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE) {
        console_log(format_args!(
            "upgrade aborted, nothing written: mlockall: {e}"
        ));
        return false;
    }
    let disk = job.disk.as_str();
    let result = apply::execute(
        &job.steps,
        &job.image,
        |label| device_of(label, disk),
        |step| match step {
            WriteStep::Invalidate { partition, .. } => {
                console_log(format_args!("upgrade: invalidating {partition}"));
            }
            WriteStep::Copy { partition, member } => console_log(format_args!(
                "upgrade: writing {partition} ({} bytes)",
                member.size
            )),
        },
    );
    match result {
        Ok(()) => {
            console_log(format_args!(
                "upgrade to {}: written and verified",
                job.version
            ));
            true
        }
        Err(e) => {
            console_log(format_args!(
                "UPGRADE FAILED: {e}. If the kernel was already invalidated the router will \
                 not boot: use the bootloader's recovery (docs/BUILD.md, Flashing)"
            ));
            false
        }
    }
}
