//! Executes [`MountStep`]s with `rustix`.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use rustix::io::Errno;
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_change, mount_move, unmount,
};

use crate::mounts::{
    MountFlag, MountStep, OLD_ROOT_DIR, PROBE_BYTES, PartlabelError, ProbeDecision, SourceSpec,
    overlay_options, parse_source, probe_decision, resolve_partlabel,
};

/// A step that must succeed failed.
#[derive(Debug, thiserror::Error)]
#[error("{step}: {detail}")]
pub(super) struct StepError {
    step: String,
    detail: String,
}

fn fail(step: impl Into<String>, detail: impl Into<String>) -> StepError {
    StepError {
        step: step.into(),
        detail: detail.into(),
    }
}

fn mount_flags(flags: &[MountFlag]) -> MountFlags {
    flags.iter().fold(MountFlags::empty(), |acc, f| {
        acc | match f {
            MountFlag::NoSuid => MountFlags::NOSUID,
            MountFlag::NoDev => MountFlags::NODEV,
            MountFlag::NoExec => MountFlags::NOEXEC,
            MountFlag::ReadOnly => MountFlags::RDONLY,
            MountFlag::NoAtime => MountFlags::NOATIME,
        }
    })
}

/// How long to wait for a partition to show up (eMMC probing is asynchronous).
const DEVICE_WAIT_ATTEMPTS: u32 = 50;
const DEVICE_WAIT_STEP: Duration = Duration::from_millis(100);

/// Resolve `PARTLABEL=x` through sysfs (`/sys/class/block/*/uevent`), or pass a path through.
/// `disk` is the board's storage device (`/dev/mmcblk0`); when known, only its partitions match.
/// A label carried by several devices is an error (retrying cannot fix it), not a guess.
fn resolve_device(source: &str, disk: Option<&str>) -> Result<String, StepError> {
    let SourceSpec::PartLabel(label) = parse_source(source) else {
        return Ok(source.to_owned());
    };
    let step = format!("resolve PARTLABEL={label}");
    for _ in 0..DEVICE_WAIT_ATTEMPTS {
        let uevents: Vec<String> = fs::read_dir("/sys/class/block")
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter_map(|e| fs::read_to_string(e.path().join("uevent")).ok())
                    .collect()
            })
            .unwrap_or_default();
        match resolve_partlabel(uevents.iter().map(String::as_str), label, disk) {
            Ok(dev) if Path::new(&dev).exists() => return Ok(dev),
            Ok(_) | Err(PartlabelError::NotFound) => {}
            Err(e @ PartlabelError::Ambiguous(_)) => return Err(fail(&step, e.to_string())),
        }
        sleep(DEVICE_WAIT_STEP);
    }
    Err(fail(&step, PartlabelError::NotFound.to_string()))
}

fn mkfs_if_needed(dev: &str, fstype: &str, disk: Option<&str>) -> Result<(), StepError> {
    let step = format!("mkfs-if-needed {dev} ({fstype})");
    let path = resolve_device(dev, disk)?;
    let mut head = vec![0u8; PROBE_BYTES];
    // A read error must never be mistaken for "blank": formatting would destroy data.
    File::open(&path)
        .and_then(|mut f| f.read_exact(&mut head))
        .map_err(|e| fail(&step, format!("probing {path}: {e}")))?;
    match probe_decision(fstype, &head) {
        ProbeDecision::Present => Ok(()),
        ProbeDecision::Mismatch(found) => Err(fail(
            &step,
            format!(
                "{path} holds {found} and not a blank {fstype} target; refusing to overwrite \
                 (data preserved, booting failsafe)"
            ),
        )),
        ProbeDecision::Format => {
            tracing::warn!("{path}: blank device, formatting as {fstype} (first boot)");
            let label = match parse_source(dev) {
                SourceSpec::PartLabel(l) | SourceSpec::Plain(l) => {
                    l.rsplit('/').next().unwrap_or(l)
                }
            };
            let status = match fstype {
                "f2fs" => Command::new("/usr/sbin/mkfs.f2fs")
                    .args(["-f", "-l", label, &path])
                    .status(),
                _ => Command::new("/usr/sbin/mkfs.ext4")
                    .args(["-F", "-L", label, &path])
                    .status(),
            };
            match status {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => Err(fail(&step, format!("mkfs exited with {s}"))),
                Err(e) => Err(fail(&step, format!("running mkfs: {e}"))),
            }
        }
    }
}

fn do_mount(step: &MountStep, disk: Option<&str>) -> Result<(), StepError> {
    let MountStep::Mount {
        source,
        target,
        fstype,
        flags,
        data,
        required,
    } = step
    else {
        return Ok(());
    };
    let name = format!("mount {fstype} on {}", target.display());
    let result = (|| {
        let src = resolve_device(source, disk)?;
        let data_c = data
            .as_deref()
            .map(CString::new)
            .transpose()
            .map_err(|e| fail(&name, e.to_string()))?;
        match mount(
            src.as_str(),
            target,
            fstype.as_str(),
            mount_flags(flags),
            data_c.as_deref(),
        ) {
            Ok(()) => Ok(()),
            // Already mounted (e.g. kernel DEVTMPFS_MOUNT).
            Err(Errno::BUSY) => {
                tracing::debug!("{name}: already mounted");
                Ok(())
            }
            Err(e) => Err(fail(&name, io::Error::from(e).to_string())),
        }
    })();
    match result {
        Err(e) if !required => {
            tracing::warn!("optional step failed: {e}");
            Ok(())
        }
        other => other,
    }
}

fn run_step(step: &MountStep, disk: Option<&str>) -> Result<(), StepError> {
    match step {
        MountStep::Mkdir(p) => {
            if !p.is_dir() {
                // Read-only root: image-provided directories are expected to exist already.
                if let Err(e) = fs::create_dir_all(p) {
                    tracing::warn!("mkdir {}: {e}", p.display());
                }
            }
            Ok(())
        }
        MountStep::Mount { .. } => do_mount(step, disk),
        MountStep::MkfsIfNeeded { dev, fstype } => mkfs_if_needed(dev, fstype, disk),
        MountStep::MakePrivate { target } => {
            if let Err(e) = mount_change(
                target,
                MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
            ) {
                tracing::warn!("make-rprivate {}: {e}", target.display());
            }
            Ok(())
        }
        MountStep::Overlay {
            lower,
            upper,
            work,
            target,
        } => {
            let opts = overlay_options(
                &lower.to_string_lossy(),
                &upper.to_string_lossy(),
                &work.to_string_lossy(),
            );
            let data = CString::new(opts).map_err(|e| fail("overlay options", e.to_string()))?;
            mount(
                "overlay",
                target,
                "overlay",
                MountFlags::empty(),
                Some(data.as_c_str()),
            )
            .map_err(|e| {
                fail(
                    format!("overlay on {}", target.display()),
                    io::Error::from(e).to_string(),
                )
            })
        }
        MountStep::Move { from, to } => mount_move(from, to).map_err(|e| {
            fail(
                format!("move {} -> {}", from.display(), to.display()),
                io::Error::from(e).to_string(),
            )
        }),
        MountStep::Umount { target } => {
            if let Err(e) = unmount(target, UnmountFlags::empty()) {
                tracing::warn!("umount {}: {e}", target.display());
            }
            Ok(())
        }
        MountStep::PivotRoot { new_root } => {
            let old = new_root.join(OLD_ROOT_DIR);
            rustix::process::pivot_root(new_root, &old).map_err(|e| {
                fail(
                    format!("pivot_root {}", new_root.display()),
                    io::Error::from(e).to_string(),
                )
            })?;
            rustix::process::chdir("/").map_err(|e| fail("chdir /", io::Error::from(e).to_string()))
        }
        MountStep::Symlink { target, link } => match rustix::fs::symlink(target.as_str(), link) {
            Ok(()) | Err(Errno::EXIST) => Ok(()),
            Err(e) => {
                tracing::warn!("symlink {}: {e}", link.display());
                Ok(())
            }
        },
    }
}

/// Run steps in order; stops at the first failing required step. `disk` is the board's storage
/// device (e.g. `/dev/mmcblk0`), used to disambiguate `PARTLABEL=` sources.
pub(super) fn run_steps(steps: &[MountStep], disk: Option<&str>) -> Result<(), StepError> {
    for step in steps {
        run_step(step, disk)?;
    }
    Ok(())
}
