//! Boot-time mount plan.
//!
//! Pure plan builders produce an ordered list of [`MountStep`]s; the Linux module executes
//! them. The kernel mounts the read-only root (`root=PARTLABEL=rootfs`, squashfs) itself, and
//! the image must ship the empty directories `/proc /sys /dev /run /tmp /mnt /overlay /rom`.
//!
//! Boot proceeds in three plan phases so that the failsafe decision can read the persistent
//! partition before choosing how to build the root:
//! 1. [`base_plan`]: pseudo filesystems.
//! 2. [`storage_plan`]: format-if-blank and mount the data partition at [`DATA_MOUNT`].
//! 3. [`root_plan`]: overlay (persistent in [`BootMode::Normal`], tmpfs in
//!    [`BootMode::Failsafe`]) mounted on [`NEW_ROOT`], pseudo filesystems moved in, `pivot_root`.

use std::fmt;
use std::path::PathBuf;

use owr_board::Storage;
use owr_common::paths::RUN_DIR;

/// Where the persistent (or, in failsafe, volatile) data filesystem is mounted.
pub const DATA_MOUNT: &str = "/overlay";
/// Staging mount point of the merged root before `pivot_root`.
pub const NEW_ROOT: &str = "/mnt";
/// Old root appears here (relative to the new root) after `pivot_root`.
pub const OLD_ROOT_DIR: &str = "rom";
/// Filesystem used for the data partition when the board does not say.
pub const DEFAULT_OVERLAY_FS: &str = "f2fs";
/// Leading bytes that must be uniformly `0x00` or `0xFF` for a device to count as blank.
pub const BLANK_PROBE_BYTES: usize = 64 * 1024;
/// Offset of the btrfs superblock magic (`_BHRfS_M`), the furthest magic [`probe_foreign`] reads.
const BTRFS_MAGIC_OFFSET: usize = 0x1_0040;
/// Bytes read from a device before deciding about `mkfs`: covers [`detect_fs`], the blank check
/// and every magic of [`probe_foreign`].
pub const PROBE_BYTES: usize = BTRFS_MAGIC_OFFSET + 8;

/// Whether to boot the persistent configuration or a clean volatile system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Normal,
    Failsafe,
}

impl BootMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Failsafe => "failsafe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountFlag {
    NoSuid,
    NoDev,
    NoExec,
    ReadOnly,
    NoAtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountStep {
    /// Create a directory (and parents); existing directories are fine.
    Mkdir(PathBuf),
    /// `source` may be `PARTLABEL=<name>`, resolved by the executor.
    Mount {
        source: String,
        target: PathBuf,
        fstype: String,
        flags: Vec<MountFlag>,
        data: Option<String>,
        /// A failure aborts boot of this phase; otherwise it is logged and skipped.
        required: bool,
    },
    /// Probe the superblock of `dev` (may be `PARTLABEL=`); `mkfs` it only if it is blank.
    MkfsIfNeeded {
        dev: String,
        fstype: String,
    },
    /// Make the whole tree private so mounts can be moved.
    MakePrivate {
        target: PathBuf,
    },
    Overlay {
        lower: PathBuf,
        upper: PathBuf,
        work: PathBuf,
        target: PathBuf,
    },
    /// `mount --move`
    Move {
        from: PathBuf,
        to: PathBuf,
    },
    /// Best-effort unmount.
    Umount {
        target: PathBuf,
    },
    /// `pivot_root(new_root, new_root/rom)` then `chdir("/")`.
    PivotRoot {
        new_root: PathBuf,
    },
    Symlink {
        target: String,
        link: PathBuf,
    },
}

/// Invalid storage description.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MountPlanError {
    #[error("unsupported overlay filesystem {0:?} (supported: f2fs, ext4)")]
    UnsupportedFs(String),
}

fn mount(
    fstype: &str,
    target: &str,
    flags: &[MountFlag],
    data: Option<&str>,
    required: bool,
) -> MountStep {
    MountStep::Mount {
        source: fstype.to_owned(),
        target: target.into(),
        fstype: fstype.to_owned(),
        flags: flags.to_vec(),
        data: data.map(str::to_owned),
        required,
    }
}

/// Pseudo filesystems every later stage depends on. debugfs is deliberately not mounted.
pub fn base_plan() -> Vec<MountStep> {
    use MountFlag::{NoDev, NoExec, NoSuid};
    let mut steps = vec![
        // hidepid=2: other users' processes are invisible (defence in depth).
        mount(
            "proc",
            "/proc",
            &[NoSuid, NoDev, NoExec],
            Some("hidepid=2"),
            true,
        ),
        mount("sysfs", "/sys", &[NoSuid, NoDev, NoExec], None, true),
        // The kernel may already have mounted devtmpfs (DEVTMPFS_MOUNT): EBUSY is tolerated.
        mount("devtmpfs", "/dev", &[NoSuid], Some("mode=0755"), true),
        MountStep::Mkdir("/dev/pts".into()),
        mount(
            "devpts",
            "/dev/pts",
            &[NoSuid, NoExec],
            Some("gid=5,mode=620,ptmxmode=666"),
            false,
        ),
    ];
    for (target, link) in [
        ("/proc/self/fd", "/dev/fd"),
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
    ] {
        steps.push(MountStep::Symlink {
            target: target.into(),
            link: link.into(),
        });
    }
    steps.extend([
        mount(
            "tmpfs",
            "/run",
            &[NoSuid, NoDev, NoExec],
            Some("mode=0755"),
            true,
        ),
        MountStep::Mkdir(RUN_DIR.into()),
        mount(
            "tmpfs",
            "/tmp",
            &[NoSuid, NoDev, NoExec],
            Some("mode=1777"),
            true,
        ),
        mount(
            "cgroup2",
            "/sys/fs/cgroup",
            &[NoSuid, NoDev, NoExec],
            None,
            false,
        ),
        mount(
            "securityfs",
            "/sys/kernel/security",
            &[NoSuid, NoDev, NoExec],
            None,
            false,
        ),
    ]);
    steps
}

fn overlay_fstype(storage: &Storage) -> Result<&str, MountPlanError> {
    let fs = storage.overlay_fs.as_deref().unwrap_or(DEFAULT_OVERLAY_FS);
    match fs {
        "f2fs" | "ext4" => Ok(fs),
        other => Err(MountPlanError::UnsupportedFs(other.to_owned())),
    }
}

/// Format-if-blank and mount the data partition. Empty if the board has no overlay partition.
pub fn storage_plan(storage: &Storage) -> Result<Vec<MountStep>, MountPlanError> {
    let Some(overlay) = &storage.overlay else {
        return Ok(Vec::new());
    };
    let fs = overlay_fstype(storage)?;
    Ok(vec![
        MountStep::Mkdir(DATA_MOUNT.into()),
        MountStep::MkfsIfNeeded {
            dev: overlay.clone(),
            fstype: fs.to_owned(),
        },
        MountStep::Mount {
            source: overlay.clone(),
            target: DATA_MOUNT.into(),
            fstype: fs.to_owned(),
            flags: vec![MountFlag::NoAtime],
            data: None,
            required: true,
        },
    ])
}

/// `lowerdir=...,upperdir=...,workdir=...` mount data for overlayfs.
pub fn overlay_options(lower: &str, upper: &str, work: &str) -> String {
    format!("lowerdir={lower},upperdir={upper},workdir={work}")
}

/// `parent/name` with a forward slash on every host (plans are Linux paths).
fn child(parent: &str, name: &str) -> PathBuf {
    PathBuf::from(format!("{parent}/{name}"))
}

/// Build the root: overlay, move pseudo filesystems, pivot.
///
/// Normal mode uses `<data>/upper` on the persistent partition. Failsafe mode unmounts the
/// data partition (if mounted) and uses a tmpfs for the upper layer instead, so the device
/// boots from the pristine image while persisted config stays untouched.
pub fn root_plan(has_data_partition: bool, mode: BootMode) -> Vec<MountStep> {
    let data = PathBuf::from(DATA_MOUNT);
    let new_root = PathBuf::from(NEW_ROOT);
    let persistent = mode == BootMode::Normal && has_data_partition;

    let mut steps = vec![MountStep::MakePrivate { target: "/".into() }];
    if !persistent {
        if has_data_partition {
            steps.push(MountStep::Umount {
                target: data.clone(),
            });
        }
        steps.push(mount(
            "tmpfs",
            DATA_MOUNT,
            &[MountFlag::NoSuid, MountFlag::NoDev],
            Some("mode=0755"),
            true,
        ));
    }
    let upper = child(DATA_MOUNT, "upper");
    let work = child(DATA_MOUNT, "work");
    steps.push(MountStep::Mkdir(upper.clone()));
    steps.push(MountStep::Mkdir(work.clone()));
    steps.push(MountStep::Overlay {
        lower: "/".into(),
        upper,
        work,
        target: new_root.clone(),
    });
    // Data first, then pseudo filesystems; /dev carries /dev/pts, /sys carries cgroup.
    let moves = [
        (DATA_MOUNT, "overlay"),
        ("/proc", "proc"),
        ("/sys", "sys"),
        ("/dev", "dev"),
        ("/run", "run"),
        ("/tmp", "tmp"),
    ];
    for (from, name) in moves {
        let to = child(NEW_ROOT, name);
        steps.push(MountStep::Mkdir(to.clone()));
        steps.push(MountStep::Move {
            from: from.into(),
            to,
        });
    }
    steps.push(MountStep::Mkdir(child(NEW_ROOT, OLD_ROOT_DIR)));
    steps.push(MountStep::PivotRoot { new_root });
    steps
}

/// The full ordered plan (what the runtime executes across its three phases).
pub fn plan(storage: &Storage, mode: BootMode) -> Result<Vec<MountStep>, MountPlanError> {
    let mut steps = base_plan();
    steps.extend(storage_plan(storage)?);
    steps.extend(root_plan(storage.overlay.is_some(), mode));
    Ok(steps)
}

/// Filesystem recognised by superblock magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    F2fs,
    Ext4,
}

impl FsKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::F2fs => "f2fs",
            Self::Ext4 => "ext4",
        }
    }
}

const F2FS_MAGIC: u32 = 0xF2F5_2010;
const F2FS_MAGIC_OFFSET: usize = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const EXT_MAGIC_OFFSET: usize = 0x438;

/// Identify a filesystem from the first [`PROBE_BYTES`] of a device.
pub fn detect_fs(head: &[u8]) -> Option<FsKind> {
    let le32 = |at: usize| {
        let b = head.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    let le16 = |at: usize| {
        let b = head.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    };
    if le32(F2FS_MAGIC_OFFSET) == Some(F2FS_MAGIC) {
        Some(FsKind::F2fs)
    } else if le16(EXT_MAGIC_OFFSET) == Some(EXT_MAGIC) {
        Some(FsKind::Ext4)
    } else {
        None
    }
}

/// Is the device blank: its first [`BLANK_PROBE_BYTES`] are all `0x00` (zeroed / discarded
/// flash) or all `0xFF` (erased flash)? A short buffer is never blank, so a truncated read
/// cannot authorise a format.
pub fn is_blank(head: &[u8]) -> bool {
    let Some(lead) = head.get(..BLANK_PROBE_BYTES) else {
        return false;
    };
    lead.iter().all(|b| *b == 0x00) || lead.iter().all(|b| *b == 0xFF)
}

/// Name a few common filesystems/containers we refuse to overwrite. Informational only: it
/// makes the refusal message actionable, it never allows a format.
pub fn probe_foreign(head: &[u8]) -> Option<&'static str> {
    let at = |offset: usize, magic: &[u8]| {
        offset
            .checked_add(magic.len())
            .and_then(|end| head.get(offset..end))
            == Some(magic)
    };
    if at(BTRFS_MAGIC_OFFSET, b"_BHRfS_M") {
        Some("btrfs")
    } else if at(0, b"XFSB") {
        Some("xfs")
    } else if at(0, b"LUKS\xba\xbe") {
        Some("a LUKS container")
    } else if at(0, b"hsqs") {
        Some("squashfs")
    } else {
        None
    }
}

/// What a data partition holds when it is not the expected filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// A supported filesystem other than the expected one.
    Fs(FsKind),
    /// A recognised foreign format (see [`probe_foreign`]).
    Foreign(&'static str),
    /// Not blank, not recognised: possibly valuable data or a damaged filesystem.
    Unrecognized,
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs(kind) => f.write_str(kind.name()),
            Self::Foreign(name) => f.write_str(name),
            Self::Unrecognized => {
                f.write_str("data that is neither blank nor a recognised f2fs/ext4 filesystem")
            }
        }
    }
}

/// What to do about a data partition given what was found on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDecision {
    /// Expected filesystem is present: mount it.
    Present,
    /// Blank device (first 64 KiB all `0x00` or all `0xFF`): first boot, format it.
    Format,
    /// Anything else; never overwrite data we did not create.
    Mismatch(Found),
}

/// Decide from the first [`PROBE_BYTES`] of the device. `mkfs` is authorised only for a blank
/// device: merely lacking an f2fs/ext4 magic is not enough (it may be a damaged filesystem or
/// another format).
pub fn probe_decision(expected: &str, head: &[u8]) -> ProbeDecision {
    match detect_fs(head) {
        Some(found) if found.name() == expected => ProbeDecision::Present,
        Some(other) => ProbeDecision::Mismatch(Found::Fs(other)),
        None => match probe_foreign(head) {
            Some(name) => ProbeDecision::Mismatch(Found::Foreign(name)),
            None if is_blank(head) => ProbeDecision::Format,
            None => ProbeDecision::Mismatch(Found::Unrecognized),
        },
    }
}

/// A `mount` source: either a plain path/pseudo name or a partition label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSpec<'a> {
    PartLabel(&'a str),
    Plain(&'a str),
}

pub fn parse_source(source: &str) -> SourceSpec<'_> {
    source
        .strip_prefix("PARTLABEL=")
        .map_or(SourceSpec::Plain(source), SourceSpec::PartLabel)
}

fn uevent_value<'a>(uevent: &'a str, key: &str) -> Option<&'a str> {
    uevent
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

/// Why a `PARTLABEL=` could not be resolved to exactly one device.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartlabelError {
    #[error("partition not found")]
    NotFound,
    #[error("ambiguous: {} block devices carry this label ({})", .0.len(), .0.join(", "))]
    Ambiguous(Vec<String>),
}

/// Is `devname` (`mmcblk0p6`, `sda2`) a partition of the disk `disk` (`mmcblk0`, `sda`)?
/// Disks whose name ends in a digit separate the partition number with `p`.
fn is_partition_of(disk: &str, devname: &str) -> bool {
    let Some(rest) = devname.strip_prefix(disk) else {
        return false;
    };
    let digits = if disk.ends_with(|c: char| c.is_ascii_digit()) {
        match rest.strip_prefix('p') {
            Some(d) => d,
            None => return false,
        }
    } else {
        rest
    };
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Find `/dev/<DEVNAME>` of the partition whose `PARTNAME=` equals `label`, given the
/// contents of the `uevent` files under `/sys/class/block/*/`. devtmpfs has no
/// `by-partlabel` symlinks without udev, so this replaces them.
///
/// Labels are not unique across devices (a USB stick can carry a `rootfs_data` too), so when
/// `disk` (the board's storage device, e.g. `/dev/mmcblk0`) is known only its own partitions
/// are considered. More than one remaining match is an error rather than a guess.
pub fn resolve_partlabel<'a>(
    uevents: impl IntoIterator<Item = &'a str>,
    label: &str,
    disk: Option<&str>,
) -> Result<String, PartlabelError> {
    let disk_name = disk.map(|d| d.rsplit('/').next().unwrap_or(d));
    let mut found: Vec<String> = uevents
        .into_iter()
        .filter(|u| uevent_value(u, "PARTNAME") == Some(label))
        .filter_map(|u| uevent_value(u, "DEVNAME"))
        .filter(|dev| disk_name.is_none_or(|d| is_partition_of(d, dev)))
        .map(|dev| format!("/dev/{dev}"))
        .collect();
    found.sort();
    found.dedup();
    match found.len() {
        0 => Err(PartlabelError::NotFound),
        1 => found.pop().ok_or(PartlabelError::NotFound),
        _ => Err(PartlabelError::Ambiguous(found)),
    }
}

/// One line of `/proc/self/mountinfo`, reduced to what shutdown needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub target: String,
    pub fstype: String,
}

fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut raw = Vec::new();
    while let Some(&b) = bytes.get(i) {
        let octal = (b == b'\\')
            .then(|| s.get(i.saturating_add(1)..i.saturating_add(4)))
            .flatten()
            .and_then(|d| u8::from_str_radix(d, 8).ok());
        if let Some(v) = octal {
            raw.push(v);
            i = i.saturating_add(4);
        } else {
            raw.push(b);
            i = i.saturating_add(1);
        }
    }
    out.push_str(&String::from_utf8_lossy(&raw));
    out
}

/// Parse `/proc/self/mountinfo`; malformed lines are skipped.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let target = unescape_mountinfo(left.split(' ').nth(4)?);
            let fstype = right.split(' ').next()?.to_owned();
            Some(MountEntry { target, fstype })
        })
        .collect()
}

/// Filesystem type mounted at `/`: the last `/` entry, since a later mount over `/` hides the
/// earlier ones. `None` when there is no `/` entry.
pub fn root_fstype(entries: &[MountEntry]) -> Option<&str> {
    entries
        .iter()
        .rev()
        .find(|e| e.target == "/")
        .map(|e| e.fstype.as_str())
}

/// Filesystems holding writable persistent data that must be quiesced before reboot.
const PERSISTENT_FS: &[&str] = &[
    "f2fs", "ext2", "ext3", "ext4", "vfat", "overlay", "ubifs", "jffs2",
];

/// Mounts to unmount (or remount read-only) at shutdown: persistent filesystems only, newest
/// mount first (reverse of mount order).
pub fn shutdown_order(entries: &[MountEntry]) -> Vec<MountEntry> {
    entries
        .iter()
        .rev()
        .filter(|e| PERSISTENT_FS.contains(&e.fstype.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn board() -> owr_board::Board {
        owr_board::builtin("glinet_gl-mt6000").unwrap()
    }

    fn mount_targets(steps: &[MountStep]) -> Vec<&str> {
        steps
            .iter()
            .filter_map(|s| match s {
                MountStep::Mount { target, .. } => target.to_str(),
                _ => None,
            })
            .collect()
    }

    fn pos(steps: &[MountStep], pred: impl Fn(&MountStep) -> bool) -> usize {
        steps
            .iter()
            .position(pred)
            .unwrap_or_else(|| unreachable!("step not found in {steps:#?}"))
    }

    #[test]
    fn base_plan_mounts_everything_in_order_without_debugfs() {
        let steps = base_plan();
        assert_eq!(
            mount_targets(&steps),
            [
                "/proc",
                "/sys",
                "/dev",
                "/dev/pts",
                "/run",
                "/tmp",
                "/sys/fs/cgroup",
                "/sys/kernel/security"
            ]
        );
        assert!(
            !steps
                .iter()
                .any(|s| matches!(s, MountStep::Mount { fstype, .. } if fstype == "debugfs"))
        );
        // /dev/pts needs a directory on the devtmpfs first.
        assert!(
            pos(&steps, |s| *s == MountStep::Mkdir("/dev/pts".into()))
                < pos(
                    &steps,
                    |s| matches!(s, MountStep::Mount { fstype, .. } if fstype == "devpts")
                )
        );
    }

    #[test]
    fn run_and_tmp_are_hardened_tmpfs() {
        for step in base_plan() {
            if let MountStep::Mount {
                target,
                flags,
                data,
                ..
            } = &step
            {
                let hardened = |f: &[MountFlag]| f.iter().all(|x| flags.contains(x));
                match target.to_str().unwrap() {
                    "/run" | "/tmp" => assert!(
                        hardened(&[MountFlag::NoSuid, MountFlag::NoDev, MountFlag::NoExec]),
                        "{target:?} must be noexec,nosuid,nodev"
                    ),
                    "/proc" => assert_eq!(data.as_deref(), Some("hidepid=2")),
                    "/dev/pts" => assert_eq!(data.as_deref(), Some("gid=5,mode=620,ptmxmode=666")),
                    _ => {}
                }
            }
            let MountStep::Mount {
                target,
                fstype,
                flags,
                data,
                required,
                ..
            } = &step
            else {
                continue;
            };
            match target.to_str().unwrap() {
                "/run" => {
                    assert_eq!(fstype, "tmpfs");
                    assert_eq!(data.as_deref(), Some("mode=0755"));
                    assert!(
                        flags.contains(&MountFlag::NoSuid) && flags.contains(&MountFlag::NoDev)
                    );
                    assert!(required);
                }
                "/tmp" => {
                    assert_eq!(data.as_deref(), Some("mode=1777"));
                    assert!(
                        flags.contains(&MountFlag::NoSuid) && flags.contains(&MountFlag::NoDev)
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn optional_mounts_are_not_required() {
        for step in base_plan() {
            if let MountStep::Mount {
                fstype, required, ..
            } = &step
            {
                let optional = ["cgroup2", "securityfs", "devpts"].contains(&fstype.as_str());
                assert_eq!(*required, !optional, "{fstype}");
            }
        }
    }

    #[test]
    fn storage_plan_formats_then_mounts_partlabel() {
        let steps = storage_plan(&board().storage).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0], MountStep::Mkdir("/overlay".into()));
        assert_eq!(
            steps[1],
            MountStep::MkfsIfNeeded {
                dev: "PARTLABEL=rootfs_data".into(),
                fstype: "f2fs".into()
            }
        );
        match &steps[2] {
            MountStep::Mount {
                source,
                target,
                fstype,
                required,
                ..
            } => {
                assert_eq!(source, "PARTLABEL=rootfs_data");
                assert_eq!(target.to_str(), Some("/overlay"));
                assert_eq!(fstype, "f2fs");
                assert!(required);
            }
            other => unreachable!("{other:?}"),
        }
    }

    #[test]
    fn storage_plan_rejects_unknown_fs_and_skips_missing_overlay() {
        let mut st = board().storage;
        st.overlay_fs = Some("ntfs".into());
        assert_eq!(
            storage_plan(&st),
            Err(MountPlanError::UnsupportedFs("ntfs".into()))
        );
        st.overlay = None;
        assert_eq!(storage_plan(&st), Ok(Vec::new()));
    }

    #[test]
    fn normal_root_plan_uses_persistent_upper_and_pivots_last() {
        let steps = root_plan(true, BootMode::Normal);
        assert!(!steps.iter().any(|s| matches!(s, MountStep::Umount { .. })));
        assert!(
            mount_targets(&steps).is_empty(),
            "normal mode mounts nothing new besides the overlay"
        );
        let ov = pos(&steps, |s| matches!(s, MountStep::Overlay { .. }));
        match &steps[ov] {
            MountStep::Overlay {
                lower,
                upper,
                work,
                target,
            } => {
                assert_eq!(lower.to_str(), Some("/"));
                assert_eq!(upper.to_str(), Some("/overlay/upper"));
                assert_eq!(work.to_str(), Some("/overlay/work"));
                assert_eq!(target.to_str(), Some("/mnt"));
            }
            _ => unreachable!(),
        }
        assert!(
            matches!(steps.last(), Some(MountStep::PivotRoot { new_root }) if new_root.to_str() == Some("/mnt"))
        );
        let moves: Vec<_> = steps
            .iter()
            .filter_map(|s| match s {
                MountStep::Move { from, to } => {
                    Some((from.to_str().unwrap(), to.to_str().unwrap()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            moves,
            [
                ("/overlay", "/mnt/overlay"),
                ("/proc", "/mnt/proc"),
                ("/sys", "/mnt/sys"),
                ("/dev", "/mnt/dev"),
                ("/run", "/mnt/run"),
                ("/tmp", "/mnt/tmp")
            ]
        );
        // Every move target directory is created after the overlay exists (it lives in the upper).
        for (_, to) in &moves {
            let mk = pos(&steps, |s| *s == MountStep::Mkdir((*to).into()));
            assert!(mk > ov);
        }
        // upper/work directories exist before the overlay mount.
        assert!(pos(&steps, |s| *s == MountStep::Mkdir("/overlay/upper".into())) < ov);
        assert!(pos(&steps, |s| *s == MountStep::Mkdir("/overlay/work".into())) < ov);
        assert!(matches!(steps[0], MountStep::MakePrivate { .. }));
    }

    #[test]
    fn failsafe_root_plan_uses_tmpfs_and_leaves_data_untouched() {
        let steps = root_plan(true, BootMode::Failsafe);
        let umount = pos(&steps, |s| {
            *s == MountStep::Umount {
                target: "/overlay".into(),
            }
        });
        let tmpfs = pos(
            &steps,
            |s| matches!(s, MountStep::Mount { fstype, target, .. } if fstype == "tmpfs" && target.to_str() == Some("/overlay")),
        );
        let ov = pos(&steps, |s| matches!(s, MountStep::Overlay { .. }));
        assert!(umount < tmpfs && tmpfs < ov);
        // Nothing in failsafe writes to the persistent partition: no mkfs, no data mount.
        assert!(
            !steps
                .iter()
                .any(|s| matches!(s, MountStep::MkfsIfNeeded { .. }))
        );
        assert!(!steps.iter().any(
            |s| matches!(s, MountStep::Mount { source, .. } if source.starts_with("PARTLABEL="))
        ));
    }

    #[test]
    fn board_without_overlay_boots_from_tmpfs_even_in_normal_mode() {
        let steps = root_plan(false, BootMode::Normal);
        assert!(
            !steps.iter().any(|s| matches!(s, MountStep::Umount { .. })),
            "nothing mounted to unmount"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, MountStep::Mount { fstype, .. } if fstype == "tmpfs"))
        );
    }

    #[test]
    fn full_plan_concatenates_phases() {
        let b = board();
        let full = plan(&b.storage, BootMode::Normal).unwrap();
        let mut expect = base_plan();
        expect.extend(storage_plan(&b.storage).unwrap());
        expect.extend(root_plan(true, BootMode::Normal));
        assert_eq!(full, expect);
        let failsafe = plan(&b.storage, BootMode::Failsafe).unwrap();
        assert!(
            pos(
                &failsafe,
                |s| matches!(s, MountStep::Mount { source, .. } if source == "PARTLABEL=rootfs_data")
            ) < pos(&failsafe, |s| matches!(s, MountStep::Umount { .. })),
            "data is mounted for the boot decision, then released"
        );
    }

    #[test]
    fn overlay_option_string() {
        assert_eq!(
            overlay_options("/", "/overlay/upper", "/overlay/work"),
            "lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work"
        );
    }

    fn sb(len: usize, patches: &[(usize, &[u8])]) -> Vec<u8> {
        let mut v = vec![0u8; len];
        for (at, bytes) in patches {
            v[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        v
    }

    #[test]
    fn detects_f2fs_and_ext4_magic() {
        assert_eq!(
            detect_fs(&sb(2048, &[(1024, &[0x10, 0x20, 0xF5, 0xF2])])),
            Some(FsKind::F2fs)
        );
        assert_eq!(
            detect_fs(&sb(2048, &[(0x438, &[0x53, 0xEF])])),
            Some(FsKind::Ext4)
        );
        assert_eq!(detect_fs(&sb(2048, &[])), None, "zeroed device is blank");
        // Big-endian byte order must not match.
        assert_eq!(
            detect_fs(&sb(2048, &[(1024, &[0xF2, 0xF5, 0x20, 0x10])])),
            None
        );
        // Truncated reads never match or panic.
        assert_eq!(detect_fs(&[]), None);
        assert_eq!(detect_fs(&sb(1026, &[(1024, &[0x10, 0x20])])), None);
        assert_eq!(detect_fs(&sb(0x439, &[])), None);
    }

    #[test]
    fn probe_decisions_never_overwrite_foreign_filesystems() {
        let f2fs = sb(PROBE_BYTES, &[(1024, &[0x10, 0x20, 0xF5, 0xF2])]);
        let ext4 = sb(PROBE_BYTES, &[(0x438, &[0x53, 0xEF])]);
        assert_eq!(probe_decision("f2fs", &f2fs), ProbeDecision::Present);
        assert_eq!(probe_decision("ext4", &ext4), ProbeDecision::Present);
        assert_eq!(
            probe_decision("f2fs", &sb(PROBE_BYTES, &[])),
            ProbeDecision::Format
        );
        assert_eq!(
            probe_decision("f2fs", &ext4),
            ProbeDecision::Mismatch(Found::Fs(FsKind::Ext4))
        );
        assert_eq!(
            probe_decision("ext4", &f2fs),
            ProbeDecision::Mismatch(Found::Fs(FsKind::F2fs))
        );
    }

    #[test]
    fn only_a_blank_device_is_formatted() {
        // All-zero and all-0xFF (erased flash) are blank.
        assert_eq!(
            probe_decision("f2fs", &vec![0xFF; PROBE_BYTES]),
            ProbeDecision::Format
        );
        // Lacking an f2fs/ext magic is not enough: one stray byte anywhere in the first 64 KiB.
        for at in [0, 5000, BLANK_PROBE_BYTES - 1] {
            assert_eq!(
                probe_decision("f2fs", &sb(PROBE_BYTES, &[(at, &[1])])),
                ProbeDecision::Mismatch(Found::Unrecognized),
                "byte at {at}"
            );
        }
        let mut mixed = vec![0xFF; PROBE_BYTES];
        mixed[10] = 0;
        assert_eq!(
            probe_decision("f2fs", &mixed),
            ProbeDecision::Mismatch(Found::Unrecognized)
        );
        // Truncated reads are never blank.
        assert!(!is_blank(&[]));
        assert!(!is_blank(&vec![0; BLANK_PROBE_BYTES - 1]));
        assert!(is_blank(&vec![0; BLANK_PROBE_BYTES]));
        assert_eq!(
            probe_decision("f2fs", &[]),
            ProbeDecision::Mismatch(Found::Unrecognized)
        );
    }

    #[test]
    fn common_foreign_formats_are_named_in_the_refusal() {
        let cases: [(usize, &[u8], &str); 4] = [
            (0x10040, b"_BHRfS_M", "btrfs"),
            (0, b"XFSB", "xfs"),
            (0, b"LUKS\xba\xbe", "a LUKS container"),
            (0, b"hsqs", "squashfs"),
        ];
        for (at, magic, name) in cases {
            let head = sb(PROBE_BYTES, &[(at, magic)]);
            assert_eq!(probe_foreign(&head), Some(name));
            let decision = probe_decision("f2fs", &head);
            assert_eq!(decision, ProbeDecision::Mismatch(Found::Foreign(name)));
            assert_ne!(decision, ProbeDecision::Format);
        }
        assert_eq!(probe_foreign(&sb(PROBE_BYTES, &[])), None);
        assert_eq!(probe_foreign(&[]), None);
        assert_eq!(Found::Foreign("btrfs").to_string(), "btrfs");
        assert!(Found::Unrecognized.to_string().contains("neither blank"));
    }

    #[test]
    fn parses_sources() {
        assert_eq!(
            parse_source("PARTLABEL=rootfs_data"),
            SourceSpec::PartLabel("rootfs_data")
        );
        assert_eq!(
            parse_source("/dev/mmcblk0p6"),
            SourceSpec::Plain("/dev/mmcblk0p6")
        );
        assert_eq!(parse_source("tmpfs"), SourceSpec::Plain("tmpfs"));
    }

    #[test]
    fn resolves_partlabel_from_uevent_files() {
        let disk = "MAJOR=179\nMINOR=0\nDEVNAME=mmcblk0\nDEVTYPE=disk\n";
        let p5 =
            "MAJOR=179\nMINOR=5\nDEVNAME=mmcblk0p5\nDEVTYPE=partition\nPARTN=5\nPARTNAME=rootfs\n";
        let p6 = "MAJOR=179\nMINOR=6\nDEVNAME=mmcblk0p6\nDEVTYPE=partition\nPARTN=6\nPARTNAME=rootfs_data\n";
        let all = [disk, p5, p6];
        assert_eq!(
            resolve_partlabel(all, "rootfs_data", None).as_deref(),
            Ok("/dev/mmcblk0p6")
        );
        assert_eq!(
            resolve_partlabel(all, "rootfs", Some("/dev/mmcblk0")).as_deref(),
            Ok("/dev/mmcblk0p5"),
            "prefix must not match"
        );
        assert_eq!(
            resolve_partlabel(all, "missing", None),
            Err(PartlabelError::NotFound)
        );
        assert_eq!(
            resolve_partlabel(["PARTNAME=x\n"], "x", None),
            Err(PartlabelError::NotFound),
            "no DEVNAME"
        );
    }

    #[test]
    fn duplicate_partlabels_are_ambiguous_unless_the_board_disk_disambiguates() {
        let emmc = "DEVNAME=mmcblk0p6\nPARTNAME=rootfs_data\n";
        let usb = "DEVNAME=sda1\nPARTNAME=rootfs_data\n";
        let all = [usb, emmc];
        // Unknown board device: refuse to guess.
        assert_eq!(
            resolve_partlabel(all, "rootfs_data", None),
            Err(PartlabelError::Ambiguous(vec![
                "/dev/mmcblk0p6".into(),
                "/dev/sda1".into()
            ]))
        );
        // Known board device: only its own partitions count.
        assert_eq!(
            resolve_partlabel(all, "rootfs_data", Some("/dev/mmcblk0")).as_deref(),
            Ok("/dev/mmcblk0p6")
        );
        assert_eq!(
            resolve_partlabel(all, "rootfs_data", Some("/dev/sda")).as_deref(),
            Ok("/dev/sda1")
        );
        // Two matches on the board's own disk are still ambiguous.
        let twin = "DEVNAME=mmcblk0p7\nPARTNAME=rootfs_data\n";
        assert!(matches!(
            resolve_partlabel([emmc, twin, usb], "rootfs_data", Some("/dev/mmcblk0")),
            Err(PartlabelError::Ambiguous(v)) if v.len() == 2
        ));
        // Only foreign devices carry the label: not found, not a wrong match.
        assert_eq!(
            resolve_partlabel([usb], "rootfs_data", Some("/dev/mmcblk0")),
            Err(PartlabelError::NotFound)
        );
    }

    #[test]
    fn partition_names_follow_the_disk_name() {
        assert!(is_partition_of("mmcblk0", "mmcblk0p6"));
        assert!(!is_partition_of("mmcblk0", "mmcblk0"));
        assert!(
            !is_partition_of("mmcblk0", "mmcblk01"),
            "needs the p separator"
        );
        assert!(!is_partition_of("mmcblk0", "mmcblk0boot0"));
        assert!(!is_partition_of("mmcblk0", "mmcblk1p6"));
        assert!(is_partition_of("sda", "sda12"));
        assert!(!is_partition_of("sda", "sdab1"));
        assert!(!is_partition_of("sda", "sda"));
    }

    const MOUNTINFO: &str = "\
22 1 0:20 / / rw,relatime shared:1 - overlay overlay rw,lowerdir=/
23 22 0:21 / /proc rw,nosuid,nodev,noexec - proc proc rw
24 22 179:6 / /overlay rw,noatime - f2fs /dev/mmcblk0p6 rw
25 22 0:22 / /tmp rw,nosuid - tmpfs tmpfs rw
26 22 179:7 / /mnt/with\\040space rw - ext4 /dev/sda1 rw
garbage line
";

    #[test]
    fn parses_mountinfo_and_orders_shutdown_newest_first() {
        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries[0],
            MountEntry {
                target: "/".into(),
                fstype: "overlay".into()
            }
        );
        assert_eq!(entries[4].target, "/mnt/with space");
        let order: Vec<_> = shutdown_order(&entries)
            .into_iter()
            .map(|e| e.target)
            .collect();
        assert_eq!(order, ["/mnt/with space", "/overlay", "/"]);
    }

    #[test]
    fn root_fstype_is_the_topmost_root_mount() {
        assert_eq!(root_fstype(&parse_mountinfo(MOUNTINFO)), Some("overlay"));
        // Initramfs boot after OpenWrt's /init switch_root: the tmpfs hides the initial rootfs.
        let initramfs = "\
1 1 0:2 / / rw - rootfs rootfs rw
20 1 0:19 / / rw,relatime - tmpfs tmpfs rw
21 20 0:20 / /proc rw - proc proc rw
";
        assert_eq!(root_fstype(&parse_mountinfo(initramfs)), Some("tmpfs"));
        let flash = "15 1 179:5 / / ro,relatime - squashfs /dev/root ro\n";
        assert_eq!(root_fstype(&parse_mountinfo(flash)), Some("squashfs"));
        assert_eq!(root_fstype(&parse_mountinfo("garbage\n")), None);
    }
}
