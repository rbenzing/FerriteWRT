//! Boot sequencing: failsafe detection, the boot-failure counter and the "reached running"
//! tracker.
//!
//! Failsafe is entered when, in priority order:
//! 1. the reset button is pressed during the first [`BUTTON_WINDOW_MS`] after the input device
//!    was opened, see [`ButtonWindow`] (the LED fast-blinks as the prompt, like `OpenWrt`),
//! 2. the kernel command line contains `owr.failsafe=1`,
//! 3. the marker file `/etc/ferritewrt/failsafe` exists (consumed on use),
//! 4. [`MAX_FAILED_BOOTS`] consecutive boots did not reach "running" within
//!    [`RUNNING_DEADLINE`] (counter in `/etc/ferritewrt/bootcount`),
//! 5. the data partition could not be mounted.
//!
//! The counter and marker live on the persistent partition, which is mounted before the
//! decision (see [`crate::mounts`]); paths below are relative to the data partition's `upper/`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use owr_common::paths::CONFIG_DIR;

use crate::mounts::{BootMode, DATA_MOUNT};

/// How long after init starts a button press forces failsafe.
pub const BUTTON_WINDOW_MS: u64 = 2000;
/// Consecutive failed boots that trigger failsafe on the next boot.
pub const MAX_FAILED_BOOTS: u32 = 3;
/// A boot must reach "running" within this time or it counts as failed.
pub const RUNNING_DEADLINE: Duration = Duration::from_secs(120);
/// Kernel command line switch that forces failsafe.
pub const CMDLINE_FLAG: &str = "owr.failsafe=1";
/// Marker file (inside the persistent config dir) that forces failsafe on the next boot.
pub const MARKER_NAME: &str = "failsafe";
/// Boot counter file name (inside the persistent config dir).
pub const BOOTCOUNT_NAME: &str = "bootcount";
/// Hostname when the config has none.
pub const DEFAULT_HOSTNAME: &str = "ferritewrt";

/// Why failsafe was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailsafeReason {
    Button,
    Cmdline,
    Marker,
    BootLoop,
    StorageError,
}

impl FailsafeReason {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Button => "reset button pressed during boot window",
            Self::Cmdline => "kernel cmdline owr.failsafe=1",
            Self::Marker => "failsafe marker file present",
            Self::BootLoop => "3 consecutive boots failed to reach running",
            Self::StorageError => "data partition unavailable",
        }
    }
}

/// Facts gathered before choosing the boot mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootInputs<'a> {
    pub button_pressed: bool,
    pub cmdline: &'a str,
    pub marker_present: bool,
    /// Value read from the boot counter file (0 if absent).
    pub failed_boots: u32,
    pub storage_ok: bool,
}

/// Outcome of [`decide`], including the persistent side effects to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootDecision {
    pub mode: BootMode,
    pub reason: Option<FailsafeReason>,
    /// New counter value to persist, or `None` to leave the file alone.
    pub write_bootcount: Option<u32>,
    /// Delete the marker file (it is one-shot).
    pub consume_marker: bool,
}

/// Filesystem types of a RAM-backed `/`: the kernel's initial `rootfs` (ramfs or tmpfs), or
/// the tmpfs that `OpenWrt`'s initramfs `/init` copies itself into before `switch_root`
/// (`target/linux/generic/other-files/init`).
const RAM_ROOT_FS: &[&str] = &["rootfs", "ramfs", "tmpfs"];

/// Booted from an initramfs (test image): `/` is RAM-backed. `root_fstype` is the filesystem
/// type mounted at `/` ([`crate::mounts::root_fstype`]).
///
/// In that case init must not touch the eMMC data partition: no probe, no mkfs, no overlay,
/// no `pivot_root` (the initramfs root is already RAM-backed and writable). Boot counter and
/// journal persistence are skipped as well.
///
/// The kernel command line cannot tell: the GL-MT6000 DTS appends `root=PARTLABEL=rootfs` to
/// every boot (`bootargs-append`), and the initramfs image carries the same DTB. An unknown
/// root type counts as initramfs, so a doubt never leads to writing flash.
pub fn is_initramfs_boot(root_fstype: Option<&str>) -> bool {
    root_fstype.is_none_or(|t| RAM_ROOT_FS.contains(&t))
}

pub fn cmdline_requests_failsafe(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|w| w == CMDLINE_FLAG)
}

/// Is a press at `elapsed_ms` after the window opened inside the failsafe window?
pub fn in_button_window(elapsed_ms: u64) -> bool {
    elapsed_ms <= BUTTON_WINDOW_MS
}

/// The failsafe button window. It starts when the `gpio-keys` device is opened, not when init
/// starts: mounting (and possibly formatting) the data partition happens first and can take
/// longer than the window itself, which would otherwise expire before anyone could press.
#[derive(Debug, Clone, Copy)]
pub struct ButtonWindow {
    opened: Instant,
}

impl ButtonWindow {
    /// The input device was opened at `opened`.
    pub fn open(opened: Instant) -> Self {
        Self { opened }
    }

    pub fn is_open(&self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.opened);
        in_button_window(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
    }
}

/// Why a factory-reset request cannot be honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FactoryResetRefusal {
    #[error(
        "failsafe boot: /overlay is a volatile tmpfs, the marker would be lost; reboot normally and retry"
    )]
    Failsafe,
    #[error("no persistent data partition is mounted; nothing to reset")]
    NotPersistent,
}

/// Where to write the factory-reset marker at run time. `/overlay` is the real data partition
/// only in a persistent normal boot; in failsafe it is a tmpfs, and a marker written there would
/// vanish at reboot while the user believes the reset was scheduled. Refuse instead of lying.
pub fn factory_reset_target(
    mode: BootMode,
    persistent: bool,
) -> Result<PathBuf, FactoryResetRefusal> {
    match (mode, persistent) {
        (BootMode::Failsafe, _) => Err(FactoryResetRefusal::Failsafe),
        (BootMode::Normal, false) => Err(FactoryResetRefusal::NotPersistent),
        (BootMode::Normal, true) => Ok(factory_reset_marker()),
    }
}

/// Parse the counter file; anything unreadable counts as 0 so a corrupt file cannot lock the
/// device into failsafe.
pub fn parse_bootcount(text: &str) -> u32 {
    text.trim().parse().unwrap_or(0)
}

pub fn format_bootcount(n: u32) -> String {
    format!("{n}\n")
}

/// Choose the boot mode and the counter/marker updates.
///
/// A normal boot increments the counter immediately (it is reset to 0 once the boot reaches
/// "running", see [`BootTracker`]). A failsafe boot does not count as a failed boot, and if
/// the counter had reached the limit it is reset so the following boot is normal again.
pub fn decide(inputs: &BootInputs<'_>) -> BootDecision {
    let boot_loop = inputs.failed_boots >= MAX_FAILED_BOOTS;
    let reason = if inputs.button_pressed {
        Some(FailsafeReason::Button)
    } else if cmdline_requests_failsafe(inputs.cmdline) {
        Some(FailsafeReason::Cmdline)
    } else if inputs.marker_present {
        Some(FailsafeReason::Marker)
    } else if boot_loop {
        Some(FailsafeReason::BootLoop)
    } else if !inputs.storage_ok {
        Some(FailsafeReason::StorageError)
    } else {
        None
    };
    match reason {
        None => BootDecision {
            mode: BootMode::Normal,
            reason: None,
            write_bootcount: Some(inputs.failed_boots.saturating_add(1)),
            consume_marker: false,
        },
        Some(reason) => BootDecision {
            mode: BootMode::Failsafe,
            reason: Some(reason),
            write_bootcount: boot_loop.then_some(0),
            consume_marker: inputs.marker_present,
        },
    }
}

/// Steps after the mode is known (pre-decision mounting is fixed and always runs first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    /// Build the root overlay and `pivot_root`.
    RootSwitch,
    Hostname,
    /// Run `/sbin/kmodloader` (bounded) so drivers exist before devices are replayed.
    KmodLoader,
    /// Replay `add` uevents for devices that appeared before the listener existed.
    Coldplug,
    /// Start the configured services under supervision.
    Services,
    /// Failsafe: only a console shell.
    RescueShell,
}

/// The ordered post-decision boot sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPlan {
    pub mode: BootMode,
    pub reason: Option<FailsafeReason>,
    pub phases: Vec<BootPhase>,
}

impl BootPlan {
    pub fn from_decision(d: &BootDecision) -> Self {
        let last = match d.mode {
            BootMode::Normal => BootPhase::Services,
            BootMode::Failsafe => BootPhase::RescueShell,
        };
        Self {
            mode: d.mode,
            reason: d.reason,
            phases: vec![
                BootPhase::RootSwitch,
                BootPhase::Hostname,
                BootPhase::KmodLoader,
                BootPhase::Coldplug,
                last,
            ],
        }
    }
}

/// Observation made on each supervisor tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Booting,
    /// Reported exactly once, on the tick the boot becomes "running".
    JustReached,
    Running,
    /// Not running after [`RUNNING_DEADLINE`]; stays overdue until it does.
    Overdue,
}

/// Latches "the boot reached running" and detects the deadline.
#[derive(Debug, Clone, Copy)]
pub struct BootTracker {
    start: Instant,
    reached: bool,
    overdue: bool,
}

impl BootTracker {
    pub fn new(start: Instant) -> Self {
        Self {
            start,
            reached: false,
            overdue: false,
        }
    }

    /// `settled`: every service that should be up is up (see `Manager::settled`).
    pub fn observe(&mut self, now: Instant, settled: bool) -> Progress {
        if self.reached {
            Progress::Running
        } else if settled {
            self.reached = true;
            // Late is better than never: a boot that got there after the deadline is running.
            self.overdue = false;
            Progress::JustReached
        } else if now.saturating_duration_since(self.start) > RUNNING_DEADLINE {
            self.overdue = true;
            Progress::Overdue
        } else {
            Progress::Booting
        }
    }

    /// The boot has reached "running" (latched).
    pub fn reached(&self) -> bool {
        self.reached
    }

    /// The deadline passed and the boot is still not running; cleared once it is.
    pub fn overdue(&self) -> bool {
        self.overdue
    }
}

/// Valid RFC 1123 host name label (what the kernel and DHCP clients accept).
pub fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Extract the hostname from `config.toml` (`[system] hostname = "..."`), if present and valid.
/// Kept tolerant on purpose: init must not depend on the config schema version.
pub fn hostname_from_config(text: &str) -> Option<String> {
    let table: toml::Table = text.parse().ok()?;
    let name = table.get("system")?.get("hostname")?.as_str()?;
    valid_hostname(name).then(|| name.to_owned())
}

/// Persistent config directory as seen *before* `pivot_root` (inside the data partition).
pub fn data_config_dir() -> PathBuf {
    PathBuf::from(format!("{DATA_MOUNT}/upper{CONFIG_DIR}"))
}

/// One-shot marker (pre-pivot path): wipe the persistent overlay on the next boot.
pub fn factory_reset_marker() -> PathBuf {
    PathBuf::from(format!("{DATA_MOUNT}/.factory-reset"))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn inputs() -> BootInputs<'static> {
        BootInputs {
            button_pressed: false,
            cmdline: "console=ttyS0,115200n1 root=PARTLABEL=rootfs rootwait",
            marker_present: false,
            failed_boots: 0,
            storage_ok: true,
        }
    }

    #[test]
    fn normal_boot_increments_counter() {
        let d = decide(&inputs());
        assert_eq!(d.mode, BootMode::Normal);
        assert_eq!(d.reason, None);
        assert_eq!(d.write_bootcount, Some(1));
        assert!(!d.consume_marker);
        let d = decide(&BootInputs {
            failed_boots: 2,
            ..inputs()
        });
        assert_eq!((d.mode, d.write_bootcount), (BootMode::Normal, Some(3)));
    }

    #[test]
    fn third_consecutive_failure_triggers_failsafe_and_resets_counter() {
        let d = decide(&BootInputs {
            failed_boots: MAX_FAILED_BOOTS,
            ..inputs()
        });
        assert_eq!(d.mode, BootMode::Failsafe);
        assert_eq!(d.reason, Some(FailsafeReason::BootLoop));
        assert_eq!(d.write_bootcount, Some(0), "next boot must be normal again");
        // Corrupt/huge counters still just mean failsafe, never overflow.
        let d = decide(&BootInputs {
            failed_boots: u32::MAX,
            ..inputs()
        });
        assert_eq!(d.reason, Some(FailsafeReason::BootLoop));
    }

    #[test]
    fn full_sequence_of_failed_boots() {
        // Simulate: boots 1..=3 never reach running, boot 4 is failsafe, boot 5 is normal.
        let mut count = 0;
        let mut modes = Vec::new();
        for _ in 0..5 {
            let d = decide(&BootInputs {
                failed_boots: count,
                ..inputs()
            });
            modes.push(d.mode);
            if let Some(n) = d.write_bootcount {
                count = n;
            }
        }
        let (n, f) = (BootMode::Normal, BootMode::Failsafe);
        assert_eq!(modes, [n, n, n, f, n]);
    }

    #[test]
    fn reaching_running_resets_counter_so_boots_stay_normal() {
        let mut count = 0;
        for _ in 0..10 {
            let d = decide(&BootInputs {
                failed_boots: count,
                ..inputs()
            });
            assert_eq!(d.mode, BootMode::Normal);
            assert_eq!(d.write_bootcount, Some(count + 1));
            count = 0; // tracker reached running -> init wrote 0
        }
    }

    #[test]
    fn button_cmdline_marker_each_force_failsafe_without_counting() {
        let d = decide(&BootInputs {
            button_pressed: true,
            failed_boots: 1,
            ..inputs()
        });
        assert_eq!(
            (d.mode, d.reason),
            (BootMode::Failsafe, Some(FailsafeReason::Button))
        );
        assert_eq!(
            d.write_bootcount, None,
            "user-requested failsafe is not a failed boot"
        );

        let d = decide(&BootInputs {
            cmdline: "quiet owr.failsafe=1",
            ..inputs()
        });
        assert_eq!(d.reason, Some(FailsafeReason::Cmdline));

        let d = decide(&BootInputs {
            marker_present: true,
            ..inputs()
        });
        assert_eq!(d.reason, Some(FailsafeReason::Marker));
        assert!(d.consume_marker);
    }

    #[test]
    fn priority_button_over_cmdline_over_marker_over_bootloop() {
        let all = BootInputs {
            button_pressed: true,
            cmdline: "owr.failsafe=1",
            marker_present: true,
            failed_boots: 9,
            storage_ok: false,
        };
        assert_eq!(decide(&all).reason, Some(FailsafeReason::Button));
        let d = decide(&BootInputs {
            button_pressed: false,
            ..all.clone()
        });
        assert_eq!(d.reason, Some(FailsafeReason::Cmdline));
        let d = decide(&BootInputs {
            button_pressed: false,
            cmdline: "",
            ..all.clone()
        });
        assert_eq!(d.reason, Some(FailsafeReason::Marker));
        let d = decide(&BootInputs {
            marker_present: false,
            button_pressed: false,
            cmdline: "",
            ..all.clone()
        });
        assert_eq!(d.reason, Some(FailsafeReason::BootLoop));
        let d = decide(&BootInputs {
            failed_boots: 0,
            marker_present: false,
            button_pressed: false,
            cmdline: "",
            ..all
        });
        assert_eq!(d.reason, Some(FailsafeReason::StorageError));
    }

    #[test]
    fn button_failsafe_with_exhausted_counter_still_resets_it() {
        let d = decide(&BootInputs {
            button_pressed: true,
            failed_boots: 3,
            ..inputs()
        });
        assert_eq!(d.reason, Some(FailsafeReason::Button));
        assert_eq!(d.write_bootcount, Some(0));
    }

    #[test]
    fn cmdline_flag_must_be_exact_word() {
        assert!(cmdline_requests_failsafe("a owr.failsafe=1 b"));
        assert!(!cmdline_requests_failsafe("owr.failsafe=0"));
        assert!(!cmdline_requests_failsafe("xowr.failsafe=1"));
        assert!(!cmdline_requests_failsafe("owr.failsafe=10"));
        assert!(!cmdline_requests_failsafe(""));
    }

    #[test]
    fn initramfs_boot_is_detected_by_a_ram_root() {
        // OpenWrt's initramfs /init switch_roots into a tmpfs; without it the root is rootfs.
        assert!(is_initramfs_boot(Some("tmpfs")));
        assert!(is_initramfs_boot(Some("rootfs")));
        assert!(is_initramfs_boot(Some("ramfs")));
        // A flash boot: the kernel mounted root= (squashfs on the GL-MT6000).
        assert!(!is_initramfs_boot(Some("squashfs")));
        assert!(!is_initramfs_boot(Some("ext4")));
        assert!(is_initramfs_boot(None), "unknown root: never touch storage");
    }

    #[test]
    fn button_window_boundary() {
        assert!(in_button_window(0));
        assert!(in_button_window(2000));
        assert!(!in_button_window(2001));
    }

    #[test]
    fn button_window_starts_when_the_device_is_opened() {
        let init_start = Instant::now();
        // Mounting/mkfs took 5 s, so the device is opened long after init started.
        let opened = init_start + Duration::from_secs(5);
        let w = ButtonWindow::open(opened);
        assert!(
            w.is_open(opened + Duration::from_millis(1900)),
            "a window measured from init start would have expired already"
        );
        assert!(w.is_open(opened + Duration::from_millis(2000)));
        assert!(!w.is_open(opened + Duration::from_millis(2001)));
        // A clock reading before the open instant never panics and counts as open.
        assert!(w.is_open(init_start));
    }

    #[test]
    fn tracker_overdue_clears_when_boot_reaches_running() {
        let t0 = Instant::now();
        let mut t = BootTracker::new(t0);
        assert!(!t.overdue() && !t.reached());
        assert_eq!(
            t.observe(t0 + Duration::from_secs(121), false),
            Progress::Overdue
        );
        assert!(t.overdue() && !t.reached());
        assert_eq!(
            t.observe(t0 + Duration::from_secs(150), true),
            Progress::JustReached
        );
        assert!(t.reached());
        assert!(
            !t.overdue(),
            "a stale overdue flag must not outlive running"
        );
        t.observe(t0 + Duration::from_secs(1000), false);
        assert!(!t.overdue(), "running is latched; no new overdue");
    }

    #[test]
    fn factory_reset_marker_is_only_written_on_the_real_data_partition() {
        assert_eq!(
            factory_reset_target(BootMode::Normal, true),
            Ok(factory_reset_marker())
        );
        assert_eq!(
            factory_reset_target(BootMode::Failsafe, true),
            Err(FactoryResetRefusal::Failsafe),
            "failsafe /overlay is a tmpfs"
        );
        assert_eq!(
            factory_reset_target(BootMode::Failsafe, false),
            Err(FactoryResetRefusal::Failsafe)
        );
        assert_eq!(
            factory_reset_target(BootMode::Normal, false),
            Err(FactoryResetRefusal::NotPersistent)
        );
        assert!(
            FactoryResetRefusal::Failsafe
                .to_string()
                .contains("failsafe")
        );
    }

    #[test]
    fn bootcount_parsing_is_forgiving() {
        assert_eq!(parse_bootcount("2\n"), 2);
        assert_eq!(parse_bootcount(" 7 "), 7);
        assert_eq!(parse_bootcount(""), 0);
        assert_eq!(parse_bootcount("abc"), 0);
        assert_eq!(parse_bootcount("-1"), 0);
        assert_eq!(parse_bootcount("99999999999999"), 0);
        assert_eq!(parse_bootcount(&format_bootcount(41)), 41);
    }

    #[test]
    fn boot_plan_orders_phases_by_mode() {
        let normal = BootPlan::from_decision(&decide(&inputs()));
        assert_eq!(
            normal.phases,
            [
                BootPhase::RootSwitch,
                BootPhase::Hostname,
                BootPhase::KmodLoader,
                BootPhase::Coldplug,
                BootPhase::Services
            ]
        );
        let fs = BootPlan::from_decision(&decide(&BootInputs {
            button_pressed: true,
            ..inputs()
        }));
        assert_eq!(fs.mode, BootMode::Failsafe);
        assert_eq!(fs.phases.last(), Some(&BootPhase::RescueShell));
        assert!(!fs.phases.contains(&BootPhase::Services));
    }

    #[test]
    fn tracker_reports_running_once_and_overdue_after_deadline() {
        let t0 = Instant::now();
        let mut t = BootTracker::new(t0);
        assert_eq!(
            t.observe(t0 + Duration::from_secs(5), false),
            Progress::Booting
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(120), false),
            Progress::Booting
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(121), false),
            Progress::Overdue
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(130), true),
            Progress::JustReached
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(131), false),
            Progress::Running,
            "latched"
        );
        assert_eq!(
            t.observe(t0 + Duration::from_secs(1000), true),
            Progress::Running
        );
    }

    #[test]
    fn hostname_validation_and_extraction() {
        assert!(valid_hostname("ferritewrt"));
        assert!(valid_hostname("a-b-1"));
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("-a"));
        assert!(!valid_hostname("a-"));
        assert!(!valid_hostname("a b"));
        assert!(!valid_hostname("a.b"));
        assert!(!valid_hostname(&"x".repeat(64)));
        assert_eq!(
            hostname_from_config("schema = 1\n[system]\nhostname = \"router1\"\n").as_deref(),
            Some("router1")
        );
        assert_eq!(
            hostname_from_config("[system]\nhostname = \"bad name\"\n"),
            None
        );
        assert_eq!(hostname_from_config("[system]\n"), None);
        assert_eq!(hostname_from_config("not toml ["), None);
        assert_eq!(hostname_from_config("[system]\nhostname = 5\n"), None);
    }
}
