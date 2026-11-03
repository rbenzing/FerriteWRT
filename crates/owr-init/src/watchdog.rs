//! Hardware watchdog policy (pure).
//!
//! `/dev/watchdog` is petted every [`PET_INTERVAL`] by a dedicated thread. The thread stops
//! petting, so the hardware resets the board, when:
//! * the main loop has not reported a heartbeat for [`STALL_LIMIT`] (init is wedged), or
//! * the main loop asked for an inhibit, see [`should_inhibit`]: a service is `failed` (crash-loop
//!   limit reached) or the boot is overdue, **while the boot has not yet reached "running" and
//!   a boot counter exists**.
//!
//! The reset is the deliberate recovery path, and it is only taken when it converges: each such
//! boot leaves the counter incremented, so after 3 the next boot is failsafe (see
//! [`crate::boot`]). Once a boot has reached running the counter is back at 0, so a reset would
//! just repeat forever; from then on a failed service is only logged and shown on the LED. Without
//! a counter (initramfs, no data partition) there is no way to ever reach failsafe, so never
//! inhibit. A clean shutdown writes `V` (magic close) so the watchdog is disarmed before reboot.

use std::time::Duration;

/// How often `\0` is written to the device.
pub const PET_INTERVAL: Duration = Duration::from_secs(10);
/// Main-loop silence after which petting stops. Generous: boot-time `mkfs` can block init.
pub const STALL_LIMIT: Duration = Duration::from_secs(90);

/// Should the watchdog thread pet now?
///
/// `keep_alive` bypasses the stall check (rescue shell: init is blocked on purpose);
/// `inhibit` still wins over it.
pub fn should_pet(now_ms: u64, last_heartbeat_ms: u64, inhibit: bool, keep_alive: bool) -> bool {
    if inhibit {
        return false;
    }
    keep_alive
        || now_ms.saturating_sub(last_heartbeat_ms)
            <= u64::try_from(STALL_LIMIT.as_millis()).unwrap_or(u64::MAX)
}

/// What the main loop knows when deciding whether to stop petting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent facts, a policy input record
pub struct InhibitInputs {
    /// Normal boot (failsafe must keep the rescue shell usable).
    pub normal_boot: bool,
    /// A persistent boot counter exists, so repeated resets lead to failsafe.
    pub bootcount_armed: bool,
    pub reached_running: bool,
    pub service_failed: bool,
    pub boot_overdue: bool,
}

/// Should petting stop (hardware reset) because of service/boot health?
///
/// Only while the boot has not reached running and the 3-strikes counter is armed: that is the
/// only situation in which a reset is guaranteed to end in failsafe rather than loop.
pub fn should_inhibit(i: InhibitInputs) -> bool {
    i.normal_boot && i.bootcount_armed && !i.reached_running && (i.service_failed || i.boot_overdue)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::boot::{BootInputs, MAX_FAILED_BOOTS, decide};
    use crate::mounts::BootMode;

    fn inputs() -> InhibitInputs {
        InhibitInputs {
            normal_boot: true,
            bootcount_armed: true,
            reached_running: false,
            service_failed: false,
            boot_overdue: false,
        }
    }

    #[test]
    fn healthy_boot_is_never_inhibited() {
        assert!(!should_inhibit(inputs()));
    }

    #[test]
    fn failure_or_overdue_before_running_inhibits() {
        assert!(should_inhibit(InhibitInputs {
            service_failed: true,
            ..inputs()
        }));
        assert!(should_inhibit(InhibitInputs {
            boot_overdue: true,
            ..inputs()
        }));
    }

    #[test]
    fn after_running_a_failed_service_never_resets_the_board() {
        // The counter was reset to 0 at running: a reset would loop forever.
        assert!(!should_inhibit(InhibitInputs {
            reached_running: true,
            service_failed: true,
            ..inputs()
        }));
        assert!(!should_inhibit(InhibitInputs {
            reached_running: true,
            boot_overdue: true,
            service_failed: true,
            ..inputs()
        }));
    }

    #[test]
    fn never_inhibits_without_a_boot_counter_or_in_failsafe() {
        let bad = InhibitInputs {
            service_failed: true,
            boot_overdue: true,
            ..inputs()
        };
        assert!(should_inhibit(bad));
        assert!(
            !should_inhibit(InhibitInputs {
                bootcount_armed: false,
                ..bad
            }),
            "initramfs / no data partition: no way to reach failsafe"
        );
        assert!(!should_inhibit(InhibitInputs {
            normal_boot: false,
            ..bad
        }));
    }

    /// A boot that never reaches running is reset by the watchdog; the counter makes the third
    /// such boot a failsafe boot, which is never inhibited, so the loop ends.
    #[test]
    fn reset_loop_converges_to_failsafe() {
        let mut count = 0;
        let mut resets = 0;
        let mut ended_in_failsafe = false;
        for _ in 0..10 {
            let d = decide(&BootInputs {
                button_pressed: false,
                cmdline: "root=PARTLABEL=rootfs",
                marker_present: false,
                failed_boots: count,
                storage_ok: true,
            });
            if let Some(n) = d.write_bootcount {
                count = n;
            }
            let inhibit = should_inhibit(InhibitInputs {
                normal_boot: d.mode == BootMode::Normal,
                bootcount_armed: true,
                reached_running: false,
                service_failed: true,
                boot_overdue: true,
            });
            if !inhibit {
                ended_in_failsafe = d.mode == BootMode::Failsafe;
                break;
            }
            resets += 1;
        }
        assert!(ended_in_failsafe);
        assert_eq!(resets, MAX_FAILED_BOOTS);
    }

    #[test]
    fn pets_while_main_loop_is_alive() {
        assert!(should_pet(1_000, 1_000, false, false));
        assert!(should_pet(50_000, 40_000, false, false));
        assert!(
            should_pet(91_000, 1_000, false, false),
            "exactly at the limit still pets"
        );
    }

    #[test]
    fn stops_when_main_loop_stalls() {
        assert!(!should_pet(91_001, 1_000, false, false));
        assert!(!should_pet(1_000_000, 0, false, false));
    }

    #[test]
    fn stops_when_inhibited_even_if_alive_or_keep_alive() {
        assert!(!should_pet(1_000, 1_000, true, false));
        assert!(!should_pet(1_000, 1_000, true, true));
    }

    #[test]
    fn keep_alive_bypasses_stall_check() {
        assert!(should_pet(1_000_000, 0, false, true));
    }

    #[test]
    fn clock_going_backwards_is_not_a_stall() {
        assert!(should_pet(10, 500, false, false));
    }
}
