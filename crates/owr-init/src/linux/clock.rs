//! Time since boot.

use rustix::time::{ClockId, clock_gettime};

/// Milliseconds since boot (`CLOCK_BOOTTIME`, includes suspend).
pub(super) fn boot_ms() -> u64 {
    let ts = clock_gettime(ClockId::Boottime);
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let millis = u64::try_from(ts.tv_nsec / 1_000_000).unwrap_or(0);
    secs.saturating_mul(1000).saturating_add(millis)
}
