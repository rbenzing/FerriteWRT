//! Final steps of a shutdown: sweep leftover processes, sync, quiesce filesystems, disarm the
//! watchdog, reboot/poweroff.

use std::fs;
use std::thread::sleep;
use std::time::Duration;

use rustix::io::Errno;
use rustix::mount::{MountFlags, UnmountFlags, mount_remount, unmount};
use rustix::process::{Pid, Signal, WaitOptions, kill_process, wait};
use rustix::system::{RebootCommand, reboot};

use super::console_log;
use super::runtime::Exit;
use super::upgrade;
use super::watchdog::Watchdog;
use crate::mounts::{parse_mountinfo, shutdown_order};

/// Time between the final SIGTERM and SIGKILL sweeps.
const SWEEP_GRACE: Duration = Duration::from_secs(2);
const REAP_STEP: Duration = Duration::from_millis(100);

/// Collect exited children so the kernel can release them.
fn reap() {
    while let Ok(Some(_)) = wait(WaitOptions::NOHANG) {}
}

/// Send `sig` to every other userspace process, like `kill(-1, sig)` (which excludes init and
/// the caller). Done by walking `/proc` because rustix's `Pid` cannot represent -1. Kernel
/// threads and zombies (empty `cmdline`) are skipped.
fn signal_all(sig: Signal) {
    let own = rustix::process::getpid();
    let Ok(rd) = fs::read_dir("/proc") else {
        console_log(format_args!("cannot read /proc; skipping process sweep"));
        return;
    };
    for entry in rd.filter_map(Result::ok) {
        let Some(raw) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        let Some(pid) = Pid::from_raw(raw) else {
            continue;
        };
        if raw <= 1 || pid == own {
            continue;
        }
        let userspace = fs::read(entry.path().join("cmdline")).is_ok_and(|c| !c.is_empty());
        if !userspace {
            continue;
        }
        match kill_process(pid, sig) {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(e) => console_log(format_args!("signal {sig:?} to pid {raw}: {e}")),
        }
    }
}

/// Last chance for anything still running (stragglers of services, orphans, the rescue shell)
/// to stop before the filesystems are unmounted: SIGTERM everyone, wait, then SIGKILL.
fn terminate_all() {
    // Never sweep unless this really is PID 1 (the sweep would hit the whole machine).
    if !rustix::process::getpid().is_init() {
        return;
    }
    signal_all(Signal::TERM);
    let mut waited = Duration::ZERO;
    while waited < SWEEP_GRACE {
        sleep(REAP_STEP);
        reap();
        waited = waited.saturating_add(REAP_STEP);
    }
    signal_all(Signal::KILL);
    sleep(REAP_STEP);
    reap();
}

/// Unmount persistent filesystems newest-first; whatever is busy (the overlay root, the data
/// partition under it) is remounted read-only instead, so no write is in flight at reset.
fn quiesce_mounts() {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        tracing::warn!("cannot read mountinfo; skipping unmount");
        return;
    };
    for entry in shutdown_order(&parse_mountinfo(&text)) {
        if unmount(entry.target.as_str(), UnmountFlags::empty()).is_ok() {
            continue;
        }
        if let Err(e) = mount_remount(entry.target.as_str(), MountFlags::RDONLY, "") {
            tracing::warn!("cannot make {} read-only: {e}", entry.target);
        }
    }
}

/// Never returns: reboots or powers off the machine.
pub(super) fn finish(exit: &Exit, watchdog: Option<Watchdog>) -> ! {
    // Services were stopped by the runtime; this catches whatever they or anyone else left
    // behind, so nothing holds a file open on the filesystems about to be unmounted.
    terminate_all();
    if let Exit::Upgrade(job) = exit {
        // Writing takes a while and the event loop is gone: keep the hardware timer fed.
        if let Some(w) = &watchdog {
            w.handle().keep_alive();
        }
        // Success or not, the next step is the reboot; the console says what happened.
        upgrade::run(job);
    }
    rustix::fs::sync();
    quiesce_mounts();
    rustix::fs::sync();
    if let Some(w) = watchdog {
        // Disarm before the final reboot call so the timer cannot fire mid-shutdown.
        w.magic_close();
    }
    let cmd = match exit {
        Exit::PowerOff => RebootCommand::PowerOff,
        Exit::Reboot | Exit::Upgrade(_) | Exit::Quit => RebootCommand::Restart,
    };
    if let Err(e) = reboot(cmd) {
        console_log(format_args!("reboot failed: {e}"));
    }
    // Returning from PID 1 would panic the kernel; park instead.
    loop {
        sleep(Duration::from_secs(3600));
    }
}
