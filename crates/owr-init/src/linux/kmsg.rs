//! `/dev/kmsg` reader: kernel log into the journal.

use std::io;
use std::os::fd::OwnedFd;
use std::thread;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::clock::boot_ms;
use super::fdwatch::wait_readable;
use crate::journal::{SharedJournal, Source, lock, parse_dev_kmsg};

/// Must be at least the kernel's maximum record size (8 KiB).
const BUF: usize = 16 * 1024;

/// Open `/dev/kmsg` non-blocking and feed the journal from a background thread. The kernel
/// replays its whole backlog first, so early boot messages are not lost.
pub(super) fn spawn(journal: SharedJournal) -> io::Result<()> {
    let fd = rustix::fs::open(
        "/dev/kmsg",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    thread::Builder::new()
        .name("kmsg".into())
        .spawn(move || run(&fd, &journal))?;
    Ok(())
}

fn run(fd: &OwnedFd, journal: &SharedJournal) {
    let mut buf = vec![0u8; BUF];
    loop {
        match wait_readable(fd) {
            Ok(true) => {
                if !drain(fd, &mut buf, journal) {
                    return;
                }
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!("/dev/kmsg poll failed: {e}");
                return;
            }
        }
    }
}

/// Read until the queue is empty. `false` means the device is unusable.
fn drain(fd: &OwnedFd, buf: &mut [u8], journal: &SharedJournal) -> bool {
    loop {
        match rustix::io::read(fd, &mut *buf) {
            Ok(0) => return false,
            Ok(n) => {
                let text = String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).into_owned();
                let rec = parse_dev_kmsg(&text);
                let ts = rec.ts_ms.unwrap_or_else(boot_ms);
                lock(journal).push(ts, rec.prio, Source::Kernel, &rec.msg);
            }
            Err(Errno::AGAIN) => return true,
            // Records were overwritten before we read them; carry on with the next one.
            Err(Errno::PIPE) => {}
            Err(e) => {
                tracing::warn!("/dev/kmsg read failed: {e}");
                return false;
            }
        }
    }
}
