//! Readiness waiting for plain file descriptors.
//!
//! The event sources (`/dev/kmsg`, the uevent socket, evdev nodes) are read by small dedicated
//! threads that `poll(2)` with a timeout and then drain the non-blocking descriptor. This
//! avoids tokio's `AsyncFd`, whose registration is `unsafe`, and keeps every blocking read off
//! the event-loop thread.

use std::io;
use std::os::fd::AsFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

/// Wait up to one second for `fd` to become readable (or hung up / errored: the following
/// read reports it). `Ok(false)` means timeout or interruption.
pub(super) fn wait_readable(fd: &impl AsFd) -> io::Result<bool> {
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    match poll(&mut fds, Some(&timeout)) {
        Ok(n) => Ok(n > 0),
        Err(Errno::INTR) => Ok(false),
        Err(e) => Err(io::Error::from(e)),
    }
}
