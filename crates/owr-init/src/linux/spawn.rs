//! Spawning supervised processes.
//!
//! Children are started with `std::process::Command` and never waited on through the std
//! `Child`: init reaps *all* children with `waitpid(-1)` (it must, as PID 1 adopts orphans),
//! and tokio's own child reaping would race with that.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use rustix::fs::{Mode, OFlags};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{ChildStderr, ChildStdout};

use super::clock::boot_ms;
use crate::journal::{LineSplitter, MAX_MSG_BYTES, SharedJournal, Source, lock};
use crate::service::ServiceSpec;
use crate::services::{CHILD_PATH, SETSID_BIN, console_argv};

/// Syslog levels for the two output streams.
const PRIO_STDOUT: u8 = 6;
const PRIO_STDERR: u8 = 4;

/// Start `spec`; returns the child's pid. Must be called inside the tokio runtime.
pub(super) fn spawn_service(spec: &ServiceSpec, journal: &SharedJournal) -> io::Result<u32> {
    // A console program gets its own session through `setsid -c` when available (it also makes
    // the console its controlling terminal, so Ctrl-C reaches the program and not init). The
    // wrapper becomes the session and group leader itself, so `process_group(0)` must not run
    // first (a group leader cannot call setsid).
    let wrapped = spec.console && Path::new(SETSID_BIN).exists();
    let argv = if spec.console {
        console_argv(&spec.exec, wrapped)
    } else {
        spec.exec.clone()
    };
    let (program, program_args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty exec"))?;
    let mut cmd = Command::new(program);
    cmd.args(program_args)
        .env_clear()
        .env("PATH", CHILD_PATH)
        .envs(spec.env.iter().map(|(k, v)| (k, v)));
    if !wrapped {
        // Own process group: signals can target the whole service.
        cmd.process_group(0);
    }

    if spec.console {
        // O_NOCTTY: opening the console must not make it init's controlling terminal.
        let console: OwnedFd = rustix::fs::open(
            "/dev/console",
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        cmd.stdin(Stdio::from(console.try_clone()?))
            .stdout(Stdio::from(console.try_clone()?))
            .stderr(Stdio::from(console));
    } else {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    let mut child = cmd.spawn()?;
    let pid = child.id();
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump(
            ChildStdout::from_std(out)?,
            journal.clone(),
            spec.name.clone(),
            PRIO_STDOUT,
        ));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump(
            ChildStderr::from_std(err)?,
            journal.clone(),
            spec.name.clone(),
            PRIO_STDERR,
        ));
    }
    // `child` is dropped without waiting; init reaps it via waitpid(-1).
    Ok(pid)
}

/// Copy a child's output into the journal line by line until EOF.
async fn pump<R: AsyncRead + Unpin>(mut reader: R, journal: SharedJournal, name: String, prio: u8) {
    let mut splitter = LineSplitter::new(MAX_MSG_BYTES);
    let mut buf = vec![0u8; 4096];
    let source = || Source::Service(name.clone());
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let lines = splitter.push(buf.get(..n).unwrap_or_default());
                if !lines.is_empty() {
                    let mut j = lock(&journal);
                    for line in lines {
                        j.push(boot_ms(), prio, source(), &line);
                    }
                }
            }
        }
    }
    if let Some(line) = splitter.finish() {
        lock(&journal).push(boot_ms(), prio, source(), &line);
    }
}
