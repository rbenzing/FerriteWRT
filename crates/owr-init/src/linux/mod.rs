//! Linux runtime: wires the pure state machines to the kernel.
//!
//! * `init`: PID 1 boot sequence (mounts, failsafe decision, pivot, hostname).
//! * `runtime`: the event loop (signals, reaping, supervision, control socket, shutdown).
//! * Helpers: `mount_exec`, `spawn`, `kmsg`, `uevent_sock`, `buttons`, `control_sock`,
//!   `watchdog`, `shutdown`, `upgrade`.
//!
//! `--test-mode <dir>` runs only the event loop as an ordinary process.

mod buttons;
mod clock;
mod control_sock;
mod fdwatch;
mod init;
mod kmsg;
mod mount_exec;
mod runtime;
mod shutdown;
mod spawn;
mod uevent_sock;
mod upgrade;
mod watchdog;

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::args::{Cli, USAGE, parse_args};
use crate::journal::{Journal, JournalLayer, SharedJournal, shared};
use crate::manager::Manager;
use crate::mounts::BootMode;
use crate::services::parse_services_toml;

/// Write one line to stderr, ignoring failures. `eprintln!` panics when the write fails (EIO on
/// a dead console), and with `panic = "abort"` a panic in PID 1 is a kernel panic. Use as
/// `console_log(format_args!("..."))`.
fn console_log(args: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "owr-init: {args}");
}

/// Console + journal logging. `OWR_LOG` overrides the default `info` filter for the console.
fn init_tracing(journal: &SharedJournal) {
    let filter = EnvFilter::try_from_env("OWR_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let layers = tracing_subscriber::registry()
        .with(filter)
        .with(JournalLayer::new(
            journal.clone(),
            clock::boot_ms,
            Level::INFO,
        ))
        .with(
            fmt::layer()
                .with_writer(io::stderr)
                .with_ansi(false)
                .without_time()
                // A failed console write is dropped silently (the default, made explicit): the
                // layer's error report is an `eprintln!`, which would panic.
                .log_internal_errors(false),
        );
    if layers.try_init().is_err() {
        console_log(format_args!("logging was already initialised"));
    }
}

fn test_mode(dir: PathBuf, services: Option<PathBuf>) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(&dir) {
        console_log(format_args!("cannot create {}: {e}", dir.display()));
        return ExitCode::from(2);
    }
    let file = services.unwrap_or_else(|| dir.join("services.toml"));
    let specs = match std::fs::read_to_string(&file)
        .map_err(|e| e.to_string())
        .and_then(|t| parse_services_toml(&t).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => {
            console_log(format_args!("{}: {e}", file.display()));
            return ExitCode::from(2);
        }
    };
    if let Err(e) = Manager::new(specs.clone()) {
        console_log(format_args!("{}: {e}", file.display()));
        return ExitCode::from(2);
    }
    let journal = shared(Journal::default());
    init_tracing(&journal);
    tracing::info!("test mode: run dir {}", dir.display());
    let cfg = runtime::RuntimeConfig {
        pid1: false,
        mode: BootMode::Normal,
        reason: None,
        journal_dir: Some(dir.join("journal")),
        run_dir: dir,
        specs,
        board: None,
        watchdog: None,
        journal,
        bootcount_path: None,
        persistent: false,
        started: Instant::now(),
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            console_log(format_args!("cannot start async runtime: {e}"));
            return ExitCode::from(1);
        }
    };
    rt.block_on(runtime::run(cfg));
    ExitCode::SUCCESS
}

/// Binary entry point.
pub fn main() -> ExitCode {
    // As PID 1 the kernel may pass leftover command-line words as arguments; ignore them all.
    if rustix::process::getpid().is_init() {
        return init::run();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Ok(Cli::Help) => {
            // Not `print!`: it panics if stdout is closed.
            let _ = write!(io::stdout(), "{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Cli::Test { dir, services }) => test_mode(dir, services),
        Ok(Cli::Pid1) => {
            console_log(format_args!(
                "not PID 1; use --test-mode <dir> to run the supervisor loop"
            ));
            ExitCode::from(2)
        }
        Err(msg) => {
            console_log(format_args!("{msg}\n{USAGE}"));
            ExitCode::from(2)
        }
    }
}
