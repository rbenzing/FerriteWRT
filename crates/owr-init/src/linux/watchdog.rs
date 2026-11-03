//! `/dev/watchdog` pet thread. Policy lives in [`crate::watchdog`].

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::clock::boot_ms;
use crate::watchdog::{PET_INTERVAL, should_pet};

const POLL: Duration = Duration::from_millis(250);

#[derive(Debug)]
struct Shared {
    last_beat_ms: AtomicU64,
    inhibit: AtomicBool,
    keep_alive: AtomicBool,
    stop: AtomicBool,
}

/// Cheap clone given to the event loop.
#[derive(Debug, Clone)]
pub(super) struct WatchdogHandle(Arc<Shared>);

impl WatchdogHandle {
    /// The main loop is alive.
    pub(super) fn beat(&self) {
        self.0.last_beat_ms.store(boot_ms(), Ordering::Relaxed);
    }

    /// Stop petting (the hardware will reset the board) while `true`.
    pub(super) fn set_inhibit(&self, inhibit: bool) {
        self.0.inhibit.store(inhibit, Ordering::Relaxed);
    }

    /// Ignore the stall check (init is intentionally blocked, e.g. in the rescue loop).
    pub(super) fn keep_alive(&self) {
        self.0.keep_alive.store(true, Ordering::Relaxed);
    }
}

/// Owner of the pet thread.
#[derive(Debug)]
pub(super) struct Watchdog {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Open the device and start petting. Opening arms the hardware timer.
    pub(super) fn start(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).open(path)?;
        let shared = Arc::new(Shared {
            last_beat_ms: AtomicU64::new(boot_ms()),
            inhibit: AtomicBool::new(false),
            keep_alive: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let thread_shared = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || pet_loop(file, &thread_shared))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    pub(super) fn handle(&self) -> WatchdogHandle {
        WatchdogHandle(Arc::clone(&self.shared))
    }

    /// Clean shutdown: write the magic close character `V` so closing disarms the timer.
    pub(super) fn magic_close(mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take()
            && t.join().is_err()
        {
            tracing::error!("watchdog thread panicked");
        }
    }
}

fn pet_loop(mut file: File, s: &Shared) {
    let mut last_pet: Option<Instant> = None;
    loop {
        if s.stop.load(Ordering::Relaxed) {
            if let Err(e) = file.write_all(b"V") {
                tracing::error!("watchdog magic close failed: {e}");
            }
            return; // dropping `file` closes the device
        }
        let due = last_pet.is_none_or(|t| t.elapsed() >= PET_INTERVAL);
        let ok = should_pet(
            boot_ms(),
            s.last_beat_ms.load(Ordering::Relaxed),
            s.inhibit.load(Ordering::Relaxed),
            s.keep_alive.load(Ordering::Relaxed),
        );
        if due && ok {
            if let Err(e) = file.write_all(b"\0") {
                tracing::error!("watchdog pet failed: {e}");
            }
            last_pet = Some(Instant::now());
        }
        thread::sleep(POLL);
    }
}
