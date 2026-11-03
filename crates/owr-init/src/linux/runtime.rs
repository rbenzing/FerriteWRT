//! The init event loop: signals, reaping, supervision ticks, control socket, buttons, LEDs,
//! watchdog flags, journal flushing and shutdown.
//!
//! One task owns the [`Manager`]; everything else (control connections, button readers, the
//! uevent listener) talks to it through an mpsc channel of [`Msg`].

use std::collections::VecDeque;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use owr_board::{Board, ButtonAction};
use rustix::io::Errno;
use rustix::process::{Pid, WaitOptions, kill_process, kill_process_group, wait};
use tokio::signal::unix::{Signal as TokioSignal, SignalKind, signal};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::Level;

use super::clock::boot_ms;
use super::spawn::spawn_service;
use super::watchdog::WatchdogHandle;
use super::{control_sock, kmsg, uevent_sock};
use crate::boot::{BootTracker, FailsafeReason, Progress, factory_reset_target};
use crate::button::Press;
use crate::control::{ERR_UNKNOWN_SERVICE, Request, error_response, ok_response, status_response};
use crate::journal::{SharedJournal, lock};
use crate::led::{LEDS_ROOT, LedState, led_writes};
use crate::manager::{Directive, Manager};
use crate::mounts::BootMode;
use crate::service::{Command, Event, ExitStatus, HealthCheck, ServiceSpec, Signal, State};
use crate::services::rescue_shell;
use crate::watchdog::{InhibitInputs, should_inhibit};

/// Longest the event loop sleeps; also the health-probe and flush granularity.
const MAX_SLEEP: Duration = Duration::from_secs(1);
const HEALTH_INTERVAL: Duration = Duration::from_secs(2);
/// Flash wear: persist the journal rarely (and at shutdown / on failure).
const FLUSH_INTERVAL: Duration = Duration::from_secs(300);
/// Total time services get to stop at shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// How long a reboot/poweroff waits for its reply to be written to the client.
const REPLY_WRITE_GRACE: Duration = Duration::from_secs(1);

/// The event loop's answer to a control request.
#[derive(Debug)]
pub(super) struct Reply {
    pub(super) text: String,
    /// Signalled by the connection once `text` is written (only requested for replies that
    /// are followed by an exit).
    pub(super) written: Option<oneshot::Sender<()>>,
}

impl Reply {
    pub(super) fn text(text: String) -> Self {
        Self {
            text,
            written: None,
        }
    }
}

/// Messages from helper tasks to the event loop.
#[derive(Debug)]
pub(super) enum Msg {
    Control {
        req: Request,
        reply: oneshot::Sender<Reply>,
    },
    Button {
        name: String,
        press: Press,
        action: ButtonAction,
    },
}

/// What to do once the loop ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Exit {
    Reboot,
    PowerOff,
    /// Test mode: just exit the process.
    Quit,
}

pub(super) struct RuntimeConfig {
    pub(super) pid1: bool,
    pub(super) mode: BootMode,
    pub(super) reason: Option<FailsafeReason>,
    pub(super) run_dir: PathBuf,
    pub(super) specs: Vec<ServiceSpec>,
    pub(super) board: Option<Board>,
    pub(super) watchdog: Option<WatchdogHandle>,
    pub(super) journal: SharedJournal,
    /// Where to persist the journal (`None`: memory only).
    pub(super) journal_dir: Option<PathBuf>,
    /// Boot counter file to reset once the boot reaches running.
    pub(super) bootcount_path: Option<PathBuf>,
    /// `/overlay` is the real data partition (normal boot with persistence), so a factory-reset
    /// marker written there survives the reboot.
    pub(super) persistent: bool,
    /// Init started at this instant (boot deadline reference).
    pub(super) started: Instant,
}

struct Runtime {
    cfg: RuntimeConfig,
    manager: Manager,
    next_wake: Option<Instant>,
    tracker: BootTracker,
    coldplug_done: bool,
    /// A failed service is currently being shown (log + LED).
    failure_shown: bool,
    /// Set while a reboot/poweroff reply is still being written to its client.
    reply_written: Option<oneshot::Receiver<()>>,
    last_health: Instant,
    last_flush: Instant,
}

async fn recv(sig: &mut Option<TokioSignal>) {
    match sig {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}

fn install(kind: SignalKind) -> Option<TokioSignal> {
    match signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("cannot install signal handler: {e}");
            None
        }
    }
}

fn exists(p: &Path) -> bool {
    p.exists()
}

fn emit(level: Level, msg: &str) {
    match level {
        Level::ERROR => tracing::error!("{msg}"),
        Level::WARN => tracing::warn!("{msg}"),
        Level::INFO => tracing::info!("{msg}"),
        _ => tracing::debug!("{msg}"),
    }
}

fn send_signal(pid: u32, sig: Signal) {
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return;
    };
    // Services run in their own process group (pgid == pid): signal the whole group, except
    // SIGHUP which is a reload request for the main process only.
    let result = match sig {
        Signal::Hup => kill_process(pid, rustix::process::Signal::HUP),
        Signal::Term => kill_process_group(pid, rustix::process::Signal::TERM),
        Signal::Kill => kill_process_group(pid, rustix::process::Signal::KILL),
    };
    match result {
        Ok(()) | Err(Errno::SRCH) => {}
        Err(e) => tracing::warn!("signal {sig:?} to pid {pid:?} failed: {e}"),
    }
}

fn probe(check: &HealthCheck) -> bool {
    match check {
        HealthCheck::UnixSocket(p) => fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()),
        HealthCheck::PidFile(p) => fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists()),
        HealthCheck::TcpPort(port) => {
            let addr = SocketAddr::from(([127, 0, 0, 1], *port));
            TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
        }
    }
}

fn exit_status(status: rustix::process::WaitStatus) -> ExitStatus {
    match (status.exit_status(), status.terminating_signal()) {
        (Some(code), _) => ExitStatus::Code(code),
        (None, Some(sig)) => ExitStatus::Signal(sig),
        (None, None) => ExitStatus::Code(-1),
    }
}

/// Run the supervisor until a shutdown is requested; returns what to do next.
pub(super) async fn run(cfg: RuntimeConfig) -> Exit {
    let manager = match Manager::new(cfg.specs.clone()) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("invalid service set: {e}; falling back to the rescue shell");
            match Manager::new(vec![rescue_shell()]) {
                Ok(m) => m,
                Err(_) => return Exit::Reboot,
            }
        }
    };
    let (tx, mut rx) = mpsc::channel::<Msg>(64);
    let (net_events, _) = broadcast::channel::<String>(64);

    match control_sock::bind(&cfg.run_dir.join("init.sock")) {
        Ok(listener) => {
            tokio::spawn(control_sock::serve(
                listener,
                cfg.journal.clone(),
                tx.clone(),
            ));
        }
        Err(e) => tracing::error!("control socket unavailable: {e}"),
    }
    if cfg.pid1 {
        if let Err(e) = kmsg::spawn(cfg.journal.clone()) {
            tracing::warn!("/dev/kmsg unavailable: {e}");
        }
        if let Err(e) = uevent_sock::spawn(cfg.board.as_ref(), net_events.clone(), tx.clone()) {
            tracing::error!("uevent socket unavailable: {e}");
        }
    }

    // Handlers first, so no child exit can slip past before the first service starts.
    let mut sigchld = install(SignalKind::child());
    let mut sigterm = install(SignalKind::terminate());
    let mut sigint = install(SignalKind::interrupt());
    let mut sigusr1 = install(SignalKind::user_defined1());
    let mut sigusr2 = install(SignalKind::user_defined2());

    let now = Instant::now();
    let mut rt = Runtime {
        tracker: BootTracker::new(cfg.started),
        manager,
        next_wake: None,
        coldplug_done: !cfg.pid1,
        failure_shown: false,
        reply_written: None,
        last_health: now,
        last_flush: now,
        cfg,
    };
    rt.apply_leds(if rt.cfg.mode == BootMode::Failsafe {
        LedState::Failsafe
    } else {
        LedState::Boot
    });
    rt.manager.start_all();
    rt.poll();

    let term_exit = if rt.cfg.pid1 {
        Exit::Reboot
    } else {
        Exit::Quit
    };
    tracing::info!(
        "supervisor loop running ({} services)",
        rt.manager.services().count()
    );

    let exit = loop {
        let sleep = rt.sleep_duration();
        let exit = tokio::select! {
            () = recv(&mut sigchld) => { rt.reap(); None }
            () = recv(&mut sigterm) => Some(term_exit),
            () = recv(&mut sigint) => Some(term_exit),
            () = recv(&mut sigusr1) => Some(Exit::Reboot),
            () = recv(&mut sigusr2) => Some(Exit::PowerOff),
            Some(msg) = rx.recv() => rt.handle_msg(msg),
            () = tokio::time::sleep(sleep) => None,
        };
        rt.reap();
        rt.poll();
        if exit.is_some() {
            break exit;
        }
    };
    let exit = exit.unwrap_or(term_exit);
    rt.await_reply_written().await;
    rt.shutdown().await;
    exit
}

impl Runtime {
    fn sleep_duration(&self) -> Duration {
        let until_wake = self
            .next_wake
            .map_or(MAX_SLEEP, |w| w.saturating_duration_since(Instant::now()));
        until_wake.min(MAX_SLEEP).max(Duration::from_millis(10))
    }

    fn uptime_ms(&self) -> u64 {
        if self.cfg.pid1 {
            boot_ms()
        } else {
            u64::try_from(self.cfg.started.elapsed().as_millis()).unwrap_or(u64::MAX)
        }
    }

    fn apply_leds(&self, state: LedState) {
        let (true, Some(board)) = (self.cfg.pid1, &self.cfg.board) else {
            return;
        };
        for w in led_writes(Path::new(LEDS_ROOT), &board.leds, state) {
            if let Err(e) = fs::write(&w.path, &w.value) {
                tracing::debug!("led write {}: {e}", w.path.display());
            }
        }
    }

    fn flush_journal(&mut self) {
        self.last_flush = Instant::now();
        let Some(dir) = &self.cfg.journal_dir else {
            return;
        };
        let result = lock(&self.cfg.journal).flush_to(dir);
        match result {
            Ok(0) => {}
            Ok(n) => tracing::debug!("journal: persisted {n} entries"),
            Err(e) => tracing::warn!("journal flush failed: {e}"),
        }
    }

    /// Carry out the commands returned by the state machines. Spawn results are fed straight
    /// back, which can produce further commands.
    fn exec(&mut self, directives: Vec<Directive>, now: Instant) {
        let mut queue: VecDeque<Directive> = directives.into();
        while let Some(d) = queue.pop_front() {
            match d.command {
                Command::Spawn(spec) => {
                    let ev = match spawn_service(&spec, &self.cfg.journal) {
                        Ok(pid) => Event::Spawned { pid },
                        Err(e) => {
                            tracing::error!("{}: spawn failed: {e}", spec.name);
                            Event::SpawnFailed
                        }
                    };
                    if let Some(more) = self.manager.deliver(&d.service, ev, now) {
                        queue.extend(more);
                    }
                }
                Command::Kill { pid, signal } => send_signal(pid, signal),
                Command::ScheduleTick(at) => {
                    self.next_wake = Some(self.next_wake.map_or(at, |w| w.min(at)));
                }
                Command::Log(level, msg) => emit(level, &msg),
            }
        }
    }

    /// Collect every exited child (init adopts orphans, so unknown pids are normal).
    fn reap(&mut self) {
        while let Ok(Some((pid, status))) = wait(WaitOptions::NOHANG) {
            let Ok(raw) = u32::try_from(pid.as_raw_nonzero().get()) else {
                continue;
            };
            let now = Instant::now();
            let ds = self.manager.on_exit(raw, exit_status(status), now);
            self.exec(ds, now);
        }
    }

    fn kmod_settled(&self) -> bool {
        self.manager
            .get("kmodloader")
            .is_none_or(|s| s.is_ready() || s.is_failed())
    }

    /// Periodic work, run after every wake-up.
    fn poll(&mut self) {
        let now = Instant::now();
        let ds = self.manager.poll(now, &exists);
        self.exec(ds, now);
        if self.next_wake.is_some_and(|w| w <= now) {
            self.next_wake = None;
        }

        if now.saturating_duration_since(self.last_health) >= HEALTH_INTERVAL {
            self.last_health = now;
            self.probe_health(now);
        }
        if !self.coldplug_done && self.kmod_settled() {
            self.coldplug_done = true;
            // Blocking sysfs writes: keep them off the event loop thread.
            tokio::task::spawn_blocking(uevent_sock::coldplug);
        }

        let settled = self.manager.settled(&exists);
        let was_overdue = self.tracker.overdue();
        match self.tracker.observe(now, settled) {
            Progress::JustReached => self.on_running(),
            Progress::Overdue if !was_overdue => {
                tracing::error!("boot did not reach running within its deadline");
                self.flush_journal();
            }
            Progress::Booting | Progress::Running | Progress::Overdue => {}
        }

        let failed = self.manager.any_failed();
        if failed != self.failure_shown {
            self.failure_shown = failed;
            self.show_failure(failed);
        }
        if let Some(wd) = &self.cfg.watchdog {
            wd.beat();
            // See `should_inhibit`: a reset is only taken while it is guaranteed to end in
            // failsafe (boot not yet running, boot counter armed). Afterwards a failed service is
            // logged and shown on the LED, never answered with an endless reset loop.
            wd.set_inhibit(should_inhibit(InhibitInputs {
                normal_boot: self.cfg.mode == BootMode::Normal,
                bootcount_armed: self.cfg.bootcount_path.is_some(),
                reached_running: self.tracker.reached(),
                service_failed: failed,
                boot_overdue: self.tracker.overdue(),
            }));
        }
        if now.saturating_duration_since(self.last_flush) >= FLUSH_INTERVAL {
            self.flush_journal();
        }
    }

    /// A service entered (or all services left) the failed state: log it, show it on the LED
    /// (failsafe pattern) and persist the journal while the evidence is fresh.
    fn show_failure(&mut self, failed: bool) {
        if failed {
            tracing::error!("a service entered the failed state");
        } else {
            tracing::info!("no service is failed any more");
        }
        if self.cfg.mode == BootMode::Normal {
            self.apply_leds(if failed {
                LedState::Failsafe
            } else if self.tracker.reached() {
                LedState::Running
            } else {
                LedState::Boot
            });
        }
        if failed {
            self.flush_journal();
        }
    }

    fn probe_health(&mut self, now: Instant) {
        let targets: Vec<(String, HealthCheck)> = self
            .manager
            .services()
            .filter(|s| matches!(s.state(), State::Running { .. }))
            .filter_map(|s| s.spec().health.clone().map(|h| (s.name().to_owned(), h)))
            .collect();
        for (name, check) in targets {
            let ev = if probe(&check) {
                Event::HealthOk
            } else {
                Event::HealthFail
            };
            if let Some(ds) = self.manager.deliver(&name, ev, now) {
                self.exec(ds, now);
            }
        }
    }

    fn on_running(&mut self) {
        tracing::info!("boot reached running after {} ms", self.uptime_ms());
        if self.cfg.mode != BootMode::Normal {
            return;
        }
        // A service may already be failed at this point (e.g. a daemon outside the boot set).
        self.apply_leds(if self.failure_shown {
            LedState::Failsafe
        } else {
            LedState::Running
        });
        if let Some(path) = &self.cfg.bootcount_path {
            match owr_common::atomic_write(path, b"0\n", 0o600) {
                Ok(_) => {}
                Err(e) => tracing::warn!("cannot reset boot counter: {e}"),
            }
        }
    }

    fn handle_msg(&mut self, msg: Msg) -> Option<Exit> {
        match msg {
            Msg::Control { req, reply } => {
                let (text, exit) = self.handle_request(req);
                let written = exit.map(|_| {
                    // The connection reports back once the reply is out, so the exit below
                    // cannot overtake it (see `await_reply_written`).
                    let (tx, rx) = oneshot::channel();
                    self.reply_written = Some(rx);
                    tx
                });
                // The client may have timed out; nothing to do about it.
                let _ = reply.send(Reply { text, written });
                exit
            }
            Msg::Button {
                name,
                press,
                action,
            } => self.handle_button(&name, press, action),
        }
    }

    /// After a reboot/poweroff request: give the connection a moment to write its reply before
    /// services are stopped and the machine goes down.
    async fn await_reply_written(&mut self) {
        if let Some(rx) = self.reply_written.take() {
            // Err means the connection dropped without writing; either way, move on.
            let _ = tokio::time::timeout(REPLY_WRITE_GRACE, rx).await;
        }
    }

    fn handle_request(&mut self, req: Request) -> (String, Option<Exit>) {
        let now = Instant::now();
        match req {
            Request::Status => {
                let unix_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let text = status_response(
                    &self.manager.statuses(now, unix_now),
                    self.uptime_ms(),
                    self.cfg.mode,
                    self.cfg.reason.map(FailsafeReason::name),
                );
                (text, None)
            }
            Request::Restart(name) => match self.manager.restart(&name, now) {
                Some(ds) => {
                    self.exec(ds, now);
                    (ok_response(), None)
                }
                None => (error_response(ERR_UNKNOWN_SERVICE), None),
            },
            Request::Reload(name) => match self.manager.reload(&name) {
                Some(ds) if !ds.is_empty() => {
                    self.exec(ds, now);
                    (ok_response(), None)
                }
                Some(_) => (error_response("service is not running"), None),
                None => (error_response(ERR_UNKNOWN_SERVICE), None),
            },
            Request::Reboot => (ok_response(), Some(Exit::Reboot)),
            Request::Poweroff => (ok_response(), Some(Exit::PowerOff)),
            // Served directly by the connection handler; never forwarded.
            Request::Journal { .. } => (error_response("unsupported"), None),
        }
    }

    fn handle_button(&self, name: &str, press: Press, action: ButtonAction) -> Option<Exit> {
        tracing::info!("button {name}: {press:?} -> {action:?}");
        match action {
            ButtonAction::Reboot => Some(Exit::Reboot),
            ButtonAction::FactoryReset => {
                // The wipe happens early next boot, before the overlay is mounted. Only the
                // real data partition keeps the marker; in failsafe /overlay is a tmpfs, so
                // refuse loudly instead of "scheduling" a reset that would silently vanish.
                let marker = match factory_reset_target(self.cfg.mode, self.cfg.persistent) {
                    Ok(marker) => marker,
                    Err(refusal) => {
                        tracing::error!("factory reset refused: {refusal}");
                        return None;
                    }
                };
                match fs::write(&marker, b"1\n") {
                    Ok(()) => Some(Exit::Reboot),
                    Err(e) => {
                        tracing::error!("factory reset: cannot write {}: {e}", marker.display());
                        None
                    }
                }
            }
            ButtonAction::WifiToggle | ButtonAction::Wps => {
                tracing::info!("button action {action:?} is not implemented yet");
                None
            }
            ButtonAction::None => None,
        }
    }

    /// Stop every service (dependents first) within [`SHUTDOWN_GRACE`], then persist the journal.
    async fn shutdown(&mut self) {
        tracing::info!("shutting down: stopping services");
        let now = Instant::now();
        let ds = self.manager.stop_all(now);
        self.exec(ds, now);
        let deadline = now.checked_add(SHUTDOWN_GRACE).unwrap_or(now);
        while !self.manager.all_down() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.reap();
            let t = Instant::now();
            // Release the next wave (dependencies) once their dependents are down.
            let mut ds = self.manager.advance_shutdown(t);
            ds.extend(self.manager.poll(t, &exists));
            self.exec(ds, t);
            if let Some(wd) = &self.cfg.watchdog {
                wd.beat();
            }
        }
        if !self.manager.all_down() {
            tracing::warn!(
                "some services did not stop within {}s",
                SHUTDOWN_GRACE.as_secs()
            );
        }
        self.flush_journal();
    }
}
