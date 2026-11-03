//! Service specification and the per-service supervision state machine.
//!
//! [`Supervisor::on_event`] is a pure transition function: it receives an [`Event`] and the
//! current time and returns the [`Command`]s the runtime must carry out. It never performs
//! I/O, which makes every restart/backoff/escalation rule host-testable.
//!
//! Policy summary:
//! * A crash (non-zero exit, signal, spawn failure) is a *failure*. Failures count in a
//!   streak that restarts when a failure arrives more than [`FAILURE_WINDOW`] after the
//!   first failure of the streak (so 5 minutes of healthy running resets it). When the
//!   streak reaches [`FAILURE_LIMIT`] the service becomes [`State::Failed`] and stays down:
//!   init never reboots the box because of one daemon.
//! * A clean exit (code 0) of a `restart = always` daemon that ran at least
//!   [`MIN_CLEAN_UPTIME`] restarts after the initial delay and is not a failure; one that
//!   exits 0 sooner is crash-looping politely and counts as a failure (backoff applies).
//!   A clean exit of a oneshot completes it.
//! * A spawn failure of a `restart = never` service leaves it stopped (no retry).
//! * Stop is SIGTERM, then SIGKILL after `stop_timeout_ms`; once the main process is gone the
//!   whole process group is `SIGKILL`ed so nothing it forked outlives the stop.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::Level;

/// A `restart = always` service that exits 0 sooner than this after its start is failing.
pub const MIN_CLEAN_UPTIME: Duration = Duration::from_secs(10);

/// Consecutive failures within [`FAILURE_WINDOW`] after which a service is [`State::Failed`].
pub const FAILURE_LIMIT: u32 = 10;
/// Length of the crash-loop observation window.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(300);
/// Consecutive failed health probes after which a running service is restarted.
pub const HEALTH_FAIL_LIMIT: u32 = 3;

/// When a service is restarted after it exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

/// Exponential restart delay: `initial_ms * factor^(n-1)` capped at `max_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Backoff {
    pub initial_ms: u64,
    pub max_ms: u64,
    pub factor: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial_ms: 500,
            max_ms: 30_000,
            factor: 2,
        }
    }
}

impl Backoff {
    /// Delay before restart number `attempt` (1-based). Never exceeds `max_ms`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let mut ms = self.initial_ms;
        for _ in 1..attempt {
            ms = ms.saturating_mul(u64::from(self.factor));
            if ms >= self.max_ms {
                break;
            }
        }
        Duration::from_millis(ms.min(self.max_ms))
    }
}

/// How the runtime decides that a running service is healthy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheck {
    /// A unix socket exists at this path.
    UnixSocket(PathBuf),
    /// The pid file exists and names a live process.
    PidFile(PathBuf),
    /// Something accepts TCP connections on `127.0.0.1:<port>`.
    TcpPort(u16),
}

const fn default_stop_timeout_ms() -> u64 {
    5000
}

const fn default_restart() -> RestartPolicy {
    RestartPolicy::Never
}

/// Declarative description of one supervised process.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub name: String,
    /// argv; `exec[0]` must be an absolute path.
    pub exec: Vec<String>,
    /// Extra environment on top of the minimal `PATH`.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default = "default_restart")]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub backoff: Backoff,
    #[serde(default = "default_stop_timeout_ms")]
    pub stop_timeout_ms: u64,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub health: Option<HealthCheck>,
    /// Runs to completion once; dependents wait for a clean exit.
    #[serde(default)]
    pub oneshot: bool,
    /// Attach stdio to `/dev/console` instead of the journal (rescue shell).
    #[serde(default)]
    pub console: bool,
    /// Do not start while this path is missing (e.g. a config rendered by `owr-apply`).
    #[serde(default)]
    pub condition_path_exists: Option<PathBuf>,
    /// Oneshot only: SIGTERM it if it runs longer than this.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Any exit, spawn failure or timeout counts as completed so dependents still proceed.
    #[serde(default)]
    pub ignore_failure: bool,
}

impl ServiceSpec {
    /// A spec with defaults: never restart, no dependencies.
    pub fn new(name: &str, exec: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            exec: exec.iter().map(|s| (*s).to_owned()).collect(),
            env: Vec::new(),
            restart: RestartPolicy::Never,
            backoff: Backoff::default(),
            stop_timeout_ms: default_stop_timeout_ms(),
            depends_on: Vec::new(),
            health: None,
            oneshot: false,
            console: false,
            condition_path_exists: None,
            timeout_ms: None,
            ignore_failure: false,
        }
    }

    fn stop_timeout(&self) -> Duration {
        Duration::from_millis(self.stop_timeout_ms)
    }
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

impl ExitStatus {
    pub fn is_success(self) -> bool {
        self == Self::Code(0)
    }
}

/// Lifecycle state of one service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    /// Spawn requested, waiting for [`Event::Spawned`].
    Starting {
        since: Instant,
    },
    Running {
        pid: u32,
        since: Instant,
    },
    /// Waiting to restart after `attempts` consecutive failures.
    Backoff {
        until: Instant,
        attempts: u32,
    },
    Stopping {
        pid: u32,
        since: Instant,
    },
    /// Crash-loop limit reached; stays down until an explicit start.
    Failed {
        attempts: u32,
    },
}

impl State {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting { .. } => "starting",
            Self::Running { .. } => "running",
            Self::Backoff { .. } => "backoff",
            Self::Stopping { .. } => "stopping",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Input to the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Spawned {
        pid: u32,
    },
    /// The runtime could not spawn the process (exec missing, EAGAIN, ...).
    SpawnFailed,
    Exited {
        pid: u32,
        status: ExitStatus,
    },
    Tick {
        now: Instant,
    },
    StopRequested,
    StartRequested,
    HealthOk,
    HealthFail,
}

/// Signals the state machine may ask the runtime to deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Kill,
    Hup,
}

/// Output of the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Spawn(ServiceSpec),
    Kill { pid: u32, signal: Signal },
    ScheduleTick(Instant),
    Log(Level, String),
}

/// Serializable snapshot for the control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: &'static str,
    pub pid: Option<u32>,
    /// Consecutive failures in the current streak.
    pub failures: u32,
    pub oneshot: bool,
    /// `None` when the service has no health check.
    pub healthy: Option<bool>,
    /// Unix time at which the service entered its current state (`owr-api` `since_unix`).
    pub since_unix: u64,
    /// How many times the service was started again after its first start (`owr-api`
    /// `restarts`).
    pub restarts: u32,
}

/// Supervision state machine for one service.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent lifecycle flags; a state enum per flag adds nothing
pub struct Supervisor {
    spec: ServiceSpec,
    state: State,
    /// Operator intent: should the service be up?
    wanted: bool,
    /// A oneshot (or non-restarting service) finished with exit code 0.
    completed: bool,
    healthy: bool,
    health_fails: u32,
    /// The current stop was caused by failing health checks: count it as a failure.
    health_kill: bool,
    /// The current stop was caused by the oneshot run-time limit.
    timed_out: bool,
    kill_sent: bool,
    streak: u32,
    streak_start: Option<Instant>,
    /// When `state` last changed variant (creation time until the first change).
    state_since: Instant,
    /// Spawn attempts requested so far.
    starts: u32,
}

fn after(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).unwrap_or(t)
}

impl Supervisor {
    pub fn new(spec: ServiceSpec) -> Self {
        Self {
            spec,
            state: State::Stopped,
            wanted: false,
            completed: false,
            healthy: false,
            health_fails: 0,
            health_kill: false,
            timed_out: false,
            kill_sent: false,
            streak: 0,
            streak_start: None,
            state_since: Instant::now(),
            starts: 0,
        }
    }

    pub fn spec(&self) -> &ServiceSpec {
        &self.spec
    }

    pub fn name(&self) -> &str {
        &self.spec.name
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn pid(&self) -> Option<u32> {
        match self.state {
            State::Running { pid, .. } | State::Stopping { pid, .. } => Some(pid),
            _ => None,
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed { .. })
    }

    /// May dependents start? Running (and healthy if a health check is configured), or a
    /// oneshot that completed cleanly.
    pub fn is_ready(&self) -> bool {
        match self.state {
            State::Running { .. } => {
                !self.spec.oneshot && (self.spec.health.is_none() || self.healthy)
            }
            State::Stopped => self.spec.oneshot && self.completed,
            _ => false,
        }
    }

    /// Snapshot at monotonic `now`, which corresponds to wall-clock `unix_now` seconds.
    pub fn status(&self, now: Instant, unix_now: u64) -> ServiceStatus {
        let age = now.saturating_duration_since(self.state_since).as_secs();
        ServiceStatus {
            name: self.spec.name.clone(),
            state: self.state.name(),
            pid: self.pid(),
            failures: self.streak,
            oneshot: self.spec.oneshot,
            healthy: self.spec.health.as_ref().map(|_| self.healthy),
            since_unix: unix_now.saturating_sub(age),
            restarts: self.starts.saturating_sub(1),
        }
    }

    /// Pure transition function. `now` is used for every event except [`Event::Tick`],
    /// which carries its own timestamp.
    pub fn on_event(&mut self, ev: Event, now: Instant) -> Vec<Command> {
        let before = std::mem::discriminant(&self.state);
        let at = match ev {
            Event::Tick { now: t } => t,
            _ => now,
        };
        let out = self.transition(ev, now);
        if std::mem::discriminant(&self.state) != before {
            self.state_since = at;
        }
        out
    }

    fn transition(&mut self, ev: Event, now: Instant) -> Vec<Command> {
        let mut out = Vec::new();
        match ev {
            Event::StartRequested => self.start_requested(now, &mut out),
            Event::StopRequested => self.stop_requested(now, &mut out),
            Event::Spawned { pid } => self.spawned(pid, now, &mut out),
            Event::SpawnFailed => self.spawn_failed(now, &mut out),
            Event::Exited { pid, status } => self.exited(pid, status, now, &mut out),
            Event::Tick { now: t } => self.tick(t, &mut out),
            Event::HealthOk => {
                if matches!(self.state, State::Running { .. }) {
                    self.healthy = true;
                    self.health_fails = 0;
                }
            }
            Event::HealthFail => self.health_failed(now, &mut out),
        }
        out
    }

    fn log(&self, out: &mut Vec<Command>, level: Level, msg: &str) {
        out.push(Command::Log(level, format!("{}: {msg}", self.spec.name)));
    }

    fn begin_start(&mut self, now: Instant, out: &mut Vec<Command>) {
        self.starts = self.starts.saturating_add(1);
        self.state = State::Starting { since: now };
        self.healthy = false;
        self.health_fails = 0;
        self.health_kill = false;
        self.timed_out = false;
        self.kill_sent = false;
        out.push(Command::Spawn(self.spec.clone()));
        self.log(out, Level::INFO, "starting");
    }

    fn begin_stop(&mut self, pid: u32, now: Instant, out: &mut Vec<Command>) {
        self.state = State::Stopping { pid, since: now };
        self.kill_sent = false;
        out.push(Command::Kill {
            pid,
            signal: Signal::Term,
        });
        out.push(Command::ScheduleTick(after(now, self.spec.stop_timeout())));
        self.log(out, Level::INFO, &format!("stopping pid {pid} (SIGTERM)"));
    }

    fn start_requested(&mut self, now: Instant, out: &mut Vec<Command>) {
        self.wanted = true;
        match self.state {
            State::Stopped | State::Failed { .. } => {
                // An explicit start clears the crash-loop history.
                self.streak = 0;
                self.streak_start = None;
                self.completed = false;
                self.begin_start(now, out);
            }
            State::Backoff { .. } => self.begin_start(now, out),
            // Starting/Running: nothing to do. Stopping: `wanted` makes it restart on exit.
            State::Starting { .. } | State::Running { .. } | State::Stopping { .. } => {}
        }
    }

    fn stop_requested(&mut self, now: Instant, out: &mut Vec<Command>) {
        self.wanted = false;
        match self.state {
            State::Running { pid, .. } => self.begin_stop(pid, now, out),
            State::Backoff { .. } | State::Failed { .. } => self.state = State::Stopped,
            // Starting is resolved when `Spawned` arrives.
            State::Starting { .. } | State::Stopped | State::Stopping { .. } => {}
        }
    }

    fn spawned(&mut self, pid: u32, now: Instant, out: &mut Vec<Command>) {
        if !matches!(self.state, State::Starting { .. }) {
            self.log(
                out,
                Level::WARN,
                &format!("unexpected spawn of pid {pid}; killing it"),
            );
            out.push(Command::Kill {
                pid,
                signal: Signal::Kill,
            });
            return;
        }
        if self.wanted {
            self.state = State::Running { pid, since: now };
            self.log(out, Level::INFO, &format!("running pid {pid}"));
        } else {
            self.begin_stop(pid, now, out);
        }
    }

    fn spawn_failed(&mut self, now: Instant, out: &mut Vec<Command>) {
        if !matches!(self.state, State::Starting { .. }) {
            return;
        }
        if self.wanted && self.spec.ignore_failure {
            self.completed = true;
            self.state = State::Stopped;
            self.streak = self.streak.saturating_add(1); // visible in status
            self.log(out, Level::ERROR, "spawn failed; ignoring (ignore_failure)");
        } else if self.wanted && self.spec.restart == RestartPolicy::Never {
            self.state = State::Stopped;
            self.log(
                out,
                Level::ERROR,
                "spawn failed; restart policy is never, not retrying",
            );
        } else if self.wanted {
            self.record_failure(now, out, "spawn failed");
        } else {
            self.state = State::Stopped;
        }
    }

    fn exited(&mut self, pid: u32, status: ExitStatus, now: Instant, out: &mut Vec<Command>) {
        match self.state {
            State::Running { pid: p, since } if p == pid => {
                let uptime = now.saturating_duration_since(since);
                self.running_exited(status, uptime, now, out);
            }
            State::Stopping { pid: p, .. } if p == pid => {
                // The main process is gone; nothing it forked may outlive the stop.
                out.push(Command::Kill {
                    pid,
                    signal: Signal::Kill,
                });
                if !self.wanted {
                    self.state = State::Stopped;
                    self.log(out, Level::INFO, "stopped");
                } else if self.timed_out {
                    self.timed_out = false;
                    // Oneshot only: the uptime rule for `always` daemons does not apply.
                    self.running_exited(status, Duration::MAX, now, out);
                } else if self.health_kill {
                    self.health_kill = false;
                    self.record_failure(now, out, "restarting after failed health checks");
                } else {
                    // Stop followed by start (restart): come straight back up.
                    self.begin_start(now, out);
                }
            }
            _ => {}
        }
    }

    fn running_exited(
        &mut self,
        status: ExitStatus,
        uptime: Duration,
        now: Instant,
        out: &mut Vec<Command>,
    ) {
        let clean = status.is_success();
        if self.spec.ignore_failure && !clean {
            self.completed = true;
            self.state = State::Stopped;
            self.streak = self.streak.saturating_add(1); // visible in status
            self.log(
                out,
                Level::ERROR,
                &format!("exited ({status:?}); ignoring (ignore_failure)"),
            );
            return;
        }
        let restart = self.spec.restart;
        if clean && (self.spec.oneshot || restart != RestartPolicy::Always) {
            self.completed = true;
            self.state = State::Stopped;
            self.log(out, Level::INFO, "exited cleanly");
        } else if restart == RestartPolicy::Never {
            self.state = State::Stopped;
            self.log(
                out,
                Level::WARN,
                &format!("exited ({status:?}); restart policy is never"),
            );
        } else if clean && uptime < MIN_CLEAN_UPTIME {
            // A daemon that "succeeds" within seconds is crash-looping: backoff and the
            // failure limit must apply or it would respawn every 500 ms forever.
            self.record_failure(
                now,
                out,
                &format!("exited cleanly after only {}ms", uptime.as_millis()),
            );
        } else if clean {
            // `always` daemon that ran for a while and exited 0: restart after the base delay.
            let until = after(now, self.spec.backoff.delay(1));
            self.state = State::Backoff {
                until,
                attempts: self.streak,
            };
            out.push(Command::ScheduleTick(until));
            self.log(out, Level::INFO, "exited cleanly; restarting");
        } else {
            self.record_failure(now, out, &format!("exited ({status:?})"));
        }
    }

    fn record_failure(&mut self, now: Instant, out: &mut Vec<Command>, why: &str) {
        let in_window = self
            .streak_start
            .is_some_and(|s| now.saturating_duration_since(s) <= FAILURE_WINDOW);
        if in_window {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.streak_start = Some(now);
            self.streak = 1;
        }
        if self.streak >= FAILURE_LIMIT {
            self.state = State::Failed {
                attempts: self.streak,
            };
            let msg = format!(
                "{why}; {} consecutive failures within {}s, giving up (state=failed)",
                self.streak,
                FAILURE_WINDOW.as_secs()
            );
            self.log(out, Level::ERROR, &msg);
        } else {
            let delay = self.spec.backoff.delay(self.streak);
            let until = after(now, delay);
            self.state = State::Backoff {
                until,
                attempts: self.streak,
            };
            out.push(Command::ScheduleTick(until));
            let msg = format!(
                "{why}; failure {} of {FAILURE_LIMIT}, restart in {}ms",
                self.streak,
                delay.as_millis()
            );
            self.log(out, Level::WARN, &msg);
        }
    }

    fn tick(&mut self, now: Instant, out: &mut Vec<Command>) {
        match self.state {
            State::Backoff { until, .. } if now >= until => {
                if self.wanted {
                    self.begin_start(now, out);
                } else {
                    self.state = State::Stopped;
                }
            }
            State::Running { pid, since }
                if self.spec.oneshot
                    && self.spec.timeout_ms.is_some_and(|t| {
                        now.saturating_duration_since(since) >= Duration::from_millis(t)
                    }) =>
            {
                self.timed_out = true;
                self.log(out, Level::WARN, "run-time limit exceeded; terminating");
                self.begin_stop(pid, now, out);
            }
            State::Stopping { pid, since }
                if !self.kill_sent
                    && now.saturating_duration_since(since) >= self.spec.stop_timeout() =>
            {
                self.kill_sent = true;
                out.push(Command::Kill {
                    pid,
                    signal: Signal::Kill,
                });
                self.log(
                    out,
                    Level::WARN,
                    &format!("pid {pid} ignored SIGTERM; sending SIGKILL"),
                );
            }
            _ => {}
        }
    }

    fn health_failed(&mut self, now: Instant, out: &mut Vec<Command>) {
        let State::Running { pid, .. } = self.state else {
            return;
        };
        self.healthy = false;
        self.health_fails = self.health_fails.saturating_add(1);
        if self.health_fails >= HEALTH_FAIL_LIMIT {
            self.health_kill = true;
            self.log(out, Level::WARN, "health check failing; restarting");
            self.begin_stop(pid, now, out);
        } else {
            self.log(
                out,
                Level::DEBUG,
                &format!("health check failed ({})", self.health_fails),
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn millis(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn daemon(restart: RestartPolicy) -> Supervisor {
        let mut spec = ServiceSpec::new("d", &["/bin/d"]);
        spec.restart = restart;
        Supervisor::new(spec)
    }

    fn up(s: &mut Supervisor, pid: u32, now: Instant) {
        s.on_event(Event::StartRequested, now);
        s.on_event(Event::Spawned { pid }, now);
        assert!(matches!(s.state(), State::Running { .. }));
    }

    fn crash(s: &mut Supervisor, pid: u32, now: Instant) -> Vec<Command> {
        s.on_event(
            Event::Exited {
                pid,
                status: ExitStatus::Code(1),
            },
            now,
        )
    }

    fn backoff_until(s: &Supervisor) -> Instant {
        match s.state() {
            State::Backoff { until, .. } => until,
            other => unreachable!("expected backoff, got {other:?}"),
        }
    }

    /// Crash the running process, wait out the backoff, respawn as `pid + 1`.
    fn crash_and_respawn(s: &mut Supervisor, pid: u32, now: Instant) -> Instant {
        crash(s, pid, now);
        let at = backoff_until(s);
        s.on_event(Event::Tick { now: at }, at);
        s.on_event(Event::Spawned { pid: pid + 1 }, at);
        at
    }

    #[test]
    fn backoff_delay_grows_and_caps() {
        let b = Backoff::default();
        let ms: Vec<u128> = (1..=9).map(|n| b.delay(n).as_millis()).collect();
        assert_eq!(
            ms,
            [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]
        );
        assert_eq!(b.delay(0).as_millis(), 500);
        assert_eq!(
            b.delay(u32::MAX).as_millis(),
            30000,
            "huge attempts must not overflow"
        );
    }

    #[test]
    fn backoff_custom_factor_saturates() {
        let b = Backoff {
            initial_ms: u64::MAX / 2,
            max_ms: 10_000,
            factor: 1000,
        };
        assert_eq!(b.delay(5).as_millis(), 10_000);
    }

    #[test]
    fn start_spawns_then_running() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        let cmds = s.on_event(Event::StartRequested, t0);
        assert!(matches!(cmds[0], Command::Spawn(_)));
        assert_eq!(s.state(), State::Starting { since: t0 });
        s.on_event(Event::Spawned { pid: 7 }, t0);
        assert_eq!(s.state(), State::Running { pid: 7, since: t0 });
        assert_eq!(s.pid(), Some(7));
        assert!(s.is_ready());
    }

    #[test]
    fn crash_restarts_with_growing_backoff() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        let mut observed = Vec::new();
        for pid in 1..=7u32 {
            crash(&mut s, pid, now);
            let until = backoff_until(&s);
            observed.push(until.duration_since(now).as_millis());
            now = until;
            let cmds = s.on_event(Event::Tick { now }, now);
            assert!(cmds.iter().any(|c| matches!(c, Command::Spawn(_))));
            s.on_event(Event::Spawned { pid: pid + 1 }, now);
        }
        assert_eq!(observed, [500, 1000, 2000, 4000, 8000, 16000, 30000]);
    }

    #[test]
    fn tick_before_deadline_does_not_restart() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        crash(&mut s, 1, t0);
        let cmds = s.on_event(
            Event::Tick {
                now: t0 + millis(100),
            },
            t0,
        );
        assert_eq!(cmds, Vec::new());
        assert!(matches!(s.state(), State::Backoff { .. }));
    }

    #[test]
    fn ten_failures_within_window_fail_the_service() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        for pid in 1..=9u32 {
            now = crash_and_respawn(&mut s, pid, now);
        }
        let last = crash(&mut s, 10, now);
        assert_eq!(s.state(), State::Failed { attempts: 10 });
        assert!(s.is_failed());
        assert!(
            last.iter()
                .any(|c| matches!(c, Command::Log(l, _) if *l == Level::ERROR))
        );
        // Failed is terminal: ticks do nothing.
        assert_eq!(
            s.on_event(
                Event::Tick {
                    now: now + secs(3600)
                },
                now
            ),
            Vec::new()
        );
    }

    #[test]
    fn nine_failures_still_back_off() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::OnFailure);
        up(&mut s, 1, t0);
        let mut now = t0;
        for pid in 1..=9u32 {
            now = crash_and_respawn(&mut s, pid, now);
        }
        assert!(matches!(s.state(), State::Running { .. }));
        assert_eq!(s.status(Instant::now(), 0).failures, 9);
    }

    #[test]
    fn five_minutes_of_running_resets_failure_window() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        for pid in 1..=9u32 {
            now = crash_and_respawn(&mut s, pid, now);
        }
        assert_eq!(s.status(Instant::now(), 0).failures, 9);
        now += secs(301);
        crash(&mut s, 10, now);
        assert!(
            matches!(s.state(), State::Backoff { attempts: 1, .. }),
            "{:?}",
            s.state()
        );
        assert_eq!(backoff_until(&s).duration_since(now).as_millis(), 500);
    }

    #[test]
    fn slow_failures_never_accumulate_to_failed() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        for pid in 1..=30u32 {
            now += secs(400); // each run outlasts the window
            crash(&mut s, pid, now);
            assert!(matches!(s.state(), State::Backoff { attempts: 1, .. }));
            let at = backoff_until(&s);
            s.on_event(Event::Tick { now: at }, at);
            s.on_event(Event::Spawned { pid: pid + 1 }, at);
            now = at;
        }
    }

    #[test]
    fn oneshot_clean_exit_completes() {
        let t0 = Instant::now();
        let mut spec = ServiceSpec::new("apply", &["/sbin/owr-apply", "boot"]);
        spec.oneshot = true;
        spec.restart = RestartPolicy::OnFailure;
        let mut s = Supervisor::new(spec);
        assert!(!s.is_ready(), "never-run oneshot is not ready");
        up(&mut s, 5, t0);
        assert!(!s.is_ready(), "running oneshot is not complete");
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Code(0),
            },
            t0,
        );
        assert_eq!(s.state(), State::Stopped);
        assert!(s.is_ready());
        assert_eq!(
            s.on_event(Event::Tick { now: t0 + secs(60) }, t0),
            Vec::new()
        );
    }

    #[test]
    fn oneshot_failure_is_retried_with_backoff() {
        let t0 = Instant::now();
        let mut spec = ServiceSpec::new("apply", &["/sbin/owr-apply"]);
        spec.oneshot = true;
        spec.restart = RestartPolicy::OnFailure;
        let mut s = Supervisor::new(spec);
        up(&mut s, 5, t0);
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Code(2),
            },
            t0,
        );
        assert!(matches!(s.state(), State::Backoff { .. }));
        assert!(!s.is_ready());
    }

    #[test]
    fn restart_never_stops_after_exit() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Never);
        up(&mut s, 1, t0);
        s.on_event(
            Event::Exited {
                pid: 1,
                status: ExitStatus::Signal(11),
            },
            t0,
        );
        assert_eq!(s.state(), State::Stopped);
        assert!(!s.is_ready());
    }

    #[test]
    fn on_failure_clean_exit_stays_stopped() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::OnFailure);
        up(&mut s, 1, t0);
        s.on_event(
            Event::Exited {
                pid: 1,
                status: ExitStatus::Code(0),
            },
            t0,
        );
        assert_eq!(s.state(), State::Stopped);
    }

    fn exit0(s: &mut Supervisor, pid: u32, now: Instant) {
        s.on_event(
            Event::Exited {
                pid,
                status: ExitStatus::Code(0),
            },
            now,
        );
    }

    #[test]
    fn always_clean_exit_after_long_uptime_restarts_without_counting_failure() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let exit_at = t0 + MIN_CLEAN_UPTIME;
        exit0(&mut s, 1, exit_at);
        assert_eq!(backoff_until(&s).duration_since(exit_at).as_millis(), 500);
        assert_eq!(s.status(exit_at, 0).failures, 0);
    }

    #[test]
    fn always_clean_exit_within_ten_seconds_is_a_failure_with_backoff() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        let mut delays = Vec::new();
        for pid in 1..=4u32 {
            now += millis(9_999); // always just under the threshold
            exit0(&mut s, pid, now);
            let until = backoff_until(&s);
            delays.push(until.duration_since(now).as_millis());
            now = until;
            s.on_event(Event::Tick { now }, now);
            s.on_event(Event::Spawned { pid: pid + 1 }, now);
        }
        assert_eq!(delays, [500, 1000, 2000, 4000], "backoff must grow");
        assert_eq!(s.status(now, 0).failures, 4);
    }

    #[test]
    fn instant_clean_exits_eventually_fail_the_service() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let mut now = t0;
        for pid in 1..FAILURE_LIMIT {
            exit0(&mut s, pid, now);
            now = backoff_until(&s);
            s.on_event(Event::Tick { now }, now);
            s.on_event(Event::Spawned { pid: pid + 1 }, now);
        }
        exit0(&mut s, FAILURE_LIMIT, now);
        assert!(s.is_failed());
    }

    #[test]
    fn spawn_failure_of_restart_never_service_is_not_retried() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Never);
        s.on_event(Event::StartRequested, t0);
        let cmds = s.on_event(Event::SpawnFailed, t0);
        assert_eq!(s.state(), State::Stopped);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, Command::Log(l, _) if *l == Level::ERROR))
        );
        assert!(
            !cmds.iter().any(|c| matches!(c, Command::ScheduleTick(_))),
            "no retry scheduled"
        );
        assert_eq!(
            s.on_event(
                Event::Tick {
                    now: t0 + secs(3600)
                },
                t0
            ),
            Vec::new()
        );
        assert!(!s.is_ready());
    }

    #[test]
    fn ignored_failure_is_visible_in_status() {
        let t0 = Instant::now();
        let mut s = kmod();
        up(&mut s, 5, t0);
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Code(3),
            },
            t0,
        );
        assert!(s.is_ready());
        assert_eq!(s.status(t0, 0).state, "stopped");
        assert_eq!(s.status(t0, 0).failures, 1);
    }

    #[test]
    fn stopped_process_group_is_killed_after_exit() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 9, t0);
        s.on_event(Event::StopRequested, t0);
        let cmds = s.on_event(
            Event::Exited {
                pid: 9,
                status: ExitStatus::Code(0),
            },
            t0,
        );
        assert!(cmds.contains(&Command::Kill {
            pid: 9,
            signal: Signal::Kill
        }));
    }

    #[test]
    fn status_reports_since_unix_and_restarts() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        let st = s.status(t0 + secs(30), 1_000_000);
        assert_eq!(
            (st.state, st.since_unix, st.restarts),
            ("running", 999_970, 0)
        );
        let crash_at = t0 + secs(40);
        crash(&mut s, 1, crash_at);
        let at = backoff_until(&s);
        s.on_event(Event::Tick { now: at }, at);
        s.on_event(Event::Spawned { pid: 2 }, at);
        let st = s.status(at + secs(5), 2_000_000);
        assert_eq!(st.restarts, 1);
        assert_eq!(st.since_unix, 2_000_000 - 5, "running since the respawn");
        let json = serde_json::to_value(&st).unwrap();
        assert_eq!(json["since_unix"], 1_999_995);
        assert_eq!(json["restarts"], 1);
    }

    #[test]
    fn stop_sends_term_then_kill_after_timeout() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 9, t0);
        let cmds = s.on_event(Event::StopRequested, t0);
        assert!(cmds.contains(&Command::Kill {
            pid: 9,
            signal: Signal::Term
        }));
        assert!(cmds.contains(&Command::ScheduleTick(t0 + millis(5000))));
        assert_eq!(s.state(), State::Stopping { pid: 9, since: t0 });

        let early = Event::Tick {
            now: t0 + millis(4999),
        };
        assert_eq!(s.on_event(early, t0), Vec::new());

        let late = Event::Tick {
            now: t0 + millis(5000),
        };
        let cmds = s.on_event(late, t0);
        assert!(cmds.contains(&Command::Kill {
            pid: 9,
            signal: Signal::Kill
        }));
        // SIGKILL is sent only once.
        let again = Event::Tick { now: t0 + secs(8) };
        assert!(
            s.on_event(again, t0)
                .iter()
                .all(|c| !matches!(c, Command::Kill { .. }))
        );

        s.on_event(
            Event::Exited {
                pid: 9,
                status: ExitStatus::Signal(9),
            },
            t0 + secs(9),
        );
        assert_eq!(s.state(), State::Stopped);
        // A stop must not trigger a restart even with restart=always.
        assert_eq!(
            s.on_event(Event::Tick { now: t0 + secs(60) }, t0),
            Vec::new()
        );
    }

    #[test]
    fn graceful_stop_exit_goes_stopped() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 9, t0);
        s.on_event(Event::StopRequested, t0);
        s.on_event(
            Event::Exited {
                pid: 9,
                status: ExitStatus::Code(0),
            },
            t0,
        );
        assert_eq!(s.state(), State::Stopped);
    }

    #[test]
    fn stop_during_starting_terminates_on_spawn() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        s.on_event(Event::StartRequested, t0);
        assert_eq!(s.on_event(Event::StopRequested, t0), Vec::new());
        let cmds = s.on_event(Event::Spawned { pid: 3 }, t0);
        assert!(cmds.contains(&Command::Kill {
            pid: 3,
            signal: Signal::Term
        }));
        assert!(matches!(s.state(), State::Stopping { pid: 3, .. }));
    }

    #[test]
    fn stop_in_backoff_cancels_restart() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        crash(&mut s, 1, t0);
        s.on_event(Event::StopRequested, t0);
        assert_eq!(s.state(), State::Stopped);
        assert_eq!(
            s.on_event(Event::Tick { now: t0 + secs(60) }, t0),
            Vec::new()
        );
    }

    #[test]
    fn restart_is_stop_then_start() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        s.on_event(Event::StopRequested, t0);
        s.on_event(Event::StartRequested, t0);
        let cmds = s.on_event(
            Event::Exited {
                pid: 1,
                status: ExitStatus::Code(0),
            },
            t0,
        );
        assert!(cmds.iter().any(|c| matches!(c, Command::Spawn(_))));
        assert!(matches!(s.state(), State::Starting { .. }));
    }

    #[test]
    fn stale_exit_is_ignored() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        assert_eq!(
            s.on_event(
                Event::Exited {
                    pid: 99,
                    status: ExitStatus::Code(1)
                },
                t0
            ),
            Vec::new()
        );
        assert!(matches!(s.state(), State::Running { pid: 1, .. }));
    }

    #[test]
    fn spawn_failure_counts_as_failure() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        s.on_event(Event::StartRequested, t0);
        s.on_event(Event::SpawnFailed, t0);
        assert!(matches!(s.state(), State::Backoff { attempts: 1, .. }));
    }

    #[test]
    fn explicit_start_revives_failed_service() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        s.on_event(Event::StartRequested, t0);
        // StartRequested out of Backoff respawns at once and keeps the streak.
        for _ in 0..FAILURE_LIMIT {
            s.on_event(Event::SpawnFailed, t0);
            if s.is_failed() {
                break;
            }
            s.on_event(Event::StartRequested, t0);
        }
        assert!(s.is_failed());
        let cmds = s.on_event(Event::StartRequested, t0);
        assert!(cmds.iter().any(|c| matches!(c, Command::Spawn(_))));
        assert_eq!(s.status(Instant::now(), 0).failures, 0);
    }

    #[test]
    fn health_failures_restart_service_and_count_as_failure() {
        let t0 = Instant::now();
        let mut spec = ServiceSpec::new("api", &["/bin/api"]);
        spec.restart = RestartPolicy::Always;
        spec.health = Some(HealthCheck::TcpPort(443));
        let mut s = Supervisor::new(spec);
        up(&mut s, 4, t0);
        assert!(!s.is_ready(), "not ready until first HealthOk");
        s.on_event(Event::HealthOk, t0);
        assert!(s.is_ready());
        assert_eq!(s.status(Instant::now(), 0).healthy, Some(true));
        s.on_event(Event::HealthFail, t0);
        s.on_event(Event::HealthFail, t0);
        assert!(matches!(s.state(), State::Running { .. }));
        let cmds = s.on_event(Event::HealthFail, t0);
        assert!(cmds.contains(&Command::Kill {
            pid: 4,
            signal: Signal::Term
        }));
        s.on_event(
            Event::Exited {
                pid: 4,
                status: ExitStatus::Signal(15),
            },
            t0,
        );
        assert!(matches!(s.state(), State::Backoff { attempts: 1, .. }));
    }

    #[test]
    fn health_ok_resets_failure_count() {
        let t0 = Instant::now();
        let mut spec = ServiceSpec::new("api", &["/bin/api"]);
        spec.health = Some(HealthCheck::UnixSocket("/run/x.sock".into()));
        let mut s = Supervisor::new(spec);
        up(&mut s, 4, t0);
        for _ in 0..5 {
            s.on_event(Event::HealthFail, t0);
            s.on_event(Event::HealthOk, t0);
        }
        assert!(matches!(s.state(), State::Running { .. }));
    }

    #[test]
    fn toml_spec_parses_with_defaults() {
        #[derive(Deserialize)]
        struct F {
            service: Vec<ServiceSpec>,
        }
        let f: F = toml::from_str(
            r#"
            [[service]]
            name = "a"
            exec = ["/bin/a"]
            restart = "on-failure"
            health = { tcp-port = 80 }
            [service.backoff]
            initial_ms = 100
            "#,
        )
        .unwrap();
        let s = &f.service[0];
        assert_eq!(s.restart, RestartPolicy::OnFailure);
        assert_eq!(
            s.backoff,
            Backoff {
                initial_ms: 100,
                max_ms: 30_000,
                factor: 2
            }
        );
        assert_eq!(s.stop_timeout_ms, 5000);
        assert_eq!(s.health, Some(HealthCheck::TcpPort(80)));
        assert!(!s.oneshot);
    }

    fn kmod() -> Supervisor {
        let mut spec = ServiceSpec::new("kmodloader", &["/sbin/kmodloader"]);
        spec.oneshot = true;
        spec.timeout_ms = Some(60_000);
        spec.ignore_failure = true;
        Supervisor::new(spec)
    }

    #[test]
    fn oneshot_timeout_terminates_and_ignore_failure_completes() {
        let t0 = Instant::now();
        let mut s = kmod();
        up(&mut s, 5, t0);
        assert_eq!(
            s.on_event(Event::Tick { now: t0 + secs(59) }, t0),
            Vec::new()
        );
        let cmds = s.on_event(Event::Tick { now: t0 + secs(60) }, t0);
        assert!(cmds.contains(&Command::Kill {
            pid: 5,
            signal: Signal::Term
        }));
        assert!(matches!(s.state(), State::Stopping { pid: 5, .. }));
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Signal(15),
            },
            t0 + secs(61),
        );
        assert_eq!(s.state(), State::Stopped);
        assert!(s.is_ready(), "dependents must proceed after a timeout");
    }

    #[test]
    fn oneshot_timeout_without_ignore_failure_follows_restart_policy() {
        let t0 = Instant::now();
        let mut spec = ServiceSpec::new("slow", &["/bin/slow"]);
        spec.oneshot = true;
        spec.timeout_ms = Some(1000);
        spec.restart = RestartPolicy::OnFailure;
        let mut s = Supervisor::new(spec);
        up(&mut s, 5, t0);
        s.on_event(Event::Tick { now: t0 + secs(2) }, t0);
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Signal(15),
            },
            t0 + secs(2),
        );
        assert!(matches!(s.state(), State::Backoff { attempts: 1, .. }));
        assert!(!s.is_ready());
    }

    #[test]
    fn timeout_does_not_apply_to_daemons() {
        let t0 = Instant::now();
        let mut s = daemon(RestartPolicy::Always);
        up(&mut s, 1, t0);
        assert_eq!(
            s.on_event(
                Event::Tick {
                    now: t0 + secs(100_000)
                },
                t0
            ),
            Vec::new()
        );
    }

    #[test]
    fn ignore_failure_completes_on_nonzero_exit_and_spawn_failure() {
        let t0 = Instant::now();
        let mut s = kmod();
        up(&mut s, 5, t0);
        s.on_event(
            Event::Exited {
                pid: 5,
                status: ExitStatus::Code(1),
            },
            t0,
        );
        assert!(s.is_ready());
        assert!(!s.is_failed());

        let mut s = kmod();
        s.on_event(Event::StartRequested, t0);
        s.on_event(Event::SpawnFailed, t0);
        assert_eq!(s.state(), State::Stopped);
        assert!(s.is_ready(), "missing kmodloader must not block boot");
    }
}
