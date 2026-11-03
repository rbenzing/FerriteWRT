//! A set of [`Supervisor`]s with dependency gating.
//!
//! The manager owns every supervisor, validates the dependency graph once at construction
//! (unique names, known dependencies, no cycles, absolute exec paths) and stores supervisors
//! in dependency order. It is still pure: callers pass `now` and a path-existence probe, and
//! receive [`Directive`]s to execute.

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use crate::service::{
    Command, Event, ExitStatus, ServiceSpec, ServiceStatus, Signal, State, Supervisor,
};

/// A [`Command`] addressed from a named service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub service: String,
    pub command: Command,
}

/// Invalid service set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManagerError {
    #[error("invalid service name {0:?} (use 1-64 of [A-Za-z0-9_.-])")]
    InvalidName(String),
    #[error("duplicate service {0:?}")]
    Duplicate(String),
    #[error("service {0:?} has an empty exec")]
    EmptyExec(String),
    #[error("service {service:?}: exec path {path:?} is not absolute")]
    RelativeExec { service: String, path: String },
    #[error("service {service:?} depends on unknown service {dep:?}")]
    UnknownDependency { service: String, dep: String },
    #[error("dependency cycle involving {0:?}")]
    Cycle(String),
}

/// Whether `name` is acceptable as a service name (also used by the control protocol).
pub fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[derive(Debug)]
struct Slot {
    sup: Supervisor,
    /// Indices of dependencies; always smaller than this slot's own index.
    deps: Vec<usize>,
    /// Start requested, waiting for dependencies / condition.
    pending: bool,
    /// Shutdown: the stop request was already issued to this service.
    stop_sent: bool,
}

/// All supervisors, ordered dependencies-first.
#[derive(Debug)]
pub struct Manager {
    slots: Vec<Slot>,
}

fn tag(name: &str, cmds: Vec<Command>) -> impl Iterator<Item = Directive> + '_ {
    cmds.into_iter().map(|command| Directive {
        service: name.to_owned(),
        command,
    })
}

impl Manager {
    pub fn new(specs: Vec<ServiceSpec>) -> Result<Self, ManagerError> {
        let mut names = HashSet::new();
        for s in &specs {
            if !valid_service_name(&s.name) {
                return Err(ManagerError::InvalidName(s.name.clone()));
            }
            if !names.insert(s.name.as_str()) {
                return Err(ManagerError::Duplicate(s.name.clone()));
            }
            match s.exec.first() {
                None => return Err(ManagerError::EmptyExec(s.name.clone())),
                Some(p) if !p.starts_with('/') => {
                    return Err(ManagerError::RelativeExec {
                        service: s.name.clone(),
                        path: p.clone(),
                    });
                }
                Some(_) => {}
            }
            for d in &s.depends_on {
                if !specs.iter().any(|o| &o.name == d) {
                    return Err(ManagerError::UnknownDependency {
                        service: s.name.clone(),
                        dep: d.clone(),
                    });
                }
            }
        }
        let order = topo_order(&specs)?;
        let mut slots: Vec<Slot> = Vec::with_capacity(specs.len());
        let mut pool: Vec<Option<ServiceSpec>> = specs.into_iter().map(Some).collect();
        for idx in order {
            let Some(spec) = pool.get_mut(idx).and_then(Option::take) else {
                continue;
            };
            let deps = spec
                .depends_on
                .iter()
                .filter_map(|d| slots.iter().position(|s| s.sup.name() == d))
                .collect();
            slots.push(Slot {
                sup: Supervisor::new(spec),
                deps,
                pending: false,
                stop_sent: false,
            });
        }
        Ok(Self { slots })
    }

    /// Supervisors in dependency order.
    pub fn services(&self) -> impl Iterator<Item = &Supervisor> {
        self.slots.iter().map(|s| &s.sup)
    }

    pub fn get(&self, name: &str) -> Option<&Supervisor> {
        self.services().find(|s| s.name() == name)
    }

    /// Snapshots at monotonic `now` == wall-clock `unix_now` seconds.
    pub fn statuses(&self, now: Instant, unix_now: u64) -> Vec<ServiceStatus> {
        self.services().map(|s| s.status(now, unix_now)).collect()
    }

    pub fn any_failed(&self) -> bool {
        self.services().any(Supervisor::is_failed)
    }

    /// No service has a process or a pending restart.
    pub fn all_down(&self) -> bool {
        self.services()
            .all(|s| matches!(s.state(), State::Stopped | State::Failed { .. }))
    }

    fn slot_mut(&mut self, name: &str) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.sup.name() == name)
    }

    /// Mark every service as wanted; [`Manager::poll`] starts them as dependencies allow.
    pub fn start_all(&mut self) {
        for s in &mut self.slots {
            s.pending = true;
        }
    }

    /// Deliver one event to a named service. `None` if the name is unknown.
    pub fn deliver(&mut self, name: &str, ev: Event, now: Instant) -> Option<Vec<Directive>> {
        let slot = self.slot_mut(name)?;
        if ev == Event::StopRequested {
            slot.pending = false;
        }
        let cmds = slot.sup.on_event(ev, now);
        Some(tag(name, cmds).collect())
    }

    /// Stop then start a service immediately (bypasses dependency gating).
    pub fn restart(&mut self, name: &str, now: Instant) -> Option<Vec<Directive>> {
        let mut out = self.deliver(name, Event::StopRequested, now)?;
        out.extend(
            self.deliver(name, Event::StartRequested, now)
                .unwrap_or_default(),
        );
        Some(out)
    }

    /// Ask a running service to reload its configuration (SIGHUP).
    pub fn reload(&self, name: &str) -> Option<Vec<Directive>> {
        let sup = self.get(name)?;
        let State::Running { pid, .. } = sup.state() else {
            return Some(Vec::new());
        };
        Some(vec![Directive {
            service: name.to_owned(),
            command: Command::Kill {
                pid,
                signal: Signal::Hup,
            },
        }])
    }

    /// Route a reaped child to the service that owns it. Unknown pids are ignored.
    pub fn on_exit(&mut self, pid: u32, status: ExitStatus, now: Instant) -> Vec<Directive> {
        let Some(slot) = self.slots.iter_mut().find(|s| s.sup.pid() == Some(pid)) else {
            return Vec::new();
        };
        let name = slot.sup.name().to_owned();
        let cmds = slot.sup.on_event(Event::Exited { pid, status }, now);
        tag(&name, cmds).collect()
    }

    /// Begin shutting everything down, dependents before their dependencies, in waves: the first
    /// wave stops the services nothing depends on. Nothing is (re)started any more. Call
    /// [`Manager::advance_shutdown`] regularly to release the next wave once the previous one is
    /// down.
    pub fn stop_all(&mut self, now: Instant) -> Vec<Directive> {
        for slot in &mut self.slots {
            slot.pending = false;
            slot.stop_sent = false;
        }
        self.advance_shutdown(now)
    }

    /// Stop every service whose dependents are all down (stopped or failed) and that was not
    /// asked to stop yet.
    pub fn advance_shutdown(&mut self, now: Instant) -> Vec<Directive> {
        let down: Vec<bool> = self
            .slots
            .iter()
            .map(|s| matches!(s.sup.state(), State::Stopped | State::Failed { .. }))
            .collect();
        let releasable: Vec<bool> = (0..self.slots.len())
            .map(|i| {
                self.slots.iter().enumerate().all(|(j, other)| {
                    !other.deps.contains(&i) || down.get(j).copied().unwrap_or(true)
                })
            })
            .collect();
        let mut out = Vec::new();
        for (slot, release) in self.slots.iter_mut().zip(releasable).rev() {
            if release && !slot.stop_sent {
                slot.stop_sent = true;
                let name = slot.sup.name().to_owned();
                let cmds = slot.sup.on_event(Event::StopRequested, now);
                out.extend(tag(&name, cmds));
            }
        }
        out
    }

    fn ready_flags(&self) -> Vec<bool> {
        self.slots.iter().map(|s| s.sup.is_ready()).collect()
    }

    fn deps_ready(slot: &Slot, ready: &[bool]) -> bool {
        slot.deps
            .iter()
            .all(|d| ready.get(*d).copied().unwrap_or(false))
    }

    fn condition_ok(slot: &Slot, exists: &dyn Fn(&Path) -> bool) -> bool {
        slot.sup
            .spec()
            .condition_path_exists
            .as_deref()
            .is_none_or(exists)
    }

    /// Advance time and start every pending service whose dependencies are ready and whose
    /// condition path exists.
    pub fn poll(&mut self, now: Instant, exists: &dyn Fn(&Path) -> bool) -> Vec<Directive> {
        let ready = self.ready_flags();
        let mut out = Vec::new();
        for slot in &mut self.slots {
            let name = slot.sup.name().to_owned();
            out.extend(tag(&name, slot.sup.on_event(Event::Tick { now }, now)));
            if slot.pending && Self::deps_ready(slot, &ready) && Self::condition_ok(slot, exists) {
                slot.pending = false;
                out.extend(tag(&name, slot.sup.on_event(Event::StartRequested, now)));
            }
        }
        out
    }

    /// Everything wanted is up: each service is ready, or is deliberately skipped because its
    /// condition path does not exist. Used to decide that the boot reached "running".
    pub fn settled(&self, exists: &dyn Fn(&Path) -> bool) -> bool {
        let ready = self.ready_flags();
        self.slots.iter().all(|s| {
            s.sup.is_ready()
                || (s.pending && Self::deps_ready(s, &ready) && !Self::condition_ok(s, exists))
        })
    }
}

/// Dependencies-first order of indices; rejects cycles.
fn topo_order(specs: &[ServiceSpec]) -> Result<Vec<usize>, ManagerError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        New,
        Visiting,
        Done,
    }
    fn visit(
        i: usize,
        specs: &[ServiceSpec],
        marks: &mut [Mark],
        order: &mut Vec<usize>,
    ) -> Result<(), ManagerError> {
        let Some(spec) = specs.get(i) else {
            return Ok(());
        };
        match marks.get(i).copied() {
            Some(Mark::Done) | None => return Ok(()),
            Some(Mark::Visiting) => return Err(ManagerError::Cycle(spec.name.clone())),
            Some(Mark::New) => {}
        }
        if let Some(m) = marks.get_mut(i) {
            *m = Mark::Visiting;
        }
        for dep in &spec.depends_on {
            if let Some(d) = specs.iter().position(|s| &s.name == dep) {
                visit(d, specs, marks, order)?;
            }
        }
        if let Some(m) = marks.get_mut(i) {
            *m = Mark::Done;
        }
        order.push(i);
        Ok(())
    }
    let mut marks = vec![Mark::New; specs.len()];
    let mut order = Vec::with_capacity(specs.len());
    for i in 0..specs.len() {
        visit(i, specs, &mut marks, &mut order)?;
    }
    Ok(order)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::service::RestartPolicy;
    use std::time::Duration;

    fn spec(name: &str, deps: &[&str]) -> ServiceSpec {
        let mut s = ServiceSpec::new(name, &["/bin/x"]);
        s.depends_on = deps.iter().map(|d| (*d).to_owned()).collect();
        s.restart = RestartPolicy::Always;
        s
    }

    fn oneshot(name: &str) -> ServiceSpec {
        let mut s = spec(name, &[]);
        s.oneshot = true;
        s.restart = RestartPolicy::OnFailure;
        s
    }

    fn always(_: &Path) -> bool {
        true
    }

    fn spawned(ds: &[Directive]) -> Vec<&str> {
        ds.iter()
            .filter(|d| matches!(d.command, Command::Spawn(_)))
            .map(|d| d.service.as_str())
            .collect()
    }

    fn run(m: &mut Manager, name: &str, pid: u32, now: Instant) {
        m.deliver(name, Event::Spawned { pid }, now).unwrap();
    }

    #[test]
    fn dependents_wait_for_oneshot_completion() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![
            spec("web", &["apply"]),
            oneshot("apply"),
            spec("dns", &["apply"]),
        ])
        .unwrap();
        // Dependency order regardless of declaration order.
        assert_eq!(m.services().next().unwrap().name(), "apply");
        m.start_all();
        let ds = m.poll(t0, &always);
        assert_eq!(spawned(&ds), ["apply"], "only the oneshot may start first");
        run(&mut m, "apply", 10, t0);
        assert!(
            spawned(&m.poll(t0, &always)).is_empty(),
            "apply still running"
        );
        let ds = m.on_exit(10, ExitStatus::Code(0), t0);
        assert!(ds.iter().all(|d| !matches!(d.command, Command::Spawn(_))));
        let ds = m.poll(t0, &always);
        assert_eq!(spawned(&ds), ["web", "dns"]);
    }

    #[test]
    fn dependents_stay_blocked_when_oneshot_fails() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![oneshot("apply"), spec("web", &["apply"])]).unwrap();
        m.start_all();
        m.poll(t0, &always);
        run(&mut m, "apply", 10, t0);
        m.on_exit(10, ExitStatus::Code(1), t0);
        assert_eq!(spawned(&m.poll(t0, &always)), Vec::<&str>::new());
        assert_eq!(m.get("web").unwrap().state(), State::Stopped);
    }

    #[test]
    fn daemon_dependency_must_be_running() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![spec("a", &[]), spec("b", &["a"])]).unwrap();
        m.start_all();
        assert_eq!(spawned(&m.poll(t0, &always)), ["a"]);
        // `a` is Starting, not Running: b waits.
        assert_eq!(spawned(&m.poll(t0, &always)), Vec::<&str>::new());
        run(&mut m, "a", 1, t0);
        assert_eq!(spawned(&m.poll(t0, &always)), ["b"]);
    }

    #[test]
    fn crashed_dependency_does_not_restart_dependents_but_blocks_new_starts() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![spec("a", &[]), spec("b", &["a"])]).unwrap();
        m.start_all();
        m.poll(t0, &always);
        run(&mut m, "a", 1, t0);
        m.poll(t0, &always);
        run(&mut m, "b", 2, t0);
        m.on_exit(1, ExitStatus::Code(1), t0);
        assert!(matches!(m.get("a").unwrap().state(), State::Backoff { .. }));
        assert!(matches!(m.get("b").unwrap().state(), State::Running { .. }));
    }

    #[test]
    fn condition_path_gates_start_and_is_settled_when_skipped() {
        let t0 = Instant::now();
        let mut hostapd = spec("hostapd-phy1", &["apply"]);
        hostapd.condition_path_exists = Some("/run/ferritewrt/hostapd-phy1.conf".into());
        let mut m = Manager::new(vec![oneshot("apply"), hostapd]).unwrap();
        m.start_all();
        m.poll(t0, &always);
        assert!(!m.settled(&always));
        run(&mut m, "apply", 1, t0);
        m.on_exit(1, ExitStatus::Code(0), t0);
        let missing = |_: &Path| false;
        assert_eq!(spawned(&m.poll(t0, &missing)), Vec::<&str>::new());
        assert!(
            m.settled(&missing),
            "skipped service must not block 'running'"
        );
        assert_eq!(spawned(&m.poll(t0, &always)), ["hostapd-phy1"]);
        assert!(!m.settled(&always), "starting is not settled");
    }

    #[test]
    fn stop_all_is_reverse_dependency_order() {
        let t0 = Instant::now();
        let mut m =
            Manager::new(vec![spec("a", &[]), spec("b", &["a"]), spec("c", &["b"])]).unwrap();
        m.start_all();
        for (i, n) in ["a", "b", "c"].iter().enumerate() {
            m.poll(t0, &always);
            run(&mut m, n, u32::try_from(i).unwrap() + 1, t0);
        }
        let term = |ds: &[Directive]| -> Vec<String> {
            ds.iter()
                .filter(|d| {
                    matches!(
                        d.command,
                        Command::Kill {
                            signal: Signal::Term,
                            ..
                        }
                    )
                })
                .map(|d| d.service.clone())
                .collect()
        };
        // Wave 1: only the service nothing depends on.
        assert_eq!(term(&m.stop_all(t0)), ["c"]);
        assert!(
            term(&m.advance_shutdown(t0)).is_empty(),
            "b must wait while c is still stopping"
        );
        // Wave 2 is released only once c is down.
        m.on_exit(3, ExitStatus::Code(0), t0);
        assert_eq!(term(&m.advance_shutdown(t0)), ["b"]);
        assert!(term(&m.advance_shutdown(t0)).is_empty(), "no repeated TERM");
        // Wave 3.
        m.on_exit(2, ExitStatus::Code(0), t0);
        assert_eq!(term(&m.advance_shutdown(t0)), ["a"]);
        m.on_exit(1, ExitStatus::Code(0), t0);
        assert!(m.all_down());
        // Stopped services never restart via poll.
        assert_eq!(
            spawned(&m.poll(t0 + Duration::from_secs(60), &always)),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn independent_services_stop_in_the_same_wave() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![
            spec("base", &[]),
            spec("x", &["base"]),
            spec("y", &["base"]),
        ])
        .unwrap();
        m.start_all();
        for (i, n) in ["base", "x", "y"].iter().enumerate() {
            m.poll(t0, &always);
            run(&mut m, n, u32::try_from(i).unwrap() + 1, t0);
        }
        let first: Vec<String> = m.stop_all(t0).into_iter().map(|d| d.service).collect();
        assert!(first.contains(&"x".to_owned()) && first.contains(&"y".to_owned()));
        assert!(!first.contains(&"base".to_owned()));
        m.on_exit(2, ExitStatus::Code(0), t0);
        assert!(
            m.advance_shutdown(t0).is_empty(),
            "base waits for both dependents"
        );
        m.on_exit(3, ExitStatus::Code(0), t0);
        assert_ne!(m.advance_shutdown(t0), Vec::new());
    }

    #[test]
    fn statuses_carry_since_unix_and_restarts() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![spec("a", &[])]).unwrap();
        m.start_all();
        m.poll(t0, &always);
        run(&mut m, "a", 1, t0);
        let st = m.statuses(t0 + Duration::from_secs(10), 5_000);
        assert_eq!(
            (st[0].state, st[0].since_unix, st[0].restarts),
            ("running", 4_990, 0)
        );
    }

    #[test]
    fn restart_and_reload() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![spec("a", &[])]).unwrap();
        m.start_all();
        m.poll(t0, &always);
        run(&mut m, "a", 7, t0);
        let ds = m.reload("a").unwrap();
        assert_eq!(
            ds[0].command,
            Command::Kill {
                pid: 7,
                signal: Signal::Hup
            }
        );
        let ds = m.restart("a", t0).unwrap();
        assert!(ds.iter().any(|d| d.command
            == Command::Kill {
                pid: 7,
                signal: Signal::Term
            }));
        let ds = m.on_exit(7, ExitStatus::Code(0), t0);
        assert_eq!(spawned(&ds), ["a"]);
        assert!(m.restart("nope", t0).is_none());
        assert!(m.reload("nope").is_none());
    }

    #[test]
    fn unknown_pid_exit_is_ignored() {
        let mut m = Manager::new(vec![spec("a", &[])]).unwrap();
        assert_eq!(
            m.on_exit(123, ExitStatus::Code(0), Instant::now()),
            Vec::new()
        );
    }

    #[test]
    fn validation_errors() {
        assert!(matches!(
            Manager::new(vec![spec("a", &[]), spec("a", &[])]),
            Err(ManagerError::Duplicate(_))
        ));
        assert!(matches!(
            Manager::new(vec![spec("a", &["zzz"])]),
            Err(ManagerError::UnknownDependency { .. })
        ));
        assert!(matches!(
            Manager::new(vec![spec("a", &["b"]), spec("b", &["a"])]),
            Err(ManagerError::Cycle(_))
        ));
        assert!(matches!(
            Manager::new(vec![spec("a", &["a"])]),
            Err(ManagerError::Cycle(_))
        ));
        assert!(matches!(
            Manager::new(vec![ServiceSpec::new("a", &["relative"])]),
            Err(ManagerError::RelativeExec { .. })
        ));
        assert!(matches!(
            Manager::new(vec![ServiceSpec::new("a", &[])]),
            Err(ManagerError::EmptyExec(_))
        ));
        assert!(matches!(
            Manager::new(vec![ServiceSpec::new("bad name", &["/x"])]),
            Err(ManagerError::InvalidName(_))
        ));
    }

    #[test]
    fn any_failed_reports_failed_service() {
        let t0 = Instant::now();
        let mut m = Manager::new(vec![spec("a", &[])]).unwrap();
        assert!(!m.any_failed());
        m.start_all();
        m.poll(t0, &always);
        for _ in 0..10 {
            m.deliver("a", Event::SpawnFailed, t0);
            if m.any_failed() {
                break;
            }
            m.deliver("a", Event::StartRequested, t0);
        }
        assert!(m.any_failed());
    }
}
