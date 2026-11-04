//! The set of services init supervises, built from the board and a few filesystem facts.
//!
//! The builder is pure: the runtime gathers the facts (is `owr-apply` installed, does
//! `ssh.enabled` exist, which radios does the board have) and gets a list of
//! [`ServiceSpec`]s back. Binaries need not exist on the host running the tests.

use owr_common::paths::{CONFIG_DIR, RUN_DIR};
use serde::Deserialize;

use crate::sandbox::profile_for;
use crate::service::{RestartPolicy, ServiceSpec};

/// Environment given to every child: only `PATH`, everything else is cleared.
pub const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// Applies the persisted config (network, firewall, wifi, daemon configs) at boot.
pub const APPLY_BIN: &str = "/sbin/owr-apply";
/// Longest `owr-apply boot` may run before it is terminated.
pub const APPLY_TIMEOUT_MS: u64 = 120_000;
/// Kernel module loader, executed directly (no shell).
pub const KMODLOADER_BIN: &str = "/sbin/kmodloader";
/// busybox `setsid`: gives a console program its own session and controlling terminal. std has
/// no safe `setsid` for children (`pre_exec` is unsafe, which this crate forbids).
pub const SETSID_BIN: &str = "/bin/setsid";

/// argv for a program attached to the console. With `setsid` available the program becomes the
/// leader of a new session and takes the console as its controlling terminal (`setsid -c`), so
/// Ctrl-C / hangups on the console reach it and not init; without it the program is run as is.
pub fn console_argv(exec: &[String], setsid_present: bool) -> Vec<String> {
    if !setsid_present {
        return exec.to_vec();
    }
    [SETSID_BIN.to_owned(), "-c".to_owned()]
        .into_iter()
        .chain(exec.iter().cloned())
        .collect()
}

/// Existence of this file turns the SSH server on.
pub fn ssh_enabled_marker() -> String {
    format!("{CONFIG_DIR}/ssh.enabled")
}

/// Facts that decide which services run. Independent yes/no facts gathered from the file
/// system, hence the bools.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServiceContext {
    pub failsafe: bool,
    /// `/sbin/owr-apply` is installed.
    pub apply_present: bool,
    pub ssh_enabled: bool,
    /// `phy_index` of every board radio; one hostapd instance each.
    pub radio_phys: Vec<u8>,
    /// Confine the network daemons ([`crate::sandbox`]); off when
    /// `/etc/ferritewrt/sandbox.off` exists.
    pub sandbox: bool,
}

/// Loads kernel modules (`/sbin/kmodloader`, from ubox, kept in the image). Bounded to 60 s;
/// failure is logged but never blocks boot.
pub fn kmodloader() -> ServiceSpec {
    let mut s = ServiceSpec::new("kmodloader", &[KMODLOADER_BIN]);
    s.oneshot = true;
    s.timeout_ms = Some(60_000);
    s.ignore_failure = true;
    s
}

/// Interactive shell on the console, restarted forever.
pub fn rescue_shell() -> ServiceSpec {
    let mut s = ServiceSpec::new("rescue-shell", &["/bin/sh"]);
    s.restart = RestartPolicy::Always;
    s.console = true;
    s
}

fn daemon(name: &str, exec: &[&str]) -> ServiceSpec {
    let mut s = ServiceSpec::new(name, exec);
    s.restart = RestartPolicy::Always;
    s.depends_on = vec!["owr-apply".to_owned()];
    s
}

/// Build the service list for this boot.
pub fn build_services(ctx: &ServiceContext) -> Vec<ServiceSpec> {
    if ctx.failsafe || !ctx.apply_present {
        return vec![kmodloader(), rescue_shell()];
    }
    // A failing or hanging apply must not take the management UI down with it: it is bounded,
    // its failure is logged at error level and shown in status (failures > 0), and nothing that
    // needs the UI waits for it.
    let mut apply = ServiceSpec::new("owr-apply", &[APPLY_BIN, "boot"]);
    apply.oneshot = true;
    apply.restart = RestartPolicy::OnFailure;
    apply.timeout_ms = Some(APPLY_TIMEOUT_MS);
    apply.ignore_failure = true;
    apply.depends_on = vec!["kmodloader".to_owned()];

    let dnsmasq_conf = format!("{RUN_DIR}/dnsmasq.conf");
    let mut dnsmasq = daemon(
        "dnsmasq",
        &[
            "/usr/sbin/dnsmasq",
            "--keep-in-foreground",
            &format!("--conf-file={dnsmasq_conf}"),
        ],
    );
    dnsmasq.condition_path_exists = Some(dnsmasq_conf.into());

    // The management UI is how a broken config gets fixed: it needs the drivers (network
    // devices), not the applied config.
    let mut api = daemon("owr-api", &["/usr/bin/owr-api"]);
    api.depends_on = vec!["kmodloader".to_owned()];

    let mut out = vec![
        kmodloader(),
        apply,
        dnsmasq,
        daemon("odhcpd", &["/usr/sbin/odhcpd"]),
        api,
    ];
    for phy in &ctx.radio_phys {
        let conf = format!("{RUN_DIR}/hostapd-phy{phy}.conf");
        let mut hostapd = daemon(&format!("hostapd-phy{phy}"), &["/usr/sbin/hostapd", &conf]);
        hostapd.condition_path_exists = Some(conf.into());
        out.push(hostapd);
    }
    if ctx.sandbox {
        for spec in &mut out {
            if profile_for(&spec.name).is_some() {
                spec.sandbox = Some(spec.name.clone());
            }
        }
    }
    if ctx.ssh_enabled {
        let mut ssh = ServiceSpec::new("dropbear", &["/usr/sbin/dropbear", "-F", "-R"]);
        ssh.restart = RestartPolicy::Always;
        out.push(ssh);
    }
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicesFile {
    #[serde(default)]
    service: Vec<ServiceSpec>,
}

/// Parse the `--test-mode` services file (`[[service]]` tables).
pub fn parse_services_toml(text: &str) -> Result<Vec<ServiceSpec>, toml::de::Error> {
    toml::from_str::<ServicesFile>(text).map(|f| f.service)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::manager::Manager;

    fn ctx() -> ServiceContext {
        ServiceContext {
            failsafe: false,
            apply_present: true,
            ssh_enabled: false,
            radio_phys: vec![0, 1],
            sandbox: true,
        }
    }

    fn names(specs: &[ServiceSpec]) -> Vec<&str> {
        specs.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn network_daemons_are_confined_unless_disabled() {
        let confined = |c: &ServiceContext| -> Vec<String> {
            build_services(c)
                .into_iter()
                .filter_map(|s| s.sandbox)
                .collect()
        };
        assert_eq!(
            confined(&ctx()),
            ["dnsmasq", "odhcpd", "hostapd-phy0", "hostapd-phy1"]
        );
        let off = ServiceContext {
            sandbox: false,
            ..ctx()
        };
        assert!(
            confined(&off).is_empty(),
            "sandbox.off disables every profile"
        );
        let mut ssh = ctx();
        ssh.ssh_enabled = true;
        assert!(
            build_services(&ssh)
                .iter()
                .any(|s| s.name == "dropbear" && s.sandbox.is_none()),
            "no profile for dropbear"
        );
    }

    #[test]
    fn normal_set_for_two_radio_board() {
        let specs = build_services(&ctx());
        assert_eq!(
            names(&specs),
            [
                "kmodloader",
                "owr-apply",
                "dnsmasq",
                "odhcpd",
                "owr-api",
                "hostapd-phy0",
                "hostapd-phy1"
            ]
        );
        let kmod = &specs[0];
        assert!(kmod.oneshot && kmod.ignore_failure);
        assert_eq!(kmod.exec, ["/sbin/kmodloader"]);
        assert_eq!(kmod.timeout_ms, Some(60_000));
        let apply = &specs[1];
        assert_eq!(apply.depends_on, ["kmodloader"]);
        assert!(apply.oneshot);
        assert_eq!(apply.exec, ["/sbin/owr-apply", "boot"]);
        assert_eq!(apply.timeout_ms, Some(120_000));
        assert!(apply.ignore_failure, "a failing apply must not block boot");
        for s in &specs[2..] {
            assert_eq!(s.restart, RestartPolicy::Always, "{}", s.name);
            let dep = if s.name == "owr-api" {
                "kmodloader"
            } else {
                "owr-apply"
            };
            assert_eq!(s.depends_on, [dep], "{}", s.name);
        }
        let h = specs.iter().find(|s| s.name == "hostapd-phy1").unwrap();
        assert_eq!(
            h.exec,
            ["/usr/sbin/hostapd", "/run/ferritewrt/hostapd-phy1.conf"]
        );
        assert_eq!(
            h.condition_path_exists.as_deref().and_then(|p| p.to_str()),
            Some("/run/ferritewrt/hostapd-phy1.conf")
        );
        let d = specs.iter().find(|s| s.name == "dnsmasq").unwrap();
        assert!(d.exec.contains(&"--keep-in-foreground".to_owned()));
        assert!(
            d.exec
                .contains(&"--conf-file=/run/ferritewrt/dnsmasq.conf".to_owned())
        );
    }

    #[test]
    fn graph_is_valid() {
        assert!(Manager::new(build_services(&ctx())).is_ok());
        let mut c = ctx();
        c.ssh_enabled = true;
        assert!(Manager::new(build_services(&c)).is_ok());
        assert!(
            Manager::new(build_services(&ServiceContext {
                failsafe: true,
                ..ctx()
            }))
            .is_ok()
        );
    }

    #[test]
    fn dropbear_only_when_enabled() {
        assert!(!names(&build_services(&ctx())).contains(&"dropbear"));
        let mut c = ctx();
        c.ssh_enabled = true;
        let specs = build_services(&c);
        let d = specs.iter().find(|s| s.name == "dropbear").unwrap();
        assert_eq!(d.exec, ["/usr/sbin/dropbear", "-F", "-R"]);
        assert_eq!(d.restart, RestartPolicy::Always);
    }

    #[test]
    fn failsafe_and_missing_apply_give_rescue_shell_only() {
        for c in [
            ServiceContext {
                failsafe: true,
                ..ctx()
            },
            ServiceContext {
                apply_present: false,
                ..ctx()
            },
        ] {
            let specs = build_services(&c);
            assert_eq!(names(&specs), ["kmodloader", "rescue-shell"]);
            assert!(specs[1].console);
            assert_eq!(specs[1].restart, RestartPolicy::Always);
            assert_eq!(specs[1].exec, ["/bin/sh"]);
        }
    }

    #[test]
    fn api_is_reachable_when_apply_fails_or_times_out() {
        use crate::service::{Event, ExitStatus, State};
        use std::path::Path;
        use std::time::{Duration, Instant};

        let t0 = Instant::now();
        let mut m = Manager::new(build_services(&ctx())).unwrap();
        let yes = |_: &Path| true;
        m.start_all();
        m.poll(t0, &yes);
        m.deliver("kmodloader", Event::Spawned { pid: 1 }, t0);
        m.on_exit(1, ExitStatus::Code(0), t0);
        let ds = m.poll(t0, &yes);
        let started = |ds: &[crate::manager::Directive], n: &str| {
            ds.iter()
                .any(|d| d.service == n && matches!(d.command, crate::service::Command::Spawn(_)))
        };
        assert!(started(&ds, "owr-apply"));
        assert!(started(&ds, "owr-api"), "api must not wait for owr-apply");
        assert!(!started(&ds, "dnsmasq"));
        // apply hangs: after its timeout it is terminated, then dependents proceed.
        m.deliver("owr-apply", Event::Spawned { pid: 2 }, t0);
        let at = t0 + Duration::from_millis(APPLY_TIMEOUT_MS);
        m.poll(at, &yes);
        assert!(matches!(
            m.get("owr-apply").unwrap().state(),
            State::Stopping { .. }
        ));
        m.on_exit(2, ExitStatus::Signal(15), at);
        let ds = m.poll(at, &yes);
        assert!(m.get("owr-apply").unwrap().is_ready());
        assert!(started(&ds, "dnsmasq"));
        assert_eq!(m.get("owr-apply").unwrap().status(at, 0).failures, 1);
    }

    #[test]
    fn console_programs_get_their_own_session_when_setsid_exists() {
        let exec = vec!["/bin/sh".to_owned()];
        assert_eq!(console_argv(&exec, true), ["/bin/setsid", "-c", "/bin/sh"]);
        assert_eq!(console_argv(&exec, false), ["/bin/sh"]);
        let two = vec!["/bin/sh".to_owned(), "-l".to_owned()];
        assert_eq!(console_argv(&two, true).len(), 4);
    }

    #[test]
    fn parses_services_toml_and_rejects_unknown_keys() {
        let specs = parse_services_toml(
            "[[service]]\nname = \"s\"\nexec = [\"/bin/sleep\", \"1\"]\nrestart = \"always\"\n",
        )
        .unwrap();
        assert_eq!(specs[0].restart, RestartPolicy::Always);
        assert!(
            parse_services_toml("[[service]]\nname = \"s\"\nexec = [\"/x\"]\nbogus = 1\n").is_err()
        );
        assert_eq!(parse_services_toml("").unwrap(), Vec::new());
    }
}
