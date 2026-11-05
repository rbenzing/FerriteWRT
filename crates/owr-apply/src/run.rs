//! Linux orchestration: drive the appliers with the plans from [`build_plans_with`].
//!
//! Order of [`apply_all`] (the pure list is [`crate::steps::apply_steps`]): hostname, a
//! bootstrap firewall (the full ruleset without the flowtable), network converge, the final
//! firewall, forwarding sysctls, daemon configs. Forwarding is only switched on after a
//! ruleset with `policy drop` on forward is loaded; if a firewall step fails, forwarding is
//! switched off again and the error is returned. The outcome says which pieces changed so
//! that the supervisor (`owr-init`) restarts only the affected daemons; on failure the
//! error still carries the outcome built so far ([`ApplyError::Partial`]).
//!
//! [`apply_all`] is idempotent: the DHCP lease reported earlier by [`on_dhcp_lease`] is
//! persisted under the run directory and merged back into the plan, so a second run keeps
//! the lease's address and routes and changes nothing. The DHCP client runs in the network
//! daemon ([`crate::daemon`]), which reports its leases through [`on_dhcp_lease`] and
//! [`on_dhcp_lost`].

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use owr_board::Board;
use owr_common::paths::RUN_DIR;
use owr_config::{Config, LanIpv6};
use owr_net::NetPlan;
use owr_net::dhcp::{Lease, merge_lease};
use serde::Serialize;
use tracing::{Instrument, error, info, info_span, warn};

use crate::files::{DaemonFiles, FilesError, write_daemon_files_partial};
use crate::lease::{forget_lease, publish_lease_dns, save_lease, with_persisted_lease};
use crate::steps::{
    Step, apply_steps, critical_links, forwarding_off, is_critical, split_forwarding,
};
use crate::ula::{self, UlaError};
use crate::{Inputs, MapError, Plans, build_plans_with};

/// Root of the sysctl tree.
const PROC_SYS: &str = "/proc/sys";
/// Run-directory subdirectory of the bootstrap firewall (its own script and marker, so the
/// bootstrap and final rulesets do not invalidate each other's "already loaded" check).
const FW_BOOTSTRAP_DIR: &str = "fw-bootstrap";

/// Where the appliers read and write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Rendered daemon configs and the persisted DHCP lease (tmpfs).
    pub run_dir: PathBuf,
    /// The `nft` binary used to load the firewall.
    pub nft_bin: PathBuf,
    /// Written with the hostname; `/proc/sys/kernel/hostname` on a real system.
    pub hostname_file: PathBuf,
    /// Persistent ULA prefix (`/etc/ferritewrt/ula-prefix`), used when `lan.ipv6 = ula`.
    pub ula_file: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            run_dir: PathBuf::from(RUN_DIR),
            nft_bin: PathBuf::from("/usr/sbin/nft"),
            hostname_file: PathBuf::from("/proc/sys/kernel/hostname"),
            ula_file: ula::default_path(),
        }
    }
}

/// What [`apply_all`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent per-daemon \"files changed\" flags, not a state"
)]
pub struct ApplyOutcome {
    /// Network actions the planner asked for (0 when already converged).
    pub net_actions: usize,
    pub fw_changed: bool,
    /// `(phy, changed)` per radio with a hostapd config.
    pub hostapd_changed: Vec<(String, bool)>,
    pub dnsmasq_changed: bool,
    pub netd_changed: bool,
    /// pppd's options changed or were removed (restart `pppoe-wan`).
    pub pppoe_changed: bool,
    /// Non-fatal problems (hostname, absent sysctls, failed-but-tolerated actions).
    pub warnings: Vec<String>,
}

/// What [`on_dhcp_lease`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LeaseOutcome {
    pub net_actions: usize,
    /// `resolv.conf.auto` changed; dnsmasq re-reads it on its own, no restart needed.
    pub resolv_changed: bool,
    pub warnings: Vec<String>,
}

/// Failure of [`apply_all`] or [`on_dhcp_lease`].
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Map(#[from] MapError),
    #[error("opening netlink socket: {0}")]
    Netlink(#[source] io::Error),
    #[error("network: {0}")]
    Net(#[from] owr_net::linux::NetError),
    /// Security-relevant sysctls or WAN/LAN link/address actions failed (reasons included).
    #[error("critical network actions failed: {}", .0.join("; "))]
    CriticalNet(Vec<String>),
    #[error("firewall: {0}")]
    Fw(#[from] owr_fw::apply::ApplyError),
    #[error("daemon configs: {0}")]
    Files(#[from] FilesError),
    #[error("ULA prefix: {0}")]
    Ula(#[from] UlaError),
    #[error("writing sysctl {key}: {source}")]
    Sysctl {
        key: String,
        #[source]
        source: io::Error,
    },
    #[error("installing signal handlers: {0}")]
    Signal(#[source] io::Error),
    #[error("the network plan has no DHCP client to attach the lease to")]
    NoDhcpClient,
    /// `source` stopped [`apply_all`] after `outcome` had been reached: the daemons whose
    /// files changed in `outcome` should still be restarted.
    #[error("{source}")]
    Partial {
        outcome: Box<ApplyOutcome>,
        source: Box<ApplyError>,
    },
}

impl ApplyError {
    /// What had been changed when the apply stopped, if anything was.
    pub fn partial_outcome(&self) -> Option<&ApplyOutcome> {
        match self {
            Self::Partial { outcome, .. } => Some(outcome),
            _ => None,
        }
    }
}

/// Whether the running kernel exposes this sysctl. Unknown keys are kept so that the
/// applier reports them, except global keys that are absent from the kernel (YAMA not
/// built in, no IPv6): those could never converge. Per-interface keys are always kept:
/// their interface may not exist yet and appears during the converge.
fn sysctl_present(key: &str) -> bool {
    match owr_net::model::sysctl_path(key) {
        Ok(path) => {
            owr_net::model::sysctl_iface(&path).is_some() || Path::new(PROC_SYS).join(path).exists()
        }
        Err(_) => true,
    }
}

/// Drop the global sysctls this kernel does not have, with a warning for each.
fn retain_present(sysctls: &mut Vec<(String, String)>, warnings: &mut Vec<String>) {
    sysctls.retain(|(key, _)| {
        let present = sysctl_present(key);
        if !present {
            warn!(key, "sysctl not available in this kernel, skipping");
            warnings.push(format!("sysctl {key} not available, skipped"));
        }
        present
    });
}

/// Converge links, addresses, routes and sysctls. Sysctls the kernel does not have (for
/// example YAMA not built in) are skipped with a warning: the applier could neither write
/// nor verify them, and the plan would never converge.
///
/// A failed action is fatal ([`ApplyError::CriticalNet`]) when it is on a security-relevant
/// sysctl or on a `critical` link (see [`is_critical`]); any other failure is a warning.
async fn converge_net(
    plan: &NetPlan,
    critical: &BTreeSet<String>,
) -> Result<(usize, Vec<String>), ApplyError> {
    let mut plan = plan.clone();
    let mut warnings = Vec::new();
    retain_present(&mut plan.sysctls, &mut warnings);

    let (conn, handle, _) = rtnetlink::new_connection().map_err(ApplyError::Netlink)?;
    let task = tokio::spawn(conn);
    let result = owr_net::linux::converge(&handle, &plan).await;
    drop(handle);
    task.abort();

    let (actions, failed) = match result {
        Ok(converged) => {
            info!(
                actions = converged.actions.len(),
                applied = converged.report.applied,
                "network converged"
            );
            (converged.actions.len(), converged.report.failed)
        }
        // The applier ran but the plan is not empty afterwards: those actions failed.
        Err(owr_net::linux::NetError::NotConverged(remaining)) => {
            let failed = remaining
                .into_iter()
                .map(|action| (action, "still pending after apply".to_owned()))
                .collect::<Vec<_>>();
            (failed.len(), failed)
        }
        Err(e) => return Err(e.into()),
    };

    let mut fatal = Vec::new();
    for (action, reason) in &failed {
        let text = format!("{action:?}: {reason}");
        if is_critical(action, critical) {
            error!(?action, reason, "critical network action failed");
            fatal.push(text);
        } else {
            warn!(?action, reason, "network action failed");
            warnings.push(text);
        }
    }
    if fatal.is_empty() {
        Ok((actions, warnings))
    } else {
        Err(ApplyError::CriticalNet(fatal))
    }
}

async fn set_hostname(name: &str, file: &Path) -> io::Result<()> {
    if let Ok(current) = tokio::fs::read_to_string(file).await
        && current.trim() == name
    {
        return Ok(());
    }
    tokio::fs::write(file, name).await
}

/// Write sysctls straight to `/proc/sys` (used for forwarding only; everything else goes
/// through the `owr-net` converge).
async fn write_sysctls(sysctls: &[(String, String)]) -> Result<(), ApplyError> {
    for (key, value) in sysctls {
        let path = owr_net::model::sysctl_path(key).map_err(|e| ApplyError::Sysctl {
            key: key.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, e.to_string()),
        })?;
        tokio::fs::write(Path::new(PROC_SYS).join(path), format!("{value}\n"))
            .await
            .map_err(|source| ApplyError::Sysctl {
                key: key.clone(),
                source,
            })?;
    }
    Ok(())
}

/// Safety fallback after a failed firewall step: switch forwarding off. The loaded ruleset
/// stays as it is.
async fn fail_closed(warnings: &mut Vec<String>) {
    error!("firewall step failed: disabling forwarding, keeping the loaded ruleset");
    if let Err(e) = write_sysctls(&forwarding_off()).await {
        error!(error = %e, "could not disable forwarding");
        warnings.push(format!("could not disable forwarding: {e}"));
    }
}

fn io_context(context: String) -> impl FnOnce(io::Error) -> FilesError {
    move |source| FilesError::Io { context, source }
}

/// Load a ruleset; on failure switch forwarding off and return the error.
async fn load_firewall(
    rs: &owr_fw::Ruleset,
    dir: &Path,
    paths: &Paths,
    warnings: &mut Vec<String>,
) -> Result<owr_fw::apply::Applied, ApplyError> {
    std::fs::create_dir_all(dir).map_err(io_context(format!("creating {}", dir.display())))?;
    match owr_fw::apply::apply(rs, &paths.nft_bin, dir).await {
        Ok(applied) => Ok(applied),
        Err(e) => {
            fail_closed(warnings).await;
            Err(e.into())
        }
    }
}

/// Run `steps` in order, recording progress in `out`.
async fn execute(
    steps: Vec<Step>,
    plans: &Plans,
    cfg: &Config,
    paths: &Paths,
    out: &mut ApplyOutcome,
) -> Result<(), ApplyError> {
    let critical = critical_links(plans);
    for step in steps {
        match step {
            Step::Hostname => {
                async {
                    if let Err(e) = set_hostname(&plans.hostname, &paths.hostname_file).await {
                        warn!(error = %e, "setting hostname failed");
                        out.warnings.push(format!("setting hostname: {e}"));
                    }
                }
                .instrument(info_span!("hostname"))
                .await;
            }
            Step::FirewallBootstrap(rs) => {
                let dir = paths.run_dir.join(FW_BOOTSTRAP_DIR);
                load_firewall(&rs, &dir, paths, &mut out.warnings)
                    .instrument(info_span!("firewall_bootstrap"))
                    .await?;
            }
            Step::ConvergeNet(plan) => {
                let (net_actions, warnings) = converge_net(&plan, &critical)
                    .instrument(info_span!("network"))
                    .await?;
                out.net_actions = net_actions;
                out.warnings.extend(warnings);
            }
            Step::FirewallFinal(rs) => {
                let applied = load_firewall(&rs, &paths.run_dir, paths, &mut out.warnings)
                    .instrument(info_span!("firewall"))
                    .await?;
                out.fw_changed = applied.changed;
            }
            Step::EnableForwarding(mut sysctls) => {
                retain_present(&mut sysctls, &mut out.warnings);
                write_sysctls(&sysctls)
                    .instrument(info_span!("forwarding"))
                    .await?;
            }
            Step::DaemonFiles => {
                let mut files = DaemonFiles::default();
                let result = info_span!("daemon_configs").in_scope(|| {
                    write_daemon_files_partial(plans, cfg, &paths.run_dir, &mut files)
                });
                out.hostapd_changed = files.hostapd_changed;
                out.dnsmasq_changed = files.dnsmasq_changed;
                out.netd_changed = files.netd_changed;
                out.pppoe_changed = files.pppoe_changed;
                result?;
            }
        }
    }
    Ok(())
}

/// The plans for `(board, cfg)`, with the persistent ULA prefix loaded (or created) when the
/// config asks for ULA addressing.
pub(crate) fn plans_for(board: &Board, cfg: &Config, paths: &Paths) -> Result<Plans, ApplyError> {
    let ula_prefix = if cfg.network.lan.ipv6 == LanIpv6::Ula {
        let (prefix, _created) = ula::load_or_create(&paths.ula_file, ula::os_random)?;
        Some(prefix)
    } else {
        None
    };
    let inputs = Inputs {
        ula_prefix,
        run_dir: Some(paths.run_dir.clone()),
    };
    Ok(build_plans_with(board, cfg, &inputs)?)
}

/// Build the plans from `(board, cfg)` and apply all of them. Idempotent: a second call
/// with the same input changes nothing and reports `false` / `0` everywhere (the persisted
/// DHCP lease is merged back into the plan, see the module documentation).
///
/// An error that happens while applying is wrapped in [`ApplyError::Partial`] together with
/// the outcome reached so far.
pub async fn apply_all(
    board: &Board,
    cfg: &Config,
    paths: &Paths,
) -> Result<ApplyOutcome, ApplyError> {
    let mut plans = plans_for(board, cfg, paths)?;
    plans.net = with_persisted_lease(&plans.net, &paths.run_dir, SystemTime::now());
    let mut out = ApplyOutcome {
        warnings: plans.warnings.clone(),
        ..ApplyOutcome::default()
    };
    std::fs::create_dir_all(&paths.run_dir)
        .map_err(io_context(format!("creating {}", paths.run_dir.display())))?;

    match execute(apply_steps(&plans), &plans, cfg, paths, &mut out).await {
        Ok(()) => Ok(out),
        Err(source) => Err(ApplyError::Partial {
            outcome: Box::new(out),
            source: Box::new(source),
        }),
    }
}

/// A DHCP client reported a lease: persist it (so [`apply_all`] keeps it), merge it into the
/// network plan (the single-writer hand-off of `owr-net`), converge, and publish the lease's
/// usable DNS servers to dnsmasq. A lease without usable DNS keeps the previous
/// `resolv.conf.auto`.
pub async fn on_dhcp_lease(
    board: &Board,
    cfg: &Config,
    lease: Lease,
    paths: &Paths,
) -> Result<LeaseOutcome, ApplyError> {
    let plans = plans_for(board, cfg, paths)?;
    let spec = plans
        .net
        .dhcp_clients
        .first()
        .ok_or(ApplyError::NoDhcpClient)?;
    save_lease(&paths.run_dir, &spec.link, &lease)?;
    let merged = merge_lease(&plans.net, spec, &lease);
    // Forwarding is owned by apply_all (it may have been switched off on purpose).
    let (merged, _) = split_forwarding(&merged);

    let (net_actions, mut warnings) = converge_net(&merged, &critical_links(&plans))
        .instrument(info_span!("network_lease"))
        .await?;
    let (resolv_changed, warning) = publish_lease_dns(&paths.run_dir, &lease)?;
    warnings.extend(warning);
    Ok(LeaseOutcome {
        net_actions,
        resolv_changed,
        warnings,
    })
}

/// The DHCP client lost its lease (NAK or expiry): forget the persisted lease and converge
/// the plan without it, which removes the lease's address and routes. `resolv.conf.auto`
/// keeps the last servers; nothing reaches them without an address anyway.
pub async fn on_dhcp_lost(
    board: &Board,
    cfg: &Config,
    paths: &Paths,
) -> Result<LeaseOutcome, ApplyError> {
    let plans = plans_for(board, cfg, paths)?;
    let spec = plans
        .net
        .dhcp_clients
        .first()
        .ok_or(ApplyError::NoDhcpClient)?;
    forget_lease(&paths.run_dir, &spec.link)?;
    let (net, _) = split_forwarding(&plans.net);
    let (net_actions, warnings) = converge_net(&net, &critical_links(&plans))
        .instrument(info_span!("network_lease_lost"))
        .await?;
    Ok(LeaseOutcome {
        net_actions,
        resolv_changed: false,
        warnings,
    })
}
