//! `owr-apply netd`: the long-running network daemon (service `owr-netd`).
//!
//! Runs what [`crate::NetdPlan`] lists: the WAN `DHCPv4` client, whose leases are applied
//! with [`on_dhcp_lease`] / [`on_dhcp_lost`], and one router advertisement sender per
//! LAN-side link with an IPv6 /64. Each lease event reloads the board and config from disk,
//! so the converge uses the configuration saved last; when the plan itself changes,
//! `netd.json` changes and the supervisor restarts the daemon. SIGTERM or SIGINT stops it;
//! SIGHUP (init's `reload`) stops it cleanly too, and the supervisor starts it again with
//! the current configuration.

use std::fmt::Display;
use std::time::Duration;

use owr_board::Board;
use owr_config::Config;
use owr_net::linux::dhcp::{DhcpClient, DhcpEvent};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::run::{ApplyError, Paths, on_dhcp_lease, on_dhcp_lost, plans_for};

/// How long the tasks get to stop after a signal.
const STOP_GRACE: Duration = Duration::from_secs(3);
/// Lease events waiting to be applied; the client blocks beyond this.
const EVENT_QUEUE: usize = 8;

/// Run until SIGTERM, SIGINT or SIGHUP. `board` and `cfg` are the startup configuration; `reload`
/// reads the current one for each lease event (on failure the startup one is used).
pub async fn run<L, E>(
    board: Board,
    cfg: Config,
    reload: L,
    paths: &Paths,
) -> Result<(), ApplyError>
where
    L: Fn() -> Result<(Board, Config), E>,
    E: Display,
{
    let netd = plans_for(&board, &cfg, paths)?.netd;
    let mut terminate = signal(SignalKind::terminate()).map_err(ApplyError::Signal)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(ApplyError::Signal)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(ApplyError::Signal)?;

    let (stop, shutdown) = watch::channel(false);
    let (events_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let mut tasks = JoinSet::new();
    for spec in netd.ra {
        tasks.spawn(owr_net::linux::ra::run(spec, shutdown.clone()));
    }
    if let Some(spec) = netd.dhcp {
        tasks.spawn(DhcpClient::run(spec, events_tx, shutdown.clone()));
    } else {
        drop(events_tx);
    }
    if tasks.is_empty() {
        info!("no DHCP client and no router advertisements configured; idle");
    }

    let startup = (board, cfg);
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => {
                info!("reload requested");
                break;
            }
            Some(event) = events.recv() => on_event(event, &startup, &reload, paths).await,
        }
    }
    info!("stopping");
    let _ = stop.send(true);
    let drained = tokio::time::timeout(STOP_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        warn!("tasks did not stop in time");
    }
    Ok(())
}

async fn on_event<L, E>(event: DhcpEvent, startup: &(Board, Config), reload: &L, paths: &Paths)
where
    L: Fn() -> Result<(Board, Config), E>,
    E: Display,
{
    let (board, cfg) = reload().unwrap_or_else(|e| {
        warn!(error = %e, "reloading the configuration failed; using the one loaded at start");
        startup.clone()
    });
    let result = match event {
        DhcpEvent::Bound(lease) | DhcpEvent::Renewed(lease) => {
            info!(addr = %lease.addr, lease_secs = lease.lease_secs, "DHCP lease");
            on_dhcp_lease(&board, &cfg, lease, paths).await
        }
        DhcpEvent::Lost => {
            warn!("DHCP lease lost");
            on_dhcp_lost(&board, &cfg, paths).await
        }
    };
    match result {
        Ok(outcome) => {
            info!(
                net_actions = outcome.net_actions,
                resolv_changed = outcome.resolv_changed,
                "lease applied"
            );
            for warning in &outcome.warnings {
                warn!(%warning, "lease applied with a warning");
            }
        }
        Err(e) => error!(error = %e, "applying the lease failed"),
    }
}
