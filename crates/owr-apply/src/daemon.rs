//! `owr-apply netd`: the long-running network daemon (service `owr-netd`).
//!
//! Runs what [`crate::NetdPlan`] lists: the WAN `DHCPv4` client, whose leases are applied
//! with [`on_dhcp_lease`] / [`on_dhcp_lost`], the `DHCPv6` prefix-delegation client, whose
//! leases are applied with [`on_dhcp6_lease`] / [`on_dhcp6_lost`] and then handed to the
//! router advertisements, and one router advertisement sender per LAN-side link. Each lease
//! event reloads the board and config from disk, so the converge uses the configuration saved
//! last; when the plan itself changes, `netd.json` changes and the supervisor restarts the
//! daemon. SIGTERM or SIGINT stops it; SIGHUP (init's `reload`) stops it cleanly too, and the
//! supervisor starts it again with the current configuration.
//!
//! The delegated prefix reaches the hosts through the advertisements: every sender has a
//! channel carrying its link's share (`pd::ra_dynamic`), a lost delegation is announced once
//! with lifetimes of zero (`pd::ra_withdrawn`), and a persisted lease seeds the channels at
//! start so that a restart of the daemon does not briefly withdraw the router.

use std::collections::HashMap;
use std::fmt::Display;
use std::time::{Duration, SystemTime};

use owr_board::Board;
use owr_config::Config;
use owr_net::dhcp6::{Dhcp6Event, Lease6};
use owr_net::linux::dhcp::{DhcpClient, DhcpEvent};
use owr_net::linux::dhcp6::Dhcp6Client;
use owr_net::ra::RaDynamic;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::lease::load_valid_lease6;
use crate::pd::{PdAssignment, PdLink, assign, needs_advertising, ra_dynamic, ra_withdrawn};
use crate::run::{
    ApplyError, LeaseOutcome, Paths, on_dhcp_lease, on_dhcp_lost, on_dhcp6_lease, on_dhcp6_lost,
    plans_for,
};

/// How long the tasks get to stop after a signal.
const STOP_GRACE: Duration = Duration::from_secs(3);
/// Lease events waiting to be applied; the client blocks beyond this.
const EVENT_QUEUE: usize = 8;

/// The advertisement senders' channels and what they were last told.
struct Advertisements {
    senders: HashMap<String, watch::Sender<RaDynamic>>,
    /// The shares of the delegation the senders advertise now.
    assigned: Vec<PdAssignment>,
    pd_links: Vec<PdLink>,
}

impl Advertisements {
    /// Tell every sender its share of `lease`. A change of what hosts should hear wakes the
    /// sender; a renewal only refreshes the lifetimes it counts down from.
    fn delegated(&mut self, lease: &Lease6) {
        self.assigned = assign(lease, &self.pd_links);
        let elapsed = SystemTime::now()
            .duration_since(lease.obtained_at)
            .unwrap_or_default();
        for (link, tx) in &self.senders {
            let new = ra_dynamic(link, &self.assigned, elapsed);
            tx.send_if_modified(|cur| {
                let notify = needs_advertising(cur, &new);
                *cur = new;
                notify
            });
        }
    }

    /// The delegation is gone: announce its prefixes once more with lifetimes of zero.
    fn withdrawn(&mut self) {
        if self.assigned.is_empty() {
            return;
        }
        for (link, tx) in &self.senders {
            let new = ra_withdrawn(link, &self.assigned);
            tx.send_if_modified(|cur| {
                let notify = needs_advertising(cur, &new);
                *cur = new;
                notify
            });
        }
        self.assigned.clear();
    }
}

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
    let (events6_tx, mut events6) = mpsc::channel(EVENT_QUEUE);
    let mut tasks = JoinSet::new();

    // A delegation that outlived the previous daemon (it is on tmpfs, so it did not outlive
    // a reboot) keeps being advertised until the client reports on it.
    let restored = netd
        .dhcp6
        .as_ref()
        .and_then(|c| load_valid_lease6(&paths.run_dir, &c.link, SystemTime::now()));
    let mut ads = Advertisements {
        senders: HashMap::new(),
        assigned: Vec::new(),
        pd_links: netd.pd_links.clone(),
    };
    if let Some(lease) = &restored {
        ads.assigned = assign(lease, &ads.pd_links);
    }
    let elapsed = restored
        .as_ref()
        .and_then(|l| SystemTime::now().duration_since(l.obtained_at).ok())
        .unwrap_or_default();
    for spec in netd.ra {
        let initial = ra_dynamic(&spec.link, &ads.assigned, elapsed);
        let (tx, rx) = watch::channel(initial);
        ads.senders.insert(spec.link.clone(), tx);
        tasks.spawn(owr_net::linux::ra::run_dynamic(spec, rx, shutdown.clone()));
    }
    if let Some(spec) = netd.dhcp {
        tasks.spawn(DhcpClient::run(spec, events_tx, shutdown.clone()));
    } else {
        drop(events_tx);
    }
    if let Some(spec) = netd.dhcp6 {
        tasks.spawn(Dhcp6Client::run(spec, events6_tx, shutdown.clone()));
    } else {
        drop(events6_tx);
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
            Some(event) = events6.recv() => {
                on_event6(event, &startup, &reload, paths, &mut ads).await;
            }
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

/// The current board and config, the startup ones when they cannot be read.
fn current<L, E>(startup: &(Board, Config), reload: &L) -> (Board, Config)
where
    L: Fn() -> Result<(Board, Config), E>,
    E: Display,
{
    reload().unwrap_or_else(|e| {
        warn!(error = %e, "reloading the configuration failed; using the one loaded at start");
        startup.clone()
    })
}

fn report(what: &str, result: Result<LeaseOutcome, ApplyError>) -> bool {
    match result {
        Ok(outcome) => {
            info!(
                net_actions = outcome.net_actions,
                resolv_changed = outcome.resolv_changed,
                "{what} applied"
            );
            for warning in &outcome.warnings {
                warn!(%warning, "{what} applied with a warning");
            }
            true
        }
        Err(e) => {
            error!(error = %e, "applying the {what} failed");
            false
        }
    }
}

async fn on_event<L, E>(event: DhcpEvent, startup: &(Board, Config), reload: &L, paths: &Paths)
where
    L: Fn() -> Result<(Board, Config), E>,
    E: Display,
{
    let (board, cfg) = current(startup, reload);
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
    report("lease", result);
}

async fn on_event6<L, E>(
    event: Dhcp6Event,
    startup: &(Board, Config),
    reload: &L,
    paths: &Paths,
    ads: &mut Advertisements,
) where
    L: Fn() -> Result<(Board, Config), E>,
    E: Display,
{
    let (board, cfg) = current(startup, reload);
    match event {
        Dhcp6Event::Bound(lease) | Dhcp6Event::Renewed(lease) => {
            info!(prefixes = ?lease.nets(), "delegated prefix");
            // The hosts are told once the router has the addresses.
            if report(
                "prefix lease",
                on_dhcp6_lease(&board, &cfg, lease.clone(), paths).await,
            ) {
                ads.delegated(&lease);
            }
        }
        Dhcp6Event::Lost => {
            warn!("delegated prefix lost");
            report("prefix loss", on_dhcp6_lost(&board, &cfg, paths).await);
            ads.withdrawn();
        }
    }
}

#[cfg(test)]
mod tests {
    use owr_net::dhcp6::DelegatedPrefix;
    use tokio::time::Instant;

    use super::*;

    fn lease(prefix: &str, valid: u32, obtained_at: SystemTime) -> Lease6 {
        Lease6 {
            prefixes: vec![DelegatedPrefix {
                prefix: prefix.parse().unwrap(),
                preferred_secs: valid / 2,
                valid_secs: valid,
            }],
            dns: Vec::new(),
            t1: valid / 2,
            t2: valid,
            server_id: vec![1],
            obtained_at,
        }
    }

    fn ads() -> (Advertisements, watch::Receiver<RaDynamic>) {
        let (tx, rx) = watch::channel(RaDynamic::none());
        let ads = Advertisements {
            senders: HashMap::from([("br-lan".to_owned(), tx)]),
            assigned: Vec::new(),
            pd_links: vec![PdLink {
                link: "br-lan".to_owned(),
                subnet: 0,
            }],
        };
        (ads, rx)
    }

    #[tokio::test]
    async fn a_new_delegation_wakes_the_sender_and_a_renewal_only_refreshes_the_lifetimes() {
        let (mut ads, mut rx) = ads();
        let now = SystemTime::now();
        ads.delegated(&lease("2001:db8:1::/56", 1000, now));
        assert!(rx.has_changed().unwrap(), "a new prefix is news");
        let first = rx.borrow_and_update().clone();
        assert_eq!(first.prefixes.len(), 1);
        assert_eq!(
            first.dns,
            vec!["2001:db8:1::1".parse::<std::net::Ipv6Addr>().unwrap()]
        );

        // the same prefix again, renewed later: stored, but nobody is woken
        tokio::time::sleep(Duration::from_millis(20)).await;
        ads.delegated(&lease("2001:db8:1::/56", 1000, SystemTime::now()));
        assert!(!rx.has_changed().unwrap(), "a renewal is not news");
        assert!(
            rx.borrow().as_of > first.as_of,
            "but the lifetimes start over"
        );

        // a different prefix is news again
        ads.delegated(&lease("2001:db8:7::/56", 1000, SystemTime::now()));
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn a_lost_delegation_is_announced_with_lifetimes_of_zero_once() {
        let (mut ads, mut rx) = ads();
        ads.delegated(&lease("2001:db8:1::/56", 1000, SystemTime::now()));
        rx.borrow_and_update();
        ads.withdrawn();
        assert!(rx.has_changed().unwrap());
        {
            let gone = rx.borrow_and_update();
            assert_eq!(gone.prefixes.len(), 1);
            assert!(gone.prefixes[0].valid.is_zero() && gone.prefixes[0].preferred.is_zero());
            assert_eq!(gone.dns.len(), 0);
        }
        assert_eq!(ads.assigned.len(), 0);
        // losing it again says nothing new
        ads.withdrawn();
        assert!(!rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn an_old_lease_is_advertised_with_the_time_already_gone() {
        let (mut ads, rx) = ads();
        let granted = SystemTime::now()
            .checked_sub(Duration::from_secs(400))
            .unwrap();
        ads.delegated(&lease("2001:db8:1::/56", 1000, granted));
        let d = rx.borrow().clone();
        let elapsed = Instant::now().duration_since(d.as_of);
        assert!(
            (Duration::from_secs(399)..Duration::from_secs(405)).contains(&elapsed),
            "{elapsed:?}"
        );
    }
}
