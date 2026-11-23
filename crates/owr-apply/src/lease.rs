//! DHCP lease persistence and publication, host-testable.
//!
//! The DHCP client reports a lease once; `owr-net` converges addresses and routes to the
//! plan, so a later `run::apply_all` that did not know the lease would remove its
//! address and routes again. `on_dhcp_lease` therefore stores the last lease as JSON in
//! `<run_dir>/lease-<link>.json` (0600, tmpfs: it never outlives a reboot) and `apply_all`
//! merges it back into the network plan while it has not expired.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use owr_common::{Outcome, atomic_write};
use owr_net::NetPlan;
use owr_net::dhcp::{INFINITE_LEASE, Lease, merge_lease};
use owr_net::dhcp6::{Dhcp6ClientSpec, INFINITE, Lease6};
use tracing::{info, warn};

use crate::dnsmasq::check_token;
use crate::files::{FilesError, write_resolv};
use crate::pd::{PdLink, merge_lease6};

/// Mode of the persisted lease (server addresses, domain).
const LEASE_MODE: u32 = 0o600;

/// Where the lease of `link` is persisted.
pub fn lease_path(run_dir: &Path, link: &str) -> PathBuf {
    run_dir.join(format!("lease-{link}.json"))
}

/// Link names become file names: only the token alphabet is accepted (no `/`).
fn safe_link(link: &str) -> bool {
    check_token("link", link).is_ok()
}

fn invalid_input(context: String) -> FilesError {
    FilesError::Io {
        context,
        source: std::io::Error::new(ErrorKind::InvalidInput, "invalid lease"),
    }
}

/// Persist `lease` for `link`; `true` when the stored content changed.
pub fn save_lease(run_dir: &Path, link: &str, lease: &Lease) -> Result<bool, FilesError> {
    if !safe_link(link) {
        return Err(invalid_input(format!("persisting lease for link {link:?}")));
    }
    let json = serde_json::to_vec(lease)
        .map_err(|e| invalid_input(format!("serializing the lease of {link}: {e}")))?;
    std::fs::create_dir_all(run_dir).map_err(|source| FilesError::Io {
        context: format!("creating {}", run_dir.display()),
        source,
    })?;
    Ok(atomic_write(&lease_path(run_dir, link), &json, LEASE_MODE)? == Outcome::Written)
}

/// Remove the persisted lease of `link`; `true` when there was one.
pub fn forget_lease(run_dir: &Path, link: &str) -> Result<bool, FilesError> {
    if !safe_link(link) {
        return Err(invalid_input(format!("forgetting lease for link {link:?}")));
    }
    let path = lease_path(run_dir, link);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FilesError::Io {
            context: format!("removing {}", path.display()),
            source,
        }),
    }
}

/// Whether the lease has run out at `now`. An infinite lease never expires; a lease whose
/// end cannot be represented is treated as expired.
pub fn is_expired(lease: &Lease, now: SystemTime) -> bool {
    if lease.lease_secs == INFINITE_LEASE {
        return false;
    }
    lease
        .obtained_at
        .checked_add(Duration::from_secs(u64::from(lease.lease_secs)))
        .is_none_or(|end| end <= now)
}

/// The persisted lease of `link`, if there is a readable one that has not expired at `now`.
pub fn load_valid_lease(run_dir: &Path, link: &str, now: SystemTime) -> Option<Lease> {
    if !safe_link(link) {
        return None;
    }
    let path = lease_path(run_dir, link);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read the persisted lease; ignoring it");
            return None;
        }
    };
    let lease: Lease = match serde_json::from_slice(&bytes) {
        Ok(lease) => lease,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "persisted lease is corrupt; ignoring it");
            return None;
        }
    };
    if is_expired(&lease, now) {
        info!(path = %path.display(), "persisted lease has expired; ignoring it");
        return None;
    }
    Some(lease)
}

/// `plan` with the persisted lease of its DHCP client merged in (unchanged when the plan has
/// no DHCP client or there is no valid persisted lease).
pub fn with_persisted_lease(plan: &NetPlan, run_dir: &Path, now: SystemTime) -> NetPlan {
    let Some(spec) = plan.dhcp_clients.first() else {
        return plan.clone();
    };
    match load_valid_lease(run_dir, &spec.link, now) {
        Some(lease) => merge_lease(plan, spec, &lease),
        None => plan.clone(),
    }
}

/// DNS servers a resolver can use: not unspecified, loopback, multicast or broadcast
/// (a broken or hostile server must not point the router at itself or at nothing).
pub fn usable_dns(dns: &[Ipv4Addr]) -> Vec<IpAddr> {
    dns.iter()
        .filter(|ip| {
            !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast())
        })
        .copied()
        .map(IpAddr::V4)
        .collect()
}

/// Publish the lease's DNS servers to `resolv.conf.auto`. Returns whether the file changed
/// and a warning when the lease carried no usable server, in which case the previous
/// `resolv.conf.auto` is kept.
pub fn publish_lease_dns(
    run_dir: &Path,
    lease: &Lease,
) -> Result<(bool, Option<String>), FilesError> {
    publish_dns(run_dir, Some(lease), None)
}

// --- DHCPv6 prefix delegation ----------------------------------------------------------

/// Where the delegated-prefix lease of `link` is persisted (tmpfs, like the `DHCPv4` lease).
pub fn lease6_path(run_dir: &Path, link: &str) -> PathBuf {
    run_dir.join(format!("lease6-{link}.json"))
}

/// Persist `lease` for `link`; `true` when the stored content changed.
pub fn save_lease6(run_dir: &Path, link: &str, lease: &Lease6) -> Result<bool, FilesError> {
    if !safe_link(link) {
        return Err(invalid_input(format!("persisting lease for link {link:?}")));
    }
    let json = serde_json::to_vec(lease)
        .map_err(|e| invalid_input(format!("serializing the prefix lease of {link}: {e}")))?;
    std::fs::create_dir_all(run_dir).map_err(|source| FilesError::Io {
        context: format!("creating {}", run_dir.display()),
        source,
    })?;
    Ok(atomic_write(&lease6_path(run_dir, link), &json, LEASE_MODE)? == Outcome::Written)
}

/// Remove the persisted prefix lease of `link`; `true` when there was one.
pub fn forget_lease6(run_dir: &Path, link: &str) -> Result<bool, FilesError> {
    if !safe_link(link) {
        return Err(invalid_input(format!("forgetting lease for link {link:?}")));
    }
    let path = lease6_path(run_dir, link);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(FilesError::Io {
            context: format!("removing {}", path.display()),
            source,
        }),
    }
}

/// Whether the delegation has run out at `now`: the shortest valid lifetime is over. A lease
/// whose end cannot be represented is treated as expired; infinite lifetimes never expire.
pub fn is_expired6(lease: &Lease6, now: SystemTime) -> bool {
    let valid = lease
        .prefixes
        .iter()
        .map(|p| p.valid_secs)
        .min()
        .unwrap_or(0);
    if valid == INFINITE {
        return false;
    }
    lease
        .obtained_at
        .checked_add(Duration::from_secs(u64::from(valid)))
        .is_none_or(|end| end <= now)
}

/// The persisted prefix lease of `link`, if there is a readable one that has not expired.
pub fn load_valid_lease6(run_dir: &Path, link: &str, now: SystemTime) -> Option<Lease6> {
    if !safe_link(link) {
        return None;
    }
    let path = lease6_path(run_dir, link);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read the persisted prefix lease; ignoring it");
            return None;
        }
    };
    let lease: Lease6 = match serde_json::from_slice(&bytes) {
        Ok(lease) => lease,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "persisted prefix lease is corrupt; ignoring it");
            return None;
        }
    };
    if is_expired6(&lease, now) {
        info!(path = %path.display(), "persisted prefix lease has expired; ignoring it");
        return None;
    }
    Some(lease)
}

/// `plan` with the persisted prefix lease merged in: the router's address on each bridge's
/// share of the delegated prefix. Unchanged without a client or a valid persisted lease.
pub fn with_persisted_lease6(
    plan: &NetPlan,
    spec: Option<&Dhcp6ClientSpec>,
    links: &[PdLink],
    run_dir: &Path,
    now: SystemTime,
) -> NetPlan {
    let Some(spec) = spec else {
        return plan.clone();
    };
    match load_valid_lease6(run_dir, &spec.link, now) {
        Some(lease) => merge_lease6(plan, &lease, links),
        None => plan.clone(),
    }
}

/// Publish the DNS servers of both leases to `resolv.conf.auto`, `DHCPv4` ones first. Returns
/// whether the file changed and a warning when neither lease carried a usable server, in which
/// case the previous `resolv.conf.auto` is kept.
pub fn publish_dns(
    run_dir: &Path,
    v4: Option<&Lease>,
    v6: Option<&Lease6>,
) -> Result<(bool, Option<String>), FilesError> {
    let mut dns = v4.map_or_else(Vec::new, |l| usable_dns(&l.dns));
    dns.extend(
        v6.into_iter()
            .flat_map(|l| l.dns.iter().copied().map(IpAddr::V6)),
    );
    if dns.is_empty() {
        let msg = "lease has no usable DNS server; keeping the previous resolv.conf.auto";
        warn!("{msg}");
        return Ok((false, Some(msg.to_owned())));
    }
    std::fs::create_dir_all(run_dir).map_err(|source| FilesError::Io {
        context: format!("creating {}", run_dir.display()),
        source,
    })?;
    Ok((write_resolv(run_dir, &dns)?, None))
}
