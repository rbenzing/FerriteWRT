//! `Config` -> `dnsmasq.conf` text and `resolv.conf` text.
//!
//! The output is deterministic (no hash maps) so that "unchanged" can be detected by
//! comparing files. No `user=` line is emitted: dnsmasq then drops to its compiled-in
//! default user, which must exist in the image. `conf-dir` is deliberately not used, so
//! nothing outside the rendered file can add directives.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use ipnet::Ipv4Net;
use owr_config::{Config, DhcpPool};

use crate::error::MapError;
use crate::files::RESOLV_AUTO;
use crate::topology::{LAN_BRIDGE, Topology};

/// Reject values that could smuggle extra directives into a daemon config: only ASCII
/// letters, digits, `-`, `_` and `.` are accepted (so no newline, comma, space or `/`).
pub(crate) fn check_token(field: &str, value: &str) -> Result<(), MapError> {
    let ok = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(MapError::injection(field))
    }
}

/// dnsmasq reads the extra fields of `dhcp-host` by shape, not position: a name that is
/// all digits, a lease time (`[0-9]+[hmd]`) or one of the keywords `ignore` / `infinite`
/// would change the meaning of the line (an ignored client, a lease time, ...).
fn check_not_reserved(field: &str, name: &str) -> Result<(), MapError> {
    let lower = name.to_ascii_lowercase();
    let digits = lower.strip_suffix(['h', 'm', 'd']).unwrap_or(&lower);
    let lease_like = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    if lease_like || matches!(lower.as_str(), "ignore" | "infinite") {
        Err(MapError::ReservedName {
            field: field.to_owned(),
        })
    } else {
        Ok(())
    }
}

/// First and last address of a DHCP pool: `network + start ..= network + start + limit - 1`.
/// The pool must be non-empty, inside the usable host range and must not contain the
/// router address.
pub(crate) fn dhcp_range(
    network: &str,
    net: Ipv4Net,
    pool: &DhcpPool,
) -> Result<(Ipv4Addr, Ipv4Addr), MapError> {
    let err = || MapError::DhcpRangeOutOfSubnet {
        network: network.to_owned(),
        subnet: net,
        start: pool.start,
        limit: pool.limit,
    };
    let base = u64::from(u32::from(net.network()));
    let first = u64::from(pool.start);
    let last = first
        .saturating_add(u64::from(pool.limit))
        .saturating_sub(1);
    let host_bits = 32u32.saturating_sub(u32::from(net.prefix_len()));
    let usable = 1u64
        .checked_shl(host_bits)
        .unwrap_or(u64::MAX)
        .saturating_sub(2);
    let router = u64::from(u32::from(net.addr())).saturating_sub(base);
    if pool.start == 0 || pool.limit == 0 || last > usable || (first..=last).contains(&router) {
        return Err(err());
    }
    let ip = |offset: u64| {
        base.checked_add(offset)
            .and_then(|v| u32::try_from(v).ok())
            .map(Ipv4Addr::from)
            .ok_or_else(err)
    };
    Ok((ip(first)?, ip(last)?))
}

/// dnsmasq lease time: whole hours as `Nh`, whole minutes as `Nm`, else seconds.
fn lease_time(d: Duration) -> String {
    let secs = d.as_secs();
    if secs != 0 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs != 0 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        secs.to_string()
    }
}

fn run_path(run_dir: &str, file: &str) -> String {
    format!("{run_dir}/{file}")
}

/// The run directory as it is written into daemon configs: absolute, and only
/// `[A-Za-z0-9._/-]` so that it cannot break out of a directive or a UCI quote.
pub(crate) fn check_run_dir(run_dir: &Path) -> Result<&str, MapError> {
    // `starts_with('/')` rather than `is_absolute`: the path is Linux-only text, and a
    // Windows host does not consider `/run/ferritewrt` absolute.
    run_dir
        .to_str()
        .filter(|s| {
            s.starts_with('/')
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        })
        .ok_or_else(|| MapError::injection("run_dir"))
}

/// A network that hands out leases.
struct Served<'a> {
    tag: &'a str,
    net: Ipv4Net,
    pool: &'a DhcpPool,
}

pub(crate) fn render_dnsmasq(
    cfg: &Config,
    topo: &Topology<'_>,
    run_dir: &Path,
) -> Result<String, MapError> {
    let d = &cfg.dhcp;
    let run_dir = check_run_dir(run_dir)?;
    check_token("network.wan.port netdev", topo.wan_dev)?;

    for v in &topo.vlans {
        check_token(&format!("network.vlans.{}", v.cfg.name), &v.cfg.name)?;
    }

    let mut pools = Vec::new();
    let lan = &cfg.network.lan;
    if lan.dhcp.enabled {
        pools.push(Served {
            tag: "lan",
            net: lan.ipv4,
            pool: &lan.dhcp,
        });
    }
    for v in &topo.vlans {
        let Some(pool) = v.cfg.dhcp.as_ref().filter(|p| p.enabled) else {
            continue;
        };
        let net = v
            .cfg
            .ipv4
            .ok_or(MapError::Unsupported("vlan DHCP without an ipv4 address"))?;
        pools.push(Served {
            tag: &v.cfg.name,
            net,
            pool,
        });
    }

    let mut l: Vec<String> = vec![
        "# Generated by owr-apply. Do not edit; changes are overwritten.".to_owned(),
        "domain-needed".to_owned(),
        "bogus-priv".to_owned(),
        "localise-queries".to_owned(),
    ];
    if d.dns_servers.is_empty() {
        l.push(format!("resolv-file={}", run_path(run_dir, RESOLV_AUTO)));
    } else {
        l.push("no-resolv".to_owned());
        l.extend(d.dns_servers.iter().map(|s: &IpAddr| format!("server={s}")));
    }
    if !d.local_domain.is_empty() {
        check_token("dhcp.local_domain", &d.local_domain)?;
        l.push(format!("local=/{}/", d.local_domain));
        l.push(format!("domain={}", d.local_domain));
        l.push("expand-hosts".to_owned());
    }
    if d.rebind_protection {
        l.push("stop-dns-rebind".to_owned());
        l.push("rebind-localhost-ok".to_owned());
    }
    l.push(format!("interface={LAN_BRIDGE}"));
    // DNS is served on every VLAN bridge, also those without a DHCP pool. All networks share
    // one resolver, so a guest VLAN client can enumerate the hostnames of the LAN (known
    // limitation, see the README).
    l.extend(topo.vlans.iter().map(|v| format!("interface={}", v.bridge)));
    l.push("bind-dynamic".to_owned());
    l.push(format!("except-interface={}", topo.wan_dev));
    l.push("dhcp-authoritative".to_owned());

    for p in &pools {
        let (start, end) = dhcp_range(p.tag, p.net, p.pool)?;
        l.push(format!(
            "dhcp-range=set:{},{start},{end},{},{}",
            p.tag,
            p.net.netmask(),
            lease_time(p.pool.lease)
        ));
        let router = p.net.addr();
        l.push(format!("dhcp-option=tag:{},option:router,{router}", p.tag));
        l.push(format!(
            "dhcp-option=tag:{},option:dns-server,{router}",
            p.tag
        ));
    }

    for (i, lease) in d.static_leases.iter().enumerate() {
        let mut line = format!("dhcp-host={},{}", lease.mac, lease.ip);
        if let Some(name) = &lease.hostname {
            let field = format!("dhcp.static_leases[{i}].hostname");
            check_token(&field, name)?;
            check_not_reserved(&field, name)?;
            line.push(',');
            line.push_str(name);
        }
        l.push(line);
    }

    l.push(format!(
        "dhcp-leasefile={}",
        run_path(run_dir, "dhcp.leases")
    ));
    l.push(format!("pid-file={}", run_path(run_dir, "dnsmasq.pid")));
    l.push("cache-size=1000".to_owned());
    l.push("dns-forward-max=300".to_owned());
    l.push("edns-packet-max=1232".to_owned());
    l.push("min-cache-ttl=0".to_owned());

    let mut text = l.join("\n");
    text.push('\n');
    Ok(text)
}

/// `resolv.conf` text for the given upstream servers, one `nameserver` line each.
pub fn resolv_conf(dns: &[IpAddr]) -> String {
    let mut lines = vec!["# Generated by owr-apply.".to_owned()];
    lines.extend(dns.iter().map(|ip| format!("nameserver {ip}")));
    let mut text = lines.join("\n");
    text.push('\n');
    text
}
