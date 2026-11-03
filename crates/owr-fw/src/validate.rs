//! Structural validation of a [`Ruleset`].

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use ipnet::IpNet;

use crate::model::{Family, FlowOffload, Ruleset, ZoneName};

/// One validation problem, located by a JSON-path-like `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub path: String,
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Netdev name check: 1-15 bytes of `[A-Za-z0-9_.-]`, not `.` or `..`.
pub fn is_valid_netdev_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Rule/redirect name allow-list `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`. Names are written
/// into nft `comment "..."` strings, which do not honour backslash escapes, so anything
/// that could terminate the string or the statement (`"`, `\`, `;`, `#`, braces,
/// newlines, non-ASCII) is rejected rather than escaped.
fn is_valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
}

/// Unicast destination for a redirect: not unspecified, loopback, multicast or broadcast.
fn is_valid_redirect_target(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast())
}

fn is_valid_table_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 31
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

struct Issues(Vec<Issue>);

impl Issues {
    fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Issue {
            path: path.into(),
            message: message.into(),
        });
    }

    fn check_name(&mut self, path: &str, name: &str) {
        if name.is_empty() {
            self.add(path, "name must not be empty");
        } else if !is_valid_name(name) {
            self.add(
                path,
                "name must match ^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$ (it is emitted inside an \
                 nft quoted string, which has no escapes)",
            );
        }
    }
}

#[cfg(test)]
mod tests;

fn is_v4(net: &IpNet) -> bool {
    matches!(net, IpNet::V4(_))
}

impl Ruleset {
    /// Check the ruleset for structural problems. Returns every issue found.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        let mut issues = Issues(Vec::new());
        self.validate_options(&mut issues);
        let zone_names = self.validate_zones(&mut issues);
        self.validate_forwardings(&mut issues, &zone_names);
        self.validate_rules(&mut issues, &zone_names);
        self.validate_redirects(&mut issues, &zone_names);
        if issues.0.is_empty() {
            Ok(())
        } else {
            Err(issues.0)
        }
    }

    fn validate_options(&self, issues: &mut Issues) {
        let opts = &self.options;
        if !is_valid_table_name(&opts.table_name) {
            issues.add(
                "options.table_name",
                format!("invalid table name {:?}", opts.table_name),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, dev) in opts.offload_devices.iter().enumerate() {
            let path = format!("options.offload_devices[{i}]");
            if !is_valid_netdev_name(dev) {
                issues.add(&path, format!("invalid netdev name {dev:?}"));
            } else if !seen.insert(dev.as_str()) {
                issues.add(&path, format!("duplicate offload device {dev:?}"));
            }
        }
        if opts.flow_offload != FlowOffload::Off && opts.offload_devices.is_empty() {
            issues.add(
                "options.offload_devices",
                "flow offload enabled but no devices listed",
            );
        }
    }

    fn validate_zones(&self, issues: &mut Issues) -> BTreeSet<&str> {
        let mut names = BTreeSet::new();
        let mut ifaces = BTreeSet::new();
        for (i, zone) in self.zones.iter().enumerate() {
            let path = format!("zones[{i}]");
            if !ZoneName::is_valid(zone.name.as_str()) {
                issues.add(
                    format!("{path}.name"),
                    format!("invalid zone name {:?}", zone.name.as_str()),
                );
            }
            if !names.insert(zone.name.as_str()) {
                issues.add(
                    format!("{path}.name"),
                    format!("duplicate zone name {}", zone.name),
                );
            }
            for (j, dev) in zone.interfaces.iter().enumerate() {
                let ipath = format!("{path}.interfaces[{j}]");
                if !is_valid_netdev_name(dev) {
                    issues.add(ipath, format!("invalid netdev name {dev:?}"));
                } else if !ifaces.insert(dev.as_str()) {
                    issues.add(
                        ipath,
                        format!("interface {dev:?} is already assigned to a zone"),
                    );
                }
            }
            if zone.interfaces.is_empty() && (zone.masquerade || zone.mss_clamp) {
                issues.add(
                    &path,
                    "masquerade/mss_clamp requires at least one interface",
                );
            }
        }
        names
    }

    fn validate_forwardings(&self, issues: &mut Issues, zones: &BTreeSet<&str>) {
        let mut seen = BTreeSet::new();
        for (i, fwd) in self.forwardings.iter().enumerate() {
            let path = format!("forwardings[{i}]");
            for (field, zone) in [("src", &fwd.src), ("dst", &fwd.dst)] {
                if !zones.contains(zone.as_str()) {
                    issues.add(format!("{path}.{field}"), format!("unknown zone {zone}"));
                }
            }
            if fwd.src == fwd.dst {
                issues.add(
                    &path,
                    "src and dst must differ (intra-zone traffic uses the zone forward policy)",
                );
            } else if !seen.insert((&fwd.src, &fwd.dst)) {
                issues.add(
                    &path,
                    format!("duplicate forwarding {} -> {}", fwd.src, fwd.dst),
                );
            }
        }
    }

    fn validate_rules(&self, issues: &mut Issues, zones: &BTreeSet<&str>) {
        for (i, rule) in self.rules.iter().enumerate() {
            let path = format!("rules[{i}]");
            issues.check_name(&format!("{path}.name"), &rule.name);
            for (field, zone) in [("src", &rule.src), ("dst", &rule.dst)] {
                if let Some(zone) = zone
                    && !zones.contains(zone.as_str())
                {
                    issues.add(format!("{path}.{field}"), format!("unknown zone {zone}"));
                }
            }
            if let Some(port) = rule.dst_port {
                if !port.is_valid() {
                    issues.add(
                        format!("{path}.dst_port"),
                        "port range must satisfy 1 <= start <= end",
                    );
                }
                if !rule.proto.has_ports() {
                    issues.add(
                        format!("{path}.dst_port"),
                        "dst_port requires proto tcp, udp or tcp_udp",
                    );
                }
            }
            for (field, net) in [("src_ip", &rule.src_ip), ("dst_ip", &rule.dst_ip)] {
                let Some(net) = net else { continue };
                let mismatch = match rule.family {
                    Family::Ipv4 => !is_v4(net),
                    Family::Ipv6 => is_v4(net),
                    Family::Any => false,
                };
                if mismatch {
                    issues.add(
                        format!("{path}.{field}"),
                        "address family does not match rule family",
                    );
                }
            }
            if let (Some(a), Some(b)) = (&rule.src_ip, &rule.dst_ip)
                && is_v4(a) != is_v4(b)
            {
                issues.add(&path, "src_ip and dst_ip have different address families");
            }
        }
    }

    fn validate_redirects(&self, issues: &mut Issues, zones: &BTreeSet<&str>) {
        for (i, redirect) in self.redirects.iter().enumerate() {
            let path = format!("redirects[{i}]");
            issues.check_name(&format!("{path}.name"), &redirect.name);
            if !zones.contains(redirect.src.as_str()) {
                issues.add(
                    format!("{path}.src"),
                    format!("unknown zone {}", redirect.src),
                );
            }
            if !redirect.proto.has_ports() {
                issues.add(
                    format!("{path}.proto"),
                    "redirects support only tcp, udp or tcp_udp",
                );
            }
            if !redirect.src_dport.is_valid() {
                issues.add(
                    format!("{path}.src_dport"),
                    "port range must satisfy 1 <= start <= end",
                );
            }
            if !is_valid_redirect_target(redirect.dest_ip) {
                issues.add(
                    format!("{path}.dest_ip"),
                    format!(
                        "dest_ip {} must be a unicast address (not 0.0.0.0, loopback, multicast or broadcast)",
                        redirect.dest_ip
                    ),
                );
            }
            if redirect.dest_port == 0 {
                issues.add(format!("{path}.dest_port"), "port must be 1-65535");
            }
        }
    }
}
