//! Ruleset -> nftables script.
//!
//! Output is deterministic: interface sets are sorted, everything else follows the
//! order of the model vectors. The script starts with `table` + `delete table`, which
//! makes loading it replace the whole table atomically and idempotently.

use crate::model::{Family, FlowOffload, Policy, PortRange, Proto, Rule, Ruleset, Zone, ZoneName};
use crate::validate::Issue;

/// Maximum length (bytes) of an nft rule comment. Validated names are already shorter
/// (64 bytes); this only bounds a ruleset that bypassed validation.
const COMMENT_MAX: usize = 128;

/// Per-source-address SYN limiters (one meter per address family, as a meter has a
/// single key type).
const SYN_FLOOD_RULES: [&str; 2] = [
    "tcp flags syn meter synflood { ip saddr limit rate over 25/second burst 50 packets } drop",
    "tcp flags syn meter synflood6 { ip6 saddr limit rate over 25/second burst 50 packets } drop",
];

/// Errors from [`render`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    #[error("ruleset is invalid: {}", summarize(.0))]
    Invalid(Vec<Issue>),
}

fn summarize(issues: &[Issue]) -> String {
    issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Validate `rs` and render it as a complete `nft -f` script.
pub fn render(rs: &Ruleset) -> Result<String, RenderError> {
    rs.validate().map_err(RenderError::Invalid)?;
    let r = Renderer { rs };
    let table = &rs.options.table_name;

    let mut sections: Vec<Vec<String>> = Vec::new();
    if let Some(ft) = r.flowtable() {
        sections.push(ft);
    }
    sections.push(r.input_chain());
    sections.push(r.forward_chain());
    sections.push(r.output_chain());
    sections.push(r.prerouting_chain());
    sections.push(r.postrouting_chain());
    sections.push(r.mangle_forward_chain());
    for zone in &rs.zones {
        sections.push(r.zone_input_chain(zone));
        sections.push(r.zone_forward_chain(zone));
    }

    let mut lines = vec![
        "#!/usr/sbin/nft -f".to_owned(),
        format!("table inet {table}"),
        format!("delete table inet {table}"),
        format!("table inet {table} {{"),
    ];
    for (i, section) in sections.into_iter().enumerate() {
        if i > 0 {
            lines.push(String::new());
        }
        lines.extend(section);
    }
    lines.push("}".to_owned());
    lines.push(String::new());
    Ok(lines.join("\n"))
}

/// Which chain a user rule lands in.
#[derive(Debug, PartialEq, Eq)]
enum Scope<'a> {
    Input,
    InputZone(&'a ZoneName),
    Forward,
    ForwardZone(&'a ZoneName),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpVersion {
    V4,
    V6,
}

struct Renderer<'a> {
    rs: &'a Ruleset,
}

/// `{ "a", "b" }` (sorted, deduplicated) or `None` when empty.
fn if_set(names: &[String]) -> Option<String> {
    let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.is_empty() {
        return None;
    }
    let items: Vec<String> = sorted.iter().map(|n| format!("\"{n}\"")).collect();
    Some(format!("{{ {} }}", items.join(", ")))
}

/// Truncate to [`COMMENT_MAX`] bytes on a char boundary.
fn truncate_comment(name: &str) -> &str {
    if name.len() <= COMMENT_MAX {
        return name;
    }
    let mut end = COMMENT_MAX;
    while !name.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    name.get(..end).unwrap_or_default()
}

/// `comment "<name>"` for use at the end of a rule.
///
/// nft quoted strings do not honour backslash escapes, so no escaping could make an
/// arbitrary name safe. Validation only admits names from a restricted allow-list
/// (`validate::is_valid_name`); as defence in depth, anything outside it is mapped to
/// `_` here so a bypassed validator can never break out of the quotes.
fn comment(name: &str) -> String {
    let mut out = String::from("comment \"");
    out.extend(truncate_comment(name).chars().map(safe_comment_char));
    out.push('"');
    out
}

fn safe_comment_char(c: char) -> char {
    if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-') {
        c
    } else {
        '_'
    }
}

/// `# <name>` line above a rule, sanitised like [`comment`] (a newline would
/// otherwise start a new statement).
fn comment_line(name: &str) -> String {
    let safe: String = truncate_comment(name)
        .chars()
        .map(safe_comment_char)
        .collect();
    format!("# {safe}")
}

fn rule_verdict(policy: Policy) -> &'static str {
    match policy {
        Policy::Accept => "accept",
        Policy::Drop => "drop",
        Policy::Reject => "reject",
    }
}

fn zone_verdict(policy: Policy) -> &'static str {
    match policy {
        Policy::Accept => "accept",
        Policy::Drop => "drop",
        Policy::Reject => "reject with icmpx type port-unreachable",
    }
}

/// Protocol (and optional destination port) match.
fn proto_match(
    proto: Proto,
    version: Option<IpVersion>,
    port: Option<PortRange>,
) -> Option<String> {
    match (proto, port) {
        (Proto::Any, _) => None,
        (Proto::Tcp, None) => Some("meta l4proto tcp".to_owned()),
        (Proto::Udp, None) => Some("meta l4proto udp".to_owned()),
        (Proto::Tcp, Some(p)) => Some(format!("tcp dport {p}")),
        (Proto::Udp, Some(p)) => Some(format!("udp dport {p}")),
        (Proto::TcpUdp, None) => Some("meta l4proto { tcp, udp }".to_owned()),
        (Proto::TcpUdp, Some(p)) => Some(format!("meta l4proto {{ tcp, udp }} th dport {p}")),
        (Proto::Icmp, _) => Some(match version {
            Some(IpVersion::V6) => "meta l4proto ipv6-icmp".to_owned(),
            _ => "meta l4proto icmp".to_owned(),
        }),
    }
}

fn addr_match(version: IpVersion, direction: &str, net: &ipnet::IpNet) -> String {
    let qualifier = match version {
        IpVersion::V4 => "ip",
        IpVersion::V6 => "ip6",
    };
    format!("{qualifier} {direction} {}", net.trunc())
}

impl Renderer<'_> {
    fn zone(&self, name: &ZoneName) -> Option<&Zone> {
        self.rs.zones.iter().find(|z| &z.name == name)
    }

    fn zone_if_set(&self, name: &ZoneName) -> Option<String> {
        self.zone(name).and_then(|z| if_set(&z.interfaces))
    }

    fn flowtable(&self) -> Option<Vec<String>> {
        let opts = &self.rs.options;
        if opts.flow_offload == FlowOffload::Off {
            return None;
        }
        let devices = if_set(&opts.offload_devices)?;
        let mut lines = vec![
            "  flowtable ft {".to_owned(),
            "    hook ingress priority 0;".to_owned(),
            format!("    devices = {devices};"),
        ];
        if opts.flow_offload == FlowOffload::Hardware {
            lines.push("    flags offload;".to_owned());
        }
        lines.push("  }".to_owned());
        Some(lines)
    }

    fn chain(name: &str, header: Option<&str>, body: &[String]) -> Vec<String> {
        let mut lines = vec![format!("  chain {name} {{")];
        if let Some(header) = header {
            lines.push(format!("    {header}"));
        }
        lines.extend(body.iter().map(|l| format!("    {l}")));
        lines.push("  }".to_owned());
        lines
    }

    fn input_chain(&self) -> Vec<String> {
        let opts = &self.rs.options;
        let mut body = vec![
            "iif lo accept".to_owned(),
            "ct state established,related accept".to_owned(),
        ];
        if opts.drop_invalid {
            body.push("ct state invalid drop".to_owned());
        }
        body.extend(self.user_rules(&Scope::Input));
        for zone in &self.rs.zones {
            if let Some(set) = if_set(&zone.interfaces) {
                body.push(format!("iifname {set} jump input_{}", zone.name));
            }
        }
        Self::chain(
            "input",
            Some("type filter hook input priority filter; policy drop;"),
            &body,
        )
    }

    fn forward_chain(&self) -> Vec<String> {
        let opts = &self.rs.options;
        let mut body = Vec::new();
        if opts.flow_offload != FlowOffload::Off {
            body.push("meta l4proto { tcp, udp } flow add @ft".to_owned());
        }
        body.push("ct state established,related accept".to_owned());
        if opts.drop_invalid {
            body.push("ct state invalid drop".to_owned());
        }
        body.extend(self.user_rules(&Scope::Forward));
        for zone in &self.rs.zones {
            if let Some(set) = if_set(&zone.interfaces) {
                body.push(format!("iifname {set} jump forward_{}", zone.name));
            }
        }
        Self::chain(
            "forward",
            Some("type filter hook forward priority filter; policy drop;"),
            &body,
        )
    }

    fn output_chain(&self) -> Vec<String> {
        let mut body = Vec::new();
        let restricted: Vec<&Zone> = self
            .rs
            .zones
            .iter()
            .filter(|z| z.output != Policy::Accept && !z.interfaces.is_empty())
            .collect();
        if !restricted.is_empty() {
            body.push("oif lo accept".to_owned());
            body.push("ct state established,related accept".to_owned());
            for zone in restricted {
                if let Some(set) = if_set(&zone.interfaces) {
                    body.push(format!("oifname {set} {}", zone_verdict(zone.output)));
                }
            }
        }
        Self::chain(
            "output",
            Some("type filter hook output priority filter; policy accept;"),
            &body,
        )
    }

    fn prerouting_chain(&self) -> Vec<String> {
        let mut body = Vec::new();
        for redirect in self.rs.redirects.iter().filter(|r| r.enabled) {
            let Some(set) = self.zone_if_set(&redirect.src) else {
                continue;
            };
            let dport = Self::redirect_match(redirect.proto, redirect.src_dport);
            body.push(comment_line(&redirect.name));
            body.push(format!(
                "iifname {set} {dport} dnat ip to {}:{} {}",
                redirect.dest_ip,
                redirect.dest_port,
                comment(&redirect.name)
            ));
        }
        Self::chain(
            "prerouting",
            Some("type nat hook prerouting priority dstnat; policy accept;"),
            &body,
        )
    }

    /// Protocol + destination-port match for a redirect (proto is validated).
    fn redirect_match(proto: Proto, port: PortRange) -> String {
        proto_match(proto, None, Some(port)).unwrap_or_default()
    }

    fn postrouting_chain(&self) -> Vec<String> {
        let body: Vec<String> = self
            .rs
            .zones
            .iter()
            .filter(|z| z.masquerade)
            .filter_map(|z| if_set(&z.interfaces))
            .map(|set| format!("meta nfproto ipv4 oifname {set} masquerade"))
            .collect();
        Self::chain(
            "postrouting",
            Some("type nat hook postrouting priority srcnat; policy accept;"),
            &body,
        )
    }

    fn mangle_forward_chain(&self) -> Vec<String> {
        let body: Vec<String> = self
            .rs
            .zones
            .iter()
            .filter(|z| z.mss_clamp)
            .filter_map(|z| if_set(&z.interfaces))
            .map(|set| format!("oifname {set} tcp flags syn tcp option maxseg size set rt mtu"))
            .collect();
        Self::chain(
            "mangle_forward",
            Some("type filter hook forward priority mangle; policy accept;"),
            &body,
        )
    }

    /// Uplink-style zones (NAT / MSS clamp) with a restrictive input policy get the
    /// protocol housekeeping a WAN needs: DHCP(v6) client, ICMP and essential `ICMPv6`.
    fn is_uplink(zone: &Zone) -> bool {
        (zone.masquerade || zone.mss_clamp) && zone.input != Policy::Accept
    }

    fn zone_input_chain(&self, zone: &Zone) -> Vec<String> {
        let mut body = Vec::new();
        // Per-source limiter on uplink zones only: a global limiter would let one
        // flooding host starve legitimate LAN/management connections.
        if self.rs.options.syn_flood_protect && (zone.masquerade || zone.mss_clamp) {
            body.extend(SYN_FLOOD_RULES.map(str::to_owned));
        }
        if Self::is_uplink(zone) {
            body.extend(
                [
                    "udp sport 67 udp dport 68 accept",
                    "ip6 daddr fe80::/10 udp dport 546 accept",
                    "icmp type echo-request limit rate 10/second accept",
                    "icmpv6 type echo-request limit rate 10/second accept",
                    "icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, \
                     parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, \
                     nd-router-advert } accept",
                ]
                .map(str::to_owned),
            );
        }
        body.extend(self.user_rules(&Scope::InputZone(&zone.name)));
        body.push(zone_verdict(zone.input).to_owned());
        Self::chain(&format!("input_{}", zone.name), None, &body)
    }

    fn zone_forward_chain(&self, zone: &Zone) -> Vec<String> {
        let mut body = self.user_rules(&Scope::ForwardZone(&zone.name));
        for redirect in self
            .rs
            .redirects
            .iter()
            .filter(|r| r.enabled && r.src == zone.name)
        {
            if if_set(&zone.interfaces).is_none() {
                continue;
            }
            let dport = proto_match(
                redirect.proto,
                None,
                Some(PortRange::single(redirect.dest_port)),
            )
            .unwrap_or_default();
            body.push(format!(
                "ip daddr {} {dport} ct status dnat accept {}",
                redirect.dest_ip,
                comment(&redirect.name)
            ));
        }
        for fwd in self.rs.forwardings.iter().filter(|f| f.src == zone.name) {
            if let Some(set) = self.zone_if_set(&fwd.dst) {
                body.push(format!("oifname {set} accept"));
            }
        }
        // Intra-zone traffic follows the zone's forward policy; anything else that no
        // forwarding allowed falls through to the base chain's drop policy.
        if let Some(set) = if_set(&zone.interfaces) {
            body.push(format!("oifname {set} {}", zone_verdict(zone.forward)));
        }
        Self::chain(&format!("forward_{}", zone.name), None, &body)
    }

    /// Where `rule` goes and the extra `oifname` match it needs. `None` = skip (the
    /// destination zone has no interfaces, so the rule can never match).
    fn classify<'r>(&self, rule: &'r Rule) -> Option<(Scope<'r>, Option<String>)> {
        match (&rule.src, &rule.dst) {
            (None, None) => Some((Scope::Input, None)),
            (Some(src), None) => Some((Scope::InputZone(src), None)),
            (src, Some(dst)) => {
                let set = self.zone_if_set(dst)?;
                let scope = src.as_ref().map_or(Scope::Forward, Scope::ForwardZone);
                Some((scope, Some(format!("oifname {set}"))))
            }
        }
    }

    fn user_rules(&self, scope: &Scope<'_>) -> Vec<String> {
        let mut out = Vec::new();
        for rule in self.rs.rules.iter().filter(|r| r.enabled) {
            let Some((rule_scope, prefix)) = self.classify(rule) else {
                continue;
            };
            if &rule_scope != scope {
                continue;
            }
            out.push(comment_line(&rule.name));
            for version in Self::versions(rule) {
                out.push(Self::rule_line(rule, version, prefix.as_deref()));
            }
        }
        out
    }

    /// IP versions a rule expands to. `Icmp` without a family restriction needs one
    /// line each for `icmp` and `ipv6-icmp`; `[None]` means "no family qualifier".
    fn versions(rule: &Rule) -> Vec<Option<IpVersion>> {
        let from_addr = [&rule.src_ip, &rule.dst_ip]
            .into_iter()
            .flatten()
            .next()
            .map(|net| match net {
                ipnet::IpNet::V4(_) => IpVersion::V4,
                ipnet::IpNet::V6(_) => IpVersion::V6,
            });
        let explicit = match rule.family {
            Family::Any => from_addr,
            Family::Ipv4 => Some(IpVersion::V4),
            Family::Ipv6 => Some(IpVersion::V6),
        };
        match explicit {
            Some(v) => vec![Some(v)],
            None if rule.proto == Proto::Icmp => vec![Some(IpVersion::V4), Some(IpVersion::V6)],
            None => vec![None],
        }
    }

    fn rule_line(rule: &Rule, version: Option<IpVersion>, prefix: Option<&str>) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(prefix.map(str::to_owned));
        let has_addr = rule.src_ip.is_some() || rule.dst_ip.is_some();
        if let Some(v) = version {
            if !has_addr {
                parts.push(
                    match v {
                        IpVersion::V4 => "meta nfproto ipv4",
                        IpVersion::V6 => "meta nfproto ipv6",
                    }
                    .to_owned(),
                );
            }
            if let Some(net) = &rule.src_ip {
                parts.push(addr_match(v, "saddr", net));
            }
            if let Some(net) = &rule.dst_ip {
                parts.push(addr_match(v, "daddr", net));
            }
        }
        parts.extend(proto_match(rule.proto, version, rule.dst_port));
        parts.push(rule_verdict(rule.action).to_owned());
        parts.push(comment(&rule.name));
        parts.join(" ")
    }
}

#[cfg(test)]
mod tests;
