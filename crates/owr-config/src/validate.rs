//! Board-independent validation. Every check appends to one issue list so a caller sees
//! all problems at once.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::RangeInclusive;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ipnet::Ipv4Net;
use password_hash::PasswordHash;

use crate::error::Issue;
use crate::model::{
    ApConfig, CURRENT_SCHEMA, Channel, Config, DhcpConfig, DhcpPool, FirewallConfig, ForwardProto,
    PortForward, RadioConfig, Role, Rule, RuleProto, ServicesConfig, StaticLease, SystemConfig,
    User, VlanConfig, WanConfig, WanProto, WirelessConfig,
};
use crate::types::Secret;

// Upper bounds on list sizes: a config is small, so anything bigger is a mistake or an attack on
// the O(n^2) checks and the appliers.
const MAX_USERS: usize = 32;
const MAX_RULES: usize = 256;
const MAX_PORT_FORWARDS: usize = 256;
const MAX_STATIC_LEASES: usize = 1024;
const MAX_SSH_KEYS: usize = 32;
const MAX_SSH_KEY_LEN: usize = 4096;

const REDACTED_MSG: &str = "redacted placeholder is not a valid value";

/// Accumulator for validation issues.
#[derive(Debug, Default)]
pub(crate) struct Issues(Vec<Issue>);

impl Issues {
    pub(crate) fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Issue::new(path, message));
    }

    /// Report `path` if `len` exceeds `max`; true when the list is within bounds.
    fn within(&mut self, path: &str, len: usize, max: usize) -> bool {
        let ok = len <= max;
        if !ok {
            self.add(path, format!("at most {max} entries allowed, got {len}"));
        }
        ok
    }

    /// Report the redaction placeholder used as a real secret; true if `secret` is it.
    fn redacted(&mut self, path: &str, secret: &Secret) -> bool {
        let hit = secret.is_redacted();
        if hit {
            self.add(path, REDACTED_MSG);
        }
        hit
    }

    pub(crate) fn into_result(self) -> Result<(), Vec<Issue>> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

/// A LAN or VLAN subnet (or the static WAN subnet) with the config path it came from.
struct Subnet {
    path: String,
    label: String,
    net: Ipv4Net,
}

impl Config {
    /// Check every invariant that does not need to know the board. Collects all issues.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        let mut issues = Issues::default();
        self.validate_into(&mut issues);
        issues.into_result()
    }

    pub(crate) fn validate_into(&self, issues: &mut Issues) {
        if self.schema != CURRENT_SCHEMA {
            issues.add(
                "schema",
                format!("must be {CURRENT_SCHEMA}, got {}", self.schema),
            );
        }
        check_system(&self.system, issues);
        check_users(&self.users, issues);
        check_network(self, issues);
        let subnets = self.lan_vlan_subnets();
        check_wireless(&self.wireless, self, issues);
        check_firewall(&self.firewall, &subnets, issues);
        check_dhcp(&self.dhcp, &subnets, issues);
        check_services(&self.services, issues);
    }

    /// LAN subnet followed by every VLAN subnet that has an address.
    fn lan_vlan_subnets(&self) -> Vec<Subnet> {
        let mut out = vec![Subnet {
            path: "network.lan.ipv4".to_owned(),
            label: "lan".to_owned(),
            net: self.network.lan.ipv4,
        }];
        for (i, v) in self.network.vlans.iter().enumerate() {
            if let Some(net) = v.ipv4 {
                out.push(Subnet {
                    path: format!("network.vlans[{i}].ipv4"),
                    label: v.name.clone(),
                    net,
                });
            }
        }
        out
    }
}

// ------------------------------------------------------------- primitives

fn is_ascii_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// RFC 1123 label: 1..=63 of `[A-Za-z0-9-]`, not starting or ending with `-`.
pub(crate) fn is_hostname_label(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| is_ascii_alnum(*c) || *c == b'-')
        && b.first().is_some_and(|c| *c != b'-')
        && b.last().is_some_and(|c| *c != b'-')
}

/// Dotted sequence of RFC 1123 labels, at most 253 bytes, no trailing dot.
pub(crate) fn is_domain_name(s: &str) -> bool {
    s.len() <= 253 && s.split('.').all(is_hostname_label)
}

/// `^[a-z_][a-z0-9_-]{0,31}$`
pub(crate) fn is_user_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || *c == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// VLAN names become interface names (`br-<name>`): `^[a-z][a-z0-9_]{0,11}$`.
fn is_vlan_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=12).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// Names for rules, forwards and radios: `^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`.
fn is_item_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b.first().is_some_and(|c| is_ascii_alnum(*c))
        && b.iter()
            .all(|c| is_ascii_alnum(*c) || matches!(*c, b'_' | b'.' | b'-'))
}

/// Shape check only: the tz database is not available to this crate.
fn is_timezone(s: &str) -> bool {
    s.len() <= 64
        && s.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| is_ascii_alnum(c) || matches!(c, b'_' | b'+' | b'-'))
        })
}

/// Accepted argon2id cost parameters: `m` in KiB (8 MiB..=1 GiB), `t` passes, `p` lanes. The
/// upper bounds keep a hostile or corrupted config from making every login allocate gigabytes.
const ARGON2_PARAMS: [(&str, RangeInclusive<u32>); 3] =
    [("m", 8192..=1_048_576), ("t", 1..=10), ("p", 1..=16)];
/// Base64 characters needed to encode 8 bytes.
const MIN_SALT_B64_LEN: usize = 11;
const MIN_HASH_BYTES: usize = 16;

/// Check an argon2id PHC string: parseable, bounded cost parameters, a salt of at least
/// 8 bytes and a hash of at least 16 bytes. Error text never contains the input.
pub(crate) fn check_phc(s: &str) -> Result<(), &'static str> {
    if !s.starts_with('$') {
        return Err("not a PHC string (must start with '$argon2id$')");
    }
    let phc = PasswordHash::new(s).map_err(|_| "malformed PHC string")?;
    if phc.algorithm.as_str() != "argon2id" {
        return Err("algorithm must be argon2id");
    }
    if phc.version.is_some_and(|v| v != 16 && v != 19) {
        return Err("unsupported argon2 version (expected v=19)");
    }
    let mut seen = [false; ARGON2_PARAMS.len()];
    for (name, value) in phc.params.iter() {
        let idx = ARGON2_PARAMS
            .iter()
            .position(|(key, _)| *key == name.as_str())
            .ok_or("unknown argon2 parameter (expected m, t, p)")?;
        let n = value
            .decimal()
            .map_err(|_| "argon2 parameters must be integers")?;
        let in_range = ARGON2_PARAMS.get(idx).is_some_and(|(_, r)| r.contains(&n));
        if !in_range {
            return Err("argon2 parameter out of range (m 8192..=1048576 KiB, t 1..=10, p 1..=16)");
        }
        match seen.get_mut(idx) {
            Some(flag) if !*flag => *flag = true,
            _ => return Err("duplicate argon2 parameter"),
        }
    }
    if seen.iter().any(|s| !s) {
        return Err("argon2 parameters m, t and p are all required");
    }
    if phc.salt.is_none_or(|salt| salt.len() < MIN_SALT_B64_LEN) {
        return Err("missing or too short salt (need at least 8 bytes)");
    }
    if phc.hash.is_none_or(|hash| hash.len() < MIN_HASH_BYTES) {
        return Err("missing or too short hash (need at least 16 bytes)");
    }
    Ok(())
}

const SSH_KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Single-line ASCII `type base64 [comment]` public key, at most [`MAX_SSH_KEY_LEN`] long, whose
/// base64 blob decodes; no options prefix is accepted.
fn is_ssh_key(s: &str) -> bool {
    if !s.is_ascii() || s.len() > MAX_SSH_KEY_LEN || s.contains(['\n', '\r']) {
        return false;
    }
    let mut parts = s.split_whitespace();
    matches!((parts.next(), parts.next()), (Some(t), Some(k))
        if SSH_KEY_TYPES.contains(&t) && STANDARD.decode(k).is_ok_and(|blob| !blob.is_empty()))
}

fn is_printable_ascii(s: &str) -> bool {
    s.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

const PPP_NAME_MSG: &str = "must be 1..=64 characters of [A-Za-z0-9._@+:/-]";

/// `PPPoE` username / service name. pppd's chap-secrets quoting is fragile, so only a
/// conservative character set is accepted.
fn is_ppp_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|c| {
            is_ascii_alnum(c) || matches!(c, b'.' | b'_' | b'@' | b'+' | b':' | b'/' | b'-')
        })
}

/// `PPPoE` password: printable ASCII except the two characters chap-secrets quoting uses.
fn is_ppp_password(s: &str) -> bool {
    (1..=128).contains(&s.len()) && is_printable_ascii(s) && !s.contains(['"', '\\'])
}

fn check_unique(
    issues: &mut Issues,
    what: &str,
    items: impl IntoIterator<Item = (String, String)>,
) {
    let mut seen: HashMap<String, String> = HashMap::new();
    for (path, key) in items {
        match seen.get(&key) {
            Some(first) => {
                issues.add(
                    &path,
                    format!("duplicate {what} '{key}' (first used at {first})"),
                );
            }
            None => {
                seen.insert(key, path);
            }
        }
    }
}

fn usable_hosts(net: Ipv4Net) -> u64 {
    let host_bits = 32u8.saturating_sub(net.prefix_len());
    1u64.checked_shl(u32::from(host_bits))
        .unwrap_or(u64::MAX)
        .saturating_sub(2)
}

fn host_offset(net: Ipv4Net, ip: Ipv4Addr) -> u64 {
    u64::from(u32::from(ip)).saturating_sub(u64::from(u32::from(net.network())))
}

fn is_unusable_unicast(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
}

/// Address-with-prefix sanity for an interface: usable prefix and a real host address.
fn check_interface_net(path: &str, net: Ipv4Net, min_prefix: u8, issues: &mut Issues) {
    if net.prefix_len() < min_prefix || net.prefix_len() > 30 {
        issues.add(
            path,
            format!(
                "prefix length /{} must be in {min_prefix}..=30",
                net.prefix_len()
            ),
        );
    } else if net.addr() == net.network() || net.addr() == net.broadcast() {
        issues.add(
            path,
            format!(
                "{} is the network or broadcast address, use a host address",
                net.addr()
            ),
        );
    }
    if is_unusable_unicast(net.addr()) {
        issues.add(
            path,
            format!("{} is not a usable unicast address", net.addr()),
        );
    }
}

// ----------------------------------------------------------------- system

fn check_system(sys: &SystemConfig, issues: &mut Issues) {
    if !is_hostname_label(&sys.hostname) {
        issues.add(
            "system.hostname",
            "must be an RFC 1123 label (1-63 of letters, digits, '-'; no leading/trailing '-')",
        );
    }
    if !is_timezone(&sys.timezone) {
        issues.add(
            "system.timezone",
            format!(
                "'{}' is not an IANA zone name like 'Europe/Berlin' or 'UTC'",
                sys.timezone
            ),
        );
    }
    for (i, s) in sys.ntp_servers.iter().enumerate() {
        if s.parse::<IpAddr>().is_err() && !is_domain_name(s) {
            issues.add(
                format!("system.ntp_servers[{i}]"),
                format!("'{s}' is not a hostname or IP address"),
            );
        }
    }
}

// ------------------------------------------------------------------ users

fn check_users(users: &[User], issues: &mut Issues) {
    if !issues.within("users", users.len(), MAX_USERS) {
        return;
    }
    for (i, u) in users.iter().enumerate() {
        if !is_user_name(&u.name) {
            issues.add(
                format!("users[{i}].name"),
                "must match ^[a-z_][a-z0-9_-]{0,31}$",
            );
        }
        let path = format!("users[{i}].password_hash");
        if !issues.redacted(&path, &u.password_hash)
            && let Err(why) = check_phc(u.password_hash.expose())
        {
            issues.add(path, why);
        }
    }
    check_unique(
        issues,
        "user",
        users
            .iter()
            .enumerate()
            .map(|(i, u)| (format!("users[{i}].name"), u.name.clone())),
    );
    // An empty list is the unconfigured first-boot state; once users exist, at least one
    // enabled admin must remain or the device is unmanageable.
    if !users.is_empty() && !users.iter().any(|u| u.enabled && u.role == Role::Admin) {
        issues.add(
            "users",
            "at least one enabled user with role 'admin' is required",
        );
    }
}

// ---------------------------------------------------------------- network

fn check_network(cfg: &Config, issues: &mut Issues) {
    let net = &cfg.network;
    check_interface_net("network.lan.ipv4", net.lan.ipv4, 8, issues);
    check_pool(
        "network.lan.dhcp",
        &net.lan.dhcp,
        Some(net.lan.ipv4),
        issues,
    );
    check_wan(&net.wan, issues);
    check_vlans(&net.vlans, issues);

    // Every port belongs to exactly one of lan / wan / one vlan.
    let mut ports = vec![("network.wan.port".to_owned(), net.wan.port.clone())];
    for (i, p) in net.lan.ports.iter().enumerate() {
        ports.push((format!("network.lan.ports[{i}]"), p.clone()));
    }
    for (vi, v) in net.vlans.iter().enumerate() {
        for (pi, p) in v.ports.iter().enumerate() {
            ports.push((format!("network.vlans[{vi}].ports[{pi}]"), p.clone()));
        }
    }
    for (path, name) in &ports {
        if name.is_empty() {
            issues.add(path, "port name must not be empty");
        }
    }
    check_unique(issues, "port", ports);

    // Subnets must not overlap.
    let mut subnets = cfg.lan_vlan_subnets();
    if let WanProto::Static { ipv4, .. } = &net.wan.proto {
        subnets.push(Subnet {
            path: "network.wan.proto.ipv4".to_owned(),
            label: "wan".to_owned(),
            net: *ipv4,
        });
    }
    for (i, a) in subnets.iter().enumerate() {
        for b in subnets.iter().skip(i.saturating_add(1)) {
            if a.net.contains(&b.net) || b.net.contains(&a.net) {
                issues.add(
                    &b.path,
                    format!(
                        "subnet {} overlaps '{}' subnet {} ({})",
                        b.net.trunc(),
                        a.label,
                        a.net.trunc(),
                        a.path
                    ),
                );
            }
        }
    }
}

/// Check a pool's start/limit/lease even when it is disabled, so a later `enabled = true`
/// cannot activate an invalid pool. `net` is `None` for a VLAN without an address, where the
/// fit against the subnet cannot be checked.
fn check_pool(path: &str, pool: &DhcpPool, net: Option<Ipv4Net>, issues: &mut Issues) {
    if pool.start == 0 {
        issues.add(format!("{path}.start"), "host offset must be >= 1");
    }
    if pool.limit == 0 {
        issues.add(format!("{path}.limit"), "must be >= 1");
    }
    let first = u64::from(pool.start);
    let last = first
        .saturating_add(u64::from(pool.limit))
        .saturating_sub(1);
    if let Some(net) = net
        && pool.start > 0
        && pool.limit > 0
    {
        if last > usable_hosts(net) {
            issues.add(
                path,
                format!(
                    "pool offsets {first}..={last} do not fit in {} ({} usable hosts)",
                    net.trunc(),
                    usable_hosts(net)
                ),
            );
        }
        let router = host_offset(net, net.addr());
        if (first..=last).contains(&router) {
            issues.add(
                path,
                format!("pool contains the router address {}", net.addr()),
            );
        }
    }
    let min = Duration::from_mins(2);
    let max = Duration::from_hours(24 * 30);
    if pool.lease < min || pool.lease > max {
        issues.add(format!("{path}.lease"), "must be between 2m and 30d");
    }
}

fn check_wan(wan: &WanConfig, issues: &mut Issues) {
    match &wan.proto {
        WanProto::Dhcp { hostname } => {
            if hostname.as_deref().is_some_and(|h| !is_hostname_label(h)) {
                issues.add("network.wan.proto.hostname", "must be an RFC 1123 label");
            }
        }
        WanProto::Static { ipv4, gateway, dns } => {
            let path = "network.wan.proto";
            check_interface_net(&format!("{path}.ipv4"), *ipv4, 1, issues);
            if !ipv4.contains(gateway) {
                issues.add(
                    format!("{path}.gateway"),
                    format!("{gateway} is not inside {}", ipv4.trunc()),
                );
            } else if *gateway == ipv4.addr()
                || *gateway == ipv4.network()
                || *gateway == ipv4.broadcast()
            {
                issues.add(
                    format!("{path}.gateway"),
                    format!("{gateway} is not a valid gateway for {ipv4}"),
                );
            }
            for (i, ip) in dns.iter().enumerate() {
                if ip.is_unspecified() || ip.is_multicast() {
                    issues.add(
                        format!("{path}.dns[{i}]"),
                        format!("{ip} is not a usable DNS server"),
                    );
                }
            }
        }
        WanProto::Pppoe {
            username,
            password,
            service,
        } => {
            let path = "network.wan.proto";
            if !is_ppp_name(username) {
                issues.add(format!("{path}.username"), PPP_NAME_MSG);
            }
            let pw_path = format!("{path}.password");
            if !issues.redacted(&pw_path, password) && !is_ppp_password(password.expose()) {
                issues.add(
                    pw_path,
                    "must be 1..=128 printable ASCII characters without '\"' or '\\'",
                );
            }
            if service.as_deref().is_some_and(|s| !is_ppp_name(s)) {
                issues.add(format!("{path}.service"), PPP_NAME_MSG);
            }
        }
    }
    if let Some(mac) = &wan.mac_override
        && (mac.is_multicast() || mac.is_zero())
    {
        issues.add(
            "network.wan.mac_override",
            format!("{mac} is not a valid unicast MAC address"),
        );
    }
    if let Some(mtu) = wan.mtu
        && !(576..=9000).contains(&mtu)
    {
        issues.add("network.wan.mtu", format!("{mtu} is outside 576..=9000"));
    }
}

fn check_vlans(vlans: &[VlanConfig], issues: &mut Issues) {
    for (i, v) in vlans.iter().enumerate() {
        let path = format!("network.vlans[{i}]");
        if !is_vlan_name(&v.name) || v.name == "lan" || v.name == "wan" {
            issues.add(
                format!("{path}.name"),
                "must match ^[a-z][a-z0-9_]{0,11}$ and not be 'lan' or 'wan'",
            );
        }
        if !(1..=4094).contains(&v.id) {
            issues.add(
                format!("{path}.id"),
                format!("{} is outside 1..=4094", v.id),
            );
        }
        if let Some(net) = v.ipv4 {
            check_interface_net(&format!("{path}.ipv4"), net, 8, issues);
        }
        if let Some(pool) = &v.dhcp {
            check_pool(&format!("{path}.dhcp"), pool, v.ipv4, issues);
            if v.ipv4.is_none() && pool.enabled {
                issues.add(
                    format!("{path}.dhcp"),
                    "DHCP requires 'ipv4' to be set on this VLAN",
                );
            }
        }
    }
    check_unique(
        issues,
        "VLAN name",
        vlans
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("network.vlans[{i}].name"), v.name.clone())),
    );
    check_unique(
        issues,
        "VLAN id",
        vlans
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("network.vlans[{i}].id"), v.id.to_string())),
    );
}

// --------------------------------------------------------------- wireless

fn check_wireless(w: &WirelessConfig, cfg: &Config, issues: &mut Issues) {
    for (i, r) in w.radios.iter().enumerate() {
        check_radio(r, &format!("wireless.radios[{i}]"), issues);
    }
    check_unique(
        issues,
        "radio",
        w.radios
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("wireless.radios[{i}].id"), r.id.clone())),
    );
    for (i, ap) in w.aps.iter().enumerate() {
        check_ap(ap, &format!("wireless.aps[{i}]"), cfg, issues);
    }
    check_unique(
        issues,
        "SSID on radio",
        w.aps.iter().enumerate().map(|(i, ap)| {
            (
                format!("wireless.aps[{i}].ssid"),
                format!("{}/{}", ap.radio, ap.ssid),
            )
        }),
    );
}

fn check_radio(r: &RadioConfig, path: &str, issues: &mut Issues) {
    if !is_item_name(&r.id) {
        issues.add(
            format!("{path}.id"),
            "must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$",
        );
    }
    if !matches!(r.width_mhz, 20 | 40 | 80 | 160) {
        issues.add(
            format!("{path}.width_mhz"),
            format!("{} is not one of 20, 40, 80, 160", r.width_mhz),
        );
    }
    if r.country.len() != 2 || !r.country.bytes().all(|c| c.is_ascii_uppercase()) {
        issues.add(
            format!("{path}.country"),
            "must be two uppercase letters (ISO 3166-1 alpha-2)",
        );
    }
    if let Channel::Fixed(c) = r.channel
        && !(1..=233).contains(&c)
    {
        issues.add(format!("{path}.channel"), format!("{c} is outside 1..=233"));
    }
    if let Some(p) = r.txpower_dbm
        && !(1..=30).contains(&p)
    {
        issues.add(
            format!("{path}.txpower_dbm"),
            format!("{p} is outside 1..=30"),
        );
    }
}

fn check_ap(ap: &ApConfig, path: &str, cfg: &Config, issues: &mut Issues) {
    match cfg.wireless.radios.iter().find(|r| r.id == ap.radio) {
        None => issues.add(
            format!("{path}.radio"),
            format!("radio '{}' is not defined in [[wireless.radios]]", ap.radio),
        ),
        Some(radio) if !radio.enabled => issues.add(
            format!("{path}.radio"),
            format!(
                "radio '{}' is disabled, so this AP could never come up",
                ap.radio
            ),
        ),
        Some(_) => {}
    }
    if ap.ssid.is_empty() || ap.ssid.len() > 32 || ap.ssid.chars().any(char::is_control) {
        issues.add(
            format!("{path}.ssid"),
            "must be 1..=32 bytes without control characters",
        );
    }
    if let Some(pass) = ap.security.passphrase() {
        let pass_path = format!("{path}.security.passphrase");
        let p = pass.expose();
        if !issues.redacted(&pass_path, pass)
            && (!(8..=63).contains(&p.len()) || !is_printable_ascii(p))
        {
            issues.add(pass_path, "must be 8..=63 printable ASCII characters");
        }
    }
    if ap.network != "lan" && !cfg.network.vlans.iter().any(|v| v.name == ap.network) {
        issues.add(
            format!("{path}.network"),
            format!("'{}' is neither 'lan' nor a VLAN name", ap.network),
        );
    }
    if ap.max_clients == Some(0) {
        issues.add(format!("{path}.max_clients"), "must be >= 1");
    }
}

// --------------------------------------------------------------- firewall

/// Is `ip` a usable host in some LAN/VLAN subnet? Appends an issue at `path` if not.
fn check_host_in_subnets(path: &str, ip: Ipv4Addr, subnets: &[Subnet], issues: &mut Issues) {
    let Some(s) = subnets.iter().find(|s| s.net.contains(&ip)) else {
        issues.add(
            path,
            format!("{ip} is not inside the LAN or any VLAN subnet"),
        );
        return;
    };
    if ip == s.net.network() || ip == s.net.broadcast() {
        issues.add(
            path,
            format!("{ip} is the network or broadcast address of '{}'", s.label),
        );
    } else if ip == s.net.addr() {
        issues.add(
            path,
            format!("{ip} is the router's own address on '{}'", s.label),
        );
    }
}

fn forward_protos_clash(a: ForwardProto, b: ForwardProto) -> bool {
    a == b || a == ForwardProto::TcpUdp || b == ForwardProto::TcpUdp
}

fn check_firewall(fw: &FirewallConfig, subnets: &[Subnet], issues: &mut Issues) {
    // Over-long lists are reported once and not walked (the overlap check is quadratic).
    let forwards: &[PortForward] = if issues.within(
        "firewall.port_forwards",
        fw.port_forwards.len(),
        MAX_PORT_FORWARDS,
    ) {
        &fw.port_forwards
    } else {
        &[]
    };
    let rules: &[Rule] = if issues.within("firewall.rules", fw.rules.len(), MAX_RULES) {
        &fw.rules
    } else {
        &[]
    };
    for (i, pf) in forwards.iter().enumerate() {
        let path = format!("firewall.port_forwards[{i}]");
        if !is_item_name(&pf.name) {
            issues.add(
                format!("{path}.name"),
                "must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$",
            );
        }
        if !pf.wan_port.is_valid() {
            issues.add(
                format!("{path}.wan_port"),
                "port range must satisfy 1 <= start <= end",
            );
        }
        if pf.dest_port == 0 {
            issues.add(format!("{path}.dest_port"), "must be >= 1");
        }
        check_host_in_subnets(&format!("{path}.dest_ip"), pf.dest_ip, subnets, issues);
        for (j, other) in forwards.iter().enumerate().take(i) {
            if pf.enabled
                && other.enabled
                && forward_protos_clash(pf.proto, other.proto)
                && pf.wan_port.overlaps(&other.wan_port)
            {
                issues.add(
                    format!("{path}.wan_port"),
                    format!("overlaps port_forwards[{j}] ('{}')", other.name),
                );
            }
        }
    }
    check_unique(
        issues,
        "port forward",
        forwards
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("firewall.port_forwards[{i}].name"), p.name.clone())),
    );
    for (i, r) in rules.iter().enumerate() {
        check_rule(r, &format!("firewall.rules[{i}]"), issues);
    }
    check_unique(
        issues,
        "rule",
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("firewall.rules[{i}].name"), r.name.clone())),
    );
}

fn check_rule(r: &Rule, path: &str, issues: &mut Issues) {
    if !is_item_name(&r.name) {
        issues.add(
            format!("{path}.name"),
            "must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$",
        );
    }
    if let Some(range) = &r.dest_port {
        if !range.is_valid() {
            issues.add(
                format!("{path}.dest_port"),
                "port range must satisfy 1 <= start <= end",
            );
        }
        if !matches!(r.proto, RuleProto::Tcp | RuleProto::Udp) {
            issues.add(
                format!("{path}.dest_port"),
                "only valid with proto 'tcp' or 'udp'",
            );
        }
    }
}

// ------------------------------------------------------------------- dhcp

fn check_dhcp(d: &DhcpConfig, subnets: &[Subnet], issues: &mut Issues) {
    let static_leases: &[StaticLease] = if issues.within(
        "dhcp.static_leases",
        d.static_leases.len(),
        MAX_STATIC_LEASES,
    ) {
        &d.static_leases
    } else {
        &[]
    };
    if !is_domain_name(&d.local_domain) {
        issues.add(
            "dhcp.local_domain",
            "must be a valid domain name such as 'lan'",
        );
    }
    for (i, ip) in d.dns_servers.iter().enumerate() {
        if ip.is_unspecified() || ip.is_multicast() {
            issues.add(
                format!("dhcp.dns_servers[{i}]"),
                format!("{ip} is not a usable DNS server"),
            );
        }
    }
    for (i, l) in static_leases.iter().enumerate() {
        let path = format!("dhcp.static_leases[{i}]");
        if l.mac.is_multicast() || l.mac.is_zero() {
            issues.add(
                format!("{path}.mac"),
                format!("{} is not a valid unicast MAC address", l.mac),
            );
        }
        check_host_in_subnets(&format!("{path}.ip"), l.ip, subnets, issues);
        if l.hostname.as_deref().is_some_and(|h| !is_hostname_label(h)) {
            issues.add(format!("{path}.hostname"), "must be an RFC 1123 label");
        }
    }
    let leases = || static_leases.iter().enumerate();
    check_unique(
        issues,
        "MAC",
        leases().map(|(i, l)| (format!("dhcp.static_leases[{i}].mac"), l.mac.to_string())),
    );
    check_unique(
        issues,
        "IP",
        leases().map(|(i, l)| (format!("dhcp.static_leases[{i}].ip"), l.ip.to_string())),
    );
    check_unique(
        issues,
        "hostname",
        leases().filter_map(|(i, l)| {
            l.hostname.as_ref().map(|h| {
                (
                    format!("dhcp.static_leases[{i}].hostname"),
                    h.to_ascii_lowercase(),
                )
            })
        }),
    );
}

// --------------------------------------------------------------- services

fn check_services(s: &ServicesConfig, issues: &mut Issues) {
    if s.api.port == 0 {
        issues.add("services.api.port", "must be >= 1");
    }
    if s.api.session_ttl < Duration::from_mins(1)
        || s.api.session_ttl > Duration::from_hours(24 * 7)
    {
        issues.add("services.api.session_ttl", "must be between 1m and 7d");
    }
    let ssh = &s.ssh;
    if ssh.port == 0 {
        issues.add("services.ssh.port", "must be >= 1");
    }
    if ssh.enabled && ssh.port == s.api.port {
        issues.add(
            "services.ssh.port",
            format!("conflicts with services.api.port ({})", s.api.port),
        );
    }
    if ssh.enabled && !ssh.password_auth && ssh.authorized_keys.is_empty() {
        issues.add(
            "services.ssh",
            "enabled with password_auth = false and no authorized_keys: nobody could log in",
        );
    }
    if issues.within(
        "services.ssh.authorized_keys",
        ssh.authorized_keys.len(),
        MAX_SSH_KEYS,
    ) {
        for (i, k) in ssh.authorized_keys.iter().enumerate() {
            if !is_ssh_key(k) {
                issues.add(
                    format!("services.ssh.authorized_keys[{i}]"),
                    "not a single-line ASCII 'type base64 [comment]' public key (max 4096 characters)",
                );
            }
        }
    }
}
