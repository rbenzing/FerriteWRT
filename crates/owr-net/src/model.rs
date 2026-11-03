//! Desired-state model: what the network should look like.
//!
//! Pure data plus [`NetPlan::validate`]. Nothing here touches the system.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Linux `IFNAMSIZ` minus the trailing NUL.
pub const IFNAME_MAX: usize = 15;
/// The main routing table (`RT_TABLE_MAIN`).
pub const TABLE_MAIN: u32 = 254;
/// Longest accepted sysctl value.
const SYSCTL_VALUE_MAX: usize = 256;

/// A 48-bit Ethernet hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

/// Error parsing a [`MacAddr`] from text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address {0:?}: expected aa:bb:cc:dd:ee:ff")]
pub struct MacParseError(String);

impl MacAddr {
    /// The raw octets.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || MacParseError(s.to_owned());
        let mut out = [0u8; 6];
        let mut parts = s.split(':');
        for slot in &mut out {
            let part = parts.next().ok_or_else(err)?;
            if part.len() != 2 {
                return Err(err());
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A link (network device) that should exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkSpec {
    /// A Linux bridge. Name must start with `br-`.
    Bridge {
        name: String,
        ports: Vec<String>,
        vlan_filtering: bool,
        mtu: Option<u32>,
        mac: Option<MacAddr>,
    },
    /// An 802.1q netdev, e.g. `eth1.100` or a bridge VLAN sub-interface `br-lan.20`.
    Vlan {
        name: String,
        parent: String,
        id: u16,
    },
    /// An existing hardware (or DSA user port) netdev. Never created or deleted.
    Physical {
        name: String,
        up: bool,
        mtu: Option<u32>,
        mac: Option<MacAddr>,
    },
}

impl LinkSpec {
    pub fn name(&self) -> &str {
        match self {
            Self::Bridge { name, .. } | Self::Vlan { name, .. } | Self::Physical { name, .. } => {
                name
            }
        }
    }
}

/// An address that should be present on a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrSpec {
    pub link: String,
    pub addr: IpNet,
}

/// Origin of a route (`rtm_protocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteProto {
    /// Installed by the kernel (connected routes). Never deleted.
    Kernel,
    Boot,
    Static,
    Dhcp,
    Other(u8),
}

impl RouteProto {
    /// Routes the planner is allowed to delete when they are not desired.
    pub fn is_ours(self) -> bool {
        matches!(self, Self::Boot | Self::Static | Self::Dhcp)
    }
}

/// A route that should be present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    /// `0.0.0.0/0` (or `::/0`) for a default route.
    pub dest: IpNet,
    pub via: Option<IpAddr>,
    pub dev: Option<String>,
    pub metric: u32,
    /// Only [`TABLE_MAIN`] (254) is supported.
    pub table: u32,
    pub proto: RouteProto,
}

impl RouteSpec {
    /// Identity used to compare desired and observed routes. The protocol is
    /// deliberately excluded, the destination is compared as its network (the
    /// kernel never reports host bits) and an IPv6 metric of 0 is the kernel's 1024.
    pub(crate) fn key(&self) -> (IpNet, Option<IpAddr>, u32, u32) {
        let metric = if self.dest.addr().is_ipv6() && self.metric == 0 {
            1024
        } else {
            self.metric
        };
        (self.dest.trunc(), self.via, metric, self.table)
    }
}

/// A `DHCPv4` client to run on a link (runtime concern; ignored by the planner).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpClientSpec {
    pub link: String,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub request_dns: bool,
    pub default_route_metric: u32,
}

/// The complete desired network state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPlan {
    pub links: Vec<LinkSpec>,
    pub addresses: Vec<AddrSpec>,
    pub routes: Vec<RouteSpec>,
    pub dhcp_clients: Vec<DhcpClientSpec>,
    /// `(key, value)`, e.g. `("net.ipv4.ip_forward", "1")`.
    pub sysctls: Vec<(String, String)>,
}

/// Why a [`NetPlan`] is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid interface name {0:?}")]
    BadName(String),
    #[error("duplicate link name {0:?}")]
    DuplicateLink(String),
    #[error("bridge name {0:?} must start with \"br-\" and be at most 15 bytes")]
    BadBridgeName(String),
    #[error("vlan name {0:?} must contain '.' or start with \"br-\" so it can be managed")]
    BadVlanName(String),
    #[error("vlan {name:?}: id {id} outside 1..=4094")]
    BadVlanId { name: String, id: u16 },
    #[error("vlan {name:?}: parent {parent:?} is itself or another vlan")]
    BadVlanParent { name: String, parent: String },
    #[error("bridge {bridge:?}: port {port:?} is a bridge")]
    BridgeAsPort { bridge: String, port: String },
    #[error("port {port:?} is in more than one bridge ({a:?}, {b:?})")]
    PortInTwoBridges { port: String, a: String, b: String },
    #[error("address {addr} refers to unknown link {link:?}")]
    AddrUnknownLink { link: String, addr: String },
    #[error("address {addr} on {link:?} is link-local (kernel managed)")]
    AddrLinkLocal { link: String, addr: String },
    #[error("duplicate address {addr} on {link:?}")]
    DuplicateAddr { link: String, addr: String },
    #[error("route {dest} refers to unknown link {dev:?}")]
    RouteUnknownLink { dest: String, dev: String },
    #[error("route {dest} needs a gateway or a device")]
    RouteNoTarget { dest: String },
    #[error("route {dest}: gateway {via} family differs from destination")]
    RouteFamilyMismatch { dest: String, via: String },
    #[error("route {dest}: only table 254 (main) is supported, got {table}")]
    RouteBadTable { dest: String, table: u32 },
    #[error("route {dest} has host bits set; use the network address")]
    RouteHostBits { dest: String },
    #[error("route {dest}: kernel-protocol routes cannot be declared")]
    RouteKernelProto { dest: String },
    #[error("dhcp client refers to unknown link {0:?}")]
    DhcpUnknownLink(String),
    #[error("more than one dhcp client on {0:?}")]
    DhcpDuplicate(String),
    #[error("dhcp client on {link:?} conflicts with static IPv4 address {addr}")]
    DhcpStaticConflict { link: String, addr: String },
    #[error("invalid sysctl key {0:?}")]
    BadSysctlKey(String),
    #[error("invalid sysctl value for {0:?}")]
    BadSysctlValue(String),
}

/// Whether `name` is usable as a Linux interface name (kernel `dev_valid_name`:
/// no `/`, `:` or whitespace, not `.` or `..`).
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= IFNAME_MAX
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == ':' || c.is_whitespace() || c.is_control())
}

/// Whether `ip` is an IPv6 link-local (`fe80::/10`) address.
pub(crate) fn is_v6_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
}

/// Whether `v` is an acceptable sysctl value: 1..=256 printable ASCII bytes.
pub fn valid_sysctl_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= SYSCTL_VALUE_MAX
        && v.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Sysctls outside `net/` and `vm/` that a plan may set: hardening knobs only.
const SAFE_SYSCTLS: [&str; 10] = [
    "kernel/kptr_restrict",
    "kernel/dmesg_restrict",
    "kernel/unprivileged_bpf_disabled",
    "kernel/yama/ptrace_scope",
    "kernel/perf_event_paranoid",
    "fs/protected_symlinks",
    "fs/protected_hardlinks",
    "fs/protected_fifos",
    "fs/protected_regular",
    "fs/suid_dumpable",
];

/// The interface a sysctl path is specific to: `net/ipv{4,6}/{conf,neigh}/<if>/...`
/// where `<if>` is neither `all` nor `default` (those are global and must be
/// written before any per-interface key, because the kernel resets the latter).
pub fn sysctl_iface(path: &str) -> Option<&str> {
    let mut parts = path.split('/');
    let (Some("net"), Some("ipv4" | "ipv6"), Some("conf" | "neigh"), Some(ifname), Some(_)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    (ifname != "all" && ifname != "default").then_some(ifname)
}

/// Map a sysctl key to its path below `/proc/sys`.
///
/// Dotted keys (`net.ipv4.ip_forward`) become `net/ipv4/ip_forward`. A key that
/// already contains `/` is taken as a path (needed for interface names with a dot:
/// `net/ipv4/conf/eth1.100/forwarding`). Only `[a-z0-9_./-]` is accepted and no
/// component may be empty or `..`. The path must be below `net/` or `vm/`, or be
/// one of a short allow-list of kernel / fs hardening keys; anything else
/// (`kernel/core_pattern`, `kernel/modprobe`, ...) is rejected.
pub fn sysctl_path(key: &str) -> Result<String, ValidationError> {
    let bad = || ValidationError::BadSysctlKey(key.to_owned());
    if key.is_empty()
        || key.len() > 256
        || !key
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'/' | b'-'))
    {
        return Err(bad());
    }
    let path = if key.contains('/') {
        key.to_owned()
    } else {
        key.replace('.', "/")
    };
    if path.split('/').any(|c| c.is_empty() || c == "..") {
        return Err(bad());
    }
    if !(path.starts_with("net/")
        || path.starts_with("vm/")
        || SAFE_SYSCTLS.contains(&path.as_str()))
    {
        return Err(bad());
    }
    Ok(path)
}

impl NetPlan {
    /// Check the plan for internal consistency. See [`ValidationError`].
    ///
    /// This is the check for *user intent*: a DHCP-managed link must not also have
    /// a static IPv4 address. [`crate::plan`] runs every check except that one so
    /// that lease-derived addresses can be merged into the plan it receives.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_inner(true)
    }

    #[allow(clippy::too_many_lines)] // one flat list of independent rules reads best
    pub(crate) fn validate_inner(&self, dhcp_static_conflict: bool) -> Result<(), ValidationError> {
        use std::collections::{HashMap, HashSet};

        let mut kinds: HashMap<&str, &LinkSpec> = HashMap::new();
        for l in &self.links {
            let name = l.name();
            if !valid_ifname(name) {
                return Err(ValidationError::BadName(name.to_owned()));
            }
            if kinds.insert(name, l).is_some() {
                return Err(ValidationError::DuplicateLink(name.to_owned()));
            }
            match l {
                LinkSpec::Bridge { .. } if !name.starts_with("br-") => {
                    return Err(ValidationError::BadBridgeName(name.to_owned()));
                }
                LinkSpec::Vlan { id, .. } if !(1..=4094).contains(id) => {
                    return Err(ValidationError::BadVlanId {
                        name: name.to_owned(),
                        id: *id,
                    });
                }
                LinkSpec::Vlan { .. } if !(name.contains('.') || name.starts_with("br-")) => {
                    return Err(ValidationError::BadVlanName(name.to_owned()));
                }
                _ => {}
            }
        }

        let mut port_owner: HashMap<&str, &str> = HashMap::new();
        for l in &self.links {
            match l {
                LinkSpec::Vlan { name, parent, .. } => {
                    if !valid_ifname(parent)
                        || parent == name
                        || matches!(kinds.get(parent.as_str()), Some(LinkSpec::Vlan { .. }))
                    {
                        return Err(ValidationError::BadVlanParent {
                            name: name.clone(),
                            parent: parent.clone(),
                        });
                    }
                }
                LinkSpec::Bridge { name, ports, .. } => {
                    for p in ports {
                        if !valid_ifname(p) {
                            return Err(ValidationError::BadName(p.clone()));
                        }
                        if p == name
                            || matches!(kinds.get(p.as_str()), Some(LinkSpec::Bridge { .. }))
                        {
                            return Err(ValidationError::BridgeAsPort {
                                bridge: name.clone(),
                                port: p.clone(),
                            });
                        }
                        if let Some(prev) = port_owner.insert(p, name) {
                            return Err(ValidationError::PortInTwoBridges {
                                port: p.clone(),
                                a: prev.to_owned(),
                                b: name.clone(),
                            });
                        }
                    }
                }
                LinkSpec::Physical { .. } => {}
            }
        }

        let mut seen_addr = HashSet::new();
        for a in &self.addresses {
            let addr = a.addr.to_string();
            if !kinds.contains_key(a.link.as_str()) {
                return Err(ValidationError::AddrUnknownLink {
                    link: a.link.clone(),
                    addr,
                });
            }
            if is_v6_link_local(a.addr.addr()) {
                return Err(ValidationError::AddrLinkLocal {
                    link: a.link.clone(),
                    addr,
                });
            }
            if !seen_addr.insert((&a.link, a.addr)) {
                return Err(ValidationError::DuplicateAddr {
                    link: a.link.clone(),
                    addr,
                });
            }
        }

        for r in &self.routes {
            let dest = r.dest.to_string();
            if r.table != TABLE_MAIN {
                return Err(ValidationError::RouteBadTable {
                    dest,
                    table: r.table,
                });
            }
            if r.dest != r.dest.trunc() {
                return Err(ValidationError::RouteHostBits { dest });
            }
            if r.proto == RouteProto::Kernel {
                return Err(ValidationError::RouteKernelProto { dest });
            }
            if r.via.is_none() && r.dev.is_none() {
                return Err(ValidationError::RouteNoTarget { dest });
            }
            if let Some(via) = r.via
                && via.is_ipv4() != r.dest.addr().is_ipv4()
            {
                return Err(ValidationError::RouteFamilyMismatch {
                    dest,
                    via: via.to_string(),
                });
            }
            if let Some(dev) = &r.dev
                && !kinds.contains_key(dev.as_str())
            {
                return Err(ValidationError::RouteUnknownLink {
                    dest,
                    dev: dev.clone(),
                });
            }
        }

        let mut dhcp_links = HashSet::new();
        for d in &self.dhcp_clients {
            if !kinds.contains_key(d.link.as_str()) {
                return Err(ValidationError::DhcpUnknownLink(d.link.clone()));
            }
            if !dhcp_links.insert(d.link.as_str()) {
                return Err(ValidationError::DhcpDuplicate(d.link.clone()));
            }
            if dhcp_static_conflict
                && let Some(a) = self
                    .addresses
                    .iter()
                    .find(|a| a.link == d.link && a.addr.addr().is_ipv4())
            {
                return Err(ValidationError::DhcpStaticConflict {
                    link: d.link.clone(),
                    addr: a.addr.to_string(),
                });
            }
        }

        for (k, v) in &self.sysctls {
            sysctl_path(k)?;
            if !valid_sysctl_value(v) {
                return Err(ValidationError::BadSysctlValue(k.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phys(name: &str) -> LinkSpec {
        LinkSpec::Physical {
            name: name.into(),
            up: true,
            mtu: None,
            mac: None,
        }
    }

    fn bridge(name: &str, ports: &[&str]) -> LinkSpec {
        LinkSpec::Bridge {
            name: name.into(),
            ports: ports.iter().map(|s| (*s).to_owned()).collect(),
            vlan_filtering: false,
            mtu: None,
            mac: None,
        }
    }

    fn plan(links: Vec<LinkSpec>) -> NetPlan {
        NetPlan {
            links,
            ..NetPlan::default()
        }
    }

    #[test]
    fn mac_round_trips_through_text_and_serde() {
        let m: MacAddr = "00:11:22:aa:BB:cc".parse().unwrap();
        assert_eq!(m.to_string(), "00:11:22:aa:bb:cc");
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"00:11:22:aa:bb:cc\"");
        assert_eq!(serde_json::from_str::<MacAddr>(&json).unwrap(), m);
    }

    #[test]
    fn mac_rejects_malformed() {
        for bad in [
            "",
            "00:11:22:33:44",
            "00:11:22:33:44:55:66",
            "0:1:2:3:4:5",
            "gg:11:22:33:44:55",
            "00-11-22-33-44-55",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn valid_plan_passes_and_serde_round_trips() {
        let mut p = plan(vec![
            phys("eth1"),
            phys("lan1"),
            bridge("br-lan", &["lan1"]),
        ]);
        p.addresses.push(AddrSpec {
            link: "br-lan".into(),
            addr: "192.168.8.1/24".parse().unwrap(),
        });
        p.sysctls.push(("net.ipv4.ip_forward".into(), "1".into()));
        assert_eq!(p.validate(), Ok(()));
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<NetPlan>(&json).unwrap(), p);
    }

    #[test]
    fn duplicate_link_names_rejected() {
        let p = plan(vec![phys("eth1"), phys("eth1")]);
        assert_eq!(
            p.validate(),
            Err(ValidationError::DuplicateLink("eth1".into()))
        );
    }

    #[test]
    fn bridge_name_rules() {
        assert!(matches!(
            plan(vec![bridge("lan", &[])]).validate(),
            Err(ValidationError::BadBridgeName(_))
        ));
        assert!(matches!(
            plan(vec![bridge("br-0123456789abc", &[])]).validate(),
            Err(ValidationError::BadName(_))
        ));
        assert_eq!(plan(vec![bridge("br-0123456789a", &[])]).validate(), Ok(()));
    }

    #[test]
    fn vlan_id_and_name_rules() {
        let v = |name: &str, id| LinkSpec::Vlan {
            name: name.into(),
            parent: "eth1".into(),
            id,
        };
        assert!(matches!(
            plan(vec![v("eth1.0", 0)]).validate(),
            Err(ValidationError::BadVlanId { .. })
        ));
        assert!(matches!(
            plan(vec![v("eth1.1", 4095)]).validate(),
            Err(ValidationError::BadVlanId { .. })
        ));
        assert!(matches!(
            plan(vec![v("guest", 10)]).validate(),
            Err(ValidationError::BadVlanName(_))
        ));
        assert_eq!(
            plan(vec![v("eth1.4094", 4094), v("br-guest", 1)]).validate(),
            Ok(())
        );
    }

    #[test]
    fn vlan_parent_must_not_be_vlan_or_self() {
        let v = |name: &str, parent: &str| LinkSpec::Vlan {
            name: name.into(),
            parent: parent.into(),
            id: 5,
        };
        assert!(matches!(
            plan(vec![v("a.5", "a.5")]).validate(),
            Err(ValidationError::BadVlanParent { .. })
        ));
        assert!(matches!(
            plan(vec![v("eth1.5", "eth1"), v("eth1.5.5", "eth1.5")]).validate(),
            Err(ValidationError::BadVlanParent { .. })
        ));
    }

    #[test]
    fn port_in_two_bridges_and_bridge_ports() {
        let p = plan(vec![bridge("br-a", &["lan1"]), bridge("br-b", &["lan1"])]);
        assert!(matches!(
            p.validate(),
            Err(ValidationError::PortInTwoBridges { .. })
        ));
        let p = plan(vec![bridge("br-a", &[]), bridge("br-b", &["br-a"])]);
        assert!(matches!(
            p.validate(),
            Err(ValidationError::BridgeAsPort { .. })
        ));
    }

    #[test]
    fn address_rules() {
        let a = |link: &str, addr: &str| AddrSpec {
            link: link.into(),
            addr: addr.parse().unwrap(),
        };
        let mut p = plan(vec![phys("eth1")]);
        p.addresses = vec![a("nope", "10.0.0.1/24")];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::AddrUnknownLink { .. })
        ));
        p.addresses = vec![a("eth1", "fe80::1/64")];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::AddrLinkLocal { .. })
        ));
        p.addresses = vec![a("eth1", "10.0.0.1/24"), a("eth1", "10.0.0.1/24")];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::DuplicateAddr { .. })
        ));
    }

    fn route(dest: &str, via: Option<&str>, dev: Option<&str>) -> RouteSpec {
        RouteSpec {
            dest: dest.parse().unwrap(),
            via: via.map(|v| v.parse().unwrap()),
            dev: dev.map(str::to_owned),
            metric: 0,
            table: TABLE_MAIN,
            proto: RouteProto::Static,
        }
    }

    #[test]
    fn route_rules() {
        let mut p = plan(vec![phys("eth1")]);
        p.routes = vec![route("0.0.0.0/0", None, None)];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteNoTarget { .. })
        ));
        p.routes = vec![route("0.0.0.0/0", None, Some("nope"))];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteUnknownLink { .. })
        ));
        p.routes = vec![route("0.0.0.0/0", Some("fe80::1"), Some("eth1"))];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteFamilyMismatch { .. })
        ));
        let mut r = route("0.0.0.0/0", Some("10.0.0.1"), Some("eth1"));
        r.table = 100;
        p.routes = vec![r];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteBadTable { .. })
        ));
        let mut r = route("0.0.0.0/0", Some("10.0.0.1"), Some("eth1"));
        r.proto = RouteProto::Kernel;
        p.routes = vec![r];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteKernelProto { .. })
        ));
        p.routes = vec![route("0.0.0.0/0", Some("10.0.0.1"), Some("eth1"))];
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn dhcp_rules() {
        let d = |link: &str| DhcpClientSpec {
            link: link.into(),
            hostname: None,
            vendor_class: None,
            request_dns: true,
            default_route_metric: 10,
        };
        let mut p = plan(vec![phys("eth1")]);
        p.dhcp_clients = vec![d("nope")];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::DhcpUnknownLink(_))
        ));
        p.dhcp_clients = vec![d("eth1"), d("eth1")];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::DhcpDuplicate(_))
        ));
        p.dhcp_clients = vec![d("eth1")];
        p.addresses = vec![AddrSpec {
            link: "eth1".into(),
            addr: "10.0.0.2/24".parse().unwrap(),
        }];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::DhcpStaticConflict { .. })
        ));
        assert_eq!(p.validate_inner(false), Ok(()));
        p.addresses = vec![AddrSpec {
            link: "eth1".into(),
            addr: "2001:db8::2/64".parse().unwrap(),
        }];
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn sysctl_keys_and_values() {
        assert_eq!(
            sysctl_path("net.ipv4.ip_forward").unwrap(),
            "net/ipv4/ip_forward"
        );
        assert_eq!(
            sysctl_path("net/ipv4/conf/eth1.100/forwarding").unwrap(),
            "net/ipv4/conf/eth1.100/forwarding"
        );
        for bad in [
            "",
            "Net.ipv4",
            "../etc",
            "net..ipv4",
            "/net/x",
            "net/../x",
            "a b",
            "net.ipv4.\n",
        ] {
            assert!(sysctl_path(bad).is_err(), "{bad:?}");
        }
        let mut p = plan(vec![]);
        p.sysctls = vec![("net.ipv4.ip_forward".into(), "1\n2".into())];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::BadSysctlValue(_))
        ));
        p.sysctls = vec![("net.ipv4.ip_forward".into(), String::new())];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::BadSysctlValue(_))
        ));
    }

    #[test]
    fn sysctl_keys_are_allow_listed() {
        for ok in [
            "net.ipv4.ip_forward",
            "net.core.bpf_jit_harden",
            "vm.swappiness",
            "kernel.kptr_restrict",
            "kernel.yama.ptrace_scope",
            "kernel/perf_event_paranoid",
            "fs.protected_regular",
            "fs.suid_dumpable",
        ] {
            assert!(sysctl_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "kernel.core_pattern",
            "kernel/core_pattern",
            "kernel.modprobe",
            "kernel.hotplug",
            "fs.binfmt_misc.register",
            "fs.protected_symlinks.x",
            "netx.foo",
            "kernel.kptr_restrict.x",
        ] {
            assert!(
                matches!(sysctl_path(bad), Err(ValidationError::BadSysctlKey(_))),
                "{bad}"
            );
        }
        let mut p = plan(vec![]);
        p.sysctls = vec![("kernel.core_pattern".into(), "|/bin/sh".into())];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::BadSysctlKey(_))
        ));
    }

    #[test]
    fn sysctl_iface_is_only_set_for_real_interfaces() {
        assert_eq!(
            sysctl_iface("net/ipv4/conf/br-lan/rp_filter"),
            Some("br-lan")
        );
        assert_eq!(
            sysctl_iface("net/ipv6/conf/eth1.100/forwarding"),
            Some("eth1.100")
        );
        assert_eq!(
            sysctl_iface("net/ipv4/neigh/br-lan/gc_stale_time"),
            Some("br-lan")
        );
        for global in [
            "net/ipv4/conf/all/forwarding",
            "net/ipv4/conf/default/rp_filter",
            "net/ipv4/ip_forward",
            "net/ipv4/conf/br-lan",
            "kernel/kptr_restrict",
        ] {
            assert_eq!(sysctl_iface(global), None, "{global}");
        }
    }

    #[test]
    fn route_destination_with_host_bits_is_rejected() {
        let mut p = plan(vec![phys("eth1")]);
        p.routes = vec![route("10.1.2.3/24", Some("10.1.2.1"), Some("eth1"))];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteHostBits { .. })
        ));
        p.routes = vec![route("2001:db8::1/64", Some("2001:db8::2"), Some("eth1"))];
        assert!(matches!(
            p.validate(),
            Err(ValidationError::RouteHostBits { .. })
        ));
        p.routes = vec![route("10.1.2.0/24", Some("10.1.2.1"), Some("eth1"))];
        assert_eq!(p.validate(), Ok(()));
        // observed and desired compare by network
        assert_eq!(
            route("10.1.2.3/24", None, Some("eth1")).key(),
            route("10.1.2.0/24", None, Some("eth1")).key()
        );
    }

    #[test]
    fn ifname_rejects_colon_slash_and_whitespace() {
        for bad in [
            "eth0:1",
            "a/b",
            "a b",
            "a\tb",
            "",
            ".",
            "..",
            "0123456789abcdef",
        ] {
            assert!(!valid_ifname(bad), "{bad:?}");
        }
        for ok in ["eth1.100", "br-lan", "lan_1", "0123456789abcde"] {
            assert!(valid_ifname(ok), "{ok:?}");
        }
        assert!(matches!(
            plan(vec![phys("eth0:1")]).validate(),
            Err(ValidationError::BadName(_))
        ));
    }
}
