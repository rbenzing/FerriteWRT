//! Observed-state model: what the kernel currently reports.

use serde::{Deserialize, Serialize};

use crate::model::{AddrSpec, MacAddr, RouteSpec};

/// Kind of an observed link.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkKind {
    Bridge,
    Vlan {
        parent_index: u32,
        id: u16,
    },
    /// Real hardware or a DSA user port (no `IFLA_INFO_KIND`, or kind `dsa`).
    #[default]
    Physical,
    /// Any other `IFLA_INFO_KIND` (veth, dummy, wireguard, ...).
    Other(String),
}

/// Interface counters (`rtnl_link_stats64` subset).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// One link as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedLink {
    pub index: u32,
    pub name: String,
    pub kind: LinkKind,
    /// Interface index of the bridge this link is enslaved to.
    pub master: Option<u32>,
    /// Administrative state (`IFF_UP`).
    pub up: bool,
    /// Link has carrier (`IFF_LOWER_UP`).
    pub carrier: bool,
    pub mtu: u32,
    pub mac: Option<MacAddr>,
    pub speed_mbps: Option<u32>,
    pub stats: LinkStats,
    /// Bridges only: `IFLA_BR_VLAN_FILTERING`. `None` is treated as off.
    #[serde(default)]
    pub vlan_filtering: Option<bool>,
    /// `IFLA_IFALIAS`. The planner only deletes links whose alias is
    /// [`crate::planner::MANAGED_ALIAS`].
    #[serde(default)]
    pub alias: Option<String>,
}

impl ObservedLink {
    /// A down, carrier-less link with MTU 1500 and no address; handy for tests
    /// and simulators.
    pub fn new(index: u32, name: impl Into<String>, kind: LinkKind) -> Self {
        Self {
            index,
            name: name.into(),
            kind,
            master: None,
            up: false,
            carrier: false,
            mtu: 1500,
            mac: None,
            speed_mbps: None,
            stats: LinkStats::default(),
            vlan_filtering: None,
            alias: None,
        }
    }
}

/// A snapshot of network state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub links: Vec<ObservedLink>,
    /// Permanent addresses only (dynamic SLAAC addresses are not reported).
    pub addresses: Vec<AddrSpec>,
    /// Main-table unicast routes.
    pub routes: Vec<RouteSpec>,
    /// Current values of the sysctls the caller asked about.
    #[serde(default)]
    pub sysctls: Vec<(String, String)>,
}
