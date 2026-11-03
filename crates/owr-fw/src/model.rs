//! Firewall domain model. Plain data; validation lives in `validate.rs`.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error for an invalid [`ZoneName`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid zone name {0:?}: must match [a-z0-9_]{{1,15}}")]
pub struct ZoneNameError(String);

/// Validated zone name: `[a-z0-9_]{1,15}`. Safe to embed in nft chain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZoneName(String);

impl ZoneName {
    pub fn new(name: &str) -> Result<Self, ZoneNameError> {
        if Self::is_valid(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(ZoneNameError(name.to_owned()))
        }
    }

    pub(crate) fn is_valid(name: &str) -> bool {
        (1..=15).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    }

    /// For compile-time-known valid names inside this crate (covered by tests).
    pub(crate) fn builtin(name: &str) -> Self {
        Self(name.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ZoneName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ZoneName {
    type Error = ZoneNameError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if Self::is_valid(&value) {
            Ok(Self(value))
        } else {
            Err(ZoneNameError(value))
        }
    }
}

impl From<ZoneName> for String {
    fn from(value: ZoneName) -> Self {
        value.0
    }
}

impl FromStr for ZoneName {
    type Err = ZoneNameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// Verdict applied to traffic that no explicit rule matched (or by a rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    Accept,
    Drop,
    Reject,
}

/// Address family restriction of a rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Both families (or derived from `src_ip` / `dst_ip` when given).
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

/// Protocol match of a rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    #[default]
    Any,
    Tcp,
    Udp,
    TcpUdp,
    /// `icmp` for IPv4 and `ipv6-icmp` for IPv6.
    Icmp,
}

impl Proto {
    pub(crate) fn has_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::TcpUdp)
    }
}

/// Error parsing a [`PortRange`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid port range {0:?}: expected \"PORT\" or \"START-END\" in 1-65535 with START <= END"
)]
pub struct ParsePortRangeError(String);

/// Inclusive destination port range. A single port has `start == end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// `start >= 1` and `start <= end`.
    pub const fn is_valid(&self) -> bool {
        self.start > 0 && self.start <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = ParsePortRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParsePortRangeError(s.to_owned());
        let range = match s.split_once('-') {
            Some((a, b)) => Self {
                start: a.parse().map_err(|_| err())?,
                end: b.parse().map_err(|_| err())?,
            },
            None => Self::single(s.parse().map_err(|_| err())?),
        };
        if range.is_valid() {
            Ok(range)
        } else {
            Err(err())
        }
    }
}

/// A firewall zone: a named set of network interfaces with default policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub name: ZoneName,
    /// Netdev names, e.g. `br-lan`, `eth1`.
    pub interfaces: Vec<String>,
    /// Policy for traffic from this zone to the device itself.
    pub input: Policy,
    /// Policy for traffic from the device out through this zone.
    pub output: Policy,
    /// Policy for traffic that enters and leaves through this zone (intra-zone).
    pub forward: Policy,
    /// Masquerade (IPv4 SNAT) traffic leaving through this zone.
    pub masquerade: bool,
    /// Clamp TCP MSS to the path MTU for traffic leaving through this zone.
    pub mss_clamp: bool,
}

/// Allow forwarding from one zone to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarding {
    pub src: ZoneName,
    pub dst: ZoneName,
}

/// A user traffic rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    /// Source zone; `None` = any interface.
    pub src: Option<ZoneName>,
    /// Destination zone; `None` = this device (input).
    pub dst: Option<ZoneName>,
    pub family: Family,
    pub proto: Proto,
    pub src_ip: Option<ipnet::IpNet>,
    pub dst_ip: Option<ipnet::IpNet>,
    pub dst_port: Option<PortRange>,
    pub action: Policy,
    pub enabled: bool,
}

/// Port forward (DNAT) from a zone to an internal IPv4 host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redirect {
    pub name: String,
    pub src: ZoneName,
    /// Must be `Tcp`, `Udp` or `TcpUdp`.
    pub proto: Proto,
    pub src_dport: PortRange,
    pub dest_ip: Ipv4Addr,
    pub dest_port: u16,
    pub enabled: bool,
}

/// Flow offloading mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowOffload {
    #[default]
    Off,
    Software,
    Hardware,
}

/// Global options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub flow_offload: FlowOffload,
    /// Netdevs attached to the flowtable (required unless `flow_offload` is `Off`).
    pub offload_devices: Vec<String>,
    pub drop_invalid: bool,
    /// Rate-limit new TCP connections to the device.
    pub syn_flood_protect: bool,
    /// Name of the dedicated `inet` table.
    pub table_name: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            flow_offload: FlowOffload::Off,
            offload_devices: Vec::new(),
            drop_invalid: true,
            syn_flood_protect: false,
            table_name: "owr".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests;

/// The complete firewall configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ruleset {
    pub zones: Vec<Zone>,
    pub forwardings: Vec<Forwarding>,
    pub rules: Vec<Rule>,
    pub redirects: Vec<Redirect>,
    pub options: Options,
}
