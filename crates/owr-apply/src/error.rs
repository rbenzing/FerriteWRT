//! The error type of the pure mapping (`(Board, Config)` to plans and daemon configs).

use std::fmt::Display;

use ipnet::Ipv4Net;

fn join<T: Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Why a configuration cannot be mapped onto the domain plans.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapError {
    #[error("unknown board port {0:?}")]
    UnknownPort(String),
    #[error("unknown radio {0:?}")]
    UnknownRadio(String),
    #[error("unknown network {0:?} (expected \"lan\" or a VLAN name)")]
    UnknownNetwork(String),
    #[error("radio {radio}: width {width} MHz exceeds the board maximum of {max} MHz")]
    WidthExceedsBoard { radio: String, width: u16, max: u16 },
    #[error(
        "{network}: DHCP pool (start {start}, limit {limit}) does not fit {subnet}; \
         it must stay inside the subnet and exclude the router address"
    )]
    DhcpRangeOutOfSubnet {
        network: String,
        subnet: Ipv4Net,
        start: u16,
        limit: u16,
    },
    #[error("invalid firewall zone name {0:?}: must match [a-z0-9_]{{1,15}}")]
    InvalidZoneName(String),
    /// A documented gap, e.g. `PPPoE` (phase 2).
    #[error("{0} is not supported yet")]
    Unsupported(&'static str),
    /// `field` holds characters that could inject extra directives into a daemon config
    /// (newline, comma, whitespace, ...). `value_redacted` is always `true`: the offending
    /// value is never echoed because it may be an attacker-controlled log payload.
    #[error("{field} contains characters that are not allowed in daemon configuration")]
    Injection { field: String, value_redacted: bool },
    /// `field` is a hostname that dnsmasq would parse as something else in a `dhcp-host` line
    /// (digits only, a lease time such as `12h`, `ignore`, `infinite`).
    #[error("{field} is a reserved word in dnsmasq host entries")]
    ReservedName { field: String },
    #[error("firewall plan is invalid: {}", join(.0))]
    Fw(Vec<owr_fw::Issue>),
    #[error("wifi plan is invalid: {}", join(.0))]
    Wifi(Vec<owr_wifi::Issue>),
    #[error("network plan is invalid: {0}")]
    Net(#[from] owr_net::ValidationError),
}

impl MapError {
    pub(crate) fn injection(field: impl Into<String>) -> Self {
        Self::Injection {
            field: field.into(),
            value_redacted: true,
        }
    }
}
