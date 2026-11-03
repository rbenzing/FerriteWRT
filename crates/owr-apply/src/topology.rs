//! Board ports resolved to netdev names once, shared by the net, firewall and dnsmasq mappers.

use owr_board::Board;
use owr_config::{Config, VlanConfig};

use crate::error::MapError;

/// The LAN bridge. Fixed: the firewall `lan` zone, dnsmasq and hostapd all refer to it.
pub(crate) const LAN_BRIDGE: &str = "br-lan";

/// Bridge name of a VLAN network.
pub(crate) fn vlan_bridge(name: &str) -> String {
    format!("br-{name}")
}

pub(crate) struct VlanTopo<'a> {
    pub(crate) cfg: &'a VlanConfig,
    pub(crate) bridge: String,
    /// `(parent port netdev, tagged sub-interface)`, in config order.
    pub(crate) members: Vec<(&'a str, String)>,
}

pub(crate) struct Topology<'a> {
    pub(crate) wan_dev: &'a str,
    pub(crate) lan_devs: Vec<&'a str>,
    pub(crate) vlans: Vec<VlanTopo<'a>>,
}

fn netdev<'a>(board: &'a Board, port: &str) -> Result<&'a str, MapError> {
    board
        .port(port)
        .map(|p| p.netdev.as_str())
        .ok_or_else(|| MapError::UnknownPort(port.to_owned()))
}

impl<'a> Topology<'a> {
    pub(crate) fn resolve(board: &'a Board, cfg: &'a Config) -> Result<Self, MapError> {
        let net = &cfg.network;
        let wan_dev = netdev(board, &net.wan.port)?;
        let lan_devs = net
            .lan
            .ports
            .iter()
            .map(|p| netdev(board, p))
            .collect::<Result<Vec<_>, _>>()?;
        let vlans = net
            .vlans
            .iter()
            .map(|v| {
                let members = v
                    .ports
                    .iter()
                    .map(|p| netdev(board, p).map(|dev| (dev, format!("{dev}.{}", v.id))))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(VlanTopo {
                    cfg: v,
                    bridge: vlan_bridge(&v.name),
                    members,
                })
            })
            .collect::<Result<Vec<_>, MapError>>()?;
        Ok(Self {
            wan_dev,
            lan_devs,
            vlans,
        })
    }

    /// Every tagged sub-interface of every VLAN.
    pub(crate) fn vlan_netdevs(&self) -> impl Iterator<Item = &str> {
        self.vlans
            .iter()
            .flat_map(|v| v.members.iter().map(|(_, dev)| dev.as_str()))
    }
}
