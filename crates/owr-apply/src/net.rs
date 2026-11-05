//! `Config` -> [`NetPlan`], plus the sysctl baseline.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use owr_board::Board;
use owr_config::{Config, LanIpv6, WanIpv6, WanProto};
use owr_net::dhcp::dhcp_link_sysctls;
use owr_net::model::TABLE_MAIN;
use owr_net::{AddrSpec, DhcpClientSpec, LinkSpec, MacAddr, NetPlan, RouteProto, RouteSpec};

use crate::error::MapError;
use crate::pppoe;
use crate::topology::{LAN_BRIDGE, Topology};

/// Prefix length of every ULA subnet handed to a bridge.
const ULA_SUBNET_PREFIX: u8 = 64;

/// Metric of the WAN default route (static or DHCP).
const WAN_METRIC: u32 = 10;

/// Sysctls that do not depend on the config. Forwarding keys are added by [`sysctls`].
pub(crate) const FIXED_SYSCTLS: &[(&str, &str)] = &[
    ("net.ipv4.conf.all.rp_filter", "1"),
    ("net.ipv4.conf.default.rp_filter", "1"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv6.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.conf.all.log_martians", "0"),
    ("kernel.kptr_restrict", "2"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.unprivileged_bpf_disabled", "1"),
    ("net.core.bpf_jit_harden", "2"),
    ("fs.protected_symlinks", "1"),
    ("fs.protected_hardlinks", "1"),
    ("kernel.yama.ptrace_scope", "1"),
];

/// The forwarding switches. They are applied by their own step, only once a firewall with
/// `policy drop` on forward is loaded (see `steps`).
const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";
pub(crate) const FORWARDING_KEYS: [&str; 2] = [IPV4_FORWARD, IPV6_FORWARD];

/// Whether any IPv6 feature is switched on (decides `net.ipv6.conf.all.forwarding`).
pub(crate) fn ipv6_enabled(cfg: &Config) -> bool {
    cfg.network.lan.ipv6 == LanIpv6::Ula || cfg.network.wan.ipv6 == WanIpv6::Dhcpv6
}

/// The full sysctl list: forwarding first, then [`FIXED_SYSCTLS`].
pub(crate) fn sysctls(ipv6: bool) -> Vec<(String, String)> {
    [
        (IPV4_FORWARD, "1"),
        (IPV6_FORWARD, if ipv6 { "1" } else { "0" }),
    ]
    .iter()
    .chain(FIXED_SYSCTLS)
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

fn physical(name: &str, mtu: Option<u16>, mac: Option<owr_config::MacAddr>) -> LinkSpec {
    LinkSpec::Physical {
        name: name.to_owned(),
        up: true,
        mtu: mtu.map(u32::from),
        mac: mac.map(|m| MacAddr(m.0)),
    }
}

/// Address `<prefix>::1/64` for subnet `subnet` of the /48 `prefix` (`subnet` 0 is the LAN,
/// a VLAN uses its VLAN id).
fn ula_addr(prefix: Ipv6Net, subnet: u16) -> Result<IpNet, MapError> {
    let [a, b, c, ..] = prefix.network().segments();
    let addr = Ipv6Addr::new(a, b, c, subnet, 0, 0, 0, 1);
    Ipv6Net::new(addr, ULA_SUBNET_PREFIX)
        .map(IpNet::V6)
        .map_err(|_| MapError::Unsupported("ULA subnet prefix length"))
}

/// The ULA prefix to use: only when the config asks for ULA, with a warning when it does but
/// no prefix is available.
fn active_ula(
    cfg: &Config,
    prefix: Option<Ipv6Net>,
    warnings: &mut Vec<String>,
) -> Option<Ipv6Net> {
    if cfg.network.lan.ipv6 != LanIpv6::Ula {
        return None;
    }
    if prefix.is_none() {
        warnings.push(
            "network.lan.ipv6 = ula but no ULA prefix is available; no IPv6 address planned"
                .to_owned(),
        );
    }
    prefix
}

pub(crate) fn build_net(
    board: &Board,
    cfg: &Config,
    topo: &Topology<'_>,
    sysctls: &[(String, String)],
    ula_prefix: Option<Ipv6Net>,
    warnings: &mut Vec<String>,
) -> Result<NetPlan, MapError> {
    let net = &cfg.network;
    let mut plan = NetPlan {
        sysctls: sysctls.to_vec(),
        ..NetPlan::default()
    };

    // On PPPoE the configured MTU is pppd's; the port only grows when the PPP frames do
    // not fit its default 1500.
    let wan_port_mtu = match net.wan.proto {
        WanProto::Pppoe { .. } => pppoe::port_mtu(net.wan.mtu.unwrap_or(pppoe::DEFAULT_MTU)),
        WanProto::Dhcp { .. } | WanProto::Static { .. } => net.wan.mtu,
    };

    // Every board port, so DSA user ports are up even when unused.
    for port in &board.ethernet.ports {
        plan.links.push(if port.netdev == topo.wan_dev {
            physical(&port.netdev, wan_port_mtu, net.wan.mac_override)
        } else {
            physical(&port.netdev, None, None)
        });
    }

    plan.links.push(LinkSpec::Bridge {
        name: LAN_BRIDGE.to_owned(),
        ports: topo.lan_devs.iter().map(|d| (*d).to_owned()).collect(),
        vlan_filtering: false,
        mtu: None,
        mac: None,
    });
    plan.addresses.push(AddrSpec {
        link: LAN_BRIDGE.to_owned(),
        addr: IpNet::V4(net.lan.ipv4),
    });

    // ULA: br-lan gets subnet 0 of the site prefix, each VLAN bridge its VLAN id.
    let ula = active_ula(cfg, ula_prefix, warnings);
    if let Some(prefix) = ula {
        plan.addresses.push(AddrSpec {
            link: LAN_BRIDGE.to_owned(),
            addr: ula_addr(prefix, 0)?,
        });
    }

    for vlan in &topo.vlans {
        plan.links.push(LinkSpec::Bridge {
            name: vlan.bridge.clone(),
            ports: vlan.members.iter().map(|(_, dev)| dev.clone()).collect(),
            vlan_filtering: false,
            mtu: None,
            mac: None,
        });
        for (parent, dev) in &vlan.members {
            plan.links.push(LinkSpec::Vlan {
                name: dev.clone(),
                parent: (*parent).to_owned(),
                id: vlan.cfg.id,
            });
        }
        if let Some(addr) = vlan.cfg.ipv4 {
            plan.addresses.push(AddrSpec {
                link: vlan.bridge.clone(),
                addr: IpNet::V4(addr),
            });
        }
        if let Some(prefix) = ula {
            plan.addresses.push(AddrSpec {
                link: vlan.bridge.clone(),
                addr: ula_addr(prefix, vlan.cfg.id)?,
            });
        }
    }

    match &net.wan.proto {
        WanProto::Dhcp { hostname } => {
            plan.dhcp_clients.push(DhcpClientSpec {
                link: topo.wan_dev.to_owned(),
                hostname: Some(
                    hostname
                        .clone()
                        .unwrap_or_else(|| cfg.system.hostname.clone()),
                ),
                vendor_class: None,
                request_dns: true,
                default_route_metric: WAN_METRIC,
            });
            // Loose rp_filter on the WAN so the DHCP server reply is not dropped.
            plan.sysctls.extend(dhcp_link_sysctls(topo.wan_dev));
        }
        WanProto::Static { ipv4, gateway, .. } => {
            plan.addresses.push(AddrSpec {
                link: topo.wan_dev.to_owned(),
                addr: IpNet::V4(*ipv4),
            });
            plan.routes.push(RouteSpec {
                dest: IpNet::V4(Ipv4Net::default()),
                via: Some(IpAddr::V4(*gateway)),
                dev: Some(topo.wan_dev.to_owned()),
                metric: WAN_METRIC,
                table: TABLE_MAIN,
                proto: RouteProto::Static,
            });
        }
        // pppd configures its own interface (address, default route); the port only
        // carries the PPPoE frames and gets no address.
        WanProto::Pppoe { .. } => {}
    }
    if net.wan.ipv6 == WanIpv6::Dhcpv6 {
        tracing::warn!("network.wan.ipv6 = dhcpv6 is not implemented yet and is ignored");
    }
    Ok(plan)
}
