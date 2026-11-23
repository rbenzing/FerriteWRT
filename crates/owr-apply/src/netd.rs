//! What the network daemon (`owr-apply netd`, service `owr-netd`) runs: the WAN `DHCPv4`
//! client and the IPv6 router advertisements of the LAN-side bridges.
//!
//! The plan is written to `<run_dir>/netd.json` with the other daemon files (see `files`),
//! so that a config change that changes it restarts the daemon, and so that what the
//! daemon runs can be read on the router. The daemon derives the same plan from the config.

use ipnet::IpNet;
use owr_net::dhcp6::Dhcp6ClientSpec;
use owr_net::ra::{RaSpec, SLAAC_PREFIX_LEN};
use owr_net::{DhcpClientSpec, NetPlan};
use serde::Serialize;

use crate::pd::PdLink;

/// The daemon's work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetdPlan {
    /// The `DHCPv4` client of a DHCP WAN.
    pub dhcp: Option<DhcpClientSpec>,
    /// The `DHCPv6` prefix-delegation client of a WAN with IPv6.
    pub dhcp6: Option<Dhcp6ClientSpec>,
    /// One router advertisement per LAN-side link with an IPv6 /64, and with a `DHCPv6` client
    /// one for every bridge that takes part of the delegated prefix.
    pub ra: Vec<RaSpec>,
    /// The bridges that take a /64 of the delegated prefix (empty without a `DHCPv6` client).
    pub pd_links: Vec<PdLink>,
}

/// Every link but the WAN that has an IPv6 /64 in `net` (today: the ULA subnets of the LAN
/// and VLAN bridges) is advertised with that prefix, and with the router's own address on
/// it as DNS server (dnsmasq listens on every address of these bridges). The first /64 of
/// a link wins.
pub(crate) fn build_netd(
    net: &NetPlan,
    wan_dev: &str,
    dhcp6: Option<Dhcp6ClientSpec>,
    pd_links: Vec<PdLink>,
) -> NetdPlan {
    let mut ra: Vec<RaSpec> = Vec::new();
    for a in &net.addresses {
        let IpNet::V6(addr) = a.addr else {
            continue;
        };
        if a.link == wan_dev
            || addr.prefix_len() != SLAAC_PREFIX_LEN
            || addr.addr().is_unicast_link_local()
            || ra.iter().any(|s| s.link == a.link)
        {
            continue;
        }
        ra.push(RaSpec {
            link: a.link.clone(),
            prefix: Some(addr.trunc()),
            dns: vec![addr.addr()],
        });
    }
    // With WAN IPv6 every bridge that takes a share is advertised, ULA or not: its hosts get
    // the delegated prefix.
    let pd_links = if dhcp6.is_some() {
        pd_links
    } else {
        Vec::new()
    };
    for l in &pd_links {
        if !ra.iter().any(|s| s.link == l.link) {
            ra.push(RaSpec {
                link: l.link.clone(),
                prefix: None,
                dns: Vec::new(),
            });
        }
    }
    NetdPlan {
        dhcp: net.dhcp_clients.first().cloned(),
        dhcp6,
        ra,
        pd_links,
    }
}

#[cfg(test)]
mod tests {
    use owr_net::AddrSpec;

    use super::*;

    fn addr(link: &str, a: &str) -> AddrSpec {
        AddrSpec {
            link: link.to_owned(),
            addr: a.parse().unwrap(),
        }
    }

    #[test]
    fn only_lan_side_slaac_prefixes_are_advertised_once_per_link() {
        let net = NetPlan {
            addresses: vec![
                addr("br-lan", "192.168.8.1/24"),
                addr("br-lan", "fd00:1:2::1/64"),
                addr("br-lan", "fd00:1:2:9::1/64"),
                addr("br-guest", "fd00:1:2:a::1/64"),
                addr("br-iot", "fd00:1:2:b::1/56"),
                addr("br-ll", "fe80::1/64"),
                addr("eth1", "2001:db8::2/64"),
            ],
            ..NetPlan::default()
        };
        let plan = build_netd(&net, "eth1", None, Vec::new());
        assert_eq!(plan.dhcp, None);
        let got: Vec<(&str, String, Vec<String>)> = plan
            .ra
            .iter()
            .map(|s| {
                (
                    s.link.as_str(),
                    s.prefix.map_or_else(String::new, |p| p.to_string()),
                    s.dns.iter().map(ToString::to_string).collect(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "br-lan",
                    "fd00:1:2::/64".to_owned(),
                    vec!["fd00:1:2::1".to_owned()]
                ),
                (
                    "br-guest",
                    "fd00:1:2:a::/64".to_owned(),
                    vec!["fd00:1:2:a::1".to_owned()]
                ),
            ]
        );
        assert!(plan.ra.iter().all(|s| s.validate().is_ok()));
    }

    fn pd(link: &str, subnet: u16) -> PdLink {
        PdLink {
            link: link.to_owned(),
            subnet,
        }
    }

    fn client() -> Dhcp6ClientSpec {
        Dhcp6ClientSpec {
            link: "eth1".to_owned(),
            identity_link: "eth1".to_owned(),
            prefix_len_hint: None,
        }
    }

    #[test]
    fn with_a_prefix_delegation_client_every_bridge_with_a_share_is_advertised() {
        // br-lan has a ULA, br-iot does not: it is advertised with the delegated prefix only.
        let net = NetPlan {
            addresses: vec![addr("br-lan", "fd00:1:2::1/64")],
            ..NetPlan::default()
        };
        let plan = build_netd(
            &net,
            "eth1",
            Some(client()),
            vec![pd("br-lan", 0), pd("br-iot", 5)],
        );
        assert_eq!(plan.dhcp6, Some(client()));
        let got: Vec<(&str, Option<String>)> = plan
            .ra
            .iter()
            .map(|s| (s.link.as_str(), s.prefix.map(|p| p.to_string())))
            .collect();
        assert_eq!(
            got,
            [
                ("br-lan", Some("fd00:1:2::/64".to_owned())),
                ("br-iot", None)
            ]
        );
        assert_eq!(plan.pd_links.len(), 2);
        assert!(plan.ra.iter().all(|s| s.validate().is_ok()));
    }

    #[test]
    fn without_a_prefix_delegation_client_nothing_about_it_is_planned() {
        let plan = build_netd(&NetPlan::default(), "eth1", None, vec![pd("br-lan", 0)]);
        assert_eq!(plan, NetdPlan::default());
    }
}
