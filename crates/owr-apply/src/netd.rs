//! What the network daemon (`owr-apply netd`, service `owr-netd`) runs: the WAN `DHCPv4`
//! client and the IPv6 router advertisements of the LAN-side bridges.
//!
//! The plan is written to `<run_dir>/netd.json` with the other daemon files (see `files`),
//! so that a config change that changes it restarts the daemon, and so that what the
//! daemon runs can be read on the router. The daemon derives the same plan from the config.

use ipnet::IpNet;
use owr_net::ra::{RaSpec, SLAAC_PREFIX_LEN};
use owr_net::{DhcpClientSpec, NetPlan};
use serde::Serialize;

/// The daemon's work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetdPlan {
    /// The `DHCPv4` client of a DHCP WAN.
    pub dhcp: Option<DhcpClientSpec>,
    /// One router advertisement per LAN-side link with an IPv6 /64.
    pub ra: Vec<RaSpec>,
}

/// Every link but the WAN that has an IPv6 /64 in `net` (today: the ULA subnets of the LAN
/// and VLAN bridges) is advertised with that prefix, and with the router's own address on
/// it as DNS server (dnsmasq listens on every address of these bridges). The first /64 of
/// a link wins.
pub(crate) fn build_netd(net: &NetPlan, wan_dev: &str) -> NetdPlan {
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
            prefix: addr.trunc(),
            dns: vec![addr.addr()],
        });
    }
    NetdPlan {
        dhcp: net.dhcp_clients.first().cloned(),
        ra,
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
        let plan = build_netd(&net, "eth1");
        assert_eq!(plan.dhcp, None);
        let got: Vec<(&str, String, Vec<String>)> = plan
            .ra
            .iter()
            .map(|s| {
                (
                    s.link.as_str(),
                    s.prefix.to_string(),
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
}
