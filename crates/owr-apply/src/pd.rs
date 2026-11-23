//! A delegated prefix on the LAN-side bridges: which /64 goes where, the router's address
//! on it, and what the router advertisements on each link are told. Pure.
//!
//! The assignment follows the ULA one: `br-lan` is subnet 0 of the delegation and a VLAN
//! bridge is the subnet that equals its VLAN id, so an address never depends on the order of
//! the config. A delegation too small for a bridge's subnet leaves that bridge without a
//! global prefix (the ULA, if any, keeps working).

use std::net::Ipv6Addr;
use std::time::Duration;

use ipnet::{IpNet, Ipv6Net};
use owr_net::dhcp6::Lease6;
use owr_net::ra::{RaDynamic, RaPrefix};
use owr_net::{AddrSpec, NetPlan};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

/// Length of every subnet cut from a delegated prefix (what SLAAC needs).
pub const PD_SUBNET_LEN: u8 = 64;

/// A LAN-side bridge that takes a subnet of the delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdLink {
    pub link: String,
    /// Index of the /64 within the delegation.
    pub subnet: u16,
}

/// One bridge's share of a delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdAssignment {
    pub link: String,
    pub net: Ipv6Net,
    /// The router's address on the subnet: `<net>::1`.
    pub router: Ipv6Addr,
    pub preferred_secs: u32,
    pub valid_secs: u32,
}

/// The /64s of `lease` for `links`; a link whose subnet is not inside the delegation gets
/// none. In link order.
pub fn assign(lease: &Lease6, links: &[PdLink]) -> Vec<PdAssignment> {
    let wanted = links
        .iter()
        .map(|l| usize::from(l.subnet))
        .max()
        .map_or(0, |m| m.saturating_add(1));
    let mut subnets: Vec<(Ipv6Net, u32, u32)> = Vec::new();
    'outer: for p in &lease.prefixes {
        let Ok(cut) = p.prefix.subnets(PD_SUBNET_LEN) else {
            continue;
        };
        for net in cut {
            if subnets.len() >= wanted {
                break 'outer;
            }
            subnets.push((net, p.preferred_secs, p.valid_secs));
        }
    }
    links
        .iter()
        .filter_map(|l| {
            let (net, preferred_secs, valid_secs) = *subnets.get(usize::from(l.subnet))?;
            let router = Ipv6Addr::from(u128::from(net.network()).saturating_add(1));
            Some(PdAssignment {
                link: l.link.clone(),
                net,
                router,
                preferred_secs,
                valid_secs,
            })
        })
        .collect()
}

/// `plan` with the router's address on every assigned subnet added (the single-writer
/// hand-off, like the `DHCPv4` lease).
pub fn merge_lease6(plan: &NetPlan, lease: &Lease6, links: &[PdLink]) -> NetPlan {
    let mut merged = plan.clone();
    for a in assign(lease, links) {
        if let Ok(addr) = Ipv6Net::new(a.router, PD_SUBNET_LEN) {
            merged.addresses.push(AddrSpec {
                link: a.link,
                addr: IpNet::V6(addr),
            });
        }
    }
    merged
}

/// What the advertisements on `link` are told while the delegation holds: its /64 with the
/// lifetimes left `elapsed` after the lease was granted, and the router's address on it for
/// RDNSS. No prefix when `link` has no share.
pub fn ra_dynamic(link: &str, assignments: &[PdAssignment], elapsed: Duration) -> RaDynamic {
    let as_of = Instant::now()
        .checked_sub(elapsed)
        .unwrap_or_else(Instant::now);
    let mine: Vec<&PdAssignment> = assignments.iter().filter(|a| a.link == link).collect();
    RaDynamic {
        prefixes: mine
            .iter()
            .map(|a| RaPrefix {
                prefix: a.net,
                valid: Duration::from_secs(u64::from(a.valid_secs)),
                preferred: Duration::from_secs(u64::from(a.preferred_secs)),
            })
            .collect(),
        dns: mine.iter().map(|a| a.router).collect(),
        as_of,
    }
}

/// Whether going from `old` to `new` changes what hosts should hear: the prefixes, the DNS
/// servers or whether there is an uplink at all. A renewal only moves the lifetimes (they are
/// stored without waking the sender), so it does not restart the advertisement schedule.
pub fn needs_advertising(old: &RaDynamic, new: &RaDynamic) -> bool {
    let nets = |d: &RaDynamic| d.prefixes.iter().map(|p| p.prefix).collect::<Vec<_>>();
    let live = |d: &RaDynamic| d.prefixes.iter().any(|p| !p.valid.is_zero());
    nets(old) != nets(new) || old.dns != new.dns || live(old) != live(new)
}

/// What the advertisements on `link` are told when the delegation is gone: the prefixes it had
/// are named once more with lifetimes of zero, so hosts deprecate their addresses.
pub fn ra_withdrawn(link: &str, previous: &[PdAssignment]) -> RaDynamic {
    RaDynamic {
        prefixes: previous
            .iter()
            .filter(|a| a.link == link)
            .map(|a| RaPrefix {
                prefix: a.net,
                valid: Duration::ZERO,
                preferred: Duration::ZERO,
            })
            .collect(),
        dns: Vec::new(),
        as_of: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use owr_net::dhcp6::DelegatedPrefix;

    use super::*;

    fn lease(prefixes: &[(&str, u32, u32)]) -> Lease6 {
        Lease6 {
            prefixes: prefixes
                .iter()
                .map(|(p, preferred, valid)| DelegatedPrefix {
                    prefix: p.parse().unwrap(),
                    preferred_secs: *preferred,
                    valid_secs: *valid,
                })
                .collect(),
            dns: Vec::new(),
            t1: 50,
            t2: 80,
            server_id: vec![1],
            obtained_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn link(name: &str, subnet: u16) -> PdLink {
        PdLink {
            link: name.to_owned(),
            subnet,
        }
    }

    fn nets(a: &[PdAssignment]) -> Vec<(String, String, String)> {
        a.iter()
            .map(|a| (a.link.clone(), a.net.to_string(), a.router.to_string()))
            .collect()
    }

    #[test]
    fn the_lan_is_subnet_zero_and_a_vlan_is_the_subnet_of_its_id() {
        let got = assign(
            &lease(&[("2001:db8:1::/56", 100, 200)]),
            &[link("br-lan", 0), link("br-iot", 5), link("br-guest", 20)],
        );
        assert_eq!(
            nets(&got),
            [
                (
                    "br-lan".into(),
                    "2001:db8:1::/64".into(),
                    "2001:db8:1::1".into()
                ),
                (
                    "br-iot".into(),
                    "2001:db8:1:5::/64".into(),
                    "2001:db8:1:5::1".into()
                ),
                (
                    "br-guest".into(),
                    "2001:db8:1:14::/64".into(),
                    "2001:db8:1:14::1".into()
                ),
            ]
        );
        assert!(
            got.iter()
                .all(|a| (a.preferred_secs, a.valid_secs) == (100, 200))
        );
    }

    #[test]
    fn a_delegation_that_is_too_small_serves_only_the_bridges_that_fit() {
        // a /62 holds four /64s: subnets 0..=3
        let got = assign(
            &lease(&[("2001:db8:1::/62", 1, 2)]),
            &[
                link("br-lan", 0),
                link("br-a", 3),
                link("br-b", 4),
                link("br-c", 100),
            ],
        );
        assert_eq!(
            got.iter().map(|a| a.link.as_str()).collect::<Vec<_>>(),
            ["br-lan", "br-a"]
        );
        // a /64 serves the LAN alone
        let one = assign(
            &lease(&[("2001:db8:1::/64", 1, 2)]),
            &[link("br-lan", 0), link("br-a", 1)],
        );
        assert_eq!(nets(&one).len(), 1);
    }

    #[test]
    fn several_delegated_prefixes_continue_one_another_with_their_own_lifetimes() {
        let got = assign(
            &lease(&[("2001:db8:1::/63", 10, 20), ("2001:db8:9::/64", 30, 40)]),
            &[link("br-lan", 0), link("br-a", 1), link("br-b", 2)],
        );
        assert_eq!(
            nets(&got).iter().map(|n| n.1.as_str()).collect::<Vec<_>>(),
            ["2001:db8:1::/64", "2001:db8:1:1::/64", "2001:db8:9::/64"]
        );
        assert_eq!(
            got.get(2).map(|a| (a.preferred_secs, a.valid_secs)),
            Some((30, 40))
        );
    }

    #[test]
    fn no_links_or_no_prefixes_assign_nothing() {
        assert_eq!(assign(&lease(&[("2001:db8:1::/56", 1, 2)]), &[]).len(), 0);
        assert_eq!(assign(&lease(&[]), &[link("br-lan", 0)]).len(), 0);
    }

    #[test]
    fn the_merged_plan_has_the_routers_address_on_each_subnet() {
        let plan = NetPlan::default();
        let merged = merge_lease6(
            &plan,
            &lease(&[("2001:db8:1::/56", 1, 2)]),
            &[link("br-lan", 0), link("br-iot", 5)],
        );
        let got: Vec<(String, String)> = merged
            .addresses
            .iter()
            .map(|a| (a.link.clone(), a.addr.to_string()))
            .collect();
        assert_eq!(
            got,
            [
                ("br-lan".into(), "2001:db8:1::1/64".into()),
                ("br-iot".into(), "2001:db8:1:5::1/64".into())
            ]
        );
        assert_eq!(plan, NetPlan::default(), "the original plan is untouched");
    }

    #[tokio::test(start_paused = true)]
    async fn the_advertisement_state_of_a_link_is_its_share_with_the_time_already_gone() {
        let assignments = assign(
            &lease(&[("2001:db8:1::/56", 100, 200)]),
            &[link("br-lan", 0), link("br-iot", 5)],
        );
        let d = ra_dynamic("br-iot", &assignments, Duration::from_secs(30));
        assert_eq!(d.prefixes.len(), 1);
        assert_eq!(d.prefixes[0].prefix, "2001:db8:1:5::/64".parse().unwrap());
        assert_eq!(d.dns, vec!["2001:db8:1:5::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(
            Instant::now().duration_since(d.as_of),
            Duration::from_secs(30)
        );
        // a link without a share gets nothing
        let none = ra_dynamic("br-other", &assignments, Duration::ZERO);
        assert!(none.prefixes.is_empty() && none.dns.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_renewal_is_not_news_but_a_new_prefix_or_the_loss_of_it_is() {
        let one = assign(
            &lease(&[("2001:db8:1::/56", 100, 200)]),
            &[link("br-lan", 0)],
        );
        let before = ra_dynamic("br-lan", &one, Duration::ZERO);
        let renewed = ra_dynamic("br-lan", &one, Duration::from_secs(50));
        assert!(!needs_advertising(&before, &renewed));
        let other = assign(
            &lease(&[("2001:db8:7::/56", 100, 200)]),
            &[link("br-lan", 0)],
        );
        assert!(needs_advertising(
            &before,
            &ra_dynamic("br-lan", &other, Duration::ZERO)
        ));
        assert!(needs_advertising(&before, &ra_withdrawn("br-lan", &one)));
        assert!(needs_advertising(&RaDynamic::none(), &before));
        assert!(!needs_advertising(&RaDynamic::none(), &RaDynamic::none()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_withdrawn_delegation_is_named_with_lifetimes_of_zero() {
        let assignments = assign(
            &lease(&[("2001:db8:1::/56", 100, 200)]),
            &[link("br-lan", 0)],
        );
        let d = ra_withdrawn("br-lan", &assignments);
        assert_eq!(d.prefixes.len(), 1);
        assert_eq!(
            (d.prefixes[0].valid, d.prefixes[0].preferred),
            (Duration::ZERO, Duration::ZERO)
        );
        assert_eq!(d.dns.len(), 0);
        assert_eq!(ra_withdrawn("br-other", &assignments).prefixes.len(), 0);
    }
}
