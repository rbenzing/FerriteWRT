//! Planner behaviour tests driven by a tiny in-memory kernel simulator.
//!
//! The simulator applies [`Action`]s to an [`Observed`] and asserts the same
//! preconditions the real kernel enforces (link must exist, MAC changes need the
//! link down, ...), so ordering bugs fail here. The central property is
//! `plan(desired, apply(plan(desired, observed))) == []`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::assert_is_empty,
    clippy::explicit_counter_loop
)]

use std::time::SystemTime;

use ipnet::IpNet;
use owr_net::dhcp::{Lease, merge_lease};
use owr_net::model::{TABLE_MAIN, sysctl_iface, sysctl_path};
use owr_net::wire::{Message, MessageType, Op};
use owr_net::{
    Action, AddrSpec, DhcpClientSpec, LinkKind, LinkSpec, MacAddr, NetPlan, Observed, ObservedLink,
    PlanError, RouteProto, RouteSpec, plan,
};
use proptest::prelude::*;

// ---------------------------------------------------------------- simulator

fn link<'a>(o: &'a mut Observed, name: &str) -> &'a mut ObservedLink {
    o.links
        .iter_mut()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("simulator: no such link {name}"))
}

fn index_of(o: &Observed, name: &str) -> u32 {
    o.links
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("simulator: no such link {name}"))
        .index
}

fn connected(link: &str, addr: IpNet) -> RouteSpec {
    RouteSpec {
        dest: addr.trunc(),
        via: None,
        dev: Some(link.to_owned()),
        metric: 0,
        table: TABLE_MAIN,
        proto: RouteProto::Kernel,
    }
}

fn remove_link(o: &mut Observed, name: &str) {
    let idx = index_of(o, name);
    let children: Vec<String> = o
        .links
        .iter()
        .filter(|l| matches!(l.kind, LinkKind::Vlan { parent_index, .. } if parent_index == idx))
        .map(|l| l.name.clone())
        .collect();
    for c in children {
        remove_link(o, &c);
    }
    o.links.retain(|l| l.name != name);
    for l in &mut o.links {
        if l.master == Some(idx) {
            l.master = None;
        }
    }
    o.addresses.retain(|a| a.link != name);
    o.routes.retain(|r| r.dev.as_deref() != Some(name));
    // the link's /proc/sys/net/*/conf/<name>/ directory goes with it
    o.sysctls
        .retain(|(k, _)| sysctl_iface(&sysctl_path(k).unwrap()) != Some(name));
}

/// Apply `actions` the way the kernel would, asserting preconditions. Requests the
/// kernel refuses with an errno (rather than a bug in the plan's ordering) are
/// returned instead of panicking.
fn apply(o: &mut Observed, actions: &[Action]) -> Vec<(Action, &'static str)> {
    let mut failed = Vec::new();
    for a in actions {
        match a {
            Action::CreateBridge {
                name,
                vlan_filtering,
            } => {
                assert!(o.links.iter().all(|l| l.name != *name), "{name} exists");
                let idx = o.links.iter().map(|l| l.index).max().unwrap_or(0) + 1;
                let mut l = ObservedLink::new(idx, name, LinkKind::Bridge);
                l.vlan_filtering = Some(*vlan_filtering);
                l.mac = Some(MacAddr([2, 0, 0, 0, 0, u8::try_from(idx).unwrap()]));
                o.links.push(l);
            }
            Action::CreateVlan { name, parent, id } => {
                assert!(o.links.iter().all(|l| l.name != *name), "{name} exists");
                let parent_index = index_of(o, parent);
                let idx = o.links.iter().map(|l| l.index).max().unwrap_or(0) + 1;
                o.links.push(ObservedLink::new(
                    idx,
                    name,
                    LinkKind::Vlan {
                        parent_index,
                        id: *id,
                    },
                ));
            }
            Action::DeleteLink { name } => remove_link(o, name),
            Action::SetMaster { link: l, master } => {
                let m = master.as_deref().map(|m| index_of(o, m));
                link(o, l).master = m;
            }
            Action::SetAlias { link: l, alias } => link(o, l).alias = Some(alias.clone()),
            Action::SetUp { link: l } => {
                let up = link(o, l);
                up.up = true;
                up.carrier = true;
                // the kernel installs the connected routes of the link's addresses
                let connected_routes: Vec<RouteSpec> = o
                    .addresses
                    .iter()
                    .filter(|a| a.link == *l && a.addr.addr().is_ipv4() && a.addr.prefix_len() < 32)
                    .map(|a| connected(l, a.addr))
                    .collect();
                for r in connected_routes {
                    if !o.routes.contains(&r) {
                        o.routes.push(r);
                    }
                }
            }
            Action::SetDown { link: l } => {
                let down = link(o, l);
                down.up = false;
                down.carrier = false;
                // taking a link down flushes its routes; addresses survive
                o.routes.retain(|r| r.dev.as_deref() != Some(l.as_str()));
            }
            Action::SetMtu { link: l, mtu } => link(o, l).mtu = *mtu,
            Action::SetMac { link: l, mac } => {
                let l = link(o, l);
                assert!(!l.up, "MAC change on up link {}", l.name);
                l.mac = Some(*mac);
            }
            Action::SetVlanFiltering { link: l, enabled } => {
                let l = link(o, l);
                assert_eq!(l.kind, LinkKind::Bridge);
                l.vlan_filtering = Some(*enabled);
            }
            Action::AddAddr { link: l, addr } => {
                index_of(o, l);
                let spec = AddrSpec {
                    link: l.clone(),
                    addr: *addr,
                };
                if !o.addresses.contains(&spec) {
                    o.addresses.push(spec);
                    if addr.addr().is_ipv4() && addr.prefix_len() < 32 {
                        o.routes.push(connected(l, *addr));
                    }
                }
            }
            Action::DelAddr { link: l, addr } => {
                let spec = AddrSpec {
                    link: l.clone(),
                    addr: *addr,
                };
                assert!(o.addresses.contains(&spec), "DelAddr of absent {addr}");
                o.addresses.retain(|a| *a != spec);
                let conn = connected(l, *addr);
                o.routes.retain(|r| *r != conn);
            }
            Action::AddRoute(r) => {
                let mut r = r.clone();
                if let Some(dev) = &r.dev {
                    index_of(o, dev);
                } else if let Some(via) = r.via {
                    // the kernel resolves the output device from a connected net
                    let dev = o
                        .addresses
                        .iter()
                        .find(|a| a.addr.trunc().contains(&via))
                        .unwrap_or_else(|| panic!("gateway {via} unreachable"))
                        .link
                        .clone();
                    r.dev = Some(dev);
                }
                if o.routes
                    .iter()
                    .any(|x| x.dest.trunc() == r.dest.trunc() && x.metric == r.metric)
                {
                    // same destination and metric already routed (maybe elsewhere)
                    failed.push((a.clone(), "EEXIST"));
                } else {
                    o.routes.push(r);
                }
            }
            Action::DelRoute(r) => {
                let before = o.routes.len();
                o.routes
                    .retain(|x| !(x.dest == r.dest && x.via == r.via && x.dev == r.dev));
                assert!(o.routes.len() < before, "DelRoute of absent route");
            }
            Action::Sysctl { key, value } => {
                // a per-interface key only exists while its link does (else ENOENT)
                if let Some(ifname) = sysctl_iface(&sysctl_path(key).unwrap()) {
                    index_of(o, ifname);
                }
                o.sysctls.retain(|(k, _)| k != key);
                o.sysctls.push((key.clone(), value.clone()));
            }
        }
    }
    failed
}

/// plan -> apply -> plan again must be empty. Returns the first plan.
fn converge(desired: &NetPlan, observed: &mut Observed) -> Vec<Action> {
    let first = plan(desired, observed).expect("plan");
    apply(observed, &first);
    let again = plan(desired, observed).expect("replan");
    assert!(again.is_empty(), "not idempotent, leftover: {again:#?}");
    first
}

// ---------------------------------------------------------------- fixtures

const LAN_PORTS: [&str; 5] = ["lan1", "lan2", "lan3", "lan4", "lan5"];

/// A freshly booted Flint 2: all ports exist, DSA user ports are down.
fn flint2_boot() -> Observed {
    let mut o = Observed::default();
    let mut idx = 1;
    for (name, up) in [("lo", true), ("eth0", true), ("eth1", false)]
        .into_iter()
        .chain(LAN_PORTS.iter().map(|n| (*n, false)))
    {
        let mut l = ObservedLink::new(idx, name, LinkKind::Physical);
        l.up = up;
        l.mac = Some(MacAddr([
            0xe4,
            0x5f,
            0x01,
            0,
            0,
            u8::try_from(idx).unwrap(),
        ]));
        o.links.push(l);
        idx += 1;
    }
    o.addresses.push(AddrSpec {
        link: "lo".into(),
        addr: "127.0.0.1/8".parse().unwrap(),
    });
    o.addresses.push(AddrSpec {
        link: "lan1".into(),
        addr: "fe80::1/64".parse().unwrap(),
    });
    o
}

fn phys(name: &str, up: bool) -> LinkSpec {
    LinkSpec::Physical {
        name: name.into(),
        up,
        mtu: None,
        mac: None,
    }
}

fn bridge(name: &str, ports: &[&str]) -> LinkSpec {
    LinkSpec::Bridge {
        name: name.into(),
        ports: ports.iter().map(|p| (*p).to_owned()).collect(),
        vlan_filtering: false,
        mtu: None,
        mac: None,
    }
}

fn addr(link: &str, a: &str) -> AddrSpec {
    AddrSpec {
        link: link.into(),
        addr: a.parse().unwrap(),
    }
}

fn dhcp(link: &str) -> DhcpClientSpec {
    DhcpClientSpec {
        link: link.into(),
        hostname: Some("flint2".into()),
        vendor_class: None,
        request_dns: true,
        default_route_metric: 10,
    }
}

fn static_route(dest: &str, via: &str, dev: &str) -> RouteSpec {
    RouteSpec {
        dest: dest.parse().unwrap(),
        via: Some(via.parse().unwrap()),
        dev: Some(dev.to_owned()),
        metric: 0,
        table: TABLE_MAIN,
        proto: RouteProto::Static,
    }
}

fn flint2_default() -> NetPlan {
    NetPlan {
        links: std::iter::once(phys("eth1", true))
            .chain(LAN_PORTS.iter().map(|p| phys(p, true)))
            .chain(std::iter::once(bridge("br-lan", &LAN_PORTS)))
            .collect(),
        addresses: vec![addr("br-lan", "192.168.8.1/24")],
        routes: vec![],
        dhcp_clients: vec![dhcp("eth1")],
        sysctls: vec![("net.ipv4.ip_forward".into(), "1".into())],
    }
}

/// br-lan with lan1..4, a guest bridge with lan5, and a VLAN sub-interface.
fn flint2_guest() -> NetPlan {
    let mut p = flint2_default();
    p.links.retain(|l| l.name() != "br-lan");
    p.links.push(LinkSpec::Bridge {
        name: "br-lan".into(),
        ports: LAN_PORTS[..4].iter().map(|s| (*s).to_owned()).collect(),
        vlan_filtering: true,
        mtu: Some(1500),
        mac: None,
    });
    p.links.push(bridge("br-guest", &["lan5"]));
    p.links.push(LinkSpec::Vlan {
        name: "br-lan.20".into(),
        parent: "br-lan".into(),
        id: 20,
    });
    p.addresses.push(addr("br-guest", "192.168.30.1/24"));
    p.addresses.push(addr("br-lan.20", "192.168.20.1/24"));
    p
}

fn pos(actions: &[Action], pred: impl Fn(&Action) -> bool) -> usize {
    actions
        .iter()
        .position(pred)
        .unwrap_or_else(|| panic!("action not found in {actions:#?}"))
}

// ---------------------------------------------------------------- tests

#[test]
fn flint2_default_converges_in_the_documented_order() {
    let mut o = flint2_boot();
    let actions = converge(&flint2_default(), &mut o);

    let sysctl = pos(&actions, |a| matches!(a, Action::Sysctl { .. }));
    let create = pos(&actions, |a| matches!(a, Action::CreateBridge { .. }));
    let master = pos(&actions, |a| matches!(a, Action::SetMaster { .. }));
    let up_br = pos(
        &actions,
        |a| matches!(a, Action::SetUp { link } if link == "br-lan"),
    );
    let up_wan = pos(
        &actions,
        |a| matches!(a, Action::SetUp { link } if link == "eth1"),
    );
    let add = pos(&actions, |a| matches!(a, Action::AddAddr { .. }));
    assert!(sysctl < create && create < master && master < up_br && up_br < add);
    assert!(up_wan < add);
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::SetMaster { .. }))
            .count(),
        5
    );

    for p in LAN_PORTS.iter().chain(&["eth1", "br-lan"]) {
        assert!(link(&mut o, p).up, "{p} should be up");
    }
    // lo's address and lan1's link-local were left alone
    assert!(o.addresses.contains(&addr("lo", "127.0.0.1/8")));
    assert!(o.addresses.contains(&addr("lan1", "fe80::1/64")));
}

#[test]
fn already_converged_state_plans_nothing() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    assert_eq!(plan(&flint2_default(), &o).unwrap(), vec![]);
}

#[test]
fn ports_not_declared_as_physical_are_still_brought_up() {
    let mut p = flint2_default();
    p.links
        .retain(|l| !matches!(l, LinkSpec::Physical { name, .. } if name.starts_with("lan")));
    let mut o = flint2_boot();
    let actions = converge(&p, &mut o);
    assert!(actions.contains(&Action::SetUp {
        link: "lan3".into()
    }));
}

#[test]
fn dhcp_lease_merges_and_converges_ignoring_kernel_connected_routes() {
    let spec = dhcp("eth1");
    let base = flint2_default();
    base.validate().unwrap();

    let mut reply = Message::new_client(1, MacAddr([2; 6]), MessageType::Ack);
    reply.op = Op::Reply;
    reply.yiaddr = "203.0.113.7".parse().unwrap();
    reply.options.server_id = Some("203.0.113.1".parse().unwrap());
    reply.options.lease_time = Some(3600);
    reply.options.subnet_mask = Some("255.255.255.0".parse().unwrap());
    reply.options.routers = vec!["203.0.113.1".parse().unwrap()];
    let lease = Lease::from_ack(&reply, SystemTime::UNIX_EPOCH).unwrap();
    let merged = merge_lease(&base, &spec, &lease);

    let mut o = flint2_boot();
    let actions = converge(&merged, &mut o);
    assert!(actions.contains(&Action::AddAddr {
        link: "eth1".into(),
        addr: "203.0.113.7/24".parse().unwrap()
    }));
    let default = actions
        .iter()
        .find_map(|a| match a {
            Action::AddRoute(r) => Some(r),
            _ => None,
        })
        .expect("default route");
    assert_eq!(default.proto, RouteProto::Dhcp);
    assert!(
        o.routes
            .iter()
            .any(|r| r.proto == RouteProto::Kernel && r.dev.as_deref() == Some("eth1"))
    );

    // lease lost: static plan again removes the DHCP address and route, keeps kernel routes
    let actions = converge(&base, &mut o);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::DelAddr { link, .. } if link == "eth1"))
    );
    assert!(actions.iter().any(|a| matches!(a, Action::DelRoute(_))));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::DelRoute(r) if r.proto == RouteProto::Kernel))
    );
}

#[test]
fn guest_vlan_variant_converges_from_boot_and_from_default() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);

    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    let actions = converge(&flint2_guest(), &mut o);
    // lan5 moves bridges directly, without a release in between
    assert!(actions.contains(&Action::SetMaster {
        link: "lan5".into(),
        master: Some("br-guest".into())
    }));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::SetMaster { master: None, .. }))
    );
    assert!(actions.contains(&Action::SetVlanFiltering {
        link: "br-lan".into(),
        enabled: true
    }));
    let parent_index = index_of(&o, "br-lan");
    assert_eq!(
        link(&mut o, "br-lan.20").kind,
        LinkKind::Vlan {
            parent_index,
            id: 20
        }
    );
}

#[test]
fn removing_guest_deletes_vlans_before_bridges_and_releases_ports() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);
    let actions = converge(&flint2_default(), &mut o);

    let del_vlan = pos(
        &actions,
        |a| matches!(a, Action::DeleteLink { name } if name == "br-lan.20"),
    );
    let del_br = pos(
        &actions,
        |a| matches!(a, Action::DeleteLink { name } if name == "br-guest"),
    );
    assert!(del_vlan < del_br);
    assert_eq!(
        actions.last(),
        Some(&Action::DeleteLink {
            name: "br-guest".into()
        })
    );
    assert!(
        o.links
            .iter()
            .all(|l| l.name != "br-guest" && l.name != "br-lan.20")
    );
    // lan5 is back in br-lan
    let lan5 = link(&mut o, "lan5").master;
    assert_eq!(lan5, Some(index_of(&o, "br-lan")));
    // physical links survived
    assert!(o.links.iter().any(|l| l.name == "lan5"));
}

#[test]
fn dropping_a_port_from_a_bridge_releases_it() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    let mut p = flint2_default();
    p.links.retain(|l| l.name() != "br-lan");
    p.links.push(bridge("br-lan", &LAN_PORTS[..4]));
    let actions = converge(&p, &mut o);
    assert_eq!(
        actions,
        vec![Action::SetMaster {
            link: "lan5".into(),
            master: None
        }]
    );
}

#[test]
fn empty_plan_removes_only_managed_virtual_links() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);
    // links the planner must not touch: foreign bridge, vlan without '.', veth
    let base = o.links.iter().map(|l| l.index).max().unwrap();
    o.links
        .push(ObservedLink::new(base + 1, "docker0", LinkKind::Bridge));
    o.links.push(ObservedLink::new(
        base + 2,
        "wanvlan",
        LinkKind::Vlan {
            parent_index: 3,
            id: 7,
        },
    ));
    o.links.push(ObservedLink::new(
        base + 3,
        "veth0",
        LinkKind::Other("veth".into()),
    ));
    // a dotted VLAN is deleted only because it carries our alias
    let mut ours = ObservedLink::new(
        base + 4,
        "eth1.50",
        LinkKind::Vlan {
            parent_index: 3,
            id: 50,
        },
    );
    ours.alias = Some(owr_net::MANAGED_ALIAS.into());
    o.links.push(ours);
    let actions = plan(&NetPlan::default(), &o).unwrap();
    let deleted: Vec<&str> = actions
        .iter()
        .filter_map(|a| match a {
            Action::DeleteLink { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(deleted, vec!["br-lan.20", "eth1.50", "br-guest", "br-lan"]);
    assert!(
        !actions.iter().any(|a| matches!(a, Action::SetDown { .. })),
        "physical links stay as they are"
    );
    apply(&mut o, &actions);
    assert!(plan(&NetPlan::default(), &o).unwrap().is_empty());
    for keep in [
        "docker0", "wanvlan", "veth0", "eth1", "lan1", "lan5", "eth0", "lo",
    ] {
        assert!(o.links.iter().any(|l| l.name == keep), "{keep} deleted");
    }
}

#[test]
fn stale_addresses_and_routes_on_managed_links_are_removed_but_protected_ones_stay() {
    let mut o = flint2_boot();
    let p = {
        let mut p = flint2_default();
        p.routes
            .push(static_route("10.9.0.0/16", "192.168.8.254", "br-lan"));
        p.dhcp_clients.clear();
        p
    };
    converge(&p, &mut o);

    // drift: stale address, stale static route, a kernel-RA route, a link-local, unmanaged addr
    o.addresses.push(addr("br-lan", "10.1.1.1/24"));
    o.routes
        .push(static_route("10.7.0.0/16", "192.168.8.254", "br-lan"));
    o.routes.push(RouteSpec {
        proto: RouteProto::Other(9),
        ..static_route("2001:db8::/32", "fe80::1", "br-lan")
    });
    o.addresses.push(addr("br-lan", "fe80::dead:beef/64"));
    o.links
        .push(ObservedLink::new(99, "wlan0", LinkKind::Physical));
    o.addresses.push(addr("wlan0", "172.16.0.1/24"));
    o.routes
        .push(static_route("10.8.0.0/16", "172.16.0.254", "wlan0"));

    let actions = plan(&p, &o).unwrap();
    assert_eq!(
        actions,
        vec![
            Action::DelAddr {
                link: "br-lan".into(),
                addr: "10.1.1.1/24".parse().unwrap()
            },
            Action::DelRoute(static_route("10.7.0.0/16", "192.168.8.254", "br-lan")),
        ]
    );
}

#[test]
fn kernel_routes_are_never_deleted_even_when_unwanted() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    assert!(o.routes.iter().any(|r| r.proto == RouteProto::Kernel));
    let mut p = flint2_default();
    p.addresses.clear();
    let actions = plan(&p, &o).unwrap();
    assert!(actions.iter().all(|a| !matches!(a, Action::DelRoute(_))));
}

#[test]
fn mac_change_on_an_up_link_goes_down_then_up() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    let mut p = flint2_default();
    let mac: MacAddr = "e4:5f:01:aa:bb:cc".parse().unwrap();
    p.links[0] = LinkSpec::Physical {
        name: "eth1".into(),
        up: true,
        mtu: Some(1492),
        mac: Some(mac),
    };
    let actions = converge(&p, &mut o);
    assert_eq!(
        actions,
        vec![
            Action::SetMtu {
                link: "eth1".into(),
                mtu: 1492
            },
            Action::SetDown {
                link: "eth1".into()
            },
            Action::SetMac {
                link: "eth1".into(),
                mac
            },
            Action::SetUp {
                link: "eth1".into()
            },
        ]
    );
}

#[test]
fn physical_up_false_brings_link_down() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    let mut p = flint2_default();
    p.links[0] = phys("eth1", false);
    assert_eq!(
        converge(&p, &mut o),
        vec![Action::SetDown {
            link: "eth1".into()
        }]
    );
}

#[test]
fn vlan_with_changed_id_is_recreated() {
    let mut p = flint2_default();
    p.links.push(LinkSpec::Vlan {
        name: "eth1.100".into(),
        parent: "eth1".into(),
        id: 100,
    });
    p.addresses.push(addr("eth1.100", "10.100.0.1/24"));
    let mut o = flint2_boot();
    converge(&p, &mut o);

    p.links.retain(|l| l.name() != "eth1.100");
    p.links.push(LinkSpec::Vlan {
        name: "eth1.100".into(),
        parent: "eth1".into(),
        id: 101,
    });
    let actions = converge(&p, &mut o);
    assert_eq!(
        actions[0],
        Action::DeleteLink {
            name: "eth1.100".into()
        }
    );
    assert!(actions.contains(&Action::CreateVlan {
        name: "eth1.100".into(),
        parent: "eth1".into(),
        id: 101
    }));
    assert!(actions.contains(&Action::AddAddr {
        link: "eth1.100".into(),
        addr: "10.100.0.1/24".parse().unwrap()
    }));
}

#[test]
fn sysctls_only_emitted_when_different_and_whitespace_normalised() {
    let p = NetPlan {
        sysctls: vec![
            ("net.ipv4.ip_forward".into(), "1".into()),
            ("net.ipv4.ping_group_range".into(), "0 2147483647".into()),
        ],
        ..NetPlan::default()
    };
    let o = Observed {
        sysctls: vec![
            ("net.ipv4.ip_forward".into(), "0".into()),
            ("net.ipv4.ping_group_range".into(), "0\t2147483647".into()),
        ],
        ..Observed::default()
    };
    assert_eq!(
        plan(&p, &o).unwrap(),
        vec![Action::Sysctl {
            key: "net.ipv4.ip_forward".into(),
            value: "1".into()
        }]
    );
}

#[test]
fn ipv6_route_metric_zero_matches_kernel_default_1024() {
    let mut o = flint2_boot();
    let mut p = flint2_default();
    p.dhcp_clients.clear();
    p.addresses.push(addr("br-lan", "fd00::1/64"));
    p.routes.push(RouteSpec {
        dest: "fd01::/64".parse().unwrap(),
        via: Some("fd00::2".parse().unwrap()),
        dev: Some("br-lan".into()),
        metric: 0,
        table: TABLE_MAIN,
        proto: RouteProto::Static,
    });
    converge(&p, &mut o);
    for r in &mut o.routes {
        if r.dest.addr().is_ipv6() && r.proto == RouteProto::Static {
            r.metric = 1024;
        }
    }
    assert_eq!(plan(&p, &o).unwrap(), vec![]);
}

#[test]
fn route_without_dev_matches_observed_route_with_resolved_dev() {
    let mut o = flint2_boot();
    let mut p = flint2_default();
    p.dhcp_clients.clear();
    p.routes.push(RouteSpec {
        dev: None,
        ..static_route("10.9.0.0/16", "192.168.8.254", "br-lan")
    });
    converge(&p, &mut o);
    assert_eq!(
        o.routes
            .iter()
            .filter(|r| r.dest.to_string() == "10.9.0.0/16")
            .count(),
        1
    );
}

#[test]
fn missing_physical_link_is_an_error_not_a_guess() {
    let mut o = flint2_boot();
    o.links.retain(|l| l.name != "lan3");
    assert_eq!(
        plan(&flint2_default(), &o),
        Err(PlanError::MissingLink("lan3".into()))
    );
}

#[test]
fn bridge_port_that_does_not_exist_is_an_error() {
    let p = NetPlan {
        links: vec![bridge("br-x", &["nope0"])],
        ..NetPlan::default()
    };
    assert_eq!(
        plan(&p, &flint2_boot()),
        Err(PlanError::MissingLink("nope0".into()))
    );
}

#[test]
fn kind_mismatch_is_refused_and_nothing_is_deleted() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    // plan says br-lan is physical
    let p = NetPlan {
        links: vec![phys("br-lan", true)],
        ..NetPlan::default()
    };
    assert!(matches!(plan(&p, &o), Err(PlanError::KindMismatch { .. })));
    // plan says eth1 is a bridge named br-... cannot happen; but a vlan named like a bridge:
    let p = NetPlan {
        links: vec![
            bridge("br-lan", &[]),
            LinkSpec::Vlan {
                name: "br-lan.5".into(),
                parent: "br-lan".into(),
                id: 5,
            },
        ],
        ..NetPlan::default()
    };
    o.links
        .push(ObservedLink::new(77, "br-lan.5", LinkKind::Bridge));
    assert!(matches!(plan(&p, &o), Err(PlanError::KindMismatch { .. })));
}

#[test]
fn invalid_plans_are_rejected_by_plan() {
    let mut p = flint2_default();
    p.addresses.push(addr("ghost", "10.0.0.1/24"));
    assert!(matches!(
        plan(&p, &flint2_boot()),
        Err(PlanError::Invalid(_))
    ));
}

#[test]
fn duplicate_observed_stale_entries_are_deleted_once() {
    let mut o = flint2_boot();
    converge(&flint2_default(), &mut o);
    let stale = addr("br-lan", "10.1.1.1/24");
    o.addresses.push(stale.clone());
    o.addresses.push(stale);
    let actions = plan(&flint2_default(), &o).unwrap();
    assert_eq!(actions.len(), 1);
}

// ---------------------------------------------------------------- review regressions

fn is_sysctl(a: &Action, key: &str) -> bool {
    matches!(a, Action::Sysctl { key: k, .. } if k == key)
}

#[test]
fn n1_per_interface_sysctls_wait_for_their_link_and_follow_conf_all() {
    let mut p = flint2_default();
    // deliberately listed per-interface first
    p.sysctls = vec![
        ("net/ipv4/conf/br-lan/forwarding".into(), "1".into()),
        ("net/ipv4/conf/br-lan/rp_filter".into(), "2".into()),
        ("net.ipv4.conf.all.forwarding".into(), "1".into()),
        ("net.ipv4.conf.default.rp_filter".into(), "1".into()),
        ("net.ipv4.ip_forward".into(), "1".into()),
    ];
    let mut o = flint2_boot();
    // the simulator answers ENOENT (panics) for conf/br-lan/* while br-lan is absent
    let actions = converge(&p, &mut o);

    let create = pos(&actions, |a| matches!(a, Action::CreateBridge { .. }));
    let up = pos(
        &actions,
        |a| matches!(a, Action::SetUp { link } if link == "br-lan"),
    );
    let add = pos(&actions, |a| matches!(a, Action::AddAddr { .. }));
    let all = pos(&actions, |a| is_sysctl(a, "net.ipv4.conf.all.forwarding"));
    let default = pos(&actions, |a| {
        is_sysctl(a, "net.ipv4.conf.default.rp_filter")
    });
    let global = pos(&actions, |a| is_sysctl(a, "net.ipv4.ip_forward"));
    let fwd = pos(&actions, |a| {
        is_sysctl(a, "net/ipv4/conf/br-lan/forwarding")
    });
    let rpf = pos(&actions, |a| is_sysctl(a, "net/ipv4/conf/br-lan/rp_filter"));
    assert!(all < create && default < create && global < create);
    assert!(up < fwd && up < rpf && fwd < add && rpf < add);
    assert!(
        all < fwd && all < rpf,
        "conf/all is written before conf/<if>"
    );
}

#[test]
fn n1_sysctl_of_a_link_that_is_being_deleted_is_not_an_action() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);
    let mut p = flint2_default();
    p.sysctls
        .push(("net/ipv4/conf/br-guest/forwarding".into(), "1".into()));
    // br-guest is deleted by this plan and is gone when the plan is re-checked
    let actions = converge(&p, &mut o);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::Sysctl { key, .. } if key.contains("br-guest")))
    );
}

#[test]
fn n1_sysctls_of_a_recreated_vlan_are_written_again() {
    let mut p = flint2_default();
    p.links.push(LinkSpec::Vlan {
        name: "eth1.100".into(),
        parent: "eth1".into(),
        id: 100,
    });
    p.sysctls
        .push(("net/ipv4/conf/eth1.100/forwarding".into(), "1".into()));
    let mut o = flint2_boot();
    converge(&p, &mut o);
    // the VLAN id changes, so the link is deleted and created anew
    p.links.retain(|l| l.name() != "eth1.100");
    p.links.push(LinkSpec::Vlan {
        name: "eth1.100".into(),
        parent: "eth1".into(),
        id: 101,
    });
    let key = "net/ipv4/conf/eth1.100/forwarding";
    assert!(o.sysctls.iter().any(|(k, v)| k == key && v == "1"));
    let actions = plan(&p, &o).unwrap();
    let del = pos(&actions, |a| matches!(a, Action::DeleteLink { .. }));
    let create = pos(&actions, |a| matches!(a, Action::CreateVlan { .. }));
    let set = pos(&actions, |a| is_sysctl(a, key));
    assert!(del < create && create < set, "{actions:#?}");
    apply(&mut o, &actions);
    assert!(plan(&p, &o).unwrap().is_empty());
}

#[test]
fn n2_routes_flushed_by_a_mac_change_are_added_again() {
    let mut p = flint2_default();
    p.dhcp_clients.clear();
    p.routes
        .push(static_route("10.9.0.0/16", "192.168.8.254", "br-lan"));
    let mut o = flint2_boot();
    converge(&p, &mut o);
    assert!(o.routes.iter().any(|r| r.dest.to_string() == "10.9.0.0/16"));

    let mac: MacAddr = "e4:5f:01:aa:bb:cc".parse().unwrap();
    for l in &mut p.links {
        if let LinkSpec::Bridge { mac: m, .. } = l {
            *m = Some(mac);
        }
    }
    let actions = converge(&p, &mut o);
    let down = pos(
        &actions,
        |a| matches!(a, Action::SetDown { link } if link == "br-lan"),
    );
    let up = pos(
        &actions,
        |a| matches!(a, Action::SetUp { link } if link == "br-lan"),
    );
    let route = pos(&actions, |a| matches!(a, Action::AddRoute(_)));
    assert!(down < up && up < route, "{actions:#?}");
    assert!(o.routes.iter().any(|r| r.dest.to_string() == "10.9.0.0/16"));
    // the address survived the down/up
    assert!(o.addresses.contains(&addr("br-lan", "192.168.8.1/24")));
}

#[test]
fn n2_observed_routes_of_a_link_the_plan_sets_down_are_not_deleted_again() {
    let mut p = flint2_default();
    p.dhcp_clients.clear();
    let mut o = flint2_boot();
    converge(&p, &mut o);
    o.routes
        .push(static_route("10.7.0.0/16", "192.168.8.254", "eth1"));
    p.links[0] = phys("eth1", false);
    // the simulator panics on DelRoute of a route that SetDown already flushed
    let actions = converge(&p, &mut o);
    assert!(!actions.iter().any(|a| matches!(a, Action::DelRoute(_))));
}

#[test]
fn n3_port_or_parent_that_the_plan_deletes_is_refused() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);
    // br-guest exists (ours) but is not in this plan, and a VLAN wants it as parent
    let mut p = flint2_default();
    p.links.push(LinkSpec::Vlan {
        name: "br-guest.5".into(),
        parent: "br-guest".into(),
        id: 5,
    });
    assert_eq!(
        plan(&p, &o),
        Err(PlanError::ReferencesObsolete {
            link: "br-guest".into()
        })
    );
    // same for a bridge port
    let mut p = flint2_default();
    p.links.push(bridge("br-x", &["br-lan.20"]));
    assert_eq!(
        plan(&p, &o),
        Err(PlanError::ReferencesObsolete {
            link: "br-lan.20".into()
        })
    );
}

#[test]
fn n4_foreign_bridges_and_vlans_without_our_alias_are_never_deleted() {
    let mut o = flint2_boot();
    converge(&flint2_guest(), &mut o);
    // created by the planner => carries the alias
    assert_eq!(
        link(&mut o, "br-guest").alias.as_deref(),
        Some(owr_net::MANAGED_ALIAS)
    );
    let base = o.links.iter().map(|l| l.index).max().unwrap();
    o.links.push(ObservedLink::new(
        base + 1,
        "br-5f3a9c1d2e4b",
        LinkKind::Bridge,
    ));
    o.links.push(ObservedLink::new(
        base + 2,
        "eth1.60",
        LinkKind::Vlan {
            parent_index: 3,
            id: 60,
        },
    ));
    let actions = plan(&NetPlan::default(), &o).unwrap();
    let deleted: Vec<&str> = actions
        .iter()
        .filter_map(|a| match a {
            Action::DeleteLink { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(deleted, vec!["br-lan.20", "br-guest", "br-lan"]);
    apply(&mut o, &actions);
    assert!(o.links.iter().any(|l| l.name == "br-5f3a9c1d2e4b"));
    assert!(o.links.iter().any(|l| l.name == "eth1.60"));
}

#[test]
fn n4_created_links_are_marked_and_existing_planned_links_are_adopted() {
    let mut o = flint2_boot();
    let actions = converge(&flint2_guest(), &mut o);
    for l in ["br-lan", "br-guest", "br-lan.20"] {
        let created = pos(
            &actions,
            |a| matches!(a, Action::CreateBridge { name, .. } | Action::CreateVlan { name, .. } if name == l),
        );
        assert_eq!(
            actions[created + 1],
            Action::SetAlias {
                link: l.into(),
                alias: owr_net::MANAGED_ALIAS.into()
            }
        );
    }
    // a bridge that already exists without the marker and is named in the plan is adopted
    let mut o = flint2_boot();
    o.links
        .push(ObservedLink::new(50, "br-lan", LinkKind::Bridge));
    let actions = converge(&flint2_default(), &mut o);
    assert!(actions.contains(&Action::SetAlias {
        link: "br-lan".into(),
        alias: owr_net::MANAGED_ALIAS.into()
    }));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::CreateBridge { .. }))
    );
    // so it is cleaned up when it leaves the plan
    let actions = converge(&NetPlan::default(), &mut o);
    assert!(actions.contains(&Action::DeleteLink {
        name: "br-lan".into()
    }));
}

#[test]
fn n6_route_that_already_exists_with_other_attributes_stays_visible() {
    let mut o = flint2_boot();
    let mut p = flint2_default();
    p.dhcp_clients.clear();
    p.routes
        .push(static_route("10.9.0.0/16", "192.168.8.254", "br-lan"));
    converge(&flint2_default(), &mut o);
    // a route of another protocol (not ours to delete) holds dest + metric
    o.routes.push(RouteSpec {
        proto: RouteProto::Other(9),
        ..static_route("10.9.0.0/16", "192.168.8.99", "br-lan")
    });
    let actions = plan(&p, &o).unwrap();
    assert_eq!(
        actions,
        vec![Action::AddRoute(static_route(
            "10.9.0.0/16",
            "192.168.8.254",
            "br-lan"
        ))]
    );
    let failed = apply(&mut o, &actions);
    assert_eq!(failed.len(), 1, "EEXIST is reported, not swallowed");
    assert_eq!(failed[0].1, "EEXIST");
    // and the planner still wants the route: not converged
    assert_eq!(plan(&p, &o).unwrap(), actions);
}

#[test]
fn n16_mtu_and_mac_are_skipped_for_links_that_have_neither() {
    let mut o = flint2_boot();
    // a non-Ethernet device: no hardware address, MTU 0
    let mut tun = ObservedLink::new(60, "wg0", LinkKind::Physical);
    tun.mtu = 0;
    tun.mac = None;
    tun.up = true;
    o.links.push(tun);
    let p = NetPlan {
        links: vec![LinkSpec::Physical {
            name: "wg0".into(),
            up: true,
            mtu: Some(1420),
            mac: Some(MacAddr([2, 0, 0, 0, 0, 9])),
        }],
        ..NetPlan::default()
    };
    assert_eq!(plan(&p, &o).unwrap(), vec![]);
    // a normal Ethernet link still gets both
    o.links.retain(|l| l.name != "wg0");
    let p = NetPlan {
        links: vec![LinkSpec::Physical {
            name: "lan1".into(),
            up: false,
            mtu: Some(1400),
            mac: Some(MacAddr([2, 0, 0, 0, 0, 9])),
        }],
        ..NetPlan::default()
    };
    let actions = plan(&p, &o).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::SetMtu { .. })));
    assert!(actions.iter().any(|a| matches!(a, Action::SetMac { .. })));
}

// ---------------------------------------------------------------- property

fn arb_plan() -> impl Strategy<Value = NetPlan> {
    (
        // bridge assignment per lan port: 0 = none, 1 = br-a, 2 = br-b
        proptest::collection::vec(0u8..3, 5),
        any::<bool>(),                             // vlan on br-a
        1u16..4095,                                // vlan id
        proptest::option::of(576u32..9000),        // mtu on br-a
        proptest::option::of(any::<u8>()),         // mac on eth1
        any::<bool>(),                             // eth1 up
        proptest::collection::vec(1u8..250, 0..3), // extra addrs on br-a
        any::<bool>(),                             // static route
        any::<bool>(),                             // vlan filtering
    )
        .prop_map(|(assign, vlan, vid, mtu, mac, wan_up, extra, route, vf)| {
            let mut links = vec![LinkSpec::Physical {
                name: "eth1".into(),
                up: wan_up,
                mtu: None,
                mac: mac.map(|m| MacAddr([2, 0, 0, 0, 0, m])),
            }];
            let ports_of = |n: u8| -> Vec<String> {
                LAN_PORTS
                    .iter()
                    .zip(&assign)
                    .filter(|(_, a)| **a == n)
                    .map(|(p, _)| (*p).to_owned())
                    .collect()
            };
            let mut addresses = vec![];
            let mut routes = vec![];
            if assign.contains(&1) {
                links.push(LinkSpec::Bridge {
                    name: "br-a".into(),
                    ports: ports_of(1),
                    vlan_filtering: vf,
                    mtu,
                    mac: None,
                });
                addresses.push(addr("br-a", "192.168.1.1/24"));
                for e in extra {
                    addresses.push(addr("br-a", &format!("10.{e}.0.1/16")));
                }
                if vlan {
                    links.push(LinkSpec::Vlan {
                        name: "br-a.7".into(),
                        parent: "br-a".into(),
                        id: vid,
                    });
                    addresses.push(addr("br-a.7", "192.168.7.1/24"));
                }
                if route {
                    routes.push(static_route("172.20.0.0/16", "192.168.1.9", "br-a"));
                }
            }
            if assign.contains(&2) {
                links.push(bridge(
                    "br-b",
                    &ports_of(2).iter().map(String::as_str).collect::<Vec<_>>(),
                ));
                addresses.push(addr("br-b", "192.168.2.1/24"));
            }
            // dedupe: extra may repeat
            addresses.dedup();
            let mut seen = std::collections::HashSet::new();
            addresses.retain(|a: &AddrSpec| seen.insert((a.link.clone(), a.addr)));
            NetPlan {
                links,
                addresses,
                routes,
                dhcp_clients: vec![],
                sysctls: vec![("net.ipv4.ip_forward".into(), "1".into())],
            }
        })
}

proptest! {
    /// Any desired plan converges from boot, and any transition A -> B converges.
    #[test]
    fn any_transition_converges_and_is_idempotent(a in arb_plan(), b in arb_plan()) {
        a.validate().unwrap();
        b.validate().unwrap();
        let mut o = flint2_boot();
        converge(&a, &mut o);
        converge(&b, &mut o);
        // physical links are never lost
        for name in ["eth1", "lan1", "lan2", "lan3", "lan4", "lan5"] {
            prop_assert!(o.links.iter().any(|l| l.name == name));
        }
        // and reverting is also clean
        converge(&a, &mut o);
    }
}
