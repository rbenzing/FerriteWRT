//! Read links, addresses, routes and sysctls from the kernel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::pin;

use futures_util::{Stream, StreamExt};
use ipnet::IpNet;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::{
    AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage,
};
use netlink_packet_route::link::{
    InfoBridge, InfoData, InfoKind, InfoVlan, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteType,
};
use tracing::{debug, warn};

use super::{MAX_DUMP_ENTRIES, NETLINK_TIMEOUT, NetError};
use crate::model::{AddrSpec, MacAddr, NetPlan, RouteProto, RouteSpec, TABLE_MAIN, sysctl_path};
use crate::observed::{LinkKind, LinkStats, Observed, ObservedLink};

/// Dump links, permanent addresses and main-table unicast routes (IPv4 + IPv6).
///
/// Each dump is bounded to [`MAX_DUMP_ENTRIES`] entries and [`NETLINK_TIMEOUT`].
/// `sysctls` is left empty; see [`observe_sysctls`].
pub async fn observe(handle: &rtnetlink::Handle) -> Result<Observed, NetError> {
    let link_msgs = collect(handle.link().get().execute(), "link dump", "links").await?;
    let mut links: Vec<ObservedLink> = link_msgs.into_iter().filter_map(convert_link).collect();
    for l in &mut links {
        l.speed_mbps = read_speed(&l.name, l.up && l.carrier).await;
    }
    let names: HashMap<u32, &str> = links.iter().map(|l| (l.index, l.name.as_str())).collect();

    let addr_msgs = collect(
        handle.address().get().execute(),
        "address dump",
        "addresses",
    )
    .await?;
    let addresses = addr_msgs
        .into_iter()
        .filter_map(|m| convert_addr(&m, &names))
        .collect();

    let mut routes = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut req = RouteMessage::default();
        req.header.address_family = family;
        let msgs = collect(handle.route().get(req).execute(), "route dump", "routes").await?;
        routes.extend(msgs.iter().filter_map(|m| convert_route(m, &names)));
        if routes.len() > MAX_DUMP_ENTRIES {
            return Err(NetError::TooMany {
                what: "routes",
                max: MAX_DUMP_ENTRIES,
            });
        }
    }
    Ok(Observed {
        links,
        addresses,
        routes,
        sysctls: Vec::new(),
    })
}

/// Fill `observed.sysctls` with the current values of the keys in `desired`
/// (unreadable keys are omitted, so the planner will try to set them).
pub async fn observe_sysctls(observed: &mut Observed, desired: &NetPlan) {
    observed.sysctls.clear();
    for (key, _) in &desired.sysctls {
        let Ok(path) = sysctl_path(key) else { continue };
        let read = tokio::time::timeout(
            NETLINK_TIMEOUT,
            tokio::fs::read_to_string(format!("/proc/sys/{path}")),
        )
        .await;
        match read {
            Ok(Ok(v)) => observed.sysctls.push((key.clone(), v.trim().to_owned())),
            Ok(Err(e)) => debug!(key, error = %e, "sysctl not readable"),
            Err(_) => warn!(key, "sysctl read timed out"),
        }
    }
}

/// Drain a netlink dump, failing on timeout, error, or more than the bound.
async fn collect<T>(
    stream: impl Stream<Item = Result<T, rtnetlink::Error>>,
    op: &'static str,
    what: &'static str,
) -> Result<Vec<T>, NetError> {
    let drain = async {
        let mut stream = pin!(stream);
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            if out.len() >= MAX_DUMP_ENTRIES {
                return Err(NetError::TooMany {
                    what,
                    max: MAX_DUMP_ENTRIES,
                });
            }
            out.push(item?);
        }
        Ok(out)
    };
    tokio::time::timeout(NETLINK_TIMEOUT, drain)
        .await
        .map_err(|_| NetError::Timeout(op))?
}

/// `/sys/class/net/<name>/speed`; absent, unreadable or `-1` yields `None`.
async fn read_speed(name: &str, link_is_up: bool) -> Option<u32> {
    if !link_is_up || name.contains('/') {
        return None;
    }
    let path = format!("/sys/class/net/{name}/speed");
    let text = tokio::time::timeout(NETLINK_TIMEOUT, tokio::fs::read_to_string(path))
        .await
        .ok()?
        .ok()?;
    text.trim().parse::<u32>().ok().filter(|s| *s > 0)
}

pub(super) fn convert_link(msg: LinkMessage) -> Option<ObservedLink> {
    let mut name = None;
    let (mut mtu, mut mac, mut master, mut parent) = (0, None, None, 0);
    let mut stats = LinkStats::default();
    let mut kind: Option<InfoKind> = None;
    let (mut vlan_id, mut vlan_filtering) = (0u16, None);
    let mut alias = None;
    for attr in msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = Some(n),
            LinkAttribute::Mtu(m) => mtu = m,
            LinkAttribute::Address(a) => {
                mac = <[u8; 6]>::try_from(a.as_slice()).ok().map(MacAddr);
            }
            LinkAttribute::Controller(i) => master = Some(i),
            LinkAttribute::Link(i) => parent = i,
            LinkAttribute::IfAlias(a) => alias = Some(a).filter(|a| !a.is_empty()),
            LinkAttribute::Stats64(s) => {
                stats = LinkStats {
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    rx_packets: s.rx_packets,
                    tx_packets: s.tx_packets,
                    rx_errors: s.rx_errors,
                    tx_errors: s.tx_errors,
                };
            }
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(k) => kind = Some(k),
                        LinkInfo::Data(InfoData::Vlan(v)) => {
                            for x in v {
                                if let InfoVlan::Id(id) = x {
                                    vlan_id = id;
                                }
                            }
                        }
                        LinkInfo::Data(InfoData::Bridge(b)) => {
                            for x in b {
                                if let InfoBridge::VlanFiltering(on) = x {
                                    vlan_filtering = Some(on);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let kind = match kind {
        // DSA user ports register kind "dsa" on recent kernels; they are hardware.
        None | Some(InfoKind::Dsa) => LinkKind::Physical,
        Some(InfoKind::Bridge) => LinkKind::Bridge,
        Some(InfoKind::Vlan) => LinkKind::Vlan {
            parent_index: parent,
            id: vlan_id,
        },
        Some(other) => LinkKind::Other(other.to_string()),
    };
    let flags = msg.header.flags;
    Some(ObservedLink {
        index: msg.header.index,
        name: name?,
        kind,
        master,
        up: flags.contains(LinkFlags::Up),
        carrier: flags.contains(LinkFlags::LowerUp),
        mtu,
        mac,
        speed_mbps: None,
        stats,
        vlan_filtering,
        alias,
    })
}

/// Permanent addresses only: dynamic (SLAAC, temporary) addresses belong to the
/// kernel / odhcpd and must not look like drift.
fn convert_addr(msg: &AddressMessage, names: &HashMap<u32, &str>) -> Option<AddrSpec> {
    let mut ip: Option<IpAddr> = None;
    let mut flags = None;
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Local(a) => ip = Some(*a),
            AddressAttribute::Address(a) if ip.is_none() => ip = Some(*a),
            AddressAttribute::Flags(f) => flags = Some(*f),
            _ => {}
        }
    }
    let permanent = flags.map_or_else(
        || msg.header.flags.contains(AddressHeaderFlags::Permanent),
        |f| f.contains(AddressFlags::Permanent),
    );
    if !permanent {
        return None;
    }
    let link = (*names.get(&msg.header.index)?).to_owned();
    match IpNet::new(ip?, msg.header.prefix_len) {
        Ok(addr) => Some(AddrSpec { link, addr }),
        Err(e) => {
            warn!(%link, error = %e, "ignoring address with bad prefix length");
            None
        }
    }
}

fn route_ip(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v4) => Some((*v4).into()),
        RouteAddress::Inet6(v6) => Some((*v6).into()),
        _ => None,
    }
}

fn convert_route(msg: &RouteMessage, names: &HashMap<u32, &str>) -> Option<RouteSpec> {
    if msg.header.kind != RouteType::Unicast {
        return None;
    }
    let family = msg.header.address_family;
    let (mut dest, mut via, mut oif, mut metric) = (None, None, None, 0);
    let mut table = u32::from(msg.header.table);
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Destination(a) => dest = route_ip(a),
            RouteAttribute::Gateway(a) => via = route_ip(a),
            RouteAttribute::Oif(i) => oif = Some(*i),
            RouteAttribute::Priority(p) => metric = *p,
            RouteAttribute::Table(t) => table = *t,
            _ => {}
        }
    }
    if table != TABLE_MAIN {
        return None;
    }
    let dest = dest.unwrap_or(match family {
        AddressFamily::Inet6 => std::net::Ipv6Addr::UNSPECIFIED.into(),
        _ => std::net::Ipv4Addr::UNSPECIFIED.into(),
    });
    let dest = IpNet::new(dest, msg.header.destination_prefix_length).ok()?;
    let proto = match msg.header.protocol {
        RouteProtocol::Kernel => RouteProto::Kernel,
        RouteProtocol::Boot => RouteProto::Boot,
        RouteProtocol::Static => RouteProto::Static,
        RouteProtocol::Dhcp => RouteProto::Dhcp,
        other => RouteProto::Other(u8::from(other)),
    };
    Some(RouteSpec {
        dest,
        via,
        dev: oif.and_then(|i| names.get(&i)).map(|n| (*n).to_owned()),
        metric,
        table,
        proto,
    })
}
