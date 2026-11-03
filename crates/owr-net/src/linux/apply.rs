//! Execute planner actions through rtnetlink / procfs.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::pin;

use futures_util::StreamExt;
use ipnet::IpNet;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::{InfoBridge, InfoData, InfoKind};
use netlink_packet_route::route::{RouteMessage, RouteProtocol, RouteScope};
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkBridge, LinkMessageBuilder, LinkUnspec, LinkVlan,
    RouteMessageBuilder,
};
use rustix::io::Errno;
use tracing::{Instrument, debug, info, info_span, warn};

use super::observe::convert_link;
use super::{NETLINK_TIMEOUT, NetError};
use crate::model::{RouteProto, RouteSpec, sysctl_iface, sysctl_path, valid_sysctl_value};
use crate::observed::{LinkKind, ObservedLink};
use crate::planner::Action;

/// Outcome of [`apply`].
#[derive(Debug, Default)]
pub struct AppliedReport {
    /// Actions that succeeded (including tolerated EEXIST on links and addresses,
    /// ENOENT on deletions).
    pub applied: usize,
    /// Actions that failed, with the reason. The rest of the list still ran.
    pub failed: Vec<(Action, String)>,
}

#[derive(Debug, thiserror::Error)]
enum StepError {
    #[error("link {0:?} not found")]
    NoSuchLink(String),
    #[error("netlink: {0}")]
    Netlink(rtnetlink::Error),
    #[error("{0}")]
    Io(std::io::Error),
    #[error("{0}")]
    Invalid(String),
}

impl From<rtnetlink::Error> for StepError {
    fn from(e: rtnetlink::Error) -> Self {
        Self::Netlink(e)
    }
}

/// Execute `actions` in order. Non-fatal failures are recorded and execution
/// continues; only a dead netlink connection aborts with `Err`.
pub async fn apply(handle: &Handle, actions: &[Action]) -> Result<AppliedReport, NetError> {
    let mut report = AppliedReport::default();
    let deleting: HashSet<&str> = actions
        .iter()
        .filter_map(|a| match a {
            Action::DeleteLink { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    for action in actions {
        let span = info_span!("net_action", action = ?action);
        let result = async {
            info!("applying");
            match tokio::time::timeout(NETLINK_TIMEOUT, step(handle, action, &deleting)).await {
                Ok(r) => r,
                Err(_) => Err(StepError::Invalid(format!(
                    "timed out after {NETLINK_TIMEOUT:?}"
                ))),
            }
        }
        .instrument(span)
        .await;
        match result {
            Ok(()) => report.applied = report.applied.saturating_add(1),
            Err(StepError::Netlink(e @ rtnetlink::Error::RequestFailed)) => {
                return Err(NetError::Netlink(e));
            }
            Err(e) => {
                warn!(?action, error = %e, "action failed");
                report.failed.push((action.clone(), e.to_string()));
            }
        }
    }
    Ok(report)
}

fn errno(e: &rtnetlink::Error) -> Option<Errno> {
    match e {
        rtnetlink::Error::NetlinkError(m) => Some(Errno::from_raw_os_error(m.raw_code().abs())),
        _ => None,
    }
}

/// Treat the listed errnos as success (idempotent add / delete).
fn tolerate(r: Result<(), rtnetlink::Error>, ok: &[Errno]) -> Result<(), StepError> {
    match r {
        Ok(()) => Ok(()),
        Err(e) if errno(&e).is_some_and(|n| ok.contains(&n)) => {
            debug!(error = %e, "tolerated");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

const EXISTS: &[Errno] = &[Errno::EXIST];
const GONE: &[Errno] = &[
    Errno::NOENT,
    Errno::SRCH,
    Errno::NODEV,
    Errno::NXIO,
    Errno::ADDRNOTAVAIL,
];

async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>, StepError> {
    let mut stream = pin!(handle.link().get().match_name(name).execute());
    match stream.next().await {
        Some(Ok(msg)) => Ok(Some(msg.header.index)),
        None => Ok(None),
        Some(Err(e)) if errno(&e) == Some(Errno::NODEV) => Ok(None),
        Some(Err(e)) => Err(e.into()),
    }
}

/// A fresh single-link get by name.
async fn link_get(handle: &Handle, name: &str) -> Result<Option<ObservedLink>, StepError> {
    let mut stream = pin!(handle.link().get().match_name(name).execute());
    match stream.next().await {
        Some(Ok(msg)) => Ok(convert_link(msg)),
        None => Ok(None),
        Some(Err(e)) if errno(&e) == Some(Errno::NODEV) => Ok(None),
        Some(Err(e)) => Err(e.into()),
    }
}

async fn need(handle: &Handle, name: &str) -> Result<u32, StepError> {
    link_index(handle, name)
        .await?
        .ok_or_else(|| StepError::NoSuchLink(name.to_owned()))
}

fn proto(p: RouteProto) -> RouteProtocol {
    match p {
        RouteProto::Kernel => RouteProtocol::Kernel,
        RouteProto::Boot => RouteProtocol::Boot,
        RouteProto::Static => RouteProtocol::Static,
        RouteProto::Dhcp => RouteProtocol::Dhcp,
        RouteProto::Other(n) => RouteProtocol::from(n),
    }
}

/// Build the route message. For deletion the protocol and scope are wildcards so
/// the kernel matches whatever is installed for this destination / metric.
async fn route_message(
    handle: &Handle,
    r: &RouteSpec,
    for_delete: bool,
) -> Result<RouteMessage, StepError> {
    let invalid = |e: String| StepError::Invalid(e);
    let mut b = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(r.dest.addr(), r.dest.prefix_len())
        .map_err(|e| invalid(e.to_string()))?
        .priority(r.metric)
        .table_id(r.table);
    if let Some(via) = r.via {
        b = b.gateway(via).map_err(|e| invalid(e.to_string()))?;
    }
    if let Some(dev) = &r.dev {
        b = b.output_interface(need(handle, dev).await?);
    }
    b = if for_delete {
        b.protocol(RouteProtocol::Unspec).scope(RouteScope::NoWhere)
    } else {
        let scope = if r.via.is_some() {
            RouteScope::Universe
        } else {
            RouteScope::Link
        };
        b.protocol(proto(r.proto)).scope(scope)
    };
    Ok(b.build())
}

fn addr_message(index: u32, addr: IpNet) -> AddressMessage {
    match addr.addr() {
        IpAddr::V4(a) => AddressMessageBuilder::<Ipv4Addr>::new()
            .index(index)
            .address(a, addr.prefix_len())
            .build(),
        IpAddr::V6(a) => AddressMessageBuilder::<Ipv6Addr>::new()
            .index(index)
            .address(a, addr.prefix_len())
            .build(),
    }
}

#[allow(clippy::too_many_lines)] // one arm per action kind
async fn step(handle: &Handle, action: &Action, deleting: &HashSet<&str>) -> Result<(), StepError> {
    match action {
        Action::CreateBridge {
            name,
            vlan_filtering,
        } => {
            let msg = LinkMessageBuilder::<LinkBridge>::new(name)
                .vlan_filtering(*vlan_filtering)
                .build();
            tolerate(handle.link().add(msg).execute().await, EXISTS)
        }
        Action::CreateVlan { name, parent, id } => {
            let parent = need(handle, parent).await?;
            let msg = LinkVlan::new(name, parent, *id).build();
            tolerate(handle.link().add(msg).execute().await, EXISTS)
        }
        // Re-check the kind right before deleting: only bridges and VLANs are ours
        // to remove, whatever the (possibly stale) plan says.
        Action::DeleteLink { name } => match link_get(handle, name).await? {
            None => Ok(()),
            Some(l) if matches!(l.kind, LinkKind::Bridge | LinkKind::Vlan { .. }) => {
                tolerate(handle.link().del(l.index).execute().await, GONE)
            }
            Some(l) => Err(StepError::Invalid(format!(
                "refusing to delete {name:?}: it is {:?}, not a bridge or vlan",
                l.kind
            ))),
        },
        Action::SetAlias { link, alias } => {
            let msg = LinkUnspec::new_with_index(need(handle, link).await?)
                .alias(alias)
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetMaster { link, master } => {
            let idx = need(handle, link).await?;
            let b = LinkUnspec::new_with_index(idx);
            let msg = match master {
                Some(m) => b.controller(need(handle, m).await?).build(),
                None => b.nocontroller().build(),
            };
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetUp { link } => {
            let msg = LinkUnspec::new_with_index(need(handle, link).await?)
                .up()
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetDown { link } => {
            let msg = LinkUnspec::new_with_index(need(handle, link).await?)
                .down()
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetMtu { link, mtu } => {
            let msg = LinkUnspec::new_with_index(need(handle, link).await?)
                .mtu(*mtu)
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetMac { link, mac } => {
            let msg = LinkUnspec::new_with_index(need(handle, link).await?)
                .address(mac.octets().to_vec())
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::SetVlanFiltering { link, enabled } => {
            let idx = need(handle, link).await?;
            let msg = LinkMessageBuilder::<LinkBridge>::new_with_info_kind(InfoKind::Bridge)
                .index(idx)
                .set_info_data(InfoData::Bridge(vec![InfoBridge::VlanFiltering(*enabled)]))
                .build();
            Ok(handle.link().set(msg).execute().await?)
        }
        Action::AddAddr { link, addr } => {
            let idx = need(handle, link).await?;
            tolerate(
                handle
                    .address()
                    .add(idx, addr.addr(), addr.prefix_len())
                    .execute()
                    .await,
                EXISTS,
            )
        }
        Action::DelAddr { link, addr } => match link_index(handle, link).await? {
            None => Ok(()),
            Some(idx) => tolerate(
                handle
                    .address()
                    .del(addr_message(idx, *addr))
                    .execute()
                    .await,
                GONE,
            ),
        },
        Action::AddRoute(r) => {
            let msg = route_message(handle, r, false).await?;
            // EEXIST is not success: the planner only adds routes it did not see, so
            // something else holds this destination / metric. Report it, never replace.
            match handle.route().add(msg).execute().await {
                Err(e) if errno(&e) == Some(Errno::EXIST) => Err(StepError::Invalid(format!(
                    "route {} metric {} already exists with different attributes",
                    r.dest, r.metric
                ))),
                other => Ok(other?),
            }
        }
        Action::DelRoute(r) => {
            if let Some(dev) = &r.dev
                && link_index(handle, dev).await?.is_none()
            {
                return Ok(());
            }
            let msg = route_message(handle, r, true).await?;
            tolerate(handle.route().del(msg).execute().await, GONE)
        }
        Action::Sysctl { key, value } => {
            let path = sysctl_path(key).map_err(|e| StepError::Invalid(e.to_string()))?;
            if !valid_sysctl_value(value) {
                return Err(StepError::Invalid(format!("invalid value for {key}")));
            }
            match tokio::fs::write(format!("/proc/sys/{path}"), value).await {
                Ok(()) => Ok(()),
                // `conf/<if>/` vanished with a link this batch deletes: nothing to set
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && sysctl_iface(&path).is_some_and(|i| deleting.contains(i)) =>
                {
                    debug!(%key, "sysctl interface is being deleted; skipped");
                    Ok(())
                }
                Err(e) => Err(StepError::Io(e)),
            }
        }
    }
}
