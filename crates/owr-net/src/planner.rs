//! Pure planner: desired state + observed state -> ordered actions.
//!
//! Guarantees:
//! * **Idempotent**: applying the returned actions and planning again yields `[]`.
//! * **Conservative**: physical links, kernel-protocol routes, IPv6 link-local
//!   addresses and anything on unmanaged links are never touched.
//!
//! Managed links are those named in the plan plus observed bridges and VLANs
//! carrying the [`MANAGED_ALIAS`] interface alias (set by [`Action::SetAlias`] on
//! every link the planner creates); only the latter may be deleted. A foreign
//! `br-*` (docker) or dotted VLAN without the alias is never touched.
//!
//! Action order: global sysctls (`conf/all`, `conf/default`, non-interface keys),
//! delete mismatched VLANs, create bridges (+ alias), create VLANs (+ alias),
//! masters (un-enslave, then enslave), MTU/MAC, link up/down, per-interface sysctls
//! (`conf/<if>/...`, they need the link), addresses (delete, then add), routes
//! (delete, then add), delete obsolete links.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::{
    AddrSpec, LinkSpec, MacAddr, NetPlan, RouteSpec, TABLE_MAIN, ValidationError, is_v6_link_local,
    sysctl_iface, sysctl_path,
};
use crate::observed::{LinkKind, Observed};

/// Interface alias (`IFLA_IFALIAS`) marking a bridge / VLAN as created by owr-net.
/// Only links carrying it may be deleted by the planner.
pub const MANAGED_ALIAS: &str = "owr";

/// One step towards the desired state. Links are addressed by name; the applier
/// resolves indexes at execution time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    CreateBridge {
        name: String,
        vlan_filtering: bool,
    },
    DeleteLink {
        name: String,
    },
    CreateVlan {
        name: String,
        parent: String,
        id: u16,
    },
    /// Enslave to `master`, or release when `None`.
    SetMaster {
        link: String,
        master: Option<String>,
    },
    SetUp {
        link: String,
    },
    SetDown {
        link: String,
    },
    SetMtu {
        link: String,
        mtu: u32,
    },
    SetMac {
        link: String,
        mac: MacAddr,
    },
    /// Set `IFLA_IFALIAS`; emitted right after a link is created so it is recognised
    /// as managed ([`MANAGED_ALIAS`]).
    SetAlias {
        link: String,
        alias: String,
    },
    /// Toggle bridge VLAN filtering on an existing bridge.
    SetVlanFiltering {
        link: String,
        enabled: bool,
    },
    AddAddr {
        link: String,
        addr: ipnet::IpNet,
    },
    DelAddr {
        link: String,
        addr: ipnet::IpNet,
    },
    AddRoute(RouteSpec),
    DelRoute(RouteSpec),
    Sysctl {
        key: String,
        value: String,
    },
}

/// Why planning failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("invalid plan: {0}")]
    Invalid(#[from] ValidationError),
    /// A physical link or bridge port is not present in the observed state.
    #[error("link {0:?} does not exist and cannot be created")]
    MissingLink(String),
    /// A link of the same name exists with an incompatible kind; the planner
    /// refuses to delete it.
    #[error("link {name:?} is a {found}, plan wants a {wanted}")]
    KindMismatch {
        name: String,
        wanted: &'static str,
        found: String,
    },
    /// A desired bridge port or VLAN parent names a link the planner is about to
    /// delete (managed, but absent from the plan).
    #[error("link {link:?} is referenced by the plan but is a managed link not in the plan")]
    ReferencesObsolete { link: String },
}

/// Mutable view of one link while actions are accumulated.
#[derive(Debug, Clone, Default)]
struct State {
    up: bool,
    mtu: Option<u32>,
    mac: Option<MacAddr>,
    master: Option<String>,
    vlan_filtering: bool,
}

fn set_alias(link: &str) -> Action {
    Action::SetAlias {
        link: link.to_owned(),
        alias: MANAGED_ALIAS.to_owned(),
    }
}

fn norm_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn route_matches(desired: &RouteSpec, observed: &RouteSpec) -> bool {
    desired.key() == observed.key() && (desired.dev.is_none() || desired.dev == observed.dev)
}

/// Compute the actions that turn `observed` into `desired`.
#[allow(clippy::too_many_lines)] // a single linear pass, split by phase comments
pub fn plan(desired: &NetPlan, observed: &Observed) -> Result<Vec<Action>, PlanError> {
    desired.validate_inner(false)?;

    let obs: HashMap<&str, &crate::observed::ObservedLink> = observed
        .links
        .iter()
        .map(|l| (l.name.as_str(), l))
        .collect();
    let name_of: HashMap<u32, &str> = observed
        .links
        .iter()
        .map(|l| (l.index, l.name.as_str()))
        .collect();
    let want: HashMap<&str, &LinkSpec> = desired.links.iter().map(|l| (l.name(), l)).collect();

    // --- existence and kind checks -------------------------------------------------
    let mut recreate: HashSet<&str> = HashSet::new();
    for spec in &desired.links {
        let found = obs.get(spec.name()).map(|o| &o.kind);
        let mismatch = |wanted: &'static str, kind: &LinkKind| PlanError::KindMismatch {
            name: spec.name().to_owned(),
            wanted,
            found: format!("{kind:?}"),
        };
        match (spec, found) {
            (LinkSpec::Physical { name, .. }, None) => {
                return Err(PlanError::MissingLink(name.clone()));
            }
            (LinkSpec::Physical { .. }, Some(k @ (LinkKind::Bridge | LinkKind::Vlan { .. }))) => {
                return Err(mismatch("physical link", k));
            }
            (LinkSpec::Bridge { .. }, Some(k)) if *k != LinkKind::Bridge => {
                return Err(mismatch("bridge", k));
            }
            (LinkSpec::Vlan { parent, id, name }, Some(k)) => match k {
                LinkKind::Vlan {
                    parent_index,
                    id: oid,
                } => {
                    if oid != id || name_of.get(parent_index) != Some(&parent.as_str()) {
                        recreate.insert(name.as_str());
                    }
                }
                other => return Err(mismatch("vlan", other)),
            },
            _ => {}
        }
    }
    // --- managed set -----------------------------------------------------------------
    // Only bridges / VLANs we created (alias) may be deleted; the name is no evidence.
    let mut obsolete: Vec<&crate::observed::ObservedLink> = observed
        .links
        .iter()
        .filter(|l| {
            matches!(l.kind, LinkKind::Bridge | LinkKind::Vlan { .. })
                && l.alias.as_deref() == Some(MANAGED_ALIAS)
                && !want.contains_key(l.name.as_str())
        })
        .collect();
    let obsolete_names: HashSet<&str> = obsolete.iter().map(|l| l.name.as_str()).collect();
    let mut managed: HashSet<&str> = want.keys().copied().collect();
    managed.extend(obsolete_names.iter().copied());

    // Every referenced parent / port must exist now or be created by the plan, and
    // must not be a link this very plan deletes.
    let will_exist = |n: &str| {
        obs.contains_key(n)
            || matches!(
                want.get(n),
                Some(LinkSpec::Bridge { .. } | LinkSpec::Vlan { .. })
            )
    };
    for spec in &desired.links {
        let refs: Vec<&String> = match spec {
            LinkSpec::Bridge { ports, .. } => ports.iter().collect(),
            LinkSpec::Vlan { parent, .. } => vec![parent],
            LinkSpec::Physical { .. } => vec![],
        };
        for r in refs {
            if !will_exist(r) {
                return Err(PlanError::MissingLink(r.clone()));
            }
            if obsolete_names.contains(r.as_str()) {
                return Err(PlanError::ReferencesObsolete { link: r.clone() });
            }
        }
    }

    // --- working state ----------------------------------------------------------------
    let mut state: HashMap<&str, State> = HashMap::new();
    for l in &observed.links {
        if recreate.contains(l.name.as_str()) {
            continue;
        }
        state.insert(
            l.name.as_str(),
            State {
                up: l.up,
                mtu: Some(l.mtu),
                mac: l.mac,
                master: l.master.map(|i| {
                    name_of
                        .get(&i)
                        .map_or_else(|| format!("#{i}"), |s| (*s).to_owned())
                }),
                vlan_filtering: l.vlan_filtering.unwrap_or(false),
            },
        );
    }

    let mut out: Vec<Action> = Vec::new();

    // --- global sysctls ---------------------------------------------------------------
    // Everything that is not `conf/<if>/...`, including `conf/all` and `conf/default`:
    // the kernel resets the per-interface values when `conf/all` is written, and new
    // links inherit `conf/default`, so these go first. Per-interface keys follow the
    // link phases (the interface must exist for the key to).
    let current: HashMap<String, String> = observed
        .sysctls
        .iter()
        .filter_map(|(k, v)| Some((sysctl_path(k).ok()?, norm_ws(v))))
        .collect();
    let mut per_iface: Vec<Action> = Vec::new();
    let exists_finally =
        |i: &str| want.contains_key(i) || (obs.contains_key(i) && !obsolete_names.contains(i));
    for (k, v) in &desired.sysctls {
        let path = sysctl_path(k)?;
        let iface = sysctl_iface(&path);
        // a recreated link starts from the defaults, whatever the old one had
        let differs =
            current.get(&path) != Some(&norm_ws(v)) || iface.is_some_and(|i| recreate.contains(i));
        let action = Action::Sysctl {
            key: k.clone(),
            value: v.clone(),
        };
        match iface {
            None if differs => out.push(action),
            // A key of an interface that will not exist (deleted below, or unknown)
            // cannot be written and would never converge; it is not an action.
            Some(i) if differs && exists_finally(i) => per_iface.push(action),
            _ => {}
        }
    }

    // --- delete VLANs whose parent or id changed --------------------------------------
    for spec in &desired.links {
        if recreate.contains(spec.name()) {
            out.push(Action::DeleteLink {
                name: spec.name().to_owned(),
            });
        }
    }

    // --- create bridges, fix vlan filtering, create vlans -----------------------------
    // Links created here get the alias at once; an existing link named in the plan
    // is adopted (marked) so it can be cleaned up when it leaves the plan.
    let is_marked = |n: &str| {
        obs.get(n)
            .is_none_or(|o| o.alias.as_deref() == Some(MANAGED_ALIAS))
    };
    for spec in &desired.links {
        if let LinkSpec::Bridge {
            name,
            vlan_filtering,
            ..
        } = spec
        {
            match state.get_mut(name.as_str()) {
                None => {
                    out.push(Action::CreateBridge {
                        name: name.clone(),
                        vlan_filtering: *vlan_filtering,
                    });
                    out.push(set_alias(name));
                    state.insert(
                        name,
                        State {
                            vlan_filtering: *vlan_filtering,
                            ..State::default()
                        },
                    );
                }
                Some(st) if st.vlan_filtering != *vlan_filtering => {
                    out.push(Action::SetVlanFiltering {
                        link: name.clone(),
                        enabled: *vlan_filtering,
                    });
                    st.vlan_filtering = *vlan_filtering;
                }
                Some(_) => {}
            }
            // an existing link named in the plan is adopted: mark it as ours
            if !is_marked(name) {
                out.push(set_alias(name));
            }
        }
    }
    for spec in &desired.links {
        if let LinkSpec::Vlan { name, parent, id } = spec
            && !state.contains_key(name.as_str())
        {
            out.push(Action::CreateVlan {
                name: name.clone(),
                parent: parent.clone(),
                id: *id,
            });
            out.push(set_alias(name));
            state.insert(name, State::default());
        } else if let LinkSpec::Vlan { name, .. } = spec
            && !is_marked(name)
        {
            out.push(set_alias(name));
        }
    }

    // --- masters ----------------------------------------------------------------------
    let desired_master: Vec<(&str, &str)> = desired
        .links
        .iter()
        .filter_map(|l| match l {
            LinkSpec::Bridge { name, ports, .. } => {
                Some(ports.iter().map(move |p| (p.as_str(), name.as_str())))
            }
            _ => None,
        })
        .flatten()
        .collect();
    let desired_master_of: HashMap<&str, &str> = desired_master.iter().copied().collect();
    for l in &observed.links {
        let Some(st) = state.get_mut(l.name.as_str()) else {
            continue;
        };
        if let Some(m) = &st.master
            && managed.contains(m.as_str())
            && !desired_master_of.contains_key(l.name.as_str())
        {
            out.push(Action::SetMaster {
                link: l.name.clone(),
                master: None,
            });
            st.master = None;
        }
    }
    for (port, bridge) in &desired_master {
        if let Some(st) = state.get_mut(port)
            && st.master.as_deref() != Some(bridge)
        {
            out.push(Action::SetMaster {
                link: (*port).to_owned(),
                master: Some((*bridge).to_owned()),
            });
            st.master = Some((*bridge).to_owned());
        }
    }

    // Links the planner sets down: the kernel flushes their routes (IPv4 addresses
    // survive), so observed routes on them no longer count.
    let mut flushed: HashSet<&str> = HashSet::new();

    // --- MTU / MAC (physical first: a bridge MTU is bounded by its ports) --------------
    for want_physical in [true, false] {
        for spec in &desired.links {
            let (name, mtu, mac) = match spec {
                LinkSpec::Physical { name, mtu, mac, .. } if want_physical => (name, mtu, mac),
                LinkSpec::Bridge { name, mtu, mac, .. } if !want_physical => (name, mtu, mac),
                _ => continue,
            };
            let Some(st) = state.get_mut(name.as_str()) else {
                continue;
            };
            // MTU 0 / no hardware address: not Ethernet, nothing to set
            let (has_mtu, has_mac) = obs
                .get(name.as_str())
                .map_or((true, true), |o| (o.mtu != 0, o.mac.is_some()));
            if let Some(mtu) = *mtu
                && has_mtu
                && st.mtu != Some(mtu)
            {
                out.push(Action::SetMtu {
                    link: name.clone(),
                    mtu,
                });
                st.mtu = Some(mtu);
            }
            if let Some(mac) = *mac
                && has_mac
                && st.mac != Some(mac)
            {
                if st.up {
                    out.push(Action::SetDown { link: name.clone() });
                    st.up = false;
                    flushed.insert(name.as_str());
                }
                out.push(Action::SetMac {
                    link: name.clone(),
                    mac,
                });
                st.mac = Some(mac);
            }
        }
    }

    // --- up / down ---------------------------------------------------------------------
    for spec in &desired.links {
        if matches!(spec, LinkSpec::Bridge { .. }) {
            bring_up(&mut state, spec.name(), &mut out);
        }
    }
    for spec in &desired.links {
        if matches!(spec, LinkSpec::Vlan { .. }) {
            bring_up(&mut state, spec.name(), &mut out);
        }
    }
    for (port, _) in &desired_master {
        if !want.contains_key(port) {
            bring_up(&mut state, port, &mut out);
        }
    }
    for spec in &desired.links {
        if let LinkSpec::Physical { name, up, .. } = spec {
            if *up {
                bring_up(&mut state, name, &mut out);
            } else if let Some(st) = state.get_mut(name.as_str())
                && st.up
            {
                out.push(Action::SetDown { link: name.clone() });
                st.up = false;
                flushed.insert(name.as_str());
            }
        }
    }

    // --- per-interface sysctls (the links exist now) ------------------------------
    out.append(&mut per_iface);

    // --- addresses ---------------------------------------------------------------------
    let live_addrs: Vec<&AddrSpec> = observed
        .addresses
        .iter()
        .filter(|a| !recreate.contains(a.link.as_str()))
        .collect();
    let mut seen: HashSet<(&str, ipnet::IpNet)> = HashSet::new();
    for a in &live_addrs {
        if managed.contains(a.link.as_str())
            && !is_v6_link_local(a.addr.addr())
            && !desired.addresses.contains(a)
            && seen.insert((a.link.as_str(), a.addr))
        {
            out.push(Action::DelAddr {
                link: a.link.clone(),
                addr: a.addr,
            });
        }
    }
    for a in &desired.addresses {
        if !live_addrs.contains(&a) {
            out.push(Action::AddAddr {
                link: a.link.clone(),
                addr: a.addr,
            });
        }
    }

    // --- routes ------------------------------------------------------------------------
    let live_routes: Vec<&RouteSpec> = observed
        .routes
        .iter()
        .filter(|r| {
            r.table == TABLE_MAIN
                && !r
                    .dev
                    .as_deref()
                    .is_some_and(|d| recreate.contains(d) || flushed.contains(d))
        })
        .collect();
    let mut seen_del = Vec::new();
    for o in &live_routes {
        if o.proto.is_ours()
            && o.dev.as_deref().is_some_and(|d| managed.contains(d))
            && !desired.routes.iter().any(|d| route_matches(d, o))
            && !seen_del.contains(&o.key())
        {
            seen_del.push(o.key());
            out.push(Action::DelRoute((*o).clone()));
        }
    }
    let mut seen_add = Vec::new();
    for d in &desired.routes {
        if !live_routes.iter().any(|o| route_matches(d, o)) && !seen_add.contains(&d.key()) {
            seen_add.push(d.key());
            out.push(Action::AddRoute(d.clone()));
        }
    }

    // --- delete obsolete links (vlans before bridges) -----------------------------------
    obsolete.sort_by_key(|l| (matches!(l.kind, LinkKind::Bridge), l.name.as_str()));
    for l in obsolete {
        out.push(Action::DeleteLink {
            name: l.name.clone(),
        });
    }

    Ok(out)
}

fn bring_up(state: &mut HashMap<&str, State>, name: &str, out: &mut Vec<Action>) {
    if let Some(st) = state.get_mut(name)
        && !st.up
    {
        out.push(Action::SetUp {
            link: name.to_owned(),
        });
        st.up = true;
    }
}
