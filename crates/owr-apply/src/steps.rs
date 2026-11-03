//! The order in which `run::apply_all` changes the system, as pure data.
//!
//! The sequence is the security argument, so it is built (and tested) on any host while the
//! Linux executor stays a thin loop over it:
//!
//! 1. [`Step::Hostname`]
//! 2. [`Step::FirewallBootstrap`]: the full ruleset but without the flowtable (the only part
//!    that needs the devices to exist; `iifname { ... }` set literals do not). From here on
//!    `forward` has `policy drop`.
//! 3. [`Step::ConvergeNet`]: links, addresses, routes and every sysctl except forwarding.
//! 4. [`Step::FirewallFinal`]: the complete ruleset, now with offload.
//! 5. [`Step::EnableForwarding`]: `ip_forward` and IPv6 forwarding, only after a ruleset
//!    with `policy drop` on forward is loaded.
//! 6. [`Step::DaemonFiles`]
//!
//! If a firewall step fails the executor sets forwarding to 0 and stops; whatever ruleset
//! is loaded (the bootstrap one at worst) stays loaded.

use std::collections::BTreeSet;

use owr_fw::{FlowOffload, Ruleset};
use owr_net::{Action, NetPlan};

use crate::Plans;
use crate::net::FORWARDING_KEYS;
use crate::topology::LAN_BRIDGE;

/// Sysctl leaf names whose failure to apply leaves the router weaker than configured.
const SECURITY_SYSCTLS: &[&str] = &[
    "rp_filter",
    "accept_redirects",
    "send_redirects",
    "kptr_restrict",
    "dmesg_restrict",
    "unprivileged_bpf_disabled",
    "bpf_jit_harden",
    "ip_forward",
];

/// One step of `run::apply_all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Hostname,
    /// Load this ruleset first; it must not need any device to exist.
    FirewallBootstrap(Ruleset),
    /// Converge the network to this plan (no forwarding sysctls in it).
    ConvergeNet(NetPlan),
    /// Load the complete ruleset.
    FirewallFinal(Ruleset),
    /// Write these forwarding sysctls.
    EnableForwarding(Vec<(String, String)>),
    DaemonFiles,
}

/// The ruleset to load before anything else: identical zones, rules, forwardings and
/// redirects (so `policy drop` and the WAN input policy are already in force), but without
/// the flowtable, whose devices must exist when it is created.
pub fn bootstrap_ruleset(rs: &Ruleset) -> Ruleset {
    let mut boot = rs.clone();
    boot.options.flow_offload = FlowOffload::Off;
    boot.options.offload_devices.clear();
    boot
}

/// `plan` without the forwarding sysctls, and those sysctls separately.
pub fn split_forwarding(plan: &NetPlan) -> (NetPlan, Vec<(String, String)>) {
    let (forwarding, rest): (Vec<_>, Vec<_>) = plan
        .sysctls
        .iter()
        .cloned()
        .partition(|(key, _)| FORWARDING_KEYS.contains(&key.as_str()));
    let mut converge = plan.clone();
    converge.sysctls = rest;
    (converge, forwarding)
}

/// The forwarding sysctls switched off: the safety fallback after a failed firewall step.
pub fn forwarding_off() -> Vec<(String, String)> {
    FORWARDING_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), "0".to_owned()))
        .collect()
}

/// The ordered steps for `plans` (see the module documentation).
pub fn apply_steps(plans: &Plans) -> Vec<Step> {
    let (converge, forwarding) = split_forwarding(&plans.net);
    vec![
        Step::Hostname,
        Step::FirewallBootstrap(bootstrap_ruleset(&plans.fw)),
        Step::ConvergeNet(converge),
        Step::FirewallFinal(plans.fw.clone()),
        Step::EnableForwarding(forwarding),
        Step::DaemonFiles,
    ]
}

/// The links whose failure cuts the router off: the WAN netdev, `br-lan` and its ports.
pub fn critical_links(plans: &Plans) -> BTreeSet<String> {
    let mut links = BTreeSet::from([plans.wan_dev.clone(), LAN_BRIDGE.to_owned()]);
    for spec in &plans.net.links {
        if let owr_net::LinkSpec::Bridge { name, ports, .. } = spec
            && name == LAN_BRIDGE
        {
            links.extend(ports.iter().cloned());
        }
    }
    links
}

/// Whether failing `action` must fail the apply: a security-relevant sysctl, or any link
/// or address action on a `critical` link (see [`critical_links`]). Everything else is a
/// warning.
pub fn is_critical(action: &Action, critical: &BTreeSet<String>) -> bool {
    let on = |link: &String| critical.contains(link);
    match action {
        Action::Sysctl { key, .. } => owr_net::model::sysctl_path(key)
            .ok()
            .and_then(|path| path.rsplit('/').next().map(str::to_owned))
            .is_some_and(|leaf| SECURITY_SYSCTLS.contains(&leaf.as_str())),
        Action::CreateBridge { name: link, .. }
        | Action::DeleteLink { name: link }
        | Action::SetUp { link }
        | Action::SetDown { link }
        | Action::SetMtu { link, .. }
        | Action::SetMac { link, .. }
        | Action::SetAlias { link, .. }
        | Action::SetVlanFiltering { link, .. }
        | Action::AddAddr { link, .. }
        | Action::DelAddr { link, .. } => on(link),
        Action::SetMaster { link, master } => on(link) || master.as_ref().is_some_and(on),
        Action::CreateVlan { .. } | Action::AddRoute(_) | Action::DelRoute(_) => false,
    }
}
