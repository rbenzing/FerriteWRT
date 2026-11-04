//! Integration layer of ferritewrt: maps the user-facing [`owr_config::Config`] plus the
//! [`owr_board::Board`] onto the domain plans of `owr-net`, `owr-fw` and `owr-wifi`,
//! renders the configs of the kept daemons (dnsmasq, hostapd) and, on Linux ([`run`]),
//! drives the appliers; [`daemon`] is the long-running network daemon (WAN `DHCPv4`
//! client, IPv6 router advertisements).
//!
//! [`build_plans`] is pure and deterministic: the same inputs always give equal [`Plans`],
//! so applying twice is a no-op. Domain crates never see `owr-config`; the mapping lives
//! here and nowhere else. Inputs that cannot be derived from the config (the persistent
//! ULA prefix, the run directory) enter through [`Inputs`] / [`build_plans_with`].

#![forbid(unsafe_code)]

mod dnsmasq;
mod error;
mod fw;
mod net;
mod topology;
mod wifi;

#[cfg(target_os = "linux")]
pub mod daemon;
pub mod files;
pub mod lease;
pub mod netd;
#[cfg(target_os = "linux")]
pub mod run;
pub mod steps;
pub mod ula;

use std::path::PathBuf;

use ipnet::Ipv6Net;
use owr_board::Board;
use owr_common::paths::RUN_DIR;
use owr_config::Config;

pub use dnsmasq::resolv_conf;
pub use error::MapError;
pub use netd::NetdPlan;
pub use wifi::redact_radios;

/// Everything derived from `(Board, Config)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plans {
    pub net: owr_net::NetPlan,
    pub fw: owr_fw::Ruleset,
    /// One entry per enabled radio that has at least one AP.
    pub radios: Vec<owr_wifi::RadioPlan>,
    pub dnsmasq_conf: String,
    /// What the network daemon runs (WAN `DHCPv4` client, router advertisements).
    pub netd: NetdPlan,
    pub hostname: String,
    /// Same list as `net.sysctls`, kept for callers that only need the kernel knobs.
    pub sysctl: Vec<(String, String)>,
    /// Netdev of the WAN port; its link and address actions are security relevant.
    pub wan_dev: String,
    /// Non-fatal mapping problems (e.g. IPv6 ULA requested but no prefix available).
    pub warnings: Vec<String>,
}

/// Inputs of the mapping that do not come from `(Board, Config)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inputs {
    /// The persistent site ULA prefix (`fd00::/8` + 40 random bits, a /48; see [`ula`]).
    /// Only used when `network.lan.ipv6 = ula`; without it no ULA address is planned and
    /// [`Plans::warnings`] says so.
    pub ula_prefix: Option<Ipv6Net>,
    /// Where dnsmasq keeps its lease and pid files; default `RUN_DIR`.
    pub run_dir: Option<PathBuf>,
}

impl Inputs {
    fn run_dir(&self) -> PathBuf {
        self.run_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(RUN_DIR))
    }
}

/// Map `cfg` onto the domain plans with default [`Inputs`] (no ULA prefix), then validate
/// each plan. See [`build_plans_with`].
pub fn build_plans(board: &Board, cfg: &Config) -> Result<Plans, MapError> {
    build_plans_with(board, cfg, &Inputs::default())
}

/// Map `cfg` onto the domain plans, then validate each plan.
///
/// `cfg` is expected to have passed `Config::validate_against(board)`; the checks here
/// only guard the mapping itself (unknown names, hardware limits, injection into daemon
/// configs) and surface the domain crates' own validation issues.
pub fn build_plans_with(board: &Board, cfg: &Config, inputs: &Inputs) -> Result<Plans, MapError> {
    dnsmasq::check_token("system.hostname", &cfg.system.hostname)?;
    let run_dir = inputs.run_dir();
    let topo = topology::Topology::resolve(board, cfg)?;
    let mut warnings = Vec::new();
    let sysctl = net::sysctls(net::ipv6_enabled(cfg));
    let net = net::build_net(board, cfg, &topo, &sysctl, inputs.ula_prefix, &mut warnings)?;
    let fw = fw::build_fw(cfg, &topo)?;
    let radios = wifi::build_radios(board, cfg)?;
    let dnsmasq_conf = dnsmasq::render_dnsmasq(cfg, &topo, &run_dir)?;
    let netd = netd::build_netd(&net, topo.wan_dev);

    net.validate()?;
    fw.validate().map_err(MapError::Fw)?;
    for radio in &radios {
        radio.validate().map_err(MapError::Wifi)?;
    }
    for ra in &netd.ra {
        ra.validate()?;
    }
    Ok(Plans {
        sysctl: net.sysctls.clone(),
        net,
        fw,
        radios,
        dnsmasq_conf,
        netd,
        hostname: cfg.system.hostname.clone(),
        wan_dev: topo.wan_dev.to_owned(),
        warnings,
    })
}

#[cfg(test)]
mod tests;
