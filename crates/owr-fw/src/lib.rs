//! Firewall domain model and nftables renderer for ferritewrt.
//!
//! The crate is pure except for [`apply`] (Linux only). A [`Ruleset`] is validated
//! ([`Ruleset::validate`]) and rendered ([`render`]) into a complete, idempotent
//! `nft -f` script that replaces one dedicated `inet` table. It deliberately does not
//! depend on `owr-config`: `owr-apply` maps configuration into this model.

#![forbid(unsafe_code)]

mod model;
mod preset;
mod render;
mod validate;

#[cfg(test)]
mod fixtures;

#[cfg(target_os = "linux")]
pub mod apply;

pub use model::{
    Family, FlowOffload, Forwarding, Options, ParsePortRangeError, Policy, PortRange, Proto,
    Redirect, Rule, Ruleset, Zone, ZoneName, ZoneNameError,
};
pub use preset::flint2_default;
pub use render::{RenderError, render};
pub use validate::{Issue, is_valid_netdev_name};
