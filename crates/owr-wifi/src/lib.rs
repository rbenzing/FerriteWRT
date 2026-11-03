//! Wi-Fi domain model and hostapd integration.
//!
//! Pure part (builds and tests on any host): the [`RadioPlan`] model, validation,
//! [`render_hostapd`], hostapd reply parsers ([`reply`]) and [`write_config`].
//! Linux-only part ([`sys`]): sysfs phy discovery and the hostapd control-socket client.
//!
//! This crate deliberately knows nothing about the user-facing configuration schema;
//! `owr-apply` maps `owr-config` into [`RadioPlan`]s.

#![forbid(unsafe_code)]

mod channel;
mod config_file;
mod model;
mod render;
pub mod reply;
mod validate;

#[cfg(target_os = "linux")]
pub mod sys;

pub use channel::{center_channel, is_valid_channel};
pub use config_file::{ConfigWriteError, write_config};
pub use model::{
    ApPlan, Band, Channel, MacAddr, MacParseError, Quirks, RadioPlan, Security, Standard,
};
pub use render::{RenderError, ctrl_dir, render_hostapd};
pub use validate::{Issue, MAX_APS, is_valid_ifname};
