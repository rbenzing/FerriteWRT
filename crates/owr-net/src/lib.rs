//! Declarative network plan, pure planner and Linux appliers (replaces netifd).
//!
//! * [`NetPlan`] describes the desired state; [`Observed`] the kernel's.
//! * [`plan`] diffs them into an ordered, idempotent list of [`Action`]s.
//! * `linux` (Linux only) observes and applies via rtnetlink and hosts the
//!   `DHCPv4` client. The pure [`wire`] and [`dhcp`] modules build on any host.
//!
//! Single-writer rule: only the applier mutates links, addresses and routes. The
//! DHCP client never configures anything; it emits [`dhcp::DhcpEvent`]s and the
//! caller merges the lease into the plan and re-runs `converge`.

#![forbid(unsafe_code)]

pub mod dhcp;
pub mod model;
pub mod observed;
pub mod planner;
pub mod wire;

#[cfg(target_os = "linux")]
pub mod linux;
pub use model::{
    AddrSpec, DhcpClientSpec, LinkSpec, MacAddr, NetPlan, RouteProto, RouteSpec, ValidationError,
};
pub use observed::{LinkKind, LinkStats, Observed, ObservedLink};
pub use planner::{Action, MANAGED_ALIAS, PlanError, plan};
