//! Linux side of `owr-net`: observe and apply via rtnetlink, and the `DHCPv4` socket.
//!
//! Single writer: [`apply`] / [`converge`] are the only code that mutates links,
//! addresses, routes and sysctls. Every await is bounded by [`NETLINK_TIMEOUT`].

mod apply;
pub mod dhcp;
mod observe;
pub mod ra;
pub mod sysfs;

use std::time::Duration;

use crate::model::NetPlan;
use crate::planner::{Action, PlanError, plan};

pub use apply::{AppliedReport, apply};
pub use observe::{observe, observe_sysctls};

/// Bound for every netlink request / dump / procfs access.
pub const NETLINK_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on links, addresses and routes accepted from one dump.
pub const MAX_DUMP_ENTRIES: usize = 4096;

/// Failure of an observe / apply / converge operation.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("netlink: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("more than {max} {what} reported; refusing to continue")]
    TooMany { what: &'static str, max: usize },
    #[error("{context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
    #[error("planning failed: {0}")]
    Plan(#[from] PlanError),
    /// After applying, the planner still wants these actions.
    #[error("network did not converge; {} action(s) remain", .0.len())]
    NotConverged(Vec<Action>),
}

/// Result of [`converge`].
#[derive(Debug)]
pub struct ConvergeReport {
    /// What the planner asked for.
    pub actions: Vec<Action>,
    /// What the applier managed to do.
    pub report: AppliedReport,
}

/// observe -> plan -> apply -> observe -> verify the plan is now empty.
pub async fn converge(
    handle: &rtnetlink::Handle,
    desired: &NetPlan,
) -> Result<ConvergeReport, NetError> {
    let mut observed = observe(handle).await?;
    observe_sysctls(&mut observed, desired).await;
    let actions = plan(desired, &observed)?;
    let report = apply(handle, &actions).await?;

    let mut after = observe(handle).await?;
    observe_sysctls(&mut after, desired).await;
    let remaining = plan(desired, &after)?;
    if !remaining.is_empty() {
        return Err(NetError::NotConverged(remaining));
    }
    Ok(ConvergeReport { actions, report })
}
