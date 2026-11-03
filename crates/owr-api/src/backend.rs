//! The boundary between the HTTP layer and the rest of the system.
//!
//! `owr-api` knows nothing about `owr-config`, `owr-net`, ... `owr-apply` implements
//! [`SystemBackend`] on top of them; [`crate::mock::MockBackend`] implements it in memory.

use std::future::Future;
use std::pin::Pin;

use crate::dto::{
    ApplyReport, BackendError, Lease, LogEntry, NetworkStatus, ServiceAction, ServiceStatus,
    SystemStatus, UserInfo, ValidationErrors, WirelessStatus,
};

/// Boxed, sendable future (keeps [`SystemBackend`] object safe).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Result alias for backend calls.
pub type BackendResult<T> = Result<T, BackendError>;

/// Everything the management API needs from the running system.
///
/// Contract notes:
/// * `config` must return a **redacted** document (secrets replaced by `"***"`);
///   `save_config` must treat `"***"` as "keep the stored secret".
/// * `verify_password` must take roughly the same time whether or not the user exists
///   (verify against a dummy hash for unknown users) and must return `None` on any
///   mismatch. Hashes never leave the backend.
/// * `set_user` with `password_hash == None` keeps the stored hash; for a new user
///   it is a [`BackendError::Invalid`] error. The hash is an Argon2id PHC string.
/// * `set_password` changes only the hash of an existing user ([`BackendError::NotFound`]
///   otherwise) and never touches role or enabled state, so a self-service password
///   change cannot revert a concurrent admin edit. `set_user` is for admin edits.
/// * `restore` is validated like `save_config` and may not remove the last administrator:
///   a backup without an enabled admin (with a valid Argon2id hash) is a
///   [`BackendError::Invalid`] error and leaves the system untouched.
/// * Mutating calls (`save_config`, `restore`, `set_user`, `set_password`, `delete_user`,
///   `service_action`, `reboot`) run in a detached task: they complete even if the HTTP
///   client disconnects or the request times out.
pub trait SystemBackend: Send + Sync + 'static {
    /// Board descriptor as JSON.
    fn board(&self) -> BoxFuture<'_, BackendResult<serde_json::Value>>;
    fn status(&self) -> BoxFuture<'_, BackendResult<SystemStatus>>;
    /// Redacted configuration document.
    fn config(&self) -> BoxFuture<'_, BackendResult<serde_json::Value>>;
    fn validate_config(
        &self,
        cfg: serde_json::Value,
    ) -> BoxFuture<'_, Result<(), ValidationErrors>>;
    /// Validate, persist and apply.
    fn save_config<'a>(
        &'a self,
        cfg: serde_json::Value,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>>;
    fn network_status(&self) -> BoxFuture<'_, BackendResult<NetworkStatus>>;
    fn wireless_status(&self) -> BoxFuture<'_, BackendResult<WirelessStatus>>;
    fn dhcp_leases(&self) -> BoxFuture<'_, BackendResult<Vec<Lease>>>;
    /// Rendered nftables ruleset text.
    fn firewall_preview(&self) -> BoxFuture<'_, BackendResult<String>>;
    /// Entries with `seq > since_seq`, ascending, at most `limit`.
    fn logs(&self, since_seq: u64, limit: u16) -> BoxFuture<'_, BackendResult<Vec<LogEntry>>>;
    fn services(&self) -> BoxFuture<'_, BackendResult<Vec<ServiceStatus>>>;
    fn service_action<'a>(
        &'a self,
        name: &'a str,
        action: ServiceAction,
    ) -> BoxFuture<'a, BackendResult<()>>;
    fn reboot(&self) -> BoxFuture<'_, BackendResult<()>>;
    fn users(&self) -> BoxFuture<'_, BackendResult<Vec<UserInfo>>>;
    /// Create or update a user.
    fn set_user(
        &self,
        user: UserInfo,
        password_hash: Option<String>,
    ) -> BoxFuture<'_, BackendResult<()>>;
    /// Replace the password hash of an existing user; nothing else changes.
    fn set_password<'a>(
        &'a self,
        name: &'a str,
        password_hash: String,
    ) -> BoxFuture<'a, BackendResult<()>>;
    fn delete_user<'a>(&'a self, name: &'a str) -> BoxFuture<'a, BackendResult<()>>;
    fn verify_password<'a>(
        &'a self,
        name: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, BackendResult<Option<UserInfo>>>;
    /// Unredacted `config.toml` bytes (admin only).
    fn backup(&self) -> BoxFuture<'_, BackendResult<Vec<u8>>>;
    fn restore<'a>(
        &'a self,
        bytes: Vec<u8>,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>>;
}
