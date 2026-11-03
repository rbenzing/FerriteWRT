//! Data transfer objects exchanged between the HTTP layer and a [`SystemBackend`].
//!
//! [`SystemBackend`]: crate::backend::SystemBackend

use std::fmt;

use serde::{Deserialize, Serialize};

/// Access level of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only access.
    Viewer,
    /// Full access.
    Admin,
}

/// A user as exposed over the API (never contains a password hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub role: Role,
    pub enabled: bool,
}

/// Memory figures in KiB (as in `/proc/meminfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInfo {
    pub total_kib: u64,
    pub free_kib: u64,
    pub available_kib: u64,
}

/// Board identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardId {
    pub id: String,
    pub vendor: String,
    pub model: String,
}

/// Firmware identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firmware {
    pub version: String,
    pub build: String,
}

/// Overall system status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    pub hostname: String,
    pub uptime_secs: u64,
    pub load: [f32; 3],
    pub mem: MemInfo,
    /// CPU temperature in millidegrees Celsius.
    pub cpu_temp_mc: Option<i32>,
    pub board: BoardId,
    pub firmware: Firmware,
    pub time_unix: u64,
}

/// One network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iface {
    pub name: String,
    pub role: Option<String>,
    pub up: bool,
    pub carrier: bool,
    pub speed_mbps: Option<u32>,
    pub mac: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// WAN uplink state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WanStatus {
    pub proto: String,
    pub addr: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub uptime_secs: u64,
}

/// Interfaces and WAN uplink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub interfaces: Vec<Iface>,
    pub wan: Option<WanStatus>,
}

/// One Wi-Fi radio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadioStatus {
    pub id: String,
    pub phy: String,
    pub band: String,
    pub channel: u32,
    pub width_mhz: u32,
    pub txpower_dbm: u32,
    pub enabled: bool,
}

/// One associated Wi-Fi station.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    pub mac: String,
    pub hostname: Option<String>,
    pub signal_dbm: i32,
    pub rx_rate_kbps: u32,
    pub tx_rate_kbps: u32,
    pub connected_secs: u64,
}

/// One access point (BSS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApStatus {
    pub ifname: String,
    pub radio: String,
    pub ssid: String,
    pub bssid: String,
    pub clients: Vec<Client>,
}

/// Radios and access points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessStatus {
    pub radios: Vec<RadioStatus>,
    pub aps: Vec<ApStatus>,
}

/// A `DHCPv4` lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub expires_unix: u64,
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub ts_ms: u64,
    /// Syslog priority (0 = emerg .. 7 = debug).
    pub prio: u8,
    pub source: String,
    pub msg: String,
}

/// State of one supervised service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: String,
    pub pid: Option<u32>,
    pub since_unix: u64,
    pub restarts: u32,
}

/// Actions that can be requested for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAction {
    Restart,
    Reload,
}

/// Result of persisting and applying a configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub changed: bool,
    pub summary: Vec<String>,
    pub warnings: Vec<String>,
}

/// One field-level validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    /// Dotted path into the config document, e.g. `wireless.aps[0].ssid`.
    pub path: String,
    pub message: String,
}

/// A set of validation problems (never empty when used as an error).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationErrors {
    pub errors: Vec<FieldError>,
}

impl ValidationErrors {
    /// Convenience constructor for a single problem.
    pub fn single(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            errors: vec![FieldError {
                path: path.into(),
                message: message.into(),
            }],
        }
    }

    pub fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.errors.push(FieldError {
            path: path.into(),
            message: message.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// `Ok(())` when empty, otherwise `Err(self)`.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} validation error(s)", self.errors.len())?;
        for e in &self.errors {
            write!(f, "; {}: {}", e.path, e.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Failure reported by a backend; mapped to HTTP 503/422/404/500.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("invalid input: {0}")]
    Invalid(ValidationErrors),
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ValidationErrors> for BackendError {
    fn from(v: ValidationErrors) -> Self {
        Self::Invalid(v)
    }
}
