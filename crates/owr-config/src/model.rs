//! The typed configuration model. Field order here is the on-disk key order.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::{MacAddr, PortRange, Secret, duration_str};

/// The schema version this build reads and writes.
pub const CURRENT_SCHEMA: u32 = 1;

const DEFAULT_LAN_NET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 8, 1), 24);

fn default_true() -> bool {
    true
}

/// The whole system configuration (`/etc/ferritewrt/config.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Required; see [`CURRENT_SCHEMA`].
    pub schema: u32,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,
    pub network: NetworkConfig,
    #[serde(default)]
    pub wireless: WirelessConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub dhcp: DhcpConfig,
    #[serde(default)]
    pub services: ServicesConfig,
}

// ---------------------------------------------------------------- system

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SystemConfig {
    /// RFC 1123 label.
    pub hostname: String,
    /// IANA zone name, e.g. `Europe/Berlin`.
    pub timezone: String,
    pub ntp_servers: Vec<String>,
    pub log_level: LogLevel,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "ferritewrt".to_owned(),
            timezone: "UTC".to_owned(),
            ntp_servers: (0..4).map(|i| format!("{i}.pool.ntp.org")).collect(),
            log_level: LogLevel::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

// ----------------------------------------------------------------- users

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// PHC string, `$argon2id$v=19$m=..,t=..,p=..$salt$hash`.
    pub password_hash: Secret,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Viewer,
}

// --------------------------------------------------------------- network

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default)]
    pub lan: LanConfig,
    pub wan: WanConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vlans: Vec<VlanConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LanConfig {
    /// Board port names bridged into the LAN.
    pub ports: Vec<String>,
    /// Router address and prefix, e.g. `192.168.8.1/24`.
    pub ipv4: Ipv4Net,
    pub ipv6: LanIpv6,
    pub dhcp: DhcpPool,
}

impl Default for LanConfig {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            ipv4: DEFAULT_LAN_NET,
            ipv6: LanIpv6::default(),
            dhcp: DhcpPool::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanIpv6 {
    #[default]
    Disabled,
    Ula,
}

/// A `DHCPv4` pool: host offsets `start ..= start + limit - 1` within the subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DhcpPool {
    pub enabled: bool,
    pub start: u16,
    pub limit: u16,
    #[serde(with = "duration_str")]
    pub lease: Duration,
}

impl Default for DhcpPool {
    fn default() -> Self {
        Self {
            enabled: true,
            start: 100,
            limit: 150,
            lease: Duration::from_hours(12),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WanConfig {
    /// Board port name.
    pub port: String,
    #[serde(default)]
    pub proto: WanProto,
    #[serde(default)]
    pub ipv6: WanIpv6,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_override: Option<MacAddr>,
    /// 576..=9000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WanProto {
    Dhcp {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    },
    Static {
        ipv4: Ipv4Net,
        gateway: Ipv4Addr,
        #[serde(default)]
        dns: Vec<IpAddr>,
    },
    Pppoe {
        username: String,
        password: Secret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
}

impl Default for WanProto {
    fn default() -> Self {
        Self::Dhcp { hostname: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WanIpv6 {
    #[default]
    Disabled,
    Dhcpv6,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlanConfig {
    pub name: String,
    /// 1..=4094.
    pub id: u16,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<DhcpPool>,
    /// No forwarding between this VLAN and the LAN.
    #[serde(default)]
    pub isolated: bool,
}

// -------------------------------------------------------------- wireless

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WirelessConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub radios: Vec<RadioConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aps: Vec<ApConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioConfig {
    /// Board radio id, e.g. `radio0`.
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub channel: Channel,
    /// 20, 40, 80 or 160. Required: a sensible default depends on the band (see
    /// [`Config::defaults_for`]).
    pub width_mhz: u16,
    /// Two uppercase letters (regulatory domain).
    pub country: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txpower_dbm: Option<u8>,
}

/// Radio channel: `"auto"` or a channel number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Channel {
    #[default]
    Auto,
    Fixed(u16),
}

impl Serialize for Channel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Auto => s.serialize_str("auto"),
            Self::Fixed(c) => s.serialize_u16(*c),
        }
    }
}

impl<'de> Deserialize<'de> for Channel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u16),
            Text(String),
        }
        match Repr::deserialize(d)? {
            Repr::Num(c) => Ok(Self::Fixed(c)),
            Repr::Text(t) if t == "auto" => Ok(Self::Auto),
            Repr::Text(_) => Err(D::Error::custom(
                "invalid channel, expected \"auto\" or a channel number",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApConfig {
    /// Radio id from `[[wireless.radios]]`.
    pub radio: String,
    /// 1..=32 bytes.
    pub ssid: String,
    #[serde(default)]
    pub hidden: bool,
    pub security: Security,
    /// `"lan"` or a VLAN name.
    #[serde(default = "default_ap_network")]
    pub network: String,
    #[serde(default)]
    pub isolate_clients: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clients: Option<u16>,
}

fn default_ap_network() -> String {
    "lan".to_owned()
}

/// Wi-Fi security. Passphrases are 8..=63 printable ASCII characters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Security {
    Open,
    Wpa2Psk { passphrase: Secret },
    Wpa3Sae { passphrase: Secret },
    Wpa2Wpa3Mixed { passphrase: Secret },
}

impl Security {
    /// The passphrase, if this mode has one.
    pub fn passphrase(&self) -> Option<&Secret> {
        match self {
            Self::Open => None,
            Self::Wpa2Psk { passphrase }
            | Self::Wpa3Sae { passphrase }
            | Self::Wpa2Wpa3Mixed { passphrase } => Some(passphrase),
        }
    }
}

// -------------------------------------------------------------- firewall

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FirewallConfig {
    pub default_wan_input: WanInput,
    /// MT7986 WED / flowtable hardware offload.
    pub hw_offload: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            default_wan_input: WanInput::default(),
            hw_offload: true,
            port_forwards: Vec::new(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WanInput {
    #[default]
    Drop,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProto {
    Tcp,
    Udp,
    TcpUdp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub name: String,
    pub proto: ForwardProto,
    pub wan_port: PortRange,
    /// Must lie inside the LAN or a VLAN subnet.
    pub dest_ip: Ipv4Addr,
    pub dest_port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    WanIn,
    LanOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleProto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

/// A custom filter rule; rules are evaluated in file order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub direction: Direction,
    pub proto: RuleProto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<IpNet>,
    /// Only meaningful for `tcp` / `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<PortRange>,
    pub action: Action,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ------------------------------------------------------------------ dhcp

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DhcpConfig {
    /// Upstream DNS override; empty means use the WAN-provided servers.
    pub dns_servers: Vec<IpAddr>,
    pub local_domain: String,
    pub rebind_protection: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub static_leases: Vec<StaticLease>,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            dns_servers: Vec::new(),
            local_domain: "lan".to_owned(),
            rebind_protection: true,
            static_leases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLease {
    pub mac: MacAddr,
    /// Must lie inside the LAN or a VLAN subnet.
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

// -------------------------------------------------------------- services

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServicesConfig {
    pub api: ApiConfig,
    pub ssh: SshConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    pub bind: ApiBind,
    pub port: u16,
    #[serde(with = "duration_str")]
    pub session_ttl: Duration,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: ApiBind::default(),
            port: 443,
            session_ttl: Duration::from_mins(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiBind {
    #[default]
    Lan,
    LanAndVlans,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SshConfig {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub authorized_keys: Vec<String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 22,
            password_auth: false,
            authorized_keys: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------- redact

/// Copy of `cfg` with every secret replaced by [`Secret::REDACTED`], for API responses.
/// SSH public keys are not secrets and are kept.
pub fn redact(cfg: &Config) -> Config {
    let mut out = cfg.clone();
    let mask = || Secret::from(Secret::REDACTED);
    for u in &mut out.users {
        u.password_hash = mask();
    }
    if let WanProto::Pppoe { password, .. } = &mut out.network.wan.proto {
        *password = mask();
    }
    for ap in &mut out.wireless.aps {
        match &mut ap.security {
            Security::Open => {}
            Security::Wpa2Psk { passphrase }
            | Security::Wpa3Sae { passphrase }
            | Security::Wpa2Wpa3Mixed { passphrase } => *passphrase = mask(),
        }
    }
    out
}
