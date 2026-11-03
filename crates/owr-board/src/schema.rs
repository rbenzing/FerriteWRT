//! Board descriptor schema. Mirrors `boards/<id>.toml`; unknown fields are rejected.

use serde::{Deserialize, Serialize};

use crate::hex;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Board {
    pub schema: u32,
    pub board: Identity,
    pub soc: Soc,
    pub memory: Memory,
    pub storage: Storage,
    pub console: Console,
    pub ethernet: Ethernet,
    pub wifi: Wifi,
    pub leds: Vec<Led>,
    pub buttons: Vec<Button>,
    #[serde(default)]
    pub usb: Usb,
    pub openwrt: OpenWrt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub vendor: String,
    pub model: String,
    pub compatible: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Soc {
    pub family: String,
    pub arch: String,
    pub cpu: String,
    pub cores: u8,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    pub ram_mib: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub kind: StorageKind,
    pub device: String,
    pub root: String,
    #[serde(default)]
    pub overlay: Option<String>,
    #[serde(default)]
    pub overlay_fs: Option<String>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    Emmc,
    Nand,
    Nor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    pub name: String,
    pub role: PartitionRole,
    /// Bytes; written as an integer or a string like `"0x80000"`.
    #[serde(default, deserialize_with = "hex::opt::deserialize")]
    pub size: Option<u64>,
    #[serde(default)]
    pub cells: Vec<Cell>,
}

/// Well-known roles are lowercase strings; anything else must be spelled `other:<name>`.
/// A bare unknown word (usually a typo of a known role) is a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum PartitionRole {
    Bootenv,
    Factory,
    Kernel,
    Bootloader,
    Rootfs,
    Overlay,
    Other(String),
}

impl TryFrom<String> for PartitionRole {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        match s.as_str() {
            "bootenv" => Ok(Self::Bootenv),
            "factory" => Ok(Self::Factory),
            "kernel" => Ok(Self::Kernel),
            "bootloader" => Ok(Self::Bootloader),
            "rootfs" => Ok(Self::Rootfs),
            "overlay" => Ok(Self::Overlay),
            _ => match s.strip_prefix("other:") {
                Some(name) if !name.is_empty() => Ok(Self::Other(name.to_owned())),
                _ => Err(format!(
                    "unknown partition role {s:?} (expected bootenv, factory, kernel, \
                     bootloader, rootfs, overlay, or other:<name>)"
                )),
            },
        }
    }
}

impl From<PartitionRole> for String {
    fn from(r: PartitionRole) -> Self {
        match r {
            PartitionRole::Bootenv => "bootenv".into(),
            PartitionRole::Factory => "factory".into(),
            PartitionRole::Kernel => "kernel".into(),
            PartitionRole::Bootloader => "bootloader".into(),
            PartitionRole::Rootfs => "rootfs".into(),
            PartitionRole::Overlay => "overlay".into(),
            PartitionRole::Other(s) => format!("other:{s}"),
        }
    }
}

/// A named byte range inside a partition (e.g. an nvmem cell).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub name: String,
    #[serde(deserialize_with = "hex::deserialize")]
    pub offset: u64,
    #[serde(deserialize_with = "hex::deserialize")]
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Console {
    pub device: String,
    pub baud: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ethernet {
    pub mac_source: String,
    #[serde(default)]
    pub switch: Option<Switch>,
    pub ports: Vec<EthernetPort>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Switch {
    pub driver: String,
    pub dsa: bool,
    pub cpu_port: u8,
    pub cpu_netdev: String,
    pub cpu_link_mbps: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthernetPort {
    pub name: String,
    pub netdev: String,
    pub role: PortRole,
    pub speed_mbps: u32,
    #[serde(default)]
    pub switch_port: Option<u8>,
    #[serde(default)]
    pub phy: Option<Phy>,
    pub mac_offset: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortRole {
    Lan,
    Wan,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phy {
    pub kind: String,
    pub mdio_addr: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wifi {
    pub driver: String,
    #[serde(default)]
    pub eeprom: Option<String>,
    #[serde(default)]
    pub mac_source: Option<String>,
    pub firmware: Vec<String>,
    pub radios: Vec<Radio>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Radio {
    pub id: String,
    pub phy_index: u8,
    pub band: Band,
    pub max_width_mhz: u16,
    pub standards: Vec<WifiStandard>,
    pub mac_offset: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Band {
    #[serde(rename = "2g")]
    G2,
    #[serde(rename = "5g")]
    G5,
    #[serde(rename = "6g")]
    G6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiStandard {
    N,
    Ac,
    Ax,
    Be,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Led {
    pub name: String,
    pub gpio: u16,
    pub active_low: bool,
    pub roles: Vec<LedRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LedRole {
    Boot,
    Failsafe,
    Running,
    Upgrade,
    Wan,
    Lan,
    Wifi,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Button {
    pub name: String,
    pub gpio: u16,
    pub active_low: bool,
    pub keycode: String,
    pub short_press: ButtonAction,
    #[serde(default)]
    pub long_press_secs: Option<u8>,
    #[serde(default)]
    pub long_press: Option<ButtonAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ButtonAction {
    Reboot,
    FactoryReset,
    WifiToggle,
    Wps,
    None,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usb {
    #[serde(default)]
    pub controllers: Vec<UsbController>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsbController {
    pub version: String,
    #[serde(default)]
    pub vbus_gpio: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenWrt {
    pub target: String,
    pub subtarget: String,
    pub profile: String,
    pub kernel_modules: Vec<String>,
    pub firmware_packages: Vec<String>,
    pub images: Vec<String>,
}
