//! Validation against, and defaults derived from, a board descriptor.

use owr_board::{Band, Board, PortRole};

use crate::error::Issue;
use crate::model::{
    CURRENT_SCHEMA, Channel, Config, DhcpConfig, FirewallConfig, LanConfig, NetworkConfig,
    RadioConfig, ServicesConfig, SystemConfig, WanConfig, WirelessConfig,
};
use crate::validate::Issues;

/// Regulatory domain written by [`Config::defaults_for`]; first-boot setup should replace it.
const DEFAULT_COUNTRY: &str = "US";

fn modulo(n: u16, m: u16) -> u16 {
    n.checked_rem(m).unwrap_or(0)
}

/// Is `c` a channel number that exists in `band`?
fn channel_in_band(band: Band, c: u16) -> bool {
    match band {
        Band::G2 => (1..=13).contains(&c),
        Band::G5 => {
            ((36..=64).contains(&c) || (100..=144).contains(&c)) && modulo(c, 4) == 0
                || (149..=177).contains(&c) && modulo(c, 4) == 1
        }
        Band::G6 => (1..=233).contains(&c) && modulo(c, 4) == 1,
    }
}

fn band_name(band: Band) -> &'static str {
    match band {
        Band::G2 => "2.4 GHz",
        Band::G5 => "5 GHz",
        Band::G6 => "6 GHz",
    }
}

/// Does fixed channel `c` start a legal wide block? Only 5 GHz 80 and 160 MHz are constrained
/// (20/40 MHz and other bands accept every channel of the band). The blocks are the
/// standard center-channel groups: 80 MHz begins at 36, 52, 100, 116, 132 or 149 and spans
/// four channels; 160 MHz is 36..=64 or 100..=128. (`owr-wifi` owns the full center-channel
/// table; this crate cannot depend on it, so the minimal rule is repeated here.)
fn channel_fits_width(band: Band, c: u16, width_mhz: u16) -> bool {
    const BLOCKS_80: [u16; 6] = [36, 52, 100, 116, 132, 149];
    const BLOCKS_160: [(u16, u16); 2] = [(36, 64), (100, 128)];
    match (band, width_mhz) {
        (Band::G5, 80) => BLOCKS_80
            .iter()
            .any(|start| (*start..=start.saturating_add(12)).contains(&c)),
        (Band::G5, 160) => BLOCKS_160.iter().any(|(lo, hi)| (*lo..=*hi).contains(&c)),
        _ => true,
    }
}

fn role_name(role: PortRole) -> &'static str {
    match role {
        PortRole::Lan => "lan",
        PortRole::Wan => "wan",
    }
}

impl Config {
    /// All issues from [`Config::validate`] plus board checks: every port and radio exists,
    /// the WAN port has the board role `wan` and LAN/VLAN ports the role `lan`, radio width
    /// fits the hardware and band, and fixed channels exist in the band, fit the width (5 GHz
    /// 80/160 MHz blocks) and are legal in the radio's country.
    pub fn validate_against(&self, board: &Board) -> Result<(), Vec<Issue>> {
        let mut issues = Issues::default();
        self.validate_into(&mut issues);

        let known = || {
            board
                .ethernet
                .ports
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut check_port = |path: String, name: &str, want: PortRole| match board.port(name) {
            None => issues.add(
                path,
                format!("unknown port '{name}' (board has: {})", known()),
            ),
            Some(p) if p.role != want => issues.add(
                path,
                format!(
                    "port '{name}' has board role '{}' but is used as {}",
                    role_name(p.role),
                    role_name(want)
                ),
            ),
            Some(_) => {}
        };
        let net = &self.network;
        check_port("network.wan.port".to_owned(), &net.wan.port, PortRole::Wan);
        for (i, p) in net.lan.ports.iter().enumerate() {
            check_port(format!("network.lan.ports[{i}]"), p, PortRole::Lan);
        }
        for (vi, v) in net.vlans.iter().enumerate() {
            for (pi, p) in v.ports.iter().enumerate() {
                check_port(format!("network.vlans[{vi}].ports[{pi}]"), p, PortRole::Lan);
            }
        }

        for (i, r) in self.wireless.radios.iter().enumerate() {
            check_radio_against(r, &format!("wireless.radios[{i}]"), board, &mut issues);
        }
        issues.into_result()
    }

    /// First-boot defaults for `board`: all LAN ports bridged, the first WAN port on DHCP,
    /// every radio enabled on auto channel at a safe width, no APs, no users.
    ///
    /// A board without a WAN port yields an empty `network.wan.port`, which
    /// [`Config::validate`] reports.
    pub fn defaults_for(board: &Board) -> Config {
        let wan_port = board
            .wan_ports()
            .next()
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let radios = board
            .wifi
            .radios
            .iter()
            .map(|r| {
                let safe = match r.band {
                    Band::G2 => 20,
                    Band::G5 | Band::G6 => 80,
                };
                RadioConfig {
                    id: r.id.clone(),
                    enabled: true,
                    channel: Channel::Auto,
                    width_mhz: safe.min(r.max_width_mhz),
                    country: DEFAULT_COUNTRY.to_owned(),
                    txpower_dbm: None,
                }
            })
            .collect();
        Config {
            schema: CURRENT_SCHEMA,
            system: SystemConfig::default(),
            users: Vec::new(),
            network: NetworkConfig {
                lan: LanConfig {
                    ports: board.lan_ports().map(|p| p.name.clone()).collect(),
                    ..LanConfig::default()
                },
                wan: WanConfig {
                    port: wan_port,
                    proto: crate::model::WanProto::default(),
                    ipv6: crate::model::WanIpv6::default(),
                    mac_override: None,
                    mtu: None,
                },
                vlans: Vec::new(),
            },
            wireless: WirelessConfig {
                radios,
                aps: Vec::new(),
            },
            firewall: FirewallConfig::default(),
            dhcp: DhcpConfig::default(),
            services: ServicesConfig::default(),
        }
    }
}

fn check_radio_against(r: &RadioConfig, path: &str, board: &Board, issues: &mut Issues) {
    let Some(hw) = board.radio(&r.id) else {
        let ids: Vec<&str> = board.wifi.radios.iter().map(|r| r.id.as_str()).collect();
        issues.add(
            format!("{path}.id"),
            format!("unknown radio '{}' (board has: {})", r.id, ids.join(", ")),
        );
        return;
    };
    if r.width_mhz > hw.max_width_mhz {
        issues.add(
            format!("{path}.width_mhz"),
            format!(
                "{} MHz exceeds the {} MHz maximum of {}",
                r.width_mhz, hw.max_width_mhz, r.id
            ),
        );
    }
    if hw.band == Band::G2 && r.width_mhz > 40 {
        issues.add(
            format!("{path}.width_mhz"),
            "2.4 GHz supports only 20 or 40 MHz",
        );
    }
    let Channel::Fixed(c) = r.channel else {
        return;
    };
    if !channel_in_band(hw.band, c) {
        issues.add(
            format!("{path}.channel"),
            format!("{c} is not a {} channel", band_name(hw.band)),
        );
        return;
    }
    if !channel_fits_width(hw.band, c, r.width_mhz) {
        issues.add(
            format!("{path}.channel"),
            format!(
                "channel {c} is not inside a valid {} MHz block on {}",
                r.width_mhz,
                band_name(hw.band)
            ),
        );
    }
    // FCC: 2.4 GHz channels 12 and 13 are not allowed in the US.
    if hw.band == Band::G2 && r.country == "US" && c >= 12 {
        issues.add(
            format!("{path}.channel"),
            format!("2.4 GHz channel {c} is not allowed in country US"),
        );
    }
}
