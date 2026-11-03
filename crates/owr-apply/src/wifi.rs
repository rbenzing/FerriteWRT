//! `Config` -> [`RadioPlan`]s, and a redaction helper for printing them.

use owr_board::Board;
use owr_config::{ApConfig, Config, Security as CfgSecurity};
use owr_wifi::{ApPlan, Band, Channel, Quirks, RadioPlan, Security, Standard};
use zeroize::Zeroizing;

use crate::error::MapError;
use crate::topology::{LAN_BRIDGE, vlan_bridge};

/// Drivers of the mt76 family that need the mt76 hostapd quirks. A board descriptor field
/// would be the better home (later improvement); until then the driver name decides.
const MT76_DRIVERS: &[&str] = &[
    "mt7915e", "mt7996e", "mt7921e", "mt7615e", "mt7603e", "mt76x2e",
];

/// The passphrase shown instead of the real one by [`redact_radios`].
const REDACTED: &str = "***";

fn band(b: owr_board::Band) -> Band {
    match b {
        owr_board::Band::G2 => Band::G2,
        owr_board::Band::G5 => Band::G5,
        owr_board::Band::G6 => Band::G6,
    }
}

fn standard(s: owr_board::WifiStandard) -> Standard {
    match s {
        owr_board::WifiStandard::N => Standard::N,
        owr_board::WifiStandard::Ac => Standard::Ac,
        owr_board::WifiStandard::Ax => Standard::Ax,
        owr_board::WifiStandard::Be => Standard::Be,
    }
}

fn security(s: &CfgSecurity) -> Security {
    let pass = |p: &owr_config::Secret| Zeroizing::new(p.expose().to_owned());
    match s {
        CfgSecurity::Open => Security::Open,
        CfgSecurity::Wpa2Psk { passphrase } => Security::Wpa2Psk {
            passphrase: pass(passphrase),
        },
        CfgSecurity::Wpa3Sae { passphrase } => Security::Wpa3Sae {
            passphrase: pass(passphrase),
        },
        CfgSecurity::Wpa2Wpa3Mixed { passphrase } => Security::Wpa2Wpa3Mixed {
            passphrase: pass(passphrase),
        },
    }
}

fn bridge_for(cfg: &Config, network: &str) -> Result<String, MapError> {
    if network == "lan" {
        Ok(LAN_BRIDGE.to_owned())
    } else if cfg.network.vlans.iter().any(|v| v.name == network) {
        Ok(vlan_bridge(network))
    } else {
        Err(MapError::UnknownNetwork(network.to_owned()))
    }
}

fn ap_plan(cfg: &Config, ap: &ApConfig, phy_index: u8, n: usize) -> Result<ApPlan, MapError> {
    Ok(ApPlan {
        ifname: if n == 0 {
            format!("wlan{phy_index}")
        } else {
            format!("wlan{phy_index}-{n}")
        },
        ssid: ap.ssid.clone(),
        hidden: ap.hidden,
        security: security(&ap.security),
        bridge: Some(bridge_for(cfg, &ap.network)?),
        isolate_clients: ap.isolate_clients,
        max_clients: ap.max_clients,
        mac: None,
    })
}

/// One plan per enabled radio that has at least one AP (radios without APs get no hostapd).
pub(crate) fn build_radios(board: &Board, cfg: &Config) -> Result<Vec<RadioPlan>, MapError> {
    let wl = &cfg.wireless;
    if let Some(ap) = wl
        .aps
        .iter()
        .find(|ap| !wl.radios.iter().any(|r| r.id == ap.radio))
    {
        return Err(MapError::UnknownRadio(ap.radio.clone()));
    }
    let mut out = Vec::new();
    for radio in &wl.radios {
        let hw = board
            .radio(&radio.id)
            .ok_or_else(|| MapError::UnknownRadio(radio.id.clone()))?;
        if !radio.enabled {
            continue;
        }
        if radio.width_mhz > hw.max_width_mhz {
            return Err(MapError::WidthExceedsBoard {
                radio: radio.id.clone(),
                width: radio.width_mhz,
                max: hw.max_width_mhz,
            });
        }
        let aps = wl
            .aps
            .iter()
            .filter(|ap| ap.radio == radio.id)
            .enumerate()
            .map(|(n, ap)| ap_plan(cfg, ap, hw.phy_index, n))
            .collect::<Result<Vec<_>, _>>()?;
        if aps.is_empty() {
            continue;
        }
        out.push(RadioPlan {
            phy: format!("phy{}", hw.phy_index),
            band: band(hw.band),
            channel: match radio.channel {
                owr_config::Channel::Auto => Channel::Auto,
                owr_config::Channel::Fixed(c) => Channel::Fixed(c),
            },
            width_mhz: radio.width_mhz,
            country: radio.country.clone(),
            txpower_dbm: radio.txpower_dbm,
            standards: hw.standards.iter().copied().map(standard).collect(),
            aps,
            driver_quirks: Quirks {
                mt76: MT76_DRIVERS.contains(&board.wifi.driver.as_str()),
            },
        });
    }
    Ok(out)
}

/// Copy of `radios` with every passphrase replaced by `***`, safe to print or log.
pub fn redact_radios(radios: &[RadioPlan]) -> Vec<RadioPlan> {
    let mask = || Zeroizing::new(REDACTED.to_owned());
    let mut out = radios.to_vec();
    for ap in out.iter_mut().flat_map(|r| r.aps.iter_mut()) {
        ap.security = match &ap.security {
            Security::Open => Security::Open,
            Security::Wpa2Psk { .. } => Security::Wpa2Psk { passphrase: mask() },
            Security::Wpa3Sae { .. } => Security::Wpa3Sae { passphrase: mask() },
            Security::Wpa2Wpa3Mixed { .. } => Security::Wpa2Wpa3Mixed { passphrase: mask() },
        };
    }
    out
}
