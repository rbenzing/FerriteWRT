//! Wi-Fi domain model. Secrets are held in [`Zeroizing`] strings and never `Debug`-printed.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Frequency band of a radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Band {
    #[serde(rename = "2g")]
    G2,
    #[serde(rename = "5g")]
    G5,
    #[serde(rename = "6g")]
    G6,
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::G2 => "2g",
            Self::G5 => "5g",
            Self::G6 => "6g",
        })
    }
}

/// Channel selection: automatic (hostapd ACS) or a fixed primary channel number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Auto,
    Fixed(u16),
}

/// IEEE 802.11 amendment a radio may advertise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standard {
    /// 802.11n (HT)
    N,
    /// 802.11ac (VHT), 5 GHz only
    Ac,
    /// 802.11ax (HE)
    Ax,
    /// 802.11be (EHT)
    Be,
}

impl fmt::Display for Standard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::N => "n",
            Self::Ac => "ac",
            Self::Ax => "ax",
            Self::Be => "be",
        })
    }
}

/// Driver-specific behaviour switches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quirks {
    /// mt76 (mt7915/mt7986) radio: advertise the full beamforming capability set
    /// (MU-MIMO beamformer, 4-antenna sounding). Other drivers get a conservative set.
    pub mt76: bool,
}

/// A 48-bit MAC address, text form `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

/// Error parsing a [`MacAddr`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid MAC address {0:?}: expected aa:bb:cc:dd:ee:ff")]
pub struct MacParseError(String);

impl MacAddr {
    /// Group (multicast/broadcast) bit set: not usable as a BSSID.
    pub fn is_multicast(self) -> bool {
        self.0.first().is_some_and(|b| b & 1 != 0)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || MacParseError(s.to_owned());
        let mut out = [0u8; 6];
        let mut parts = s.split(':');
        for slot in &mut out {
            let part = parts.next().ok_or_else(err)?;
            // from_str_radix would accept a leading '+', so check digits explicitly.
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err());
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(out))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Authentication mode of one BSS.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Security {
    Open,
    Wpa2Psk { passphrase: Zeroizing<String> },
    Wpa3Sae { passphrase: Zeroizing<String> },
    Wpa2Wpa3Mixed { passphrase: Zeroizing<String> },
}

impl Security {
    /// The passphrase, if this mode has one.
    pub fn passphrase(&self) -> Option<&str> {
        match self {
            Self::Open => None,
            Self::Wpa2Psk { passphrase }
            | Self::Wpa3Sae { passphrase }
            | Self::Wpa2Wpa3Mixed { passphrase } => Some(passphrase.as_str()),
        }
    }
}

impl fmt::Debug for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Open => return f.write_str("Open"),
            Self::Wpa2Psk { .. } => "Wpa2Psk",
            Self::Wpa3Sae { .. } => "Wpa3Sae",
            Self::Wpa2Wpa3Mixed { .. } => "Wpa2Wpa3Mixed",
        };
        f.debug_struct(name)
            .field("passphrase", &format_args!("<redacted>"))
            .finish()
    }
}

/// One BSS (virtual AP) on a radio.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApPlan {
    /// Interface name, e.g. `wlan0`, `wlan0-1` (at most 15 bytes).
    pub ifname: String,
    /// 1..=32 bytes.
    pub ssid: String,
    pub hidden: bool,
    pub security: Security,
    /// Bridge to attach to, e.g. `br-lan`.
    pub bridge: Option<String>,
    pub isolate_clients: bool,
    pub max_clients: Option<u16>,
    pub mac: Option<MacAddr>,
}

/// Everything needed to configure one radio (phy) and its BSSes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadioPlan {
    /// Kernel phy name, e.g. `phy0`.
    pub phy: String,
    pub band: Band,
    pub channel: Channel,
    /// 20, 40, 80 or 160.
    pub width_mhz: u16,
    /// ISO 3166 alpha-2, upper case.
    pub country: String,
    /// Not expressible in hostapd.conf; carried for the applier (`iw ... set txpower`).
    pub txpower_dbm: Option<u8>,
    pub standards: Vec<Standard>,
    pub aps: Vec<ApPlan>,
    #[serde(default)]
    pub driver_quirks: Quirks,
}

impl RadioPlan {
    /// Whether `standard` is enabled on this radio.
    pub fn has(&self, standard: Standard) -> bool {
        self.standards.contains(&standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trip() {
        let mac: MacAddr = "AA:bb:0c:dd:ee:0F".parse().unwrap();
        assert_eq!(mac, MacAddr([0xaa, 0xbb, 0x0c, 0xdd, 0xee, 0x0f]));
        assert_eq!(mac.to_string(), "aa:bb:0c:dd:ee:0f");
        assert_eq!(mac.to_string().parse::<MacAddr>().unwrap(), mac);
    }

    #[test]
    fn mac_rejects_malformed() {
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa-bb-cc-dd-ee-ff",
            "aa:bb:cc:dd:ee:fg",
            "+a:bb:cc:dd:ee:ff",
            "a:bb:cc:dd:ee:ff",
            "aaa:bb:cc:dd:ee:ff",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad:?} should fail");
        }
    }

    #[test]
    fn mac_serde_as_string() {
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, "\"01:02:03:04:05:06\"");
        assert_eq!(serde_json::from_str::<MacAddr>(&json).unwrap(), mac);
        assert!(serde_json::from_str::<MacAddr>("\"nope\"").is_err());
    }

    #[test]
    fn security_debug_is_redacted() {
        let sec = Security::Wpa3Sae {
            passphrase: Zeroizing::new("hunter2hunter2".into()),
        };
        let dbg = format!("{sec:?} {sec:#?}");
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("<redacted>"));
        assert_eq!(format!("{:?}", Security::Open), "Open");
    }

    #[test]
    fn plan_debug_does_not_leak_passphrase() {
        let plan = RadioPlan {
            phy: "phy0".into(),
            band: Band::G2,
            channel: Channel::Auto,
            width_mhz: 20,
            country: "US".into(),
            txpower_dbm: None,
            standards: vec![Standard::N],
            aps: vec![ApPlan {
                ifname: "wlan0".into(),
                ssid: "x".into(),
                hidden: false,
                security: Security::Wpa2Psk {
                    passphrase: Zeroizing::new("s3cretpassword".into()),
                },
                bridge: None,
                isolate_clients: false,
                max_clients: None,
                mac: None,
            }],
            driver_quirks: Quirks::default(),
        };
        assert!(!format!("{plan:?}").contains("s3cretpassword"));
    }

    #[test]
    fn security_serde_round_trip() {
        let sec = Security::Wpa2Wpa3Mixed {
            passphrase: Zeroizing::new("passphrase1".into()),
        };
        let json = serde_json::to_string(&sec).unwrap();
        assert!(json.contains("\"mode\":\"wpa2_wpa3_mixed\""));
        assert_eq!(serde_json::from_str::<Security>(&json).unwrap(), sec);
    }

    #[test]
    fn enums_use_documented_wire_names() {
        assert_eq!(serde_json::to_string(&Band::G5).unwrap(), "\"5g\"");
        assert_eq!(serde_json::to_string(&Channel::Auto).unwrap(), "\"auto\"");
        assert_eq!(
            serde_json::to_string(&Channel::Fixed(36)).unwrap(),
            "{\"fixed\":36}"
        );
        assert_eq!(serde_json::to_string(&Standard::Ax).unwrap(), "\"ax\"");
    }
}
