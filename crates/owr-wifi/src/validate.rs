//! Plan validation. Every rule reports an [`Issue`]; all issues are collected, not just the first.

use std::collections::HashSet;

use crate::channel::{center_channel, is_valid_channel};
use crate::model::{Band, Channel, MacAddr, RadioPlan, Security, Standard};

/// Maximum BSSes per radio. mt7915 supports 16; we cap lower to keep beacon airtime sane.
pub const MAX_APS: usize = 8;
/// Largest `max_num_sta` hostapd accepts (`MAX_STA_COUNT` is 2007).
const MAX_CLIENTS: u16 = 2007;

/// One validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Issue {
    #[error("phy name {0:?} must be 1..=15 chars of [a-z0-9_]")]
    PhyName(String),
    #[error("country {0:?} must be two uppercase ASCII letters")]
    Country(String),
    #[error("at least one AP is required")]
    NoAps,
    #[error("{count} APs configured, at most {MAX_APS} are supported per radio")]
    TooManyAps { count: usize },
    #[error("at least one wifi standard is required")]
    NoStandards,
    #[error("channel width {0} MHz is not one of 20, 40, 80, 160")]
    WidthNotAllowed(u16),
    #[error("2.4 GHz supports at most 40 MHz, got {0} MHz")]
    WidthTooWideFor2g(u16),
    #[error("160 MHz requires 802.11ac or 802.11ax")]
    Width160NeedsAcOrAx,
    #[error("802.11{standard} is not supported on {band}")]
    StandardNotOnBand { standard: Standard, band: Band },
    #[error("channel {channel} is not valid on {band}")]
    ChannelInvalid { band: Band, channel: u16 },
    #[error("channel {channel} has no {width} MHz block")]
    NoCenterChannel { channel: u16, width: u16 },
    #[error("interface name {0:?} must be 1..=15 chars of [A-Za-z0-9._-]")]
    IfnameInvalid(String),
    #[error("duplicate interface name {0:?}")]
    IfnameDuplicate(String),
    #[error("{ifname}: bridge name {bridge:?} is not a valid interface name")]
    BridgeInvalid { ifname: String, bridge: String },
    #[error("{ifname}: SSID must be 1..=32 bytes, got {len}")]
    SsidLength { ifname: String, len: usize },
    #[error("{ifname}: SSID must not contain control characters")]
    SsidControlChars { ifname: String },
    #[error("{ifname}: passphrase must be 8..=63 characters, got {len}")]
    PassphraseLength { ifname: String, len: usize },
    #[error("{ifname}: passphrase must be printable ASCII")]
    PassphraseChars { ifname: String },
    #[error(
        "{ifname}: passphrase must not contain '|' (hostapd treats it as the sae_password field separator)"
    )]
    PassphraseDelimiter { ifname: String },
    #[error("802.11{standard} on {band} also requires 802.11{needs}")]
    StandardNeeds {
        standard: Standard,
        band: Band,
        needs: Standard,
    },
    #[error("6 GHz requires 802.11ax")]
    SixGhzNeedsAx,
    #[error("{ifname}: 6 GHz requires WPA3-SAE (open and WPA2 are not allowed)")]
    SixGhzNeedsSae { ifname: String },
    #[error("{ifname}: BSSID {mac} must be a unicast address (multicast bit set)")]
    MacNotUnicast { ifname: String, mac: MacAddr },
    #[error("duplicate BSSID {0}")]
    MacDuplicate(MacAddr),
    #[error("{ifname}: max_clients must be 1..=2007, got {value}")]
    MaxClients { ifname: String, value: u16 },
    #[error("2.4 GHz channel 14 does not allow 802.11n or channel widths above 20 MHz")]
    Channel14Unsupported,
    #[error("40 MHz is not available on 5 GHz channel {0}")]
    Width40NotOnChannel(u16),
}

/// Linux interface name rule used for APs and bridges: 1..=15 bytes of `[A-Za-z0-9._-]`.
/// Doubles as a path-traversal guard since the name becomes a socket file name.
pub fn is_valid_ifname(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "."
        && name != ".."
}

impl RadioPlan {
    /// Check the plan; returns every problem found.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        let mut issues = Vec::new();
        self.validate_radio(&mut issues);
        self.validate_aps(&mut issues);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn validate_radio(&self, issues: &mut Vec<Issue>) {
        // The phy name becomes part of a file name.
        let phy_ok = (1..=15).contains(&self.phy.len())
            && self
                .phy
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !phy_ok {
            issues.push(Issue::PhyName(self.phy.clone()));
        }
        if !(self.country.len() == 2 && self.country.bytes().all(|b| b.is_ascii_uppercase())) {
            issues.push(Issue::Country(self.country.clone()));
        }
        if self.standards.is_empty() {
            issues.push(Issue::NoStandards);
        }
        if !matches!(self.width_mhz, 20 | 40 | 80 | 160) {
            issues.push(Issue::WidthNotAllowed(self.width_mhz));
        } else if self.band == Band::G2 && self.width_mhz > 40 {
            issues.push(Issue::WidthTooWideFor2g(self.width_mhz));
        }
        if self.width_mhz == 160 && !self.has(Standard::Ac) && !self.has(Standard::Ax) {
            issues.push(Issue::Width160NeedsAcOrAx);
        }
        if self.has(Standard::Ac) && self.band != Band::G5 {
            issues.push(Issue::StandardNotOnBand {
                standard: Standard::Ac,
                band: self.band,
            });
        }
        if self.has(Standard::N) && self.band == Band::G6 {
            issues.push(Issue::StandardNotOnBand {
                standard: Standard::N,
                band: self.band,
            });
        }
        self.validate_standards(issues);
        if let Channel::Fixed(channel) = self.channel {
            if !is_valid_channel(self.band, channel) {
                issues.push(Issue::ChannelInvalid {
                    band: self.band,
                    channel,
                });
            } else if self.width_mhz >= 80
                && self.band != Band::G2
                && center_channel(self.band, channel, self.width_mhz).is_none()
            {
                issues.push(Issue::NoCenterChannel {
                    channel,
                    width: self.width_mhz,
                });
            }
            self.validate_fixed_channel_width(channel, issues);
        }
    }

    /// Cross-field standard dependencies (conservative: what hostapd/clients expect).
    fn validate_standards(&self, issues: &mut Vec<Issue>) {
        let mut need = |standard, needs| {
            if self.has(standard) && !self.has(needs) {
                issues.push(Issue::StandardNeeds {
                    standard,
                    band: self.band,
                    needs,
                });
            }
        };
        if self.band == Band::G5 {
            need(Standard::Ax, Standard::Ac);
            need(Standard::Ax, Standard::N);
        }
        need(Standard::Be, Standard::Ax);
        if self.band == Band::G6 && !self.has(Standard::Ax) {
            issues.push(Issue::SixGhzNeedsAx);
        }
    }

    /// Width restrictions that depend on the fixed primary channel.
    fn validate_fixed_channel_width(&self, channel: u16, issues: &mut Vec<Issue>) {
        if self.band == Band::G2 && channel == 14 && (self.has(Standard::N) || self.width_mhz > 20)
        {
            issues.push(Issue::Channel14Unsupported);
        }
        // Channel 165 has no secondary channel to pair with.
        if self.band == Band::G5 && channel == 165 && self.width_mhz == 40 {
            issues.push(Issue::Width40NotOnChannel(channel));
        }
    }

    fn validate_aps(&self, issues: &mut Vec<Issue>) {
        if self.aps.is_empty() {
            issues.push(Issue::NoAps);
        }
        if self.aps.len() > MAX_APS {
            issues.push(Issue::TooManyAps {
                count: self.aps.len(),
            });
        }
        let mut seen = HashSet::new();
        let mut seen_macs = HashSet::new();
        for ap in &self.aps {
            let ifname = &ap.ifname;
            if let Some(mac) = ap.mac {
                if mac.is_multicast() {
                    issues.push(Issue::MacNotUnicast {
                        ifname: ifname.clone(),
                        mac,
                    });
                } else if !seen_macs.insert(mac) {
                    issues.push(Issue::MacDuplicate(mac));
                }
            }
            if let Some(value) = ap.max_clients.filter(|v| !(1..=MAX_CLIENTS).contains(v)) {
                issues.push(Issue::MaxClients {
                    ifname: ifname.clone(),
                    value,
                });
            }
            if self.band == Band::G6 && !matches!(ap.security, Security::Wpa3Sae { .. }) {
                issues.push(Issue::SixGhzNeedsSae {
                    ifname: ifname.clone(),
                });
            }
            if !is_valid_ifname(ifname) {
                issues.push(Issue::IfnameInvalid(ifname.clone()));
            } else if !seen.insert(ifname.as_str()) {
                issues.push(Issue::IfnameDuplicate(ifname.clone()));
            }
            if let Some(bridge) = ap.bridge.as_ref().filter(|b| !is_valid_ifname(b)) {
                issues.push(Issue::BridgeInvalid {
                    ifname: ifname.clone(),
                    bridge: bridge.clone(),
                });
            }
            if !(1..=32).contains(&ap.ssid.len()) {
                issues.push(Issue::SsidLength {
                    ifname: ifname.clone(),
                    len: ap.ssid.len(),
                });
            }
            // A newline in the SSID would inject arbitrary hostapd.conf lines.
            if ap.ssid.chars().any(char::is_control) {
                issues.push(Issue::SsidControlChars {
                    ifname: ifname.clone(),
                });
            }
            if let Some(pass) = ap.security.passphrase() {
                if !(8..=63).contains(&pass.len()) {
                    issues.push(Issue::PassphraseLength {
                        ifname: ifname.clone(),
                        len: pass.len(),
                    });
                }
                if !pass.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                    issues.push(Issue::PassphraseChars {
                        ifname: ifname.clone(),
                    });
                }
                // `sae_password=<pw>|mac=..|id=..`: a `|` would be parsed as a field separator.
                if pass.contains('|') {
                    issues.push(Issue::PassphraseDelimiter {
                        ifname: ifname.clone(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::indexing_slicing)]

    use zeroize::Zeroizing;

    use super::*;
    use crate::model::{ApPlan, MacAddr, Quirks, Security};

    pub(crate) fn ap(ifname: &str) -> ApPlan {
        ApPlan {
            ifname: ifname.into(),
            ssid: "home".into(),
            hidden: false,
            security: Security::Wpa3Sae {
                passphrase: Zeroizing::new("correct horse".into()),
            },
            bridge: Some("br-lan".into()),
            isolate_clients: false,
            max_clients: None,
            mac: None,
        }
    }

    pub(crate) fn plan_5g() -> RadioPlan {
        RadioPlan {
            phy: "phy1".into(),
            band: Band::G5,
            channel: Channel::Fixed(36),
            width_mhz: 80,
            country: "US".into(),
            txpower_dbm: None,
            standards: vec![Standard::N, Standard::Ac, Standard::Ax],
            aps: vec![ap("wlan1")],
            driver_quirks: Quirks { mt76: true },
        }
    }

    pub(crate) fn plan_2g() -> RadioPlan {
        RadioPlan {
            phy: "phy0".into(),
            band: Band::G2,
            channel: Channel::Fixed(6),
            width_mhz: 40,
            country: "US".into(),
            txpower_dbm: None,
            standards: vec![Standard::N, Standard::Ax],
            aps: vec![ap("wlan0")],
            driver_quirks: Quirks { mt76: true },
        }
    }

    fn issues(plan: &RadioPlan) -> Vec<Issue> {
        plan.validate().unwrap_err()
    }

    #[test]
    fn valid_plans_pass() {
        plan_5g().validate().unwrap();
        plan_2g().validate().unwrap();
    }

    #[test]
    fn ssid_length_bounds() {
        let mut p = plan_2g();
        p.aps[0].ssid = String::new();
        assert!(matches!(issues(&p)[..], [Issue::SsidLength { len: 0, .. }]));
        p.aps[0].ssid = "x".repeat(33);
        assert!(matches!(
            issues(&p)[..],
            [Issue::SsidLength { len: 33, .. }]
        ));
        p.aps[0].ssid = "x".repeat(32);
        p.validate().unwrap();
        // 11 chars but 33 bytes
        p.aps[0].ssid = "\u{20ac}".repeat(11);
        assert!(matches!(
            issues(&p)[..],
            [Issue::SsidLength { len: 33, .. }]
        ));
    }

    #[test]
    fn ssid_rejects_newline_injection() {
        let mut p = plan_2g();
        p.aps[0].ssid = "a\nwpa=0".into();
        assert!(matches!(issues(&p)[..], [Issue::SsidControlChars { .. }]));
    }

    #[test]
    fn passphrase_rules() {
        let mut p = plan_2g();
        for (pass, ok) in [
            ("1234567", false),
            ("12345678", true),
            (&"a".repeat(63), true),
            (&"a".repeat(64), false),
            ("tab\there!", false),
            ("p\u{e4}ssword1", false),
            ("with space ok", true),
        ] {
            p.aps[0].security = Security::Wpa2Psk {
                passphrase: Zeroizing::new(pass.to_string()),
            };
            assert_eq!(p.validate().is_ok(), ok, "{pass:?}");
        }
    }

    #[test]
    fn passphrase_checked_for_every_psk_mode() {
        let mut p = plan_2g();
        let short = || Zeroizing::new("short".to_string());
        for sec in [
            Security::Wpa2Psk {
                passphrase: short(),
            },
            Security::Wpa3Sae {
                passphrase: short(),
            },
            Security::Wpa2Wpa3Mixed {
                passphrase: short(),
            },
        ] {
            p.aps[0].security = sec;
            assert!(matches!(
                issues(&p)[..],
                [Issue::PassphraseLength { len: 5, .. }]
            ));
        }
        p.aps[0].security = Security::Open;
        p.validate().unwrap();
    }

    #[test]
    fn ifname_rules() {
        for bad in ["", "wlan0/../x", "a b", "sixteen_chars_xx", ".."] {
            let mut p = plan_2g();
            p.aps[0].ifname = bad.into();
            assert_eq!(
                issues(&p),
                vec![Issue::IfnameInvalid(bad.into())],
                "{bad:?}"
            );
        }
        assert!(is_valid_ifname("wlan0-1"));
        assert!(is_valid_ifname("fifteen_chars_x"));
    }

    #[test]
    fn ifnames_must_be_unique() {
        let mut p = plan_2g();
        p.aps.push(ap("wlan0"));
        assert_eq!(issues(&p), vec![Issue::IfnameDuplicate("wlan0".into())]);
    }

    #[test]
    fn bridge_name_validated() {
        let mut p = plan_2g();
        p.aps[0].bridge = Some("br lan".into());
        assert!(matches!(issues(&p)[..], [Issue::BridgeInvalid { .. }]));
    }

    #[test]
    fn width_2g_limited_to_40() {
        let mut p = plan_2g();
        p.width_mhz = 80;
        assert_eq!(issues(&p), vec![Issue::WidthTooWideFor2g(80)]);
    }

    #[test]
    fn width_must_be_in_allowed_set() {
        let mut p = plan_5g();
        p.width_mhz = 30;
        assert_eq!(issues(&p), vec![Issue::WidthNotAllowed(30)]);
    }

    #[test]
    fn width_160_needs_ac_or_ax() {
        let mut p = plan_5g();
        p.width_mhz = 160;
        p.standards = vec![Standard::N];
        assert_eq!(issues(&p), vec![Issue::Width160NeedsAcOrAx]);
        p.standards = vec![Standard::N, Standard::Ac];
        p.validate().unwrap();
    }

    #[test]
    fn ac_only_on_5g() {
        let mut p = plan_2g();
        p.standards.push(Standard::Ac);
        assert_eq!(
            issues(&p),
            vec![Issue::StandardNotOnBand {
                standard: Standard::Ac,
                band: Band::G2
            }]
        );
    }

    #[test]
    fn n_not_on_6g() {
        let mut p = plan_5g();
        p.band = Band::G6;
        p.channel = Channel::Auto;
        p.standards = vec![Standard::N, Standard::Ax];
        assert_eq!(
            issues(&p),
            vec![Issue::StandardNotOnBand {
                standard: Standard::N,
                band: Band::G6
            }]
        );
    }

    #[test]
    fn fixed_channel_must_fit_band() {
        let mut p = plan_2g();
        p.channel = Channel::Fixed(15);
        assert_eq!(
            issues(&p),
            vec![Issue::ChannelInvalid {
                band: Band::G2,
                channel: 15
            }]
        );
        let mut p = plan_5g();
        p.channel = Channel::Fixed(37);
        assert_eq!(
            issues(&p),
            vec![Issue::ChannelInvalid {
                band: Band::G5,
                channel: 37
            }]
        );
        p.channel = Channel::Fixed(6);
        assert!(p.validate().is_err());
    }

    #[test]
    fn wide_channel_needs_centre_block() {
        let mut p = plan_5g();
        p.channel = Channel::Fixed(165);
        assert_eq!(
            issues(&p),
            vec![Issue::NoCenterChannel {
                channel: 165,
                width: 80
            }]
        );
        p.channel = Channel::Auto;
        p.validate().unwrap();
    }

    #[test]
    fn country_must_be_two_uppercase_letters() {
        for bad in ["us", "USA", "U", "", "U1", "\u{dc}S"] {
            let mut p = plan_2g();
            p.country = bad.into();
            assert_eq!(issues(&p), vec![Issue::Country(bad.into())], "{bad:?}");
        }
    }

    #[test]
    fn ap_count_bounds() {
        let mut p = plan_2g();
        p.aps.clear();
        assert_eq!(issues(&p), vec![Issue::NoAps]);
        p.aps = (0..=MAX_APS).map(|i| ap(&format!("wlan0-{i}"))).collect();
        assert_eq!(issues(&p), vec![Issue::TooManyAps { count: MAX_APS + 1 }]);
        p.aps.pop();
        p.validate().unwrap();
    }

    #[test]
    fn standards_must_not_be_empty() {
        let mut p = plan_2g();
        p.standards.clear();
        assert_eq!(issues(&p), vec![Issue::NoStandards]);
    }

    #[test]
    fn phy_name_is_path_safe() {
        let mut p = plan_2g();
        p.phy = "../phy0".into();
        assert_eq!(issues(&p), vec![Issue::PhyName("../phy0".into())]);
    }

    #[test]
    fn all_issues_are_collected() {
        let mut p = plan_2g();
        p.country = "xx".into();
        p.width_mhz = 160;
        p.aps.clear();
        assert!(issues(&p).len() >= 3);
    }

    fn sae(pass: &str) -> Security {
        Security::Wpa3Sae {
            passphrase: Zeroizing::new(pass.to_string()),
        }
    }

    #[test]
    fn passphrase_must_not_contain_pipe() {
        let mut p = plan_2g();
        for security in [
            Security::Wpa2Psk {
                passphrase: Zeroizing::new("pass|word1".into()),
            },
            sae("pass|word1"),
            Security::Wpa2Wpa3Mixed {
                passphrase: Zeroizing::new("pass|word1".into()),
            },
        ] {
            p.aps[0].security = security;
            assert_eq!(
                issues(&p),
                vec![Issue::PassphraseDelimiter {
                    ifname: "wlan0".into()
                }]
            );
        }
        p.aps[0].security = sae("password1");
        p.validate().unwrap();
    }

    #[test]
    fn ax_on_5g_needs_ac_and_n() {
        let mut p = plan_5g();
        p.standards = vec![Standard::Ax];
        assert_eq!(
            issues(&p),
            vec![
                Issue::StandardNeeds {
                    standard: Standard::Ax,
                    band: Band::G5,
                    needs: Standard::Ac
                },
                Issue::StandardNeeds {
                    standard: Standard::Ax,
                    band: Band::G5,
                    needs: Standard::N
                },
            ]
        );
        p.standards = vec![Standard::N, Standard::Ac, Standard::Ax];
        p.validate().unwrap();
    }

    #[test]
    fn be_needs_ax() {
        let mut p = plan_2g();
        p.standards = vec![Standard::N, Standard::Be];
        assert_eq!(
            issues(&p),
            vec![Issue::StandardNeeds {
                standard: Standard::Be,
                band: Band::G2,
                needs: Standard::Ax
            }]
        );
        p.standards = vec![Standard::N, Standard::Ax, Standard::Be];
        p.validate().unwrap();
    }

    fn plan_6g() -> RadioPlan {
        let mut p = plan_5g();
        p.band = Band::G6;
        p.channel = Channel::Fixed(5);
        p.standards = vec![Standard::Ax];
        p
    }

    #[test]
    fn six_ghz_needs_ax_and_sae() {
        plan_6g().validate().unwrap();

        let mut p = plan_6g();
        p.standards = vec![Standard::Be];
        assert!(issues(&p).contains(&Issue::SixGhzNeedsAx));

        for security in [
            Security::Open,
            Security::Wpa2Psk {
                passphrase: Zeroizing::new("password1".into()),
            },
            Security::Wpa2Wpa3Mixed {
                passphrase: Zeroizing::new("password1".into()),
            },
        ] {
            let mut p = plan_6g();
            p.aps[0].security = security;
            assert_eq!(
                issues(&p),
                vec![Issue::SixGhzNeedsSae {
                    ifname: "wlan1".into()
                }]
            );
        }
    }

    #[test]
    fn bssid_must_be_unicast_and_unique() {
        let mut p = plan_2g();
        p.aps[0].mac = Some(MacAddr([0x02, 0, 0, 0, 0, 1]));
        p.validate().unwrap();

        for first in [0x01, 0x03, 0xff] {
            p.aps[0].mac = Some(MacAddr([first, 0, 0, 0, 0, 1]));
            assert_eq!(
                issues(&p),
                vec![Issue::MacNotUnicast {
                    ifname: "wlan0".into(),
                    mac: MacAddr([first, 0, 0, 0, 0, 1])
                }]
            );
        }

        p.aps[0].mac = Some(MacAddr([0x02, 0, 0, 0, 0, 1]));
        let mut second = ap("wlan0-1");
        second.mac = p.aps[0].mac;
        p.aps.push(second);
        assert_eq!(
            issues(&p),
            vec![Issue::MacDuplicate(MacAddr([0x02, 0, 0, 0, 0, 1]))]
        );
        p.aps[1].mac = Some(MacAddr([0x02, 0, 0, 0, 0, 2]));
        p.validate().unwrap();
    }

    #[test]
    fn max_clients_bounds() {
        let mut p = plan_2g();
        for (value, ok) in [(0, false), (1, true), (2007, true), (2008, false)] {
            p.aps[0].max_clients = Some(value);
            assert_eq!(p.validate().is_ok(), ok, "{value}");
        }
        p.aps[0].max_clients = Some(0);
        assert_eq!(
            issues(&p),
            vec![Issue::MaxClients {
                ifname: "wlan0".into(),
                value: 0
            }]
        );
    }

    #[test]
    fn channel_14_only_legacy_20mhz() {
        let mut p = plan_2g();
        p.channel = Channel::Fixed(14);
        assert_eq!(issues(&p), vec![Issue::Channel14Unsupported]); // N + 40 MHz
        p.width_mhz = 20;
        assert_eq!(issues(&p), vec![Issue::Channel14Unsupported]); // N
        p.standards = vec![Standard::Ax];
        p.validate().unwrap();
        p.width_mhz = 40;
        assert_eq!(issues(&p), vec![Issue::Channel14Unsupported]); // wide
    }

    #[test]
    fn forty_mhz_not_on_5g_channel_165() {
        let mut p = plan_5g();
        p.channel = Channel::Fixed(165);
        p.width_mhz = 40;
        assert_eq!(issues(&p), vec![Issue::Width40NotOnChannel(165)]);
        p.width_mhz = 20;
        p.validate().unwrap();
        p.channel = Channel::Fixed(161);
        p.width_mhz = 40;
        p.validate().unwrap();
    }
}
