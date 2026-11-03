//! Pure parsers for hostapd control-interface replies (`STATUS`, `STA-*`).
//!
//! Kept free of I/O and OS dependencies so they are unit-tested on every host.

use std::collections::HashMap;

use crate::model::MacAddr;

/// Summary of one BSS as reported by `STATUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApStatus {
    /// hostapd interface state: `ENABLED`, `DISABLED`, `ACS`, `HT_SCAN`, `DFS`, ...
    pub state: String,
    /// Primary channel; 0 when hostapd has not chosen one yet (ACS running).
    pub channel: u16,
    /// Primary frequency in MHz; 0 if unknown.
    pub freq: u32,
    pub ssid: String,
    pub bssid: Option<MacAddr>,
    pub num_sta: u32,
}

/// One associated station as reported by `STA-FIRST` / `STA-NEXT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Station {
    pub mac: MacAddr,
    /// Signal strength; `None` when hostapd reports no (or a non-negative, i.e. bogus) value.
    pub signal_dbm: Option<i32>,
    /// Last receive rate in kbit/s; 0 when not reported. hostapd prints `rx_rate_info` in
    /// units of 100 kbit/s; [`parse_station`] converts (saturating).
    pub rx_rate_kbps: u32,
    /// Last transmit rate in kbit/s; 0 when not reported (`tx_rate_info` is in 100 kbit/s).
    pub tx_rate_kbps: u32,
    /// Seconds since association; 0 when not reported.
    pub connected_secs: u64,
    /// Milliseconds since last activity; 0 when not reported.
    pub inactive_msecs: u64,
}

/// Malformed or unexpected reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    #[error("hostapd replied FAIL")]
    Fail,
    #[error("empty reply")]
    Empty,
    #[error("reply is missing required field {0:?}")]
    MissingField(&'static str),
    #[error("field {key:?} has invalid value {value:?}")]
    BadValue { key: &'static str, value: String },
    #[error("invalid station MAC {0:?}")]
    BadMac(String),
    #[error("STATUS reply has no bss[] entry for interface {0:?}")]
    NoSuchBss(String),
    #[error(
        "control socket is out of sync after a timeout; reconnect before sending more requests"
    )]
    Desynced,
}

fn kv_map(reply: &str) -> HashMap<&str, &str> {
    reply.lines().filter_map(|l| l.split_once('=')).collect()
}

fn number<T: std::str::FromStr>(
    map: &HashMap<&str, &str>,
    key: &'static str,
) -> Result<Option<T>, ReplyError> {
    map.get(key)
        .map(|v| {
            v.trim().parse().map_err(|_| ReplyError::BadValue {
                key,
                value: (*v).to_owned(),
            })
        })
        .transpose()
}

/// A hostapd rate field (units of 100 kbit/s) as kbit/s; 0 when absent.
fn rate_kbps(map: &HashMap<&str, &str>, key: &'static str) -> Result<u32, ReplyError> {
    Ok(number::<u32>(map, key)?.unwrap_or(0).saturating_mul(100))
}

/// Parse a `STATUS` reply for the BSS named `ifname`.
///
/// hostapd lists every BSS of the radio as `bss[i]=`, `bssid[i]=`, `ssid[i]=`,
/// `num_sta[i]=`; the entry whose `bss[i]` equals `ifname` is selected. No match is an error
/// ([`ReplyError::NoSuchBss`]): reporting another BSS's state as this one's would be wrong.
pub fn parse_status(reply: &str, ifname: &str) -> Result<ApStatus, ReplyError> {
    if reply.trim().is_empty() {
        return Err(ReplyError::Empty);
    }
    if reply.trim() == "FAIL" {
        return Err(ReplyError::Fail);
    }
    let map = kv_map(reply);
    let state = (*map.get("state").ok_or(ReplyError::MissingField("state"))?).to_owned();
    let idx = map
        .iter()
        .filter(|&(_, &v)| v == ifname)
        .find_map(|(k, _)| {
            k.strip_prefix("bss[")?
                .strip_suffix(']')?
                .parse::<usize>()
                .ok()
        })
        .ok_or_else(|| ReplyError::NoSuchBss(ifname.to_owned()))?;
    let get = |name: &str| map.get(format!("{name}[{idx}]").as_str()).copied();
    let bssid = get("bssid")
        .map(|v| v.parse().map_err(|_| ReplyError::BadMac(v.to_owned())))
        .transpose()?;
    let num_sta = get("num_sta")
        .map(|v| {
            v.trim().parse().map_err(|_| ReplyError::BadValue {
                key: "num_sta",
                value: v.to_owned(),
            })
        })
        .transpose()?
        .unwrap_or(0);
    Ok(ApStatus {
        state,
        channel: number(&map, "channel")?.unwrap_or(0),
        freq: number(&map, "freq")?.unwrap_or(0),
        ssid: get("ssid").unwrap_or_default().to_owned(),
        bssid,
        num_sta,
    })
}

/// Parse one station block: a MAC line followed by `key=value` lines.
pub fn parse_station(block: &str) -> Result<Station, ReplyError> {
    let mut lines = block.lines();
    let first = lines
        .next()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .ok_or(ReplyError::Empty)?;
    if first == "FAIL" {
        return Err(ReplyError::Fail);
    }
    let mac = first
        .parse()
        .map_err(|_| ReplyError::BadMac(first.to_owned()))?;
    let map = kv_map(block);
    Ok(Station {
        mac,
        signal_dbm: number::<i32>(&map, "signal")?.filter(|s| *s < 0),
        rx_rate_kbps: rate_kbps(&map, "rx_rate_info")?,
        tx_rate_kbps: rate_kbps(&map, "tx_rate_info")?,
        connected_secs: number(&map, "connected_time")?.unwrap_or(0),
        inactive_msecs: number(&map, "inactive_msec")?.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STA: &str = "aa:bb:cc:dd:ee:ff\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-55\n\
                       rx_rate_info=8660\ntx_rate_info=7800\nconnected_time=1234\n\
                       inactive_msec=200\n";

    const STATUS: &str = "state=ENABLED\nphy=phy1\nfreq=5180\nnum_sta_non_erp=0\n\
        channel=36\nsecondary_channel=1\nbss[0]=wlan1\nbssid[0]=02:00:00:00:00:01\n\
        ssid[0]=Main\nnum_sta[0]=3\nbss[1]=wlan1-1\nbssid[1]=02:00:00:00:00:02\n\
        ssid[1]=Guest\nnum_sta[1]=7\n";

    #[test]
    fn station_full_block() {
        let sta = parse_station(STA).unwrap();
        assert_eq!(sta.mac, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(sta.signal_dbm, Some(-55));
        assert_eq!(sta.rx_rate_kbps, 866_000);
        assert_eq!(sta.tx_rate_kbps, 780_000);
        assert_eq!(sta.connected_secs, 1234);
        assert_eq!(sta.inactive_msecs, 200);
    }

    #[test]
    fn station_rates_are_converted_from_100kbps_units_and_saturate() {
        let sta =
            parse_station("aa:bb:cc:dd:ee:ff\nrx_rate_info=1\ntx_rate_info=4294967295\n").unwrap();
        assert_eq!(sta.rx_rate_kbps, 100);
        assert_eq!(sta.tx_rate_kbps, u32::MAX);
    }

    #[test]
    fn station_minimal_block_defaults() {
        let sta = parse_station("aa:bb:cc:dd:ee:ff\nflags=[AUTH]\n").unwrap();
        assert_eq!(sta.signal_dbm, None);
        assert_eq!(
            (sta.rx_rate_kbps, sta.tx_rate_kbps, sta.connected_secs),
            (0, 0, 0)
        );
    }

    #[test]
    fn station_bogus_signal_is_none() {
        let sta = parse_station("aa:bb:cc:dd:ee:ff\nsignal=0\n").unwrap();
        assert_eq!(sta.signal_dbm, None);
    }

    #[test]
    fn station_errors() {
        assert_eq!(parse_station(""), Err(ReplyError::Empty));
        assert_eq!(parse_station("FAIL\n"), Err(ReplyError::Fail));
        assert!(matches!(
            parse_station("nonsense\nsignal=-1\n"),
            Err(ReplyError::BadMac(_))
        ));
        assert!(matches!(
            parse_station("aa:bb:cc:dd:ee:ff\nsignal=loud\n"),
            Err(ReplyError::BadValue { key: "signal", .. })
        ));
    }

    #[test]
    fn status_selects_bss_by_ifname() {
        let main = parse_status(STATUS, "wlan1").unwrap();
        assert_eq!(main.state, "ENABLED");
        assert_eq!((main.channel, main.freq), (36, 5180));
        assert_eq!(main.ssid, "Main");
        assert_eq!(main.bssid, Some(MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(main.num_sta, 3);
        let guest = parse_status(STATUS, "wlan1-1").unwrap();
        assert_eq!((guest.ssid.as_str(), guest.num_sta), ("Guest", 7));
    }

    #[test]
    fn status_unknown_ifname_is_an_error_not_a_fallback() {
        assert_eq!(
            parse_status(STATUS, "other"),
            Err(ReplyError::NoSuchBss("other".into()))
        );
        // A reply without any bss[] list cannot be attributed to the interface either.
        assert_eq!(
            parse_status("state=ENABLED\nchannel=1\nssid[0]=x\n", "wlan0"),
            Err(ReplyError::NoSuchBss("wlan0".into()))
        );
    }

    #[test]
    fn status_during_acs_has_no_channel() {
        let st = parse_status("state=ACS\nphy=phy0\nbss[0]=wlan0\nssid[0]=x\n", "wlan0").unwrap();
        assert_eq!(
            (st.state.as_str(), st.channel, st.freq, st.num_sta),
            ("ACS", 0, 0, 0)
        );
        assert_eq!(st.bssid, None);
    }

    #[test]
    fn status_errors() {
        assert_eq!(parse_status("", "w"), Err(ReplyError::Empty));
        assert_eq!(parse_status("FAIL\n", "w"), Err(ReplyError::Fail));
        assert_eq!(
            parse_status("phy=phy0\n", "w"),
            Err(ReplyError::MissingField("state"))
        );
        assert!(matches!(
            parse_status("state=ENABLED\nbss[0]=w\nchannel=x\n", "w"),
            Err(ReplyError::BadValue { key: "channel", .. })
        ));
    }
}
