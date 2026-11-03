//! Pure parsers for the kernel and daemon files the production backend reads
//! (`/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, thermal zones, the dnsmasq lease
//! file). No I/O here, so everything is tested on every host.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::dto::{Lease, MemInfo};

/// At most this many lease lines are read from the lease file.
pub const MAX_LEASE_LINES: usize = 4096;
/// Longest hostname kept from a lease (RFC 1123 label length).
const MAX_HOSTNAME: usize = 63;

/// `/proc/uptime`: seconds since boot as `"12345.67 ..."`; millisecond precision.
pub fn parse_uptime(text: &str) -> Option<Duration> {
    let first = text.split_whitespace().next()?;
    let (secs, frac) = first.split_once('.').unwrap_or((first, ""));
    let secs: u64 = secs.parse().ok()?;
    let mut millis = frac.chars().take(3).collect::<String>();
    while millis.len() < 3 {
        millis.push('0');
    }
    let millis: u64 = millis.parse().ok()?;
    Some(Duration::from_secs(secs).saturating_add(Duration::from_millis(millis)))
}

/// `/proc/loadavg`: the 1, 5 and 15 minute averages.
pub fn parse_loadavg(text: &str) -> Option<[f32; 3]> {
    let mut fields = text
        .split_whitespace()
        .map(|f| f.parse::<f32>().ok().filter(|v| v.is_finite()));
    Some([fields.next()??, fields.next()??, fields.next()??])
}

/// `/proc/meminfo`: `MemTotal` and `MemFree` are required; a kernel without `MemAvailable`
/// is reported with `MemFree` as the available figure.
pub fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let (mut total, mut free, mut available) = (None, None, None);
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let slot = match key {
            "MemTotal" => &mut total,
            "MemFree" => &mut free,
            "MemAvailable" => &mut available,
            _ => continue,
        };
        *slot = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok());
    }
    let free = free?;
    Some(MemInfo {
        total_kib: total?,
        free_kib: free,
        available_kib: available.unwrap_or(free),
    })
}

/// A thermal zone: its `type` and the temperature, if it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermalZone {
    pub kind: String,
    pub temp_mc: Option<i32>,
}

/// `thermal_zone*/temp`: millidegrees Celsius.
pub fn parse_temp_mc(text: &str) -> Option<i32> {
    text.trim().parse().ok()
}

/// The CPU temperature: the first readable zone whose type mentions `cpu`, otherwise the
/// first readable zone.
pub fn choose_cpu_temp(zones: &[ThermalZone]) -> Option<i32> {
    let readable = || zones.iter().filter_map(|z| Some((z, z.temp_mc?)));
    readable()
        .find(|(z, _)| z.kind.to_ascii_lowercase().contains("cpu"))
        .or_else(|| readable().next())
        .map(|(_, t)| t)
}

/// `aa:bb:cc:dd:ee:ff` in either case; returned lower-cased.
pub fn normalize_mac(text: &str) -> Option<String> {
    let mut groups = 0usize;
    for group in text.split(':') {
        if group.len() != 2 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        groups = groups.saturating_add(1);
    }
    (groups == 6).then(|| text.to_ascii_lowercase())
}

/// A hostname as dnsmasq writes it; anything else (including `*`, "none") is `""`.
fn clean_hostname(text: &str) -> String {
    let ok = !text.is_empty()
        && text.len() <= MAX_HOSTNAME
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok { text.to_owned() } else { String::new() }
}

/// dnsmasq lease file: `"<expires> <mac> <ip> <hostname> <clientid>"` per line. `expires` is
/// a unix time (0 = never). Lines that are not IPv4 leases (the `duid` line, `DHCPv6` leases)
/// or are malformed are skipped; at most [`MAX_LEASE_LINES`] lines are read.
pub fn parse_leases(text: &str) -> Vec<Lease> {
    text.lines()
        .take(MAX_LEASE_LINES)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let expires_unix = fields.next()?.parse().ok()?;
            let mac = normalize_mac(fields.next()?)?;
            let ip: Ipv4Addr = fields.next()?.parse().ok()?;
            let hostname = clean_hostname(fields.next()?);
            Some(Lease {
                mac,
                ip: ip.to_string(),
                hostname,
                expires_unix,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime() {
        assert_eq!(
            parse_uptime("12345.67 54321.00\n"),
            Some(Duration::from_millis(12_345_670))
        );
        assert_eq!(parse_uptime("7 3"), Some(Duration::from_secs(7)));
        assert_eq!(parse_uptime("1.5"), Some(Duration::from_millis(1500)));
        assert_eq!(
            parse_uptime("1.123456 0"),
            Some(Duration::from_millis(1123))
        );
        assert_eq!(parse_uptime(""), None);
        assert_eq!(parse_uptime("abc 1"), None);
        assert_eq!(parse_uptime("1.x"), None);
        assert_eq!(parse_uptime("-5.0"), None);
    }

    #[test]
    fn loadavg() {
        assert_eq!(
            parse_loadavg("0.12 0.18 0.15 1/123 4567\n"),
            Some([0.12, 0.18, 0.15])
        );
        assert_eq!(parse_loadavg("0.1 0.2"), None);
        assert_eq!(parse_loadavg("0.1 x 0.3"), None);
        assert_eq!(parse_loadavg("NaN 1 2"), None);
        assert_eq!(parse_loadavg("inf 1 2"), None);
    }

    const MEMINFO: &str = "MemTotal:        1007616 kB\nMemFree:          742300 kB\n\
MemAvailable:     801120 kB\nBuffers:           12000 kB\nSwapTotal:             0 kB\n";

    #[test]
    fn meminfo() {
        let m = parse_meminfo(MEMINFO).unwrap();
        assert_eq!(
            (m.total_kib, m.free_kib, m.available_kib),
            (1_007_616, 742_300, 801_120)
        );
        let old = parse_meminfo("MemTotal: 100 kB\nMemFree: 40 kB\n").unwrap();
        assert_eq!(old.available_kib, 40);
        assert_eq!(parse_meminfo("MemFree: 40 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: 100 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: lots kB\nMemFree: 1 kB\n"), None);
        assert_eq!(parse_meminfo(""), None);
    }

    #[test]
    fn temperature() {
        assert_eq!(parse_temp_mc("52300\n"), Some(52_300));
        assert_eq!(parse_temp_mc("-5000"), Some(-5000));
        assert_eq!(parse_temp_mc("hot"), None);
        let zone = |kind: &str, t: Option<i32>| ThermalZone {
            kind: kind.to_owned(),
            temp_mc: t,
        };
        // cpu zone wins over an earlier zone
        assert_eq!(
            choose_cpu_temp(&[
                zone("wifi", Some(40_000)),
                zone("cpu-thermal", Some(55_000))
            ]),
            Some(55_000)
        );
        // an unreadable cpu zone is skipped; fall back to the first readable one
        assert_eq!(
            choose_cpu_temp(&[zone("cpu", None), zone("wifi", Some(41_000))]),
            Some(41_000)
        );
        assert_eq!(choose_cpu_temp(&[zone("cpu", None)]), None);
        assert_eq!(choose_cpu_temp(&[]), None);
    }

    #[test]
    fn mac_normalisation() {
        assert_eq!(
            normalize_mac("AA:bb:0C:dd:ee:FF").as_deref(),
            Some("aa:bb:0c:dd:ee:ff")
        );
        for bad in [
            "",
            "aa:bb",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:zz",
            "aabbccddeeff",
            "a:b:c:d:e:f",
        ] {
            assert_eq!(normalize_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn leases() {
        let text = "\
duid 00:01:00:01:2a:5e:aa:bb:cc:dd:ee:ff:00:11
1700000000 AA:bb:cc:00:11:22 192.168.8.101 laptop 01:aa:bb:cc:00:11:22
1700000500 3c:22:fb:aa:bb:cc 192.168.8.102 * *
0 b8:27:eb:12:34:56 192.168.8.10 nas *
1700000900 f0:18:98:de:ad:01 192.168.8.103 bad<host> 01:f0
1700000000 12345 fd00::10 v6host 00:01:00:01
nonsense
1700000000 aa:bb:cc:00:11:22 not-an-ip x *
x aa:bb:cc:00:11:22 192.168.8.5 x *
";
        let leases = parse_leases(text);
        assert_eq!(leases.len(), 4, "{leases:?}");
        assert_eq!(leases[0].mac, "aa:bb:cc:00:11:22");
        assert_eq!(leases[0].ip, "192.168.8.101");
        assert_eq!(leases[0].hostname, "laptop");
        assert_eq!(leases[0].expires_unix, 1_700_000_000);
        assert_eq!(leases[1].hostname, "", "* means unknown");
        assert_eq!(leases[2].expires_unix, 0);
        assert_eq!(leases[3].hostname, "", "unsafe hostnames are dropped");
        assert_eq!(parse_leases(""), Vec::<Lease>::new());
    }

    #[test]
    fn lease_file_is_bounded() {
        let line = "1700000000 aa:bb:cc:00:11:22 192.168.8.101 h *\n";
        let text = line.repeat(MAX_LEASE_LINES + 100);
        assert_eq!(parse_leases(&text).len(), MAX_LEASE_LINES);
    }

    #[test]
    fn overlong_hostnames_are_dropped() {
        let long = "h".repeat(MAX_HOSTNAME + 1);
        let text = format!("1 aa:bb:cc:00:11:22 192.168.8.101 {long} *\n");
        assert_eq!(parse_leases(&text)[0].hostname, "");
        let ok = "h".repeat(MAX_HOSTNAME);
        let text = format!("1 aa:bb:cc:00:11:22 192.168.8.101 {ok} *\n");
        assert_eq!(parse_leases(&text)[0].hostname, ok);
    }
}
