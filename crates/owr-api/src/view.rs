//! Mapping of observed system state (netlink dump, hostapd replies, init replies) onto the
//! API's DTOs. Pure: the production backend gathers the inputs, this module shapes them.

use std::collections::HashMap;
use std::time::SystemTime;

use owr_board::Board;
use owr_config::{Channel, Config, WanProto};
use owr_init::client::{JournalEntry, ServiceInfo};
use owr_net::dhcp::Lease as DhcpLease;
use owr_net::{LinkKind, Observed, ObservedLink};
use owr_wifi::RadioPlan;
use owr_wifi::reply::{ApStatus as HostapdStatus, Station};

use crate::dto::{
    ApStatus, Client, Iface, Lease, LogEntry, NetworkStatus, RadioStatus, ServiceStatus, WanStatus,
    WirelessStatus,
};

/// init's service table in the API's shape.
pub fn map_services(list: Vec<ServiceInfo>) -> Vec<ServiceStatus> {
    list.into_iter()
        .map(|s| ServiceStatus {
            name: s.name,
            state: s.state,
            pid: s.pid,
            since_unix: s.since_unix,
            restarts: s.restarts,
        })
        .collect()
}

/// Journal entries in the API's shape. init stamps entries with milliseconds since boot;
/// the API (and the UI) use wall-clock milliseconds, so `boot_unix_ms` (the wall-clock time
/// of boot) is added.
pub fn map_journal(entries: Vec<JournalEntry>, boot_unix_ms: u64) -> Vec<LogEntry> {
    entries
        .into_iter()
        .map(|e| LogEntry {
            seq: e.seq,
            ts_ms: e.ts_ms.saturating_add(boot_unix_ms),
            prio: e.prio,
            source: e.source,
            msg: e.msg,
        })
        .collect()
}

/// What a board port is used for: `wan`, a VLAN name, or `lan`.
pub fn port_role(cfg: &Config, port: &str) -> String {
    if cfg.network.wan.port == port {
        "wan".to_owned()
    } else if let Some(vlan) = cfg
        .network
        .vlans
        .iter()
        .find(|v| v.ports.iter().any(|p| p == port))
    {
        vlan.name.clone()
    } else {
        "lan".to_owned()
    }
}

fn iface(link: &ObservedLink, role: Option<String>, obs: &Observed) -> Iface {
    let addrs = |v4: bool| {
        obs.addresses
            .iter()
            .filter(|a| a.link == link.name && a.addr.addr().is_ipv4() == v4)
            .map(|a| a.addr.to_string())
            .collect()
    };
    Iface {
        name: link.name.clone(),
        role,
        up: link.up,
        carrier: link.carrier,
        speed_mbps: link.speed_mbps,
        mac: link.mac.map(|m| m.to_string()).unwrap_or_default(),
        ipv4: addrs(true),
        ipv6: addrs(false),
        rx_bytes: link.stats.rx_bytes,
        tx_bytes: link.stats.tx_bytes,
    }
}

/// Board ports (with their configured role) followed by the bridges the kernel reports.
/// A port the kernel does not know (driver not loaded) is omitted.
pub fn network_status(
    board: &Board,
    cfg: &Config,
    obs: &Observed,
    wan: Option<WanStatus>,
) -> NetworkStatus {
    let mut interfaces = Vec::new();
    for port in &board.ethernet.ports {
        if let Some(link) = obs.links.iter().find(|l| l.name == port.netdev) {
            interfaces.push(iface(link, Some(port_role(cfg, &port.name)), obs));
        }
    }
    interfaces.extend(
        obs.links
            .iter()
            .filter(|l| l.kind == LinkKind::Bridge)
            .map(|l| iface(l, Some("bridge".to_owned()), obs)),
    );
    NetworkStatus { interfaces, wan }
}

/// The WAN uplink. A DHCP WAN prefers the persisted lease (server, DNS, age); everything
/// else, and a DHCP WAN without a valid lease, falls back to what the kernel reports for
/// `wan_dev`. `None` while the WAN has no IPv4 address.
pub fn wan_status(
    cfg: &Config,
    wan_dev: &str,
    obs: &Observed,
    lease: Option<&DhcpLease>,
    now: SystemTime,
) -> Option<WanStatus> {
    match (&cfg.network.wan.proto, lease) {
        (WanProto::Dhcp { .. }, Some(l)) => Some(WanStatus {
            proto: "dhcp".to_owned(),
            addr: l.addr.to_string(),
            gateway: l
                .routers
                .first()
                .map(ToString::to_string)
                .unwrap_or_default(),
            dns: l.dns.iter().map(ToString::to_string).collect(),
            uptime_secs: now.duration_since(l.obtained_at).map_or(0, |d| d.as_secs()),
        }),
        (WanProto::Static { ipv4, gateway, dns }, _) => {
            let up = obs.addresses.iter().any(|a| a.link == wan_dev);
            up.then(|| WanStatus {
                proto: "static".to_owned(),
                addr: ipv4.to_string(),
                gateway: gateway.to_string(),
                dns: dns.iter().map(ToString::to_string).collect(),
                uptime_secs: 0,
            })
        }
        (proto, _) => {
            let addr = obs
                .addresses
                .iter()
                .find(|a| a.link == wan_dev && a.addr.addr().is_ipv4())?;
            let gateway = obs
                .routes
                .iter()
                .find(|r| {
                    r.dest.prefix_len() == 0
                        && r.dest.addr().is_ipv4()
                        && r.dev.as_deref() == Some(wan_dev)
                })
                .and_then(|r| r.via);
            Some(WanStatus {
                proto: match proto {
                    WanProto::Dhcp { .. } => "dhcp",
                    WanProto::Static { .. } => "static",
                    WanProto::Pppoe { .. } => "pppoe",
                }
                .to_owned(),
                addr: addr.addr.to_string(),
                gateway: gateway.map(|g| g.to_string()).unwrap_or_default(),
                dns: Vec::new(),
                uptime_secs: 0,
            })
        }
    }
}

/// What hostapd said about one access point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApProbe {
    pub status: Option<HostapdStatus>,
    pub stations: Vec<Station>,
}

const fn band_name(band: owr_board::Band) -> &'static str {
    match band {
        owr_board::Band::G2 => "2g",
        owr_board::Band::G5 => "5g",
        owr_board::Band::G6 => "6g",
    }
}

/// Radios and access points. Every configured radio is listed; access points exist for the
/// enabled ones that have APs (`plans`, from `owr_apply::build_plans`). `probes` is keyed by
/// AP ifname; an AP hostapd did not answer for is listed without clients. The channel is the
/// one hostapd reports, else the configured fixed channel, else 0 (auto, not yet chosen).
pub fn wireless_status<S: std::hash::BuildHasher>(
    board: &Board,
    cfg: &Config,
    plans: &[RadioPlan],
    probes: &HashMap<String, ApProbe, S>,
    leases: &[Lease],
) -> WirelessStatus {
    let host = |mac: &str| {
        leases
            .iter()
            .find(|l| l.mac == mac && !l.hostname.is_empty())
            .map(|l| l.hostname.clone())
    };
    let mut radios = Vec::new();
    let mut aps = Vec::new();
    for radio in &cfg.wireless.radios {
        let Some(hw) = board.radio(&radio.id) else {
            continue;
        };
        let phy = format!("phy{}", hw.phy_index);
        let plan = plans.iter().find(|p| p.phy == phy);
        let mut reported = 0;
        for ap in plan.map_or(&[][..], |p| p.aps.as_slice()) {
            let probe = probes.get(&ap.ifname);
            if reported == 0 {
                reported = probe
                    .and_then(|p| p.status.as_ref())
                    .map_or(0, |s| u32::from(s.channel));
            }
            let status = probe.and_then(|p| p.status.as_ref());
            let clients = probe.map_or_else(Vec::new, |p| {
                p.stations
                    .iter()
                    .map(|s| {
                        let mac = s.mac.to_string();
                        Client {
                            hostname: host(&mac),
                            mac,
                            signal_dbm: s.signal_dbm.unwrap_or(0),
                            rx_rate_kbps: s.rx_rate_kbps,
                            tx_rate_kbps: s.tx_rate_kbps,
                            connected_secs: s.connected_secs,
                        }
                    })
                    .collect()
            });
            aps.push(ApStatus {
                ifname: ap.ifname.clone(),
                radio: radio.id.clone(),
                ssid: ap.ssid.clone(),
                bssid: status
                    .and_then(|s| s.bssid)
                    .map(|m| m.to_string())
                    .unwrap_or_default(),
                clients,
            });
        }
        let channel = if reported != 0 {
            reported
        } else {
            match radio.channel {
                Channel::Fixed(c) => u32::from(c),
                Channel::Auto => 0,
            }
        };
        radios.push(RadioStatus {
            id: radio.id.clone(),
            phy,
            band: band_name(hw.band).to_owned(),
            channel,
            width_mhz: u32::from(radio.width_mhz),
            txpower_dbm: radio.txpower_dbm.map_or(0, u32::from),
            enabled: radio.enabled,
        });
    }
    WirelessStatus { radios, aps }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use owr_net::{AddrSpec, LinkStats, MacAddr, RouteProto, RouteSpec};
    use owr_wifi::MacAddr as WifiMac;

    use super::*;

    fn board() -> Board {
        owr_board::builtin("glinet_gl-mt6000").unwrap()
    }

    fn link(index: u32, name: &str, kind: LinkKind, up: bool) -> ObservedLink {
        let mut l = ObservedLink::new(index, name, kind);
        l.up = up;
        l.carrier = up;
        l.mac = Some(MacAddr([
            0x94,
            0x83,
            0xc4,
            0,
            0,
            u8::try_from(index).unwrap(),
        ]));
        l.speed_mbps = up.then_some(1000);
        l.stats = LinkStats {
            rx_bytes: 10 * u64::from(index),
            tx_bytes: 5,
            ..LinkStats::default()
        };
        l
    }

    fn addr(link: &str, net: &str) -> AddrSpec {
        AddrSpec {
            link: link.to_owned(),
            addr: net.parse().unwrap(),
        }
    }

    fn default_route(dev: &str, via: &str) -> RouteSpec {
        RouteSpec {
            dest: "0.0.0.0/0".parse().unwrap(),
            via: Some(via.parse().unwrap()),
            dev: Some(dev.to_owned()),
            metric: 10,
            table: 254,
            proto: RouteProto::Dhcp,
        }
    }

    fn dhcp_lease(obtained: SystemTime) -> DhcpLease {
        DhcpLease {
            addr: "203.0.113.42/24".parse().unwrap(),
            routers: vec!["203.0.113.1".parse().unwrap()],
            dns: vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            domain: None,
            classless_routes: Vec::new(),
            lease_secs: 3600,
            t1: 1800,
            t2: 3150,
            server: "203.0.113.1".parse().unwrap(),
            obtained_at: obtained,
        }
    }

    fn defaults() -> (Board, Config) {
        let b = board();
        let c = Config::defaults_for(&b);
        (b, c)
    }

    #[test]
    fn services_and_journal_are_mapped() {
        let services = map_services(vec![ServiceInfo {
            name: "dnsmasq".into(),
            state: "running".into(),
            pid: Some(7),
            since_unix: 100,
            restarts: 2,
            failures: 9,
            oneshot: false,
            healthy: Some(true),
        }]);
        assert_eq!(
            services,
            [ServiceStatus {
                name: "dnsmasq".into(),
                state: "running".into(),
                pid: Some(7),
                since_unix: 100,
                restarts: 2
            }]
        );
        let logs = map_journal(
            vec![JournalEntry {
                seq: 9,
                ts_ms: 1500,
                prio: 3,
                source: "service:dnsmasq".into(),
                msg: "boom".into(),
            }],
            1_700_000_000_000,
        );
        assert_eq!(logs[0].ts_ms, 1_700_000_001_500);
        assert_eq!((logs[0].seq, logs[0].prio), (9, 3));
        assert_eq!(logs[0].source, "service:dnsmasq");
        let late = map_journal(
            vec![JournalEntry {
                seq: 1,
                ts_ms: u64::MAX,
                prio: 6,
                source: "init".into(),
                msg: String::new(),
            }],
            5,
        );
        assert_eq!(late[0].ts_ms, u64::MAX, "saturates");
    }

    #[test]
    fn port_roles_follow_the_config() {
        let (_, mut cfg) = defaults();
        let wan = cfg.network.wan.port.clone();
        let lan = cfg.network.lan.ports[0].clone();
        assert_eq!(port_role(&cfg, &wan), "wan");
        assert_eq!(port_role(&cfg, &lan), "lan");
        cfg.network.vlans.push(owr_config::VlanConfig {
            name: "guest".into(),
            id: 20,
            ports: vec![lan.clone()],
            ipv4: None,
            dhcp: None,
            isolated: true,
        });
        assert_eq!(port_role(&cfg, &lan), "guest");
    }

    #[test]
    fn network_status_lists_ports_then_bridges() {
        let (b, cfg) = defaults();
        let wan_port = b.port(&cfg.network.wan.port).unwrap().clone();
        let lan_port = b.port(&cfg.network.lan.ports[0]).unwrap().clone();
        let obs = Observed {
            links: vec![
                link(2, &lan_port.netdev, LinkKind::Physical, true),
                link(3, &wan_port.netdev, LinkKind::Physical, false),
                link(9, "br-lan", LinkKind::Bridge, true),
                link(10, "wlan0", LinkKind::Other("veth".into()), true),
            ],
            addresses: vec![
                addr("br-lan", "192.168.8.1/24"),
                addr("br-lan", "fd12:3456:789a::1/64"),
            ],
            routes: Vec::new(),
            sysctls: Vec::new(),
        };
        let st = network_status(&b, &cfg, &obs, None);
        let names: Vec<_> = st.interfaces.iter().map(|i| i.name.as_str()).collect();
        // board order: the descriptor lists lan ports before wan; unknown ports omitted
        assert_eq!(names.last(), Some(&"br-lan"));
        assert_eq!(names.len(), 3, "{names:?}");
        let lan = st
            .interfaces
            .iter()
            .find(|i| i.name == lan_port.netdev)
            .unwrap();
        assert_eq!(lan.role.as_deref(), Some("lan"));
        assert!(lan.up && lan.carrier);
        assert_eq!(lan.speed_mbps, Some(1000));
        assert_eq!(lan.mac, "94:83:c4:00:00:02");
        assert_eq!(lan.rx_bytes, 20);
        let wan = st
            .interfaces
            .iter()
            .find(|i| i.name == wan_port.netdev)
            .unwrap();
        assert_eq!(wan.role.as_deref(), Some("wan"));
        assert!(!wan.up);
        let br = st.interfaces.last().unwrap();
        assert_eq!(br.role.as_deref(), Some("bridge"));
        assert_eq!(br.ipv4, ["192.168.8.1/24"]);
        assert_eq!(br.ipv6, ["fd12:3456:789a::1/64"]);
        assert_eq!(st.wan, None);
    }

    #[test]
    fn dhcp_wan_uses_the_lease() {
        let (_, cfg) = defaults();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let lease = dhcp_lease(now - Duration::from_secs(120));
        let wan = wan_status(&cfg, "eth1", &Observed::default(), Some(&lease), now).unwrap();
        assert_eq!(wan.proto, "dhcp");
        assert_eq!(wan.addr, "203.0.113.42/24");
        assert_eq!(wan.gateway, "203.0.113.1");
        assert_eq!(wan.dns, ["1.1.1.1", "9.9.9.9"]);
        assert_eq!(wan.uptime_secs, 120);
        // clock stepped back: no negative uptime
        let future = dhcp_lease(now + Duration::from_secs(60));
        let wan = wan_status(&cfg, "eth1", &Observed::default(), Some(&future), now).unwrap();
        assert_eq!(wan.uptime_secs, 0);
    }

    #[test]
    fn dhcp_wan_without_lease_falls_back_to_observed_state() {
        let (_, cfg) = defaults();
        let now = SystemTime::UNIX_EPOCH;
        assert_eq!(
            wan_status(&cfg, "eth1", &Observed::default(), None, now),
            None
        );
        let obs = Observed {
            addresses: vec![
                addr("eth1", "198.51.100.7/24"),
                addr("br-lan", "192.168.8.1/24"),
            ],
            routes: vec![default_route("eth1", "198.51.100.1")],
            ..Observed::default()
        };
        let wan = wan_status(&cfg, "eth1", &obs, None, now).unwrap();
        assert_eq!(
            (wan.proto.as_str(), wan.addr.as_str(), wan.gateway.as_str()),
            ("dhcp", "198.51.100.7/24", "198.51.100.1")
        );
        assert_eq!(wan.dns.len(), 0);
    }

    #[test]
    fn static_wan_comes_from_the_config_once_the_address_is_there() {
        let (_, mut cfg) = defaults();
        cfg.network.wan.proto = WanProto::Static {
            ipv4: "203.0.113.5/24".parse().unwrap(),
            gateway: "203.0.113.1".parse().unwrap(),
            dns: vec!["9.9.9.9".parse().unwrap()],
        };
        let now = SystemTime::UNIX_EPOCH;
        assert_eq!(
            wan_status(&cfg, "eth1", &Observed::default(), None, now),
            None
        );
        let obs = Observed {
            addresses: vec![addr("eth1", "203.0.113.5/24")],
            ..Observed::default()
        };
        let wan = wan_status(&cfg, "eth1", &obs, None, now).unwrap();
        assert_eq!(wan.proto, "static");
        assert_eq!(wan.gateway, "203.0.113.1");
        assert_eq!(wan.dns, ["9.9.9.9"]);
    }

    fn wireless_fixture() -> (Board, Config, Vec<RadioPlan>) {
        let (b, mut cfg) = defaults();
        let ap = |radio: &str, ssid: &str| owr_config::ApConfig {
            radio: radio.to_owned(),
            ssid: ssid.to_owned(),
            hidden: false,
            security: owr_config::Security::Wpa3Sae {
                passphrase: owr_config::Secret::from("correct-horse-battery"),
            },
            network: "lan".to_owned(),
            isolate_clients: false,
            max_clients: None,
        };
        cfg.wireless.aps = vec![ap("radio0", "home"), ap("radio0", "guest")];
        cfg.wireless.radios[1].enabled = false;
        cfg.validate_against(&b).unwrap();
        let plans = owr_apply::build_plans(&b, &cfg).unwrap().radios;
        (b, cfg, plans)
    }

    fn station(mac: [u8; 6], signal: Option<i32>) -> Station {
        Station {
            mac: WifiMac(mac),
            signal_dbm: signal,
            rx_rate_kbps: 72_200,
            tx_rate_kbps: 65_000,
            connected_secs: 300,
            inactive_msecs: 10,
        }
    }

    #[test]
    fn wireless_combines_config_plans_and_probes() {
        let (b, cfg, plans) = wireless_fixture();
        assert_eq!(plans.len(), 1, "disabled radio has no plan");
        let mut probes = HashMap::new();
        probes.insert(
            "wlan0".to_owned(),
            ApProbe {
                status: Some(HostapdStatus {
                    state: "ENABLED".into(),
                    channel: 6,
                    freq: 2437,
                    ssid: "home".into(),
                    bssid: Some(WifiMac([0x94, 0x83, 0xc4, 0xa1, 0x10, 0x00])),
                    num_sta: 2,
                }),
                stations: vec![
                    station([0xb8, 0x27, 0xeb, 0x12, 0x34, 0x56], Some(-61)),
                    station([0xf0, 0x18, 0x98, 0xde, 0xad, 0x01], None),
                ],
            },
        );
        let leases = vec![
            Lease {
                mac: "b8:27:eb:12:34:56".into(),
                ip: "192.168.8.102".into(),
                hostname: "thermostat".into(),
                expires_unix: 0,
            },
            Lease {
                mac: "f0:18:98:de:ad:01".into(),
                ip: "192.168.8.103".into(),
                hostname: String::new(),
                expires_unix: 0,
            },
        ];
        let st = wireless_status(&b, &cfg, &plans, &probes, &leases);
        assert_eq!(st.radios.len(), 2);
        let r0 = &st.radios[0];
        assert_eq!(
            (r0.id.as_str(), r0.phy.as_str(), r0.band.as_str()),
            ("radio0", "phy0", "2g")
        );
        assert_eq!((r0.channel, r0.enabled), (6, true));
        assert!(!st.radios[1].enabled);
        assert_eq!(st.aps.len(), 2, "only the enabled radio has APs");
        let home = &st.aps[0];
        assert_eq!(
            (
                home.ifname.as_str(),
                home.radio.as_str(),
                home.ssid.as_str()
            ),
            ("wlan0", "radio0", "home")
        );
        assert_eq!(home.bssid, "94:83:c4:a1:10:00");
        assert_eq!(home.clients.len(), 2);
        assert_eq!(home.clients[0].hostname.as_deref(), Some("thermostat"));
        assert_eq!(home.clients[0].signal_dbm, -61);
        assert_eq!(home.clients[1].hostname, None);
        assert_eq!(home.clients[1].signal_dbm, 0);
        // the second AP of the radio is wlan0-1 and hostapd did not answer for it
        let guest = &st.aps[1];
        assert_eq!(
            (guest.ifname.as_str(), guest.ssid.as_str()),
            ("wlan0-1", "guest")
        );
        assert_eq!(guest.bssid, "");
        assert_eq!(guest.clients.len(), 0);
    }

    #[test]
    fn channel_falls_back_to_the_configured_one() {
        let (b, mut cfg, plans) = wireless_fixture();
        let st = wireless_status(&b, &cfg, &plans, &HashMap::new(), &[]);
        assert_eq!(st.radios[0].channel, 0, "auto and unknown");
        cfg.wireless.radios[0].channel = Channel::Fixed(11);
        let st = wireless_status(&b, &cfg, &plans, &HashMap::new(), &[]);
        assert_eq!(st.radios[0].channel, 11);
    }
}
