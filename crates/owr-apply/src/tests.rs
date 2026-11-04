//! Mapping tests: GL-MT6000 board plus configs built from `Config::defaults_for`.

#![allow(clippy::panic)] // test helpers fail loudly, as in owr-board/tests

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use owr_board::Board;
use owr_config as c;
use owr_fw as f;
use owr_net::{LinkSpec, RouteProto};
use owr_wifi as w;

use crate::{MapError, Plans, build_plans, redact_radios, resolv_conf};

type ApNames<'a> = Vec<(&'a str, Option<&'a str>)>;

const PASSPHRASE: &str = "correct horse battery";

fn board() -> Board {
    owr_board::builtin("glinet_gl-mt6000").unwrap()
}

fn defaults() -> c::Config {
    c::Config::defaults_for(&board())
}

fn plans(cfg: &c::Config) -> Plans {
    build_plans(&board(), cfg).unwrap()
}

fn net(s: &str) -> ipnet::Ipv4Net {
    s.parse().unwrap()
}

fn pool(start: u16, limit: u16, lease: Duration) -> c::DhcpPool {
    c::DhcpPool {
        enabled: true,
        start,
        limit,
        lease,
    }
}

fn vlan(name: &str, id: u16, isolated: bool) -> c::VlanConfig {
    c::VlanConfig {
        name: name.to_owned(),
        id,
        ports: vec!["lan4".to_owned()],
        ipv4: Some(net("10.20.0.1/24")),
        dhcp: Some(pool(50, 100, Duration::from_hours(1))),
        isolated,
    }
}

/// Defaults plus VLAN `guest` (id 20) on `lan4`, which leaves the LAN. Checked against the
/// board so the fixtures stay valid configs.
fn with_guest(isolated: bool) -> c::Config {
    let mut cfg = defaults();
    cfg.network.lan.ports.retain(|p| p != "lan4");
    cfg.network.vlans.push(vlan("guest", 20, isolated));
    cfg.validate_against(&board()).unwrap();
    cfg
}

fn ap(radio: &str, ssid: &str, network: &str) -> c::ApConfig {
    c::ApConfig {
        radio: radio.to_owned(),
        ssid: ssid.to_owned(),
        hidden: false,
        security: c::Security::Wpa3Sae {
            passphrase: PASSPHRASE.into(),
        },
        network: network.to_owned(),
        isolate_clients: false,
        max_clients: None,
    }
}

fn with_ap() -> c::Config {
    let mut cfg = defaults();
    cfg.wireless.aps.push(ap("radio1", "flint2", "lan"));
    cfg.validate_against(&board()).unwrap();
    cfg
}

fn zone(name: &str) -> f::ZoneName {
    f::ZoneName::new(name).unwrap()
}

fn forwards(p: &Plans, src: &str, dst: &str) -> bool {
    p.fw.forwardings
        .iter()
        .any(|x| x.src == zone(src) && x.dst == zone(dst))
}

fn link<'a>(p: &'a Plans, name: &str) -> &'a LinkSpec {
    p.net.links.iter().find(|l| l.name() == name).unwrap()
}

fn conf_lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

// ------------------------------------------------------------------ network

#[test]
fn defaults_build() {
    let p = plans(&defaults());
    assert_eq!(p.hostname, "ferritewrt");
    assert_eq!(p.net.validate(), Ok(()));
    assert_eq!(p.fw.validate(), Ok(()));
}

#[test]
fn br_lan_bridges_every_lan_port() {
    let p = plans(&defaults());
    let LinkSpec::Bridge {
        ports,
        vlan_filtering,
        ..
    } = link(&p, "br-lan")
    else {
        panic!("br-lan is not a bridge");
    };
    assert_eq!(ports, &["lan1", "lan2", "lan3", "lan4", "lan5"]);
    assert!(!vlan_filtering);
}

#[test]
fn every_board_port_is_a_physical_link_that_is_up() {
    let p = plans(&defaults());
    for port in &board().ethernet.ports {
        assert!(
            matches!(link(&p, &port.netdev), LinkSpec::Physical { up: true, .. }),
            "{} must be physical and up",
            port.netdev
        );
    }
}

#[test]
fn lan_address_is_on_the_bridge() {
    let p = plans(&defaults());
    assert!(
        p.net
            .addresses
            .iter()
            .any(|a| a.link == "br-lan" && a.addr.to_string() == "192.168.8.1/24")
    );
}

#[test]
fn wan_dhcp_client_on_eth1() {
    let p = plans(&defaults());
    assert!(matches!(
        link(&p, "eth1"),
        LinkSpec::Physical {
            up: true,
            mtu: None,
            mac: None,
            ..
        }
    ));
    assert_eq!(
        p.net.dhcp_clients,
        [owr_net::DhcpClientSpec {
            link: "eth1".to_owned(),
            hostname: Some("ferritewrt".to_owned()),
            vendor_class: None,
            request_dns: true,
            default_route_metric: 10,
        }]
    );
    assert_eq!(p.net.routes, Vec::new());
}

#[test]
fn wan_dhcp_hostname_override_wins() {
    let mut cfg = defaults();
    cfg.network.wan.proto = c::WanProto::Dhcp {
        hostname: Some("edge".to_owned()),
    };
    let p = plans(&cfg);
    assert_eq!(p.net.dhcp_clients[0].hostname.as_deref(), Some("edge"));
}

#[test]
fn wan_mac_and_mtu_overrides_apply_to_the_wan_netdev_only() {
    let mut cfg = defaults();
    cfg.network.wan.mac_override = Some(c::MacAddr([2, 0, 0, 0, 0, 1]));
    cfg.network.wan.mtu = Some(1492);
    let p = plans(&cfg);
    assert_eq!(
        link(&p, "eth1"),
        &LinkSpec::Physical {
            name: "eth1".to_owned(),
            up: true,
            mtu: Some(1492),
            mac: Some(owr_net::MacAddr([2, 0, 0, 0, 0, 1])),
        }
    );
    assert!(matches!(
        link(&p, "lan1"),
        LinkSpec::Physical {
            mtu: None,
            mac: None,
            ..
        }
    ));
}

#[test]
fn wan_static_maps_address_and_default_route() {
    let mut cfg = defaults();
    cfg.network.wan.proto = c::WanProto::Static {
        ipv4: net("203.0.113.2/24"),
        gateway: Ipv4Addr::new(203, 0, 113, 1),
        dns: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
    };
    let p = plans(&cfg);
    assert_eq!(p.net.dhcp_clients, Vec::new());
    assert!(
        p.net
            .addresses
            .iter()
            .any(|a| a.link == "eth1" && a.addr.to_string() == "203.0.113.2/24")
    );
    let [route] = p.net.routes.as_slice() else {
        panic!("expected exactly one route");
    };
    assert_eq!(route.dest.to_string(), "0.0.0.0/0");
    assert_eq!(route.via, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    assert_eq!(route.dev.as_deref(), Some("eth1"));
    assert_eq!(route.metric, 10);
    assert_eq!(route.proto, RouteProto::Static);
}

#[test]
fn pppoe_is_unsupported() {
    let mut cfg = defaults();
    cfg.network.wan.proto = c::WanProto::Pppoe {
        username: "user".to_owned(),
        password: "hunter2hunter2".into(),
        service: None,
    };
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::Unsupported("pppoe")
    );
}

#[test]
fn vlan_gets_bridge_and_tagged_subinterface() {
    let p = plans(&with_guest(true));
    assert_eq!(
        link(&p, "lan4.20"),
        &LinkSpec::Vlan {
            name: "lan4.20".to_owned(),
            parent: "lan4".to_owned(),
            id: 20,
        }
    );
    assert_eq!(
        link(&p, "br-guest"),
        &LinkSpec::Bridge {
            name: "br-guest".to_owned(),
            ports: vec!["lan4.20".to_owned()],
            vlan_filtering: false,
            mtu: None,
            mac: None,
        }
    );
    assert!(
        p.net
            .addresses
            .iter()
            .any(|a| a.link == "br-guest" && a.addr.to_string() == "10.20.0.1/24")
    );
    // lan4 left the LAN bridge.
    let LinkSpec::Bridge { ports, .. } = link(&p, "br-lan") else {
        panic!("br-lan is not a bridge");
    };
    assert_eq!(ports, &["lan1", "lan2", "lan3", "lan5"]);
}

#[test]
fn vlan_port_is_distinct_from_the_lan_ports() {
    // Config validation requires every port to belong to exactly one network; the fixture
    // is validated by `with_guest`, and sharing a port is rejected before mapping.
    let cfg = with_guest(true);
    let p = plans(&cfg);
    let LinkSpec::Bridge { ports, .. } = link(&p, "br-lan") else {
        panic!("br-lan is not a bridge");
    };
    assert!(!ports.contains(&"lan4".to_owned()));
    let LinkSpec::Bridge { ports, .. } = link(&p, "br-guest") else {
        panic!("br-guest is not a bridge");
    };
    assert_eq!(ports, &["lan4.20"]);
    assert_eq!(p.net.validate(), Ok(()));

    let mut shared = cfg;
    shared.network.lan.ports.push("lan4".to_owned());
    assert!(shared.validate_against(&board()).is_err());
}

#[test]
fn vlan_without_address_has_no_address_entry() {
    let mut cfg = with_guest(true);
    cfg.network.vlans[0].ipv4 = None;
    cfg.network.vlans[0].dhcp = None;
    let p = plans(&cfg);
    assert!(!p.net.addresses.iter().any(|a| a.link == "br-guest"));
}

#[test]
fn sysctl_baseline_is_present_in_plans_and_net_plan() {
    let p = plans(&defaults());
    for (k, v) in crate::net::FIXED_SYSCTLS {
        assert!(
            p.sysctl.contains(&((*k).to_owned(), (*v).to_owned())),
            "missing {k}={v}"
        );
    }
    let has = |k: &str, v: &str| p.sysctl.contains(&(k.to_owned(), v.to_owned()));
    assert!(has("net.ipv4.ip_forward", "1"));
    assert!(has("net.ipv6.conf.all.forwarding", "0"));
    assert!(has("kernel.yama.ptrace_scope", "1"));
    // The DHCP WAN also gets its loose rp_filter (see `dhcp_wan_gets_the_loose_rp_filter`).
    assert_eq!(p.sysctl.len(), crate::net::FIXED_SYSCTLS.len() + 3);
    assert_eq!(p.net.sysctls, p.sysctl);
}

#[test]
fn ipv6_forwarding_follows_ipv6_settings() {
    let mut cfg = defaults();
    cfg.network.lan.ipv6 = c::LanIpv6::Ula;
    let p = plans(&cfg);
    assert!(
        p.sysctl
            .contains(&("net.ipv6.conf.all.forwarding".to_owned(), "1".to_owned()))
    );
}

#[test]
fn unknown_lan_port_is_rejected() {
    let mut cfg = defaults();
    cfg.network.lan.ports.push("lan9".to_owned());
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownPort("lan9".to_owned())
    );
}

#[test]
fn unknown_wan_and_vlan_ports_are_rejected() {
    let mut cfg = defaults();
    cfg.network.wan.port = "uplink".to_owned();
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownPort("uplink".to_owned())
    );
    let mut cfg = with_guest(true);
    cfg.network.vlans[0].ports = vec!["lan7".to_owned()];
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownPort("lan7".to_owned())
    );
}

#[test]
fn duplicate_vlan_netdev_surfaces_the_net_validation_error() {
    let mut cfg = with_guest(true);
    cfg.network.vlans.push(vlan("other", 20, true));
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::Net(owr_net::ValidationError::DuplicateLink(
            "lan4.20".to_owned()
        ))
    );
}

#[test]
fn vlan_named_lan_collides_with_the_lan_bridge() {
    let mut cfg = defaults();
    cfg.network.vlans.push(vlan("lan", 30, false));
    assert!(matches!(
        build_plans(&board(), &cfg),
        Err(MapError::Net(owr_net::ValidationError::DuplicateLink(n))) if n == "br-lan"
    ));
}

#[test]
fn building_twice_gives_equal_plans() {
    let mut cfg = with_guest(true);
    cfg.wireless.aps.push(ap("radio1", "flint2", "guest"));
    cfg.dhcp.static_leases.push(c::StaticLease {
        mac: c::MacAddr([2, 0, 0, 0, 0, 9]),
        ip: Ipv4Addr::new(192, 168, 8, 20),
        hostname: Some("printer".to_owned()),
    });
    assert_eq!(plans(&cfg), plans(&cfg));
}

// ----------------------------------------------------------------- firewall

#[test]
fn default_firewall_snapshot() {
    let p = plans(&defaults());
    assert_eq!(p.fw.zones.len(), 2);
    insta::assert_snapshot!("default_firewall", f::render(&p.fw).unwrap());
}

#[test]
fn wan_input_policy_follows_config() {
    let wan_input = |input| {
        let mut cfg = defaults();
        cfg.firewall.default_wan_input = input;
        let p = plans(&cfg);
        p.fw.zones
            .iter()
            .find(|z| z.name == zone("wan"))
            .unwrap()
            .input
    };
    assert_eq!(wan_input(c::WanInput::Drop), f::Policy::Drop);
    assert_eq!(wan_input(c::WanInput::Reject), f::Policy::Reject);
}

#[test]
fn hardware_offload_devices_cover_wan_lan_ports_and_vlans() {
    let p = plans(&with_guest(true));
    assert_eq!(p.fw.options.flow_offload, f::FlowOffload::Hardware);
    assert_eq!(
        p.fw.options.offload_devices,
        ["eth1", "lan1", "lan2", "lan3", "lan5", "lan4.20"]
    );
}

#[test]
fn offload_off_means_no_devices() {
    let mut cfg = with_guest(true);
    cfg.firewall.hw_offload = false;
    let p = plans(&cfg);
    assert_eq!(p.fw.options.flow_offload, f::FlowOffload::Off);
    assert_eq!(p.fw.options.offload_devices, Vec::<String>::new());
}

#[test]
fn isolated_vlan_zone_and_forwardings() {
    let p = plans(&with_guest(true));
    let z = p.fw.zones.iter().find(|z| z.name == zone("guest")).unwrap();
    assert_eq!(z.interfaces, ["br-guest"]);
    assert_eq!(z.input, f::Policy::Drop);
    assert!(forwards(&p, "guest", "wan"));
    assert!(!forwards(&p, "guest", "lan"));
    assert!(forwards(&p, "lan", "guest"));
    assert!(forwards(&p, "lan", "wan"));

    let rules: Vec<_> =
        p.fw.rules
            .iter()
            .map(|r| (r.name.as_str(), r.proto, r.dst_port))
            .collect();
    assert_eq!(
        rules,
        [
            (
                "guest-dhcp",
                f::Proto::Udp,
                Some(f::PortRange { start: 67, end: 68 })
            ),
            (
                "guest-dns",
                f::Proto::TcpUdp,
                Some(f::PortRange::single(53))
            ),
            ("guest-icmp", f::Proto::Icmp, None),
        ]
    );
    for r in &p.fw.rules {
        assert_eq!(r.src, Some(zone("guest")));
        assert_eq!(r.dst, None);
        assert_eq!(r.action, f::Policy::Accept);
    }
}

#[test]
fn open_vlan_accepts_input_and_forwards_to_the_lan() {
    let p = plans(&with_guest(false));
    let z = p.fw.zones.iter().find(|z| z.name == zone("guest")).unwrap();
    assert_eq!(z.input, f::Policy::Accept);
    // The only restriction is the management API (default bind = lan).
    let names: Vec<_> = p.fw.rules.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["guest-api-block"]);
    assert!(forwards(&p, "guest", "lan"));
    assert!(forwards(&p, "guest", "wan"));
    assert!(forwards(&p, "lan", "guest"));
}

#[test]
fn vlan_firewall_snapshot() {
    let p = plans(&with_guest(true));
    insta::assert_snapshot!("isolated_vlan_firewall", f::render(&p.fw).unwrap());
}

#[test]
fn invalid_zone_name_is_rejected() {
    let mut cfg = with_guest(true);
    cfg.network.vlans[0].name = "Guest".to_owned();
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::InvalidZoneName("Guest".to_owned())
    );
}

#[test]
fn too_long_zone_name_is_rejected() {
    let mut cfg = with_guest(true);
    cfg.network.vlans[0].name = "a_very_long_zone_name".to_owned();
    assert!(matches!(
        build_plans(&board(), &cfg),
        Err(MapError::InvalidZoneName(_))
    ));
}

#[test]
fn port_forward_becomes_a_wan_redirect() {
    let mut cfg = defaults();
    cfg.firewall.port_forwards.push(c::PortForward {
        name: "web".to_owned(),
        proto: c::ForwardProto::TcpUdp,
        wan_port: c::PortRange {
            start: 8080,
            end: 8081,
        },
        dest_ip: Ipv4Addr::new(192, 168, 8, 50),
        dest_port: 80,
        enabled: false,
    });
    let p = plans(&cfg);
    assert_eq!(
        p.fw.redirects,
        [f::Redirect {
            name: "web".to_owned(),
            src: zone("wan"),
            proto: f::Proto::TcpUdp,
            src_dport: f::PortRange {
                start: 8080,
                end: 8081
            },
            dest_ip: Ipv4Addr::new(192, 168, 8, 50),
            dest_port: 80,
            enabled: false,
        }]
    );
    assert!(f::render(&p.fw).is_ok());
}

#[test]
fn rule_directions_map_to_zones() {
    let mut cfg = defaults();
    cfg.firewall.rules = vec![
        c::Rule {
            name: "ssh-in".to_owned(),
            direction: c::Direction::WanIn,
            proto: c::RuleProto::Tcp,
            src: Some("198.51.100.0/24".parse().unwrap()),
            dest_port: Some(c::PortRange::single(22)),
            action: c::Action::Accept,
            enabled: true,
        },
        c::Rule {
            name: "no-telnet".to_owned(),
            direction: c::Direction::LanOut,
            proto: c::RuleProto::Any,
            src: None,
            dest_port: None,
            action: c::Action::Reject,
            enabled: false,
        },
    ];
    let p = plans(&cfg);
    let [wan_in, lan_out] = p.fw.rules.as_slice() else {
        panic!("expected two rules");
    };
    assert_eq!(wan_in.src, Some(zone("wan")));
    assert_eq!(wan_in.dst, None);
    assert_eq!(wan_in.proto, f::Proto::Tcp);
    assert_eq!(wan_in.src_ip, Some("198.51.100.0/24".parse().unwrap()));
    assert_eq!(wan_in.dst_port, Some(f::PortRange::single(22)));
    assert_eq!(wan_in.action, f::Policy::Accept);
    assert!(wan_in.enabled);

    assert_eq!(lan_out.src, Some(zone("lan")));
    assert_eq!(lan_out.dst, Some(zone("wan")));
    assert_eq!(lan_out.proto, f::Proto::Any);
    assert_eq!(lan_out.action, f::Policy::Reject);
    assert!(!lan_out.enabled);
    assert!(f::render(&p.fw).is_ok());
}

#[test]
fn firewall_issues_are_surfaced() {
    let mut cfg = defaults();
    cfg.firewall.rules = vec![c::Rule {
        name: "bad\u{7}name".to_owned(),
        direction: c::Direction::WanIn,
        proto: c::RuleProto::Icmp,
        src: None,
        dest_port: None,
        action: c::Action::Drop,
        enabled: true,
    }];
    let Err(MapError::Fw(issues)) = build_plans(&board(), &cfg) else {
        panic!("expected a firewall issue");
    };
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].path, "rules[0].name");
}

// ----------------------------------------------------------------- wireless

#[test]
fn defaults_have_no_radio_plans() {
    assert_eq!(plans(&defaults()).radios, Vec::new());
}

#[test]
fn wpa3_ap_maps_and_renders_hostapd_snapshot() {
    let p = plans(&with_ap());
    let [radio] = p.radios.as_slice() else {
        panic!("expected one radio plan");
    };
    assert_eq!(radio.phy, "phy1");
    assert_eq!(radio.band, w::Band::G5);
    assert_eq!(radio.channel, w::Channel::Auto);
    assert_eq!(radio.width_mhz, 80);
    assert_eq!(radio.country, "US");
    let [bss] = radio.aps.as_slice() else {
        panic!("expected one AP");
    };
    assert_eq!(bss.ifname, "wlan1");
    assert_eq!(bss.bridge.as_deref(), Some("br-lan"));
    assert_eq!(bss.security.passphrase(), Some(PASSPHRASE));
    insta::assert_snapshot!("wpa3_hostapd", w::render_hostapd(radio).unwrap());
}

#[test]
fn board_standards_and_quirks_carry_over() {
    let p = plans(&with_ap());
    let radio = &p.radios[0];
    assert_eq!(
        radio.standards,
        [w::Standard::N, w::Standard::Ac, w::Standard::Ax]
    );
    assert!(radio.driver_quirks.mt76);
}

#[test]
fn second_ap_gets_a_suffix_and_vlan_bridge() {
    let mut cfg = with_guest(true);
    cfg.wireless.aps.push(ap("radio1", "main", "lan"));
    cfg.wireless.aps.push(ap("radio1", "guests", "guest"));
    cfg.wireless.aps.push(ap("radio0", "main-2g", "lan"));
    cfg.validate_against(&board()).unwrap();
    let p = plans(&cfg);
    let ifnames: Vec<(&str, ApNames<'_>)> = p
        .radios
        .iter()
        .map(|r| {
            (
                r.phy.as_str(),
                r.aps
                    .iter()
                    .map(|a| (a.ifname.as_str(), a.bridge.as_deref()))
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        ifnames,
        [
            ("phy0", vec![("wlan0", Some("br-lan"))]),
            (
                "phy1",
                vec![("wlan1", Some("br-lan")), ("wlan1-1", Some("br-guest"))]
            ),
        ]
    );
}

#[test]
fn ap_options_and_security_modes_map() {
    let mut cfg = defaults();
    let mut open = ap("radio1", "open", "lan");
    open.security = c::Security::Open;
    open.hidden = true;
    open.isolate_clients = true;
    open.max_clients = Some(12);
    let mut mixed = ap("radio1", "mixed", "lan");
    mixed.security = c::Security::Wpa2Wpa3Mixed {
        passphrase: "another passphrase".into(),
    };
    let mut wpa2 = ap("radio1", "wpa2", "lan");
    wpa2.security = c::Security::Wpa2Psk {
        passphrase: "yet another one".into(),
    };
    cfg.wireless.aps = vec![open, mixed, wpa2];
    let p = plans(&cfg);
    let aps = &p.radios[0].aps;
    assert_eq!(aps[0].security, w::Security::Open);
    assert!(aps[0].hidden && aps[0].isolate_clients);
    assert_eq!(aps[0].max_clients, Some(12));
    assert!(matches!(
        &aps[1].security,
        w::Security::Wpa2Wpa3Mixed { .. }
    ));
    assert_eq!(aps[1].security.passphrase(), Some("another passphrase"));
    assert!(matches!(&aps[2].security, w::Security::Wpa2Psk { .. }));
}

#[test]
fn fixed_channel_and_txpower_carry_over() {
    let mut cfg = with_ap();
    cfg.wireless.radios[1].channel = c::Channel::Fixed(36);
    cfg.wireless.radios[1].txpower_dbm = Some(17);
    let p = plans(&cfg);
    assert_eq!(p.radios[0].channel, w::Channel::Fixed(36));
    assert_eq!(p.radios[0].txpower_dbm, Some(17));
}

#[test]
fn disabled_radio_is_skipped() {
    let mut cfg = with_ap();
    cfg.wireless.radios[1].enabled = false;
    assert_eq!(plans(&cfg).radios, Vec::new());
}

#[test]
fn width_beyond_the_board_maximum_is_rejected() {
    let mut cfg = defaults();
    cfg.wireless.radios[0].width_mhz = 80;
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::WidthExceedsBoard {
            radio: "radio0".to_owned(),
            width: 80,
            max: 40,
        }
    );
}

#[test]
fn full_width_on_the_5ghz_radio_is_accepted() {
    let mut cfg = with_ap();
    cfg.wireless.radios[1].width_mhz = 160;
    assert_eq!(plans(&cfg).radios[0].width_mhz, 160);
}

#[test]
fn unknown_radio_is_rejected() {
    let mut cfg = defaults();
    cfg.wireless.radios[0].id = "radio9".to_owned();
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownRadio("radio9".to_owned())
    );
}

#[test]
fn ap_on_an_undeclared_radio_is_rejected() {
    let mut cfg = defaults();
    cfg.wireless.aps.push(ap("radio7", "x", "lan"));
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownRadio("radio7".to_owned())
    );
}

#[test]
fn ap_on_an_unknown_network_is_rejected() {
    let mut cfg = defaults();
    cfg.wireless.aps.push(ap("radio1", "x", "iot"));
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::UnknownNetwork("iot".to_owned())
    );
}

#[test]
fn wifi_issues_are_surfaced() {
    let mut cfg = with_ap();
    cfg.wireless.radios[1].country = "usa".to_owned();
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::Wifi(vec![w::Issue::Country("usa".to_owned())])
    );
}

#[test]
fn redaction_hides_passphrases_without_touching_the_plan() {
    let p = plans(&with_ap());
    let json = serde_json::to_string(&redact_radios(&p.radios)).unwrap();
    assert!(!json.contains(PASSPHRASE));
    assert!(json.contains("***"));
    assert_eq!(p.radios[0].aps[0].security.passphrase(), Some(PASSPHRASE));
}

// ------------------------------------------------------------------ dnsmasq

#[test]
fn default_dnsmasq_snapshot() {
    insta::assert_snapshot!("default_dnsmasq", plans(&defaults()).dnsmasq_conf);
}

#[test]
fn vlan_and_static_lease_dnsmasq_snapshot() {
    let mut cfg = with_guest(true);
    cfg.dhcp.dns_servers = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        "2606:4700:4700::1111".parse().unwrap(),
    ];
    cfg.dhcp.static_leases = vec![
        c::StaticLease {
            mac: c::MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]),
            ip: Ipv4Addr::new(192, 168, 8, 20),
            hostname: Some("printer".to_owned()),
        },
        c::StaticLease {
            mac: c::MacAddr([0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x33]),
            ip: Ipv4Addr::new(10, 20, 0, 5),
            hostname: None,
        },
    ];
    cfg.validate_against(&board()).unwrap();
    insta::assert_snapshot!("vlan_lease_dnsmasq", plans(&cfg).dnsmasq_conf);
}

#[test]
fn lan_dhcp_range_math_matches_the_pool() {
    let conf = plans(&defaults()).dnsmasq_conf;
    let lines = conf_lines(&conf);
    assert!(lines.contains(&"dhcp-range=set:lan,192.168.8.100,192.168.8.249,255.255.255.0,12h"));
    assert!(lines.contains(&"dhcp-option=tag:lan,option:router,192.168.8.1"));
    assert!(lines.contains(&"dhcp-option=tag:lan,option:dns-server,192.168.8.1"));
}

#[test]
fn dhcp_range_function_covers_the_edges() {
    let range = |n: &str, start, limit| {
        crate::dnsmasq::dhcp_range("lan", net(n), &pool(start, limit, Duration::from_hours(1)))
    };
    assert_eq!(
        range("192.168.8.1/24", 100, 150),
        Ok((
            Ipv4Addr::new(192, 168, 8, 100),
            Ipv4Addr::new(192, 168, 8, 249)
        ))
    );
    // Last usable host of a /24 is .254.
    assert_eq!(
        range("192.168.8.1/24", 254, 1),
        Ok((
            Ipv4Addr::new(192, 168, 8, 254),
            Ipv4Addr::new(192, 168, 8, 254)
        ))
    );
    assert!(range("192.168.8.1/24", 200, 100).is_err());
    assert!(range("192.168.8.1/24", 255, 1).is_err());
    assert!(range("192.168.8.1/24", 0, 10).is_err());
    assert!(range("192.168.8.1/24", 10, 0).is_err());
    // Router is .1: pools that contain it are refused, pools next to it are fine.
    assert!(range("192.168.8.1/24", 1, 10).is_err());
    assert!(range("192.168.8.1/24", 2, 10).is_ok());
    // The pool is relative to the network address, not the router address.
    assert_eq!(
        range("10.0.0.200/24", 100, 50),
        Ok((Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 149)))
    );
    assert!(range("10.0.0.130/24", 100, 50).is_err());
    // Tiny subnets.
    assert!(range("10.0.0.1/30", 2, 1).is_ok());
    assert!(range("10.0.0.1/30", 2, 2).is_err());
    assert!(range("10.0.0.1/31", 1, 1).is_err());
}

#[test]
fn pool_outside_the_subnet_is_rejected() {
    let mut cfg = defaults();
    cfg.network.lan.dhcp = pool(200, 100, Duration::from_hours(12));
    assert_eq!(
        build_plans(&board(), &cfg).unwrap_err(),
        MapError::DhcpRangeOutOfSubnet {
            network: "lan".to_owned(),
            subnet: net("192.168.8.1/24"),
            start: 200,
            limit: 100,
        }
    );
}

#[test]
fn vlan_pool_outside_the_subnet_is_rejected() {
    let mut cfg = with_guest(true);
    cfg.network.vlans[0].dhcp = Some(pool(250, 20, Duration::from_hours(1)));
    assert!(matches!(
        build_plans(&board(), &cfg),
        Err(MapError::DhcpRangeOutOfSubnet { network, .. }) if network == "guest"
    ));
}

#[test]
fn disabled_dhcp_renders_no_range() {
    let mut cfg = defaults();
    cfg.network.lan.dhcp.enabled = false;
    let conf = plans(&cfg).dnsmasq_conf;
    assert!(!conf.contains("dhcp-range"));
    assert!(conf.lines().any(|l| l == "interface=br-lan"));
}

#[test]
fn lease_times_use_the_shortest_exact_unit() {
    let lease = |d| {
        let mut cfg = defaults();
        cfg.network.lan.dhcp.lease = d;
        let conf = plans(&cfg).dnsmasq_conf;
        let line = conf.lines().find(|l| l.starts_with("dhcp-range")).unwrap();
        line.rsplit(',').next().unwrap().to_owned()
    };
    assert_eq!(lease(Duration::from_hours(12)), "12h");
    assert_eq!(lease(Duration::from_mins(90)), "90m");
    assert_eq!(lease(Duration::from_secs(150)), "150");
}

#[test]
fn explicit_dns_servers_replace_the_resolv_file() {
    let mut cfg = defaults();
    cfg.dhcp.dns_servers = vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))];
    let conf = plans(&cfg).dnsmasq_conf;
    let lines = conf_lines(&conf);
    assert!(lines.contains(&"no-resolv"));
    assert!(lines.contains(&"server=9.9.9.9"));
    assert!(!conf.contains("resolv-file"));

    let conf = plans(&defaults()).dnsmasq_conf;
    assert!(conf.contains("resolv-file=/run/ferritewrt/resolv.conf.auto"));
    assert!(!conf.contains("no-resolv"));
}

#[test]
fn rebind_protection_is_optional() {
    let mut cfg = defaults();
    cfg.dhcp.rebind_protection = false;
    let conf = plans(&cfg).dnsmasq_conf;
    assert!(!conf.contains("stop-dns-rebind"));
    assert!(!conf.contains("rebind-localhost-ok"));
    assert!(plans(&defaults()).dnsmasq_conf.contains("stop-dns-rebind"));
}

#[test]
fn dnsmasq_never_listens_on_the_wan_and_has_no_user_or_conf_dir() {
    let conf = plans(&defaults()).dnsmasq_conf;
    assert!(conf.lines().any(|l| l == "except-interface=eth1"));
    assert!(
        conf.lines()
            .all(|l| !l.starts_with("user=") && !l.starts_with("conf-dir"))
    );
}

// ---------------------------------------------------------------- injection

fn assert_injection(cfg: &c::Config, field: &str) {
    match build_plans(&board(), cfg).unwrap_err() {
        err @ MapError::Injection {
            value_redacted: true,
            ..
        } => {
            let MapError::Injection { field: got, .. } = &err else {
                unreachable!()
            };
            assert_eq!(got, field);
            let text = err.to_string();
            assert!(!text.contains("server=") && !text.contains('\n'), "{text}");
        }
        other => panic!("expected an injection error, got {other:?}"),
    }
}

#[test]
fn system_hostname_with_newline_is_rejected() {
    let mut cfg = defaults();
    cfg.system.hostname = "router\nserver=203.0.113.9".to_owned();
    assert_injection(&cfg, "system.hostname");
}

#[test]
fn static_lease_hostname_with_comma_or_newline_is_rejected() {
    for bad in ["a,b", "evil\ndhcp-option=3,1.2.3.4", "with space", ""] {
        let mut cfg = defaults();
        cfg.dhcp.static_leases = vec![c::StaticLease {
            mac: c::MacAddr([2, 0, 0, 0, 0, 1]),
            ip: Ipv4Addr::new(192, 168, 8, 20),
            hostname: Some(bad.to_owned()),
        }];
        assert_injection(&cfg, "dhcp.static_leases[0].hostname");
    }
}

#[test]
fn local_domain_with_injected_directive_is_rejected() {
    let mut cfg = defaults();
    cfg.dhcp.local_domain = "lan\nserver=203.0.113.9".to_owned();
    assert_injection(&cfg, "dhcp.local_domain");
}

#[test]
fn empty_local_domain_omits_the_domain_lines() {
    let mut cfg = defaults();
    cfg.dhcp.local_domain = String::new();
    let conf = plans(&cfg).dnsmasq_conf;
    assert!(
        !conf.contains("local=/") && !conf.contains("domain=") && !conf.contains("expand-hosts")
    );
}

// ------------------------------------------------------------------- resolv

#[test]
fn resolv_conf_lists_one_nameserver_per_line() {
    let text = resolv_conf(&[
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        "2606:4700:4700::1111".parse().unwrap(),
    ]);
    assert_eq!(
        text,
        "# Generated by owr-apply.\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"
    );
    assert_eq!(resolv_conf(&[]), "# Generated by owr-apply.\n");
}

// -------------------------------------------------------------------- files

mod files {
    use super::*;
    use crate::files::{
        DNSMASQ_CONF, NETD_PLAN, RESOLV_AUTO, netd_json, write_daemon_files, write_resolv,
    };

    #[test]
    fn writes_every_file_then_reports_unchanged() {
        let cfg = with_ap();
        let p = plans(&cfg);
        let dir = tempfile::tempdir().unwrap();
        let first = write_daemon_files(&p, &cfg, dir.path()).unwrap();
        assert!(first.dnsmasq_changed && first.netd_changed);
        assert_eq!(first.hostapd_changed, [("phy1".to_owned(), true)]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(DNSMASQ_CONF)).unwrap(),
            p.dnsmasq_conf
        );
        let netd = std::fs::read_to_string(dir.path().join(NETD_PLAN)).unwrap();
        assert_eq!(netd, netd_json(&p.netd).unwrap());
        let json: serde_json::Value = serde_json::from_str(&netd).unwrap();
        assert_eq!(json["dhcp"]["link"], "eth1");
        assert_eq!(json["ra"], serde_json::json!([]));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("hostapd-phy1.conf")).unwrap(),
            w::render_hostapd(&p.radios[0]).unwrap()
        );
        let second = write_daemon_files(&p, &cfg, dir.path()).unwrap();
        assert!(!second.dnsmasq_changed && !second.netd_changed);
        assert_eq!(second.hostapd_changed, [("phy1".to_owned(), false)]);
    }

    #[test]
    fn a_changed_config_reports_only_the_affected_daemon() {
        let mut cfg = with_ap();
        let dir = tempfile::tempdir().unwrap();
        write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        cfg.dhcp.rebind_protection = false;
        let again = write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        assert!(again.dnsmasq_changed);
        assert!(!again.netd_changed);
        assert_eq!(again.hostapd_changed, [("phy1".to_owned(), false)]);

        // The DHCP client sends the hostname: the network daemon must restart.
        let mut renamed = cfg.clone();
        renamed.network.wan.proto = c::WanProto::Dhcp {
            hostname: Some("edge".to_owned()),
        };
        let again = write_daemon_files(&plans(&renamed), &renamed, dir.path()).unwrap();
        assert!(again.netd_changed);
    }

    #[test]
    fn dhcp_wan_creates_an_empty_resolv_file_but_never_clobbers_a_lease() {
        let cfg = defaults();
        let dir = tempfile::tempdir().unwrap();
        write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        let resolv = dir.path().join(RESOLV_AUTO);
        assert_eq!(std::fs::read_to_string(&resolv).unwrap(), resolv_conf(&[]));

        write_resolv(dir.path(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))]).unwrap();
        write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        assert!(
            std::fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 192.0.2.53")
        );
    }

    #[test]
    fn static_wan_publishes_its_dns_servers() {
        let mut cfg = defaults();
        cfg.network.wan.proto = c::WanProto::Static {
            ipv4: net("203.0.113.2/24"),
            gateway: Ipv4Addr::new(203, 0, 113, 1),
            dns: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
        };
        let dir = tempfile::tempdir().unwrap();
        write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        assert!(
            std::fs::read_to_string(dir.path().join(RESOLV_AUTO))
                .unwrap()
                .contains("nameserver 9.9.9.9")
        );
    }

    #[test]
    fn write_resolv_reports_changes() {
        let dir = tempfile::tempdir().unwrap();
        let dns = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        assert!(write_resolv(dir.path(), &dns).unwrap());
        assert!(!write_resolv(dir.path(), &dns).unwrap());
    }

    #[test]
    fn missing_run_dir_is_created() {
        let cfg = defaults();
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        write_daemon_files(&plans(&cfg), &cfg, &nested).unwrap();
        assert!(nested.join(DNSMASQ_CONF).exists());
    }
}

mod followups;
