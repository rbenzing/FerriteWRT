//! Unit tests. The README example doubles as the canonical valid config fixture.
// Tests index into fixtures they have just built; a panic there is the failure signal.
#![allow(clippy::indexing_slicing)]

use std::net::Ipv4Addr;
use std::time::Duration;

use proptest::prelude::*;

use crate::*;

const README: &str = include_str!("../README.md");
const PASSPHRASE: &str = "correct horse battery";
const SALT: &str = "c29tZXNhbHRzb21lc2FsdA";
const DIGEST: &str = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy";
const HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy";

fn example_toml() -> &'static str {
    let (_, rest) = README.split_once("```toml\n").unwrap();
    rest.split_once("\n```").unwrap().0
}

fn board() -> owr_board::Board {
    owr_board::builtin("glinet_gl-mt6000").unwrap()
}

fn base() -> Config {
    Config::from_toml_str(example_toml()).unwrap()
}

fn issues(cfg: &Config) -> Vec<Issue> {
    cfg.validate().err().unwrap_or_default()
}

/// Assert the config is rejected with exactly one issue, at `path`.
fn assert_only(cfg: &Config, path: &str) {
    let found = issues(cfg);
    let paths: Vec<&str> = found.iter().map(|i| i.path.as_str()).collect();
    assert_eq!(paths, [path], "issues: {found:?}");
}

fn assert_board_issue(cfg: &Config, path: &str) {
    let found = cfg.validate_against(&board()).unwrap_err();
    assert!(
        found.iter().any(|i| i.path == path),
        "want {path} in {found:?}"
    );
}

fn mutated(f: impl FnOnce(&mut Config)) -> Config {
    let mut c = base();
    f(&mut c);
    c
}

fn vlan(c: &mut Config) -> &mut VlanConfig {
    c.network.vlans.first_mut().unwrap()
}

fn ap(c: &mut Config) -> &mut ApConfig {
    c.wireless.aps.first_mut().unwrap()
}

fn radio<'a>(c: &'a mut Config, id: &str) -> &'a mut RadioConfig {
    c.wireless.radios.iter_mut().find(|r| r.id == id).unwrap()
}

fn user(c: &mut Config) -> &mut User {
    c.users.first_mut().unwrap()
}

fn forward(c: &mut Config) -> &mut PortForward {
    c.firewall.port_forwards.first_mut().unwrap()
}

fn lease(mac: &str, ip: [u8; 4]) -> StaticLease {
    StaticLease {
        mac: mac.parse().unwrap(),
        ip: Ipv4Addr::from(ip),
        hostname: None,
    }
}

// ------------------------------------------------------------ parse / model

#[test]
fn readme_example_is_valid_and_fits_the_flint2() {
    let cfg = base();
    cfg.validate_against(&board()).unwrap();
    assert_eq!(cfg.network.vlans.len(), 1);
    assert_eq!(cfg.services.api.session_ttl, Duration::from_mins(30));
}

#[test]
fn toml_round_trip_is_lossless() {
    let cfg = base();
    let text = cfg.to_toml_string().unwrap();
    assert_eq!(Config::from_toml_str(&text).unwrap(), cfg);
    // Canonical output is a fixed point.
    assert_eq!(
        Config::from_toml_str(&text)
            .unwrap()
            .to_toml_string()
            .unwrap(),
        text
    );
}

#[test]
fn every_wan_proto_and_channel_round_trips() {
    for proto in [
        WanProto::Dhcp {
            hostname: Some("flint".into()),
        },
        WanProto::Static {
            ipv4: "203.0.113.2/24".parse().unwrap(),
            gateway: "203.0.113.1".parse().unwrap(),
            dns: vec![
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ],
        },
        WanProto::Pppoe {
            username: "u".into(),
            password: Secret::from("p"),
            service: Some("isp".into()),
        },
    ] {
        let mut cfg = base();
        cfg.network.wan.proto = proto;
        cfg.network.wan.mac_override = Some("02:00:00:00:00:01".parse().unwrap());
        radio(&mut cfg, "radio1").channel = Channel::Fixed(36);
        let text = cfg.to_toml_string().unwrap();
        assert_eq!(
            Config::from_toml_str(&text).unwrap(),
            cfg,
            "{}",
            redact(&cfg).to_toml_string().unwrap()
        );
    }
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    let text = example_toml();
    for (from, to) in [
        ("schema = 1\n", "schema = 1\nbogus = 1\n"),
        ("[system]\n", "[system]\nbogus = 1\n"),
        (
            "proto = { type = \"dhcp\" }",
            "proto = { type = \"dhcp\", bogus = 1 }",
        ),
        ("ports = [\"lan5\"]\n", "ports = [\"lan5\"]\nbogus = 1\n"),
        ("[services.api]\n", "[services.api]\nbogus = 1\n"),
    ] {
        assert!(text.contains(from), "fixture lost {from:?}");
        let err = Config::from_toml_str(&text.replace(from, to)).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{from:?} -> {err}");
    }
}

#[test]
fn schema_must_be_present_and_supported() {
    let without = example_toml().replacen("schema = 1\n", "", 1);
    let err = Config::from_toml_str(&without).unwrap_err();
    assert_eq!(
        err.issues().first().map(|i| i.path.as_str()),
        Some("schema")
    );
    for bad in [0, 2, 99] {
        let text = example_toml().replacen("schema = 1", &format!("schema = {bad}"), 1);
        assert!(
            matches!(Config::from_toml_str(&text), Err(ConfigError::UnsupportedSchema(n)) if n == bad)
        );
    }
    let text = example_toml().replacen("schema = 1", "schema = \"one\"", 1);
    assert!(
        Config::from_toml_str(&text)
            .unwrap_err()
            .issues()
            .iter()
            .any(|i| i.path == "schema")
    );
    assert!(Config::migrate(toml::Value::Integer(1)).is_err());
}

#[test]
fn parse_errors_do_not_echo_secret_lines() {
    let text = example_toml().replacen(PASSPHRASE, &format!("{PASSPHRASE}\" oops \""), 1);
    let msg = Config::from_toml_str(&text).unwrap_err().to_string();
    assert!(!msg.contains(PASSPHRASE), "{msg}");
}

#[test]
fn durations_parse_and_reject_garbage() {
    let cfg = base();
    assert_eq!(cfg.network.lan.dhcp.lease, Duration::from_hours(12));
    let text = example_toml().replacen("lease = \"12h\"", "lease = \"soon\"", 1);
    assert!(matches!(
        Config::from_toml_str(&text),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn channel_accepts_auto_or_number_only() {
    let text = example_toml().replacen("channel = \"auto\"", "channel = 6", 1);
    assert_eq!(
        radio(&mut Config::from_toml_str(&text).unwrap(), "radio0").channel,
        Channel::Fixed(6)
    );
    let text = example_toml().replacen("channel = \"auto\"", "channel = \"best\"", 1);
    assert!(matches!(
        Config::from_toml_str(&text),
        Err(ConfigError::Parse(_))
    ));
}

// --------------------------------------------------------------- defaults

#[test]
fn defaults_for_flint2_are_valid_and_board_correct() {
    let b = board();
    let cfg = Config::defaults_for(&b);
    cfg.validate().unwrap();
    cfg.validate_against(&b).unwrap();
    assert_eq!(
        cfg.network.lan.ports,
        ["lan1", "lan2", "lan3", "lan4", "lan5"]
    );
    assert_eq!(cfg.network.wan.port, "wan");
    assert_eq!(cfg.network.wan.proto, WanProto::Dhcp { hostname: None });
    assert_eq!(cfg.network.lan.ipv4.to_string(), "192.168.8.1/24");
    assert_eq!(
        (cfg.network.lan.dhcp.start, cfg.network.lan.dhcp.limit),
        (100, 150)
    );
    assert!(cfg.users.is_empty() && cfg.wireless.aps.is_empty());
    let widths: Vec<(&str, u16)> = cfg
        .wireless
        .radios
        .iter()
        .map(|r| (r.id.as_str(), r.width_mhz))
        .collect();
    assert_eq!(widths, [("radio0", 20), ("radio1", 80)]);
    assert!(
        cfg.wireless
            .radios
            .iter()
            .all(|r| r.enabled && r.channel == Channel::Auto)
    );
    assert!(cfg.firewall.hw_offload);
    assert_eq!(cfg.services.api.port, 443);
    assert_eq!(cfg.services.api.bind, ApiBind::Lan);
}

#[test]
fn defaults_survive_a_text_round_trip() {
    let cfg = Config::defaults_for(&board());
    let text = cfg.to_toml_string().unwrap();
    assert_eq!(Config::from_toml_str(&text).unwrap(), cfg);
}

// ------------------------------------------------------------ system/users

#[test]
fn hostname_must_be_an_rfc1123_label() {
    for bad in ["", "-a", "a-", "a_b", "a.b", "with space", &"x".repeat(64)] {
        assert_only(
            &mutated(|c| c.system.hostname = bad.into()),
            "system.hostname",
        );
    }
    for good in ["a", "flint-2", "0day", &"x".repeat(63)] {
        mutated(|c| c.system.hostname = good.into())
            .validate()
            .unwrap();
    }
}

#[test]
fn timezone_and_ntp_are_checked() {
    for bad in ["", "Europe//Berlin", "/UTC", "Mars Base", "a;b"] {
        assert_only(
            &mutated(|c| c.system.timezone = bad.into()),
            "system.timezone",
        );
    }
    mutated(|c| c.system.timezone = "America/Argentina/Buenos_Aires".into())
        .validate()
        .unwrap();
    assert_only(
        &mutated(|c| c.system.ntp_servers = vec!["ok.example.org".into(), "bad host".into()]),
        "system.ntp_servers[1]",
    );
    mutated(|c| c.system.ntp_servers = vec!["10.0.0.1".into(), "fd00::1".into()])
        .validate()
        .unwrap();
}

#[test]
fn user_name_rules_and_uniqueness() {
    for bad in ["", "Admin", "1root", "a b", &"a".repeat(33)] {
        assert_only(&mutated(|c| user(c).name = bad.into()), "users[0].name");
    }
    let dup = mutated(|c| {
        let mut second = c.users[0].clone();
        second.role = Role::Viewer;
        c.users.push(second);
    });
    assert_only(&dup, "users[1].name");
}

#[test]
fn users_need_an_enabled_admin_unless_unconfigured() {
    assert_only(&mutated(|c| user(c).enabled = false), "users");
    assert_only(&mutated(|c| user(c).role = Role::Viewer), "users");
    mutated(|c| c.users.clear()).validate().unwrap();
}

#[test]
fn invalid_phc_hashes_are_rejected_without_leaking() {
    let secret = "SuperSecretSaltValue123";
    let bad = [
        "plaintext".to_owned(),
        "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21l$Zm9vYmFyZm9vYmFyZm9v".to_owned(),
        "$argon2id$v=19$m=19456,t=2$c29tZXNhbHRzb21l$Zm9vYmFyZm9vYmFyZm9v".to_owned(),
        "$argon2id$v=19$m=0,t=2,p=1$c29tZXNhbHRzb21l$Zm9vYmFyZm9vYmFyZm9v".to_owned(),
        "$argon2id$v=19$m=1,t=2,p=1,x=1$c29tZXNhbHRzb21l$Zm9vYmFyZm9vYmFyZm9v".to_owned(),
        "$argon2id$v=99$m=19456,t=2,p=1$c29tZXNhbHRzb21l$Zm9vYmFyZm9vYmFyZm9v".to_owned(),
        format!("$argon2id$v=19$m=19456,t=2,p=1${secret}!$Zm9vYmFyZm9vYmFyZm9v"),
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21l$short".to_owned(),
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21l".to_owned(),
        String::new(),
    ];
    for h in bad {
        let cfg = mutated(|c| user(c).password_hash = Secret::from(h.as_str()));
        assert_only(&cfg, "users[0].password_hash");
        let msg = Config::from_toml_str(&cfg.to_toml_string().unwrap())
            .unwrap_err()
            .to_string();
        assert!(!msg.contains(secret), "{msg}");
    }
    // The version segment is optional in PHC.
    mutated(|c| {
        user(c).password_hash = Secret::from(format!("$argon2id$m=19456,t=2,p=1${SALT}${DIGEST}"));
    })
    .validate()
    .unwrap();
}

#[test]
fn argon2_parameters_and_lengths_are_bounded() {
    let hash = |params: &str, salt: &str, digest: &str| {
        mutated(|c| {
            user(c).password_hash =
                Secret::from(format!("$argon2id$v=19$m={params}${salt}${digest}"));
        })
    };
    // OWASP minimum and a heavier-but-sane setting are accepted; so are the exact bounds.
    for ok in [
        "19456,t=2,p=1",
        "65536,t=3,p=4",
        "8192,t=1,p=1",
        "1048576,t=10,p=16",
    ] {
        hash(ok, SALT, DIGEST).validate().unwrap();
    }
    for bad in [
        "8191,t=2,p=1",
        "1048577,t=2,p=1",
        "4294967295,t=2,p=1",
        "19456,t=0,p=1",
        "19456,t=11,p=1",
        "19456,t=2,p=0",
        "19456,t=2,p=17",
        "19456,t=2,p=1,m=19456",
    ] {
        assert_only(&hash(bad, SALT, DIGEST), "users[0].password_hash");
    }
    // 10 base64 characters is 7.5 bytes; 11 is the minimum.
    assert_only(
        &hash("19456,t=2,p=1", "c29tZXNhbH", DIGEST),
        "users[0].password_hash",
    );
    hash("19456,t=2,p=1", "c29tZXNhbHQ", DIGEST)
        .validate()
        .unwrap();
    // 15 bytes (20 chars) is too short, 16 bytes (22 chars) is the minimum.
    assert_only(
        &hash("19456,t=2,p=1", SALT, "Zm9vYmFyZm9vYmFyZm9v"),
        "users[0].password_hash",
    );
    hash("19456,t=2,p=1", SALT, "Zm9vYmFyZm9vYmFyZm9vYg")
        .validate()
        .unwrap();
}

// ---------------------------------------------------------------- network

#[test]
fn lan_address_must_be_a_usable_host() {
    for bad in [
        "192.168.8.0/24",
        "192.168.8.255/24",
        "127.0.0.1/8",
        "192.168.8.1/31",
        "10.0.0.1/7",
    ] {
        let cfg = mutated(|c| c.network.lan.ipv4 = bad.parse().unwrap());
        assert!(
            issues(&cfg).iter().any(|i| i.path == "network.lan.ipv4"),
            "{bad}"
        );
    }
}

#[test]
fn overlapping_subnets_are_rejected() {
    let lan_vlan = mutated(|c| vlan(c).ipv4 = Some("192.168.8.129/25".parse().unwrap()));
    let found = issues(&lan_vlan);
    assert!(
        found
            .iter()
            .any(|i| i.path == "network.vlans[0].ipv4" && i.message.contains("overlaps")),
        "{found:?}"
    );

    let vlan_vlan = mutated(|c| {
        let mut v = c.network.vlans[0].clone();
        v.name = "guest".into();
        v.id = 30;
        v.ports.clear();
        v.ipv4 = Some("10.20.0.129/25".parse().unwrap());
        v.dhcp = None;
        c.network.vlans.push(v);
    });
    assert_only(&vlan_vlan, "network.vlans[1].ipv4");

    let wan = mutated(|c| {
        c.network.wan.proto = WanProto::Static {
            ipv4: "192.168.0.2/16".parse().unwrap(),
            gateway: "192.168.0.1".parse().unwrap(),
            dns: vec![],
        };
    });
    assert_only(&wan, "network.wan.proto.ipv4");
}

#[test]
fn dhcp_pool_must_fit_and_avoid_the_router() {
    let too_big = mutated(|c| {
        c.network.lan.dhcp.start = 200;
        c.network.lan.dhcp.limit = 100;
    });
    assert_only(&too_big, "network.lan.dhcp");
    let router = mutated(|c| {
        c.network.lan.dhcp.start = 1;
        c.network.lan.dhcp.limit = 10;
    });
    assert_only(&router, "network.lan.dhcp");
    assert_only(
        &mutated(|c| c.network.lan.dhcp.start = 0),
        "network.lan.dhcp.start",
    );
    assert_only(
        &mutated(|c| c.network.lan.dhcp.limit = 0),
        "network.lan.dhcp.limit",
    );
    assert_only(
        &mutated(|c| c.network.lan.dhcp.lease = Duration::from_secs(10)),
        "network.lan.dhcp.lease",
    );
    // A disabled pool is checked too: flipping `enabled` later must not activate garbage.
    assert_only(
        &mutated(|c| {
            c.network.lan.dhcp.enabled = false;
            c.network.lan.dhcp.limit = 0;
        }),
        "network.lan.dhcp.limit",
    );
    assert_only(
        &mutated(|c| {
            c.network.lan.dhcp.enabled = false;
            c.network.lan.dhcp.start = 0;
        }),
        "network.lan.dhcp.start",
    );
    assert_only(
        &mutated(|c| {
            c.network.lan.dhcp.enabled = false;
            c.network.lan.dhcp.lease = Duration::from_secs(10);
        }),
        "network.lan.dhcp.lease",
    );
    assert_only(
        &mutated(|c| {
            c.network.lan.dhcp.enabled = false;
            c.network.lan.dhcp.start = 200;
            c.network.lan.dhcp.limit = 100;
        }),
        "network.lan.dhcp",
    );
    assert_only(
        &mutated(|c| {
            let v = vlan(c);
            v.ipv4 = None;
            v.dhcp = Some(DhcpPool {
                enabled: false,
                limit: 0,
                ..DhcpPool::default()
            });
        }),
        "network.vlans[0].dhcp.limit",
    );
    // A valid disabled pool is fine.
    mutated(|c| c.network.lan.dhcp.enabled = false)
        .validate()
        .unwrap();
}

#[test]
fn wan_settings_are_checked() {
    let gw = mutated(|c| {
        c.network.wan.proto = WanProto::Static {
            ipv4: "203.0.113.2/24".parse().unwrap(),
            gateway: "198.51.100.1".parse().unwrap(),
            dns: vec![],
        };
    });
    assert_only(&gw, "network.wan.proto.gateway");
    assert_only(
        &mutated(|c| c.network.wan.mtu = Some(575)),
        "network.wan.mtu",
    );
    assert_only(
        &mutated(|c| c.network.wan.mtu = Some(9001)),
        "network.wan.mtu",
    );
    mutated(|c| c.network.wan.mtu = Some(576))
        .validate()
        .unwrap();
    assert_only(
        &mutated(|c| c.network.wan.mac_override = Some("01:00:5e:00:00:01".parse().unwrap())),
        "network.wan.mac_override",
    );
    let pppoe = mutated(|c| {
        c.network.wan.proto = WanProto::Pppoe {
            username: String::new(),
            password: Secret::from("x"),
            service: None,
        };
    });
    assert_only(&pppoe, "network.wan.proto.username");
    assert_only(
        &mutated(|c| {
            c.network.wan.proto = WanProto::Dhcp {
                hostname: Some("bad_name".into()),
            }
        }),
        "network.wan.proto.hostname",
    );
}

#[test]
fn vlan_rules() {
    for id in [0, 4095] {
        assert_only(&mutated(|c| vlan(c).id = id), "network.vlans[0].id");
    }
    for name in ["lan", "wan", "", "Iot", "waytoolongvlanname"] {
        assert_only(
            &mutated(|c| vlan(c).name = name.into()),
            "network.vlans[0].name",
        );
    }
    assert_only(&mutated(|c| vlan(c).ipv4 = None), "network.vlans[0].dhcp");
    let dup = mutated(|c| {
        let mut v = c.network.vlans[0].clone();
        v.ports.clear();
        v.ipv4 = Some("10.30.0.1/24".parse().unwrap());
        v.dhcp = None;
        c.network.vlans.push(v);
    });
    let paths: Vec<String> = issues(&dup).into_iter().map(|i| i.path).collect();
    assert_eq!(paths, ["network.vlans[1].name", "network.vlans[1].id"]);
}

#[test]
fn a_port_may_only_be_used_once() {
    assert_only(
        &mutated(|c| vlan(c).ports = vec!["lan1".into()]),
        "network.vlans[0].ports[0]",
    );
    assert_only(
        &mutated(|c| c.network.lan.ports.push("wan".into())),
        "network.lan.ports[4]",
    );
    assert_only(
        &mutated(|c| c.network.lan.ports.push("lan1".into())),
        "network.lan.ports[4]",
    );
    assert_only(
        &mutated(|c| c.network.wan.port = String::new()),
        "network.wan.port",
    );
}

// --------------------------------------------------------------- wireless

#[test]
fn radio_rules() {
    assert_only(
        &mutated(|c| radio(c, "radio1").width_mhz = 100),
        "wireless.radios[1].width_mhz",
    );
    for country in ["de", "DEU", "", "D1"] {
        assert_only(
            &mutated(|c| radio(c, "radio1").country = country.into()),
            "wireless.radios[1].country",
        );
    }
    assert_only(
        &mutated(|c| radio(c, "radio1").channel = Channel::Fixed(0)),
        "wireless.radios[1].channel",
    );
    assert_only(
        &mutated(|c| radio(c, "radio1").txpower_dbm = Some(0)),
        "wireless.radios[1].txpower_dbm",
    );
    let dup = mutated(|c| {
        let r = c.wireless.radios[0].clone();
        c.wireless.radios.push(r);
    });
    assert_only(&dup, "wireless.radios[2].id");
}

#[test]
fn passphrase_length_and_charset_are_enforced() {
    for bad in [
        "short",
        "x".repeat(64).as_str(),
        "caf\u{e9} au lait!",
        "tab\tin\tphrase",
    ] {
        let cfg = mutated(|c| {
            ap(c).security = Security::Wpa2Psk {
                passphrase: Secret::from(bad),
            };
        });
        assert_only(&cfg, "wireless.aps[0].security.passphrase");
    }
    for ok in ["8chars!!", "x".repeat(63).as_str()] {
        let cfg = mutated(|c| {
            ap(c).security = Security::Wpa2Wpa3Mixed {
                passphrase: Secret::from(ok),
            };
        });
        cfg.validate().unwrap();
    }
    mutated(|c| ap(c).security = Security::Open)
        .validate()
        .unwrap();
}

#[test]
fn ap_rules() {
    for ssid in ["", &"s".repeat(33), "two\nlines"] {
        assert_only(
            &mutated(|c| ap(c).ssid = ssid.into()),
            "wireless.aps[0].ssid",
        );
    }
    mutated(|c| ap(c).ssid = "\u{1f4f6}".repeat(8))
        .validate()
        .unwrap(); // 32 bytes
    assert_only(
        &mutated(|c| ap(c).ssid = "\u{1f4f6}".repeat(9)),
        "wireless.aps[0].ssid",
    );
    assert_only(
        &mutated(|c| ap(c).network = "guest".into()),
        "wireless.aps[0].network",
    );
    mutated(|c| ap(c).network = "iot".into())
        .validate()
        .unwrap();
    assert_only(
        &mutated(|c| ap(c).radio = "radio9".into()),
        "wireless.aps[0].radio",
    );
    assert_only(
        &mutated(|c| ap(c).max_clients = Some(0)),
        "wireless.aps[0].max_clients",
    );
    let dup = mutated(|c| {
        let a = c.wireless.aps[0].clone();
        c.wireless.aps.push(a);
    });
    assert_only(&dup, "wireless.aps[1].ssid");
}

// --------------------------------------------------------------- firewall

#[test]
fn port_forward_rules() {
    assert_only(
        &mutated(|c| forward(c).dest_ip = "172.16.0.5".parse().unwrap()),
        "firewall.port_forwards[0].dest_ip",
    );
    assert_only(
        &mutated(|c| forward(c).dest_ip = "192.168.8.1".parse().unwrap()),
        "firewall.port_forwards[0].dest_ip",
    );
    assert_only(
        &mutated(|c| forward(c).dest_ip = "192.168.8.255".parse().unwrap()),
        "firewall.port_forwards[0].dest_ip",
    );
    mutated(|c| forward(c).dest_ip = "10.20.0.7".parse().unwrap())
        .validate()
        .unwrap();
    assert_only(
        &mutated(|c| forward(c).dest_port = 0),
        "firewall.port_forwards[0].dest_port",
    );
    assert_only(
        &mutated(|c| forward(c).wan_port = PortRange { start: 90, end: 80 }),
        "firewall.port_forwards[0].wan_port",
    );
    assert_only(
        &mutated(|c| forward(c).name = "bad name".into()),
        "firewall.port_forwards[0].name",
    );
}

#[test]
fn overlapping_enabled_forwards_are_rejected() {
    let with_second = |proto, range: &str, enabled| {
        mutated(|c| {
            let mut f = c.firewall.port_forwards[0].clone();
            f.name = "other".into();
            f.proto = proto;
            f.wan_port = range.parse().unwrap();
            f.enabled = enabled;
            c.firewall.port_forwards.push(f);
        })
    };
    assert_only(
        &with_second(ForwardProto::Tcp, "8081-8090", true),
        "firewall.port_forwards[1].wan_port",
    );
    assert_only(
        &with_second(ForwardProto::TcpUdp, "8080", true),
        "firewall.port_forwards[1].wan_port",
    );
    with_second(ForwardProto::Udp, "8080-8081", true)
        .validate()
        .unwrap();
    with_second(ForwardProto::Tcp, "8080", false)
        .validate()
        .unwrap();
    with_second(ForwardProto::Tcp, "8082-8083", true)
        .validate()
        .unwrap();
}

#[test]
fn custom_rules_are_checked() {
    let rule = |proto, port: Option<PortRange>, name: &str| Rule {
        name: name.into(),
        direction: Direction::WanIn,
        proto,
        src: Some("198.51.100.0/24".parse().unwrap()),
        dest_port: port,
        action: Action::Accept,
        enabled: true,
    };
    let ok = mutated(|c| {
        c.firewall.rules = vec![rule(RuleProto::Tcp, Some(PortRange::single(22)), "ssh")];
    });
    ok.validate().unwrap();
    assert_eq!(
        Config::from_toml_str(&ok.to_toml_string().unwrap()).unwrap(),
        ok
    );
    let icmp = mutated(|c| {
        c.firewall.rules = vec![rule(RuleProto::Icmp, Some(PortRange::single(1)), "ping")];
    });
    assert_only(&icmp, "firewall.rules[0].dest_port");
    let bad_range = mutated(|c| {
        c.firewall.rules = vec![rule(
            RuleProto::Udp,
            Some(PortRange { start: 0, end: 5 }),
            "dns",
        )];
    });
    assert_only(&bad_range, "firewall.rules[0].dest_port");
    let dup = mutated(|c| {
        c.firewall.rules = vec![
            rule(RuleProto::Any, None, "x"),
            rule(RuleProto::Any, None, "x"),
        ];
    });
    assert_only(&dup, "firewall.rules[1].name");
}

// ------------------------------------------------------------------- dhcp

#[test]
fn static_lease_rules() {
    let with = |l: Vec<StaticLease>| mutated(|c| c.dhcp.static_leases = l);
    with(vec![
        lease("aa:bb:cc:dd:ee:01", [192, 168, 8, 50]),
        lease("aa:bb:cc:dd:ee:02", [10, 20, 0, 9]),
    ])
    .validate()
    .unwrap();
    assert_only(
        &with(vec![lease("aa:bb:cc:dd:ee:01", [172, 16, 0, 5])]),
        "dhcp.static_leases[0].ip",
    );
    assert_only(
        &with(vec![lease("aa:bb:cc:dd:ee:01", [192, 168, 8, 1])]),
        "dhcp.static_leases[0].ip",
    );
    assert_only(
        &with(vec![lease("01:bb:cc:dd:ee:01", [192, 168, 8, 9])]),
        "dhcp.static_leases[0].mac",
    );
    assert_only(
        &with(vec![
            lease("aa:bb:cc:dd:ee:01", [192, 168, 8, 9]),
            lease("AA:BB:CC:DD:EE:01", [192, 168, 8, 10]),
        ]),
        "dhcp.static_leases[1].mac",
    );
    assert_only(
        &with(vec![
            lease("aa:bb:cc:dd:ee:01", [192, 168, 8, 9]),
            lease("aa:bb:cc:dd:ee:02", [192, 168, 8, 9]),
        ]),
        "dhcp.static_leases[1].ip",
    );
    let mut named = lease("aa:bb:cc:dd:ee:01", [192, 168, 8, 9]);
    named.hostname = Some("nas_1".into());
    assert_only(&with(vec![named]), "dhcp.static_leases[0].hostname");
}

#[test]
fn dhcp_domain_and_dns_are_checked() {
    assert_only(
        &mutated(|c| c.dhcp.local_domain = "bad domain".into()),
        "dhcp.local_domain",
    );
    assert_only(
        &mutated(|c| c.dhcp.dns_servers = vec!["0.0.0.0".parse().unwrap()]),
        "dhcp.dns_servers[0]",
    );
    mutated(|c| c.dhcp.dns_servers = vec!["9.9.9.9".parse().unwrap()])
        .validate()
        .unwrap();
}

// --------------------------------------------------------------- services

#[test]
fn ssh_and_api_rules() {
    fn ssh(f: impl FnOnce(&mut SshConfig)) -> Config {
        mutated(|c| {
            c.services.ssh.enabled = true;
            c.services.ssh.password_auth = true;
            f(&mut c.services.ssh);
        })
    }
    ssh(|_| {}).validate().unwrap();
    assert_only(&ssh(|s| s.password_auth = false), "services.ssh");
    assert_only(&ssh(|s| s.port = 443), "services.ssh.port");
    assert_only(&ssh(|s| s.port = 0), "services.ssh.port");
    assert_only(
        &ssh(|s| s.authorized_keys = vec!["not a key".into()]),
        "services.ssh.authorized_keys[0]",
    );
    assert_only(
        &ssh(|s| s.authorized_keys = vec!["ssh-ed25519 AAAA\nssh-rsa BBBB".into()]),
        "services.ssh.authorized_keys[0]",
    );
    let key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host";
    ssh(|s| {
        s.password_auth = false;
        s.authorized_keys = vec![key.into()];
    })
    .validate()
    .unwrap();
    // Port clash only matters while ssh is enabled.
    mutated(|c| c.services.ssh.port = 443).validate().unwrap();
    assert_only(&mutated(|c| c.services.api.port = 0), "services.api.port");
    for ttl in [Duration::from_secs(5), Duration::from_hours(24 * 30)] {
        assert_only(
            &mutated(|c| c.services.api.session_ttl = ttl),
            "services.api.session_ttl",
        );
    }
}

#[test]
fn validate_reports_every_issue_not_just_the_first() {
    let cfg = mutated(|c| {
        c.system.hostname = "-bad".into();
        c.network.wan.mtu = Some(1);
        ap(c).ssid = String::new();
        forward(c).dest_port = 0;
        c.services.api.port = 0;
    });
    let paths: Vec<String> = issues(&cfg).into_iter().map(|i| i.path).collect();
    assert_eq!(
        paths,
        [
            "system.hostname",
            "network.wan.mtu",
            "wireless.aps[0].ssid",
            "firewall.port_forwards[0].dest_port",
            "services.api.port"
        ]
    );
    let err = ConfigError::Invalid(issues(&cfg)).to_string();
    assert!(
        err.contains("5 issue(s)") && err.contains("network.wan.mtu"),
        "{err}"
    );
}

// ------------------------------------------------------ board validation

#[test]
fn board_unknown_ports_are_rejected() {
    assert_board_issue(
        &mutated(|c| c.network.wan.port = "eth9".into()),
        "network.wan.port",
    );
    assert_board_issue(
        &mutated(|c| c.network.lan.ports[0] = "lan9".into()),
        "network.lan.ports[0]",
    );
    assert_board_issue(
        &mutated(|c| vlan(c).ports = vec!["nope".into()]),
        "network.vlans[0].ports[0]",
    );
}

#[test]
fn board_validation_includes_internal_rules() {
    assert_board_issue(
        &mutated(|c| vlan(c).ports = vec!["lan1".into()]),
        "network.vlans[0].ports[0]",
    );
}

#[test]
fn board_radio_rules() {
    assert_board_issue(
        &mutated(|c| radio(c, "radio1").id = "radio7".into()),
        "wireless.radios[1].id",
    );
    assert_board_issue(
        &mutated(|c| radio(c, "radio0").width_mhz = 80),
        "wireless.radios[0].width_mhz",
    );
    // 2.4 GHz hardware here tops out at 40 MHz; 5 GHz allows 160.
    mutated(|c| radio(c, "radio0").width_mhz = 40)
        .validate_against(&board())
        .unwrap();
    mutated(|c| radio(c, "radio1").width_mhz = 160)
        .validate_against(&board())
        .unwrap();
    assert_board_issue(
        &mutated(|c| radio(c, "radio0").channel = Channel::Fixed(14)),
        "wireless.radios[0].channel",
    );
    assert_board_issue(
        &mutated(|c| radio(c, "radio1").channel = Channel::Fixed(6)),
        "wireless.radios[1].channel",
    );
    assert_board_issue(
        &mutated(|c| radio(c, "radio1").channel = Channel::Fixed(37)),
        "wireless.radios[1].channel",
    );
    for ok in [36, 64, 100, 144, 149] {
        mutated(|c| radio(c, "radio1").channel = Channel::Fixed(ok))
            .validate_against(&board())
            .unwrap();
    }
    // 165 has no 80 MHz block; it is fine at 20 MHz.
    mutated(|c| {
        let r = radio(c, "radio1");
        r.width_mhz = 20;
        r.channel = Channel::Fixed(165);
    })
    .validate_against(&board())
    .unwrap();
    mutated(|c| radio(c, "radio0").channel = Channel::Fixed(13))
        .validate_against(&board())
        .unwrap();
}

#[test]
fn board_without_wan_port_yields_an_invalid_default() {
    let mut b = board();
    b.ethernet
        .ports
        .retain(|p| p.role != owr_board::PortRole::Wan);
    assert_only(&Config::defaults_for(&b), "network.wan.port");
}

// ------------------------------------------------------------ value types

#[test]
fn port_range_parses_and_prints() {
    assert_eq!("80".parse::<PortRange>().unwrap(), PortRange::single(80));
    assert_eq!(
        "8000-8010".parse::<PortRange>().unwrap(),
        PortRange {
            start: 8000,
            end: 8010
        }
    );
    assert_eq!("7-7".parse::<PortRange>().unwrap().to_string(), "7");
    assert_eq!(
        PortRange {
            start: 1,
            end: 65535
        }
        .to_string(),
        "1-65535"
    );
    for bad in [
        "", "0", "0-5", "10-5", "a", "1-", "-5", "70000", "1-70000", "1-2-3", " 80", "+80", "80 ",
    ] {
        assert!(
            bad.parse::<PortRange>().is_err(),
            "{bad:?} should not parse"
        );
    }
}

#[test]
fn port_range_serde_forms() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct W {
        p: PortRange,
    }
    let from = |s: &str| toml::from_str::<W>(s).map(|w| w.p);
    assert_eq!(from("p = 80").unwrap(), PortRange::single(80));
    assert_eq!(from("p = \"80\"").unwrap(), PortRange::single(80));
    assert_eq!(
        from("p = \"8000-8010\"").unwrap(),
        PortRange {
            start: 8000,
            end: 8010
        }
    );
    assert!(from("p = \"9-1\"").is_err());
    assert!(from("p = 0").is_ok_and(|p| !p.is_valid()) || from("p = 0").is_err());
    let out = toml::to_string(&W {
        p: PortRange {
            start: 8000,
            end: 8010,
        },
    })
    .unwrap();
    assert_eq!(out.trim(), "p = \"8000-8010\"");
    assert!(PortRange { start: 5, end: 9 }.overlaps(&PortRange { start: 9, end: 12 }));
    assert!(!PortRange { start: 5, end: 8 }.overlaps(&PortRange { start: 9, end: 12 }));
}

#[test]
fn mac_addresses_parse_strictly_and_print_lowercase() {
    let m: MacAddr = "AA:bb:0C:dd:ee:01".parse().unwrap();
    assert_eq!(m.to_string(), "aa:bb:0c:dd:ee:01");
    assert!(!m.is_multicast() && !m.is_zero());
    for bad in [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa-bb-cc-dd-ee-ff",
        "aa:bb:cc:dd:ee:f",
        "+a:bb:cc:dd:ee:ff",
        "gg:bb:cc:dd:ee:ff",
    ] {
        assert!(bad.parse::<MacAddr>().is_err(), "{bad:?}");
    }
}

proptest! {
    #[test]
    fn port_range_display_parse_round_trip(a in 1u16..=65535, b in 1u16..=65535) {
        let r = PortRange { start: a.min(b), end: a.max(b) };
        prop_assert_eq!(r.to_string().parse::<PortRange>().unwrap(), r);
    }

    #[test]
    fn port_range_parse_never_yields_invalid(s in "\\PC{0,12}") {
        if let Ok(r) = s.parse::<PortRange>() {
            prop_assert!(r.is_valid());
        }
    }

    #[test]
    fn generated_labels_are_valid_hostnames(s in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?") {
        prop_assert!(validate::is_hostname_label(&s));
    }

    #[test]
    fn accepted_hostnames_match_rfc1123(s in "\\PC{0,70}") {
        if validate::is_hostname_label(&s) {
            prop_assert!(s.len() <= 63 && !s.starts_with('-') && !s.ends_with('-'));
            prop_assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        }
    }
}

// ------------------------------------------------------ redact / hashing

#[test]
fn redact_masks_every_secret_and_nothing_else() {
    let mut cfg = base();
    cfg.network.wan.proto = WanProto::Pppoe {
        username: "isp-user".into(),
        password: Secret::from("pppoe-pw-123"),
        service: None,
    };
    let red = redact(&cfg);
    let text = red.to_toml_string().unwrap();
    for secret in [HASH, PASSPHRASE, "pppoe-pw-123"] {
        assert!(!text.contains(secret), "leaked {secret}");
    }
    assert_eq!(text.matches("\"***\"").count(), 3);
    assert!(text.contains("isp-user") && text.contains("flint2"));
    assert_eq!(red.users[0].name, "admin");
    // The input is untouched.
    assert_eq!(user(&mut cfg).password_hash.expose(), HASH);
}

#[test]
fn debug_output_never_contains_secrets() {
    let dump = format!("{:?}", base());
    assert!(!dump.contains(HASH) && !dump.contains(PASSPHRASE), "{dump}");
}

#[test]
fn content_hash_ignores_formatting_and_section_order_but_not_content() {
    let canonical = base();
    // Same document with two tables swapped and comments/blank lines added.
    let mut blocks: Vec<String> = Vec::new();
    for line in example_toml().lines() {
        if line.starts_with('[') || blocks.is_empty() {
            blocks.push(String::new());
        }
        if let Some(last) = blocks.last_mut() {
            last.push_str(line);
            last.push('\n');
        }
    }
    let sys = blocks
        .iter()
        .position(|b| b.starts_with("[system]"))
        .unwrap();
    let api = blocks
        .iter()
        .position(|b| b.starts_with("[services.api]"))
        .unwrap();
    blocks.swap(sys, api);
    let reordered = blocks.join("\n# a comment\n");
    assert_ne!(reordered, example_toml());
    let other = Config::from_toml_str(&reordered).unwrap();
    assert_eq!(other, canonical);
    assert_eq!(
        Store::content_hash(&other).unwrap(),
        Store::content_hash(&canonical).unwrap()
    );

    let h = Store::content_hash(&canonical).unwrap();
    assert_eq!(h.len(), 64);
    assert!(
        h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_ne!(
        h,
        Store::content_hash(&mutated(|c| c.system.hostname = "other".into())).unwrap()
    );
    let new_hash = Secret::from(format!("{HASH}x"));
    assert_ne!(
        h,
        Store::content_hash(&mutated(|c| user(c).password_hash = new_hash)).unwrap()
    );
}

// ------------------------------------------------------------------ store

#[test]
fn store_round_trip_and_idempotent_save() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("etc").join("config.toml"));
    let cfg = base();
    assert_eq!(store.save(&cfg).unwrap(), owr_common::Outcome::Written);
    assert_eq!(store.load().unwrap(), cfg);
    assert_eq!(store.save(&cfg).unwrap(), owr_common::Outcome::Unchanged);
    let changed = mutated(|c| c.system.hostname = "other".into());
    assert_eq!(store.save(&changed).unwrap(), owr_common::Outcome::Written);
    assert_eq!(store.load().unwrap().system.hostname, "other");
}

#[cfg(unix)]
#[test]
fn saved_config_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("config.toml"));
    store.save(&base()).unwrap();
    let mode = std::fs::metadata(store.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn save_refuses_invalid_configs_and_leaves_the_old_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("config.toml"));
    let bad = mutated(|c| c.system.hostname = "-".into());
    assert!(matches!(store.save(&bad), Err(ConfigError::Invalid(_))));
    assert!(!store.path().exists());
    store.save(&base()).unwrap();
    assert!(matches!(store.save(&bad), Err(ConfigError::Invalid(_))));
    assert_eq!(store.load().unwrap(), base());
}

#[test]
fn load_errors_are_distinguished() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("config.toml"));
    assert!(matches!(store.load(), Err(ConfigError::Io { .. })));
    std::fs::write(store.path(), "this is [not toml").unwrap();
    assert!(matches!(store.load(), Err(ConfigError::Parse(_))));
    std::fs::write(
        store.path(),
        example_toml().replace("hostname = \"flint2\"", "hostname = \"-\""),
    )
    .unwrap();
    assert!(matches!(store.load(), Err(ConfigError::Invalid(_))));
}

#[test]
fn load_or_default_creates_once_and_never_clobbers_a_broken_file() {
    let b = board();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("nested").join("config.toml"));
    let (cfg, created) = store.load_or_default(&b).unwrap();
    assert!(created);
    assert_eq!(cfg, Config::defaults_for(&b));
    let (again, created) = store.load_or_default(&b).unwrap();
    assert!(!created);
    assert_eq!(again, cfg);

    std::fs::write(store.path(), "schema = 1\n[network.wan]\nport = \"\"\n").unwrap();
    assert!(matches!(
        store.load_or_default(&b),
        Err(ConfigError::Invalid(_))
    ));
    assert!(
        std::fs::read_to_string(store.path())
            .unwrap()
            .contains("port = \"\"")
    );
}

#[test]
fn default_store_points_at_the_system_path() {
    assert_eq!(
        Store::default().path(),
        std::path::Path::new(owr_common::paths::CONFIG_FILE)
    );
}

// ------------------------------------------------- review fixes: parse errors

fn assert_parse_error_hides(text: &str, secret: &str, path: &str) {
    let err = Config::from_toml_str(text).unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    let msg = err.to_string();
    assert!(!msg.contains(secret), "{secret:?} leaked: {msg}");
    assert!(msg.contains(path), "{path:?} missing: {msg}");
}

#[test]
fn type_errors_name_the_field_path_but_never_the_value() {
    let text = example_toml();
    // A passphrase written as an integer (the security table is internally tagged, so the
    // path stops at the AP's `security` field).
    assert_parse_error_hides(
        &text.replacen(
            &format!("passphrase = \"{PASSPHRASE}\""),
            "passphrase = 12345678",
            1,
        ),
        "12345678",
        "wireless.aps[0].security",
    );
    // A password hash written as a boolean.
    assert_parse_error_hides(
        &text.replacen(
            &format!("password_hash = \"{HASH}\""),
            "password_hash = true",
            1,
        ),
        "`true`",
        "users[0].password_hash",
    );
    // A password hash written as a number.
    assert_parse_error_hides(
        &text.replacen(
            &format!("password_hash = \"{HASH}\""),
            "password_hash = 987654321",
            1,
        ),
        "987654321",
        "users[0].password_hash",
    );
    // An unknown enum variant that looks like a secret.
    assert_parse_error_hides(
        &text.replacen("role = \"admin\"", "role = \"hunter2-Secret\"", 1),
        "hunter2-Secret",
        "users[0].role",
    );
    // An unknown key that looks like a secret.
    assert_parse_error_hides(
        &text.replacen("[system]\n", "[system]\nhunter2-key = 1\n", 1),
        "hunter2-key",
        "system",
    );
    // Free-text values rejected by custom deserializers.
    assert_parse_error_hides(
        &text.replacen("channel = \"auto\"", "channel = \"hunter2-best\"", 1),
        "hunter2-best",
        "wireless.radios[0].channel",
    );
    assert_parse_error_hides(
        &text.replacen("lease = \"12h\"", "lease = \"hunter2-soon\"", 1),
        "hunter2-soon",
        "network.lan.dhcp.lease",
    );
}

#[test]
fn missing_required_fields_are_named() {
    // `width_mhz` has no serde default: its sensible value depends on the band.
    let text = example_toml().replacen("width_mhz = 80\n", "", 1);
    let msg = Config::from_toml_str(&text).unwrap_err().to_string();
    assert!(msg.contains("wireless.radios[1]"), "{msg}");
    assert!(msg.contains("width_mhz"), "{msg}");
    // Neither has `schema`: a file without it is not silently read as the current schema.
    let err = toml::from_str::<Config>("[network.wan]\nport = \"wan\"\n").unwrap_err();
    assert!(err.message().contains("schema"), "{err}");
}

#[test]
fn redact_values_hides_quoted_input_and_keeps_the_rest() {
    use crate::error::redact_values;
    assert_eq!(
        redact_values("invalid type: integer `12345678`, expected a string"),
        "invalid type: integer `…`, expected a string"
    );
    assert_eq!(
        redact_values(r#"unknown variant "a\"b", expected one of `x`, `y`"#),
        r#"unknown variant "…", expected one of `…`, `…`"#
    );
    assert_eq!(
        redact_values("invalid duration 'soon': bad"),
        "invalid duration '…': bad"
    );
    // An apostrophe inside a word is not a quote; an unterminated quote hides the rest.
    assert_eq!(redact_values("it doesn't matter"), "it doesn't matter");
    assert_eq!(redact_values("bad value `abc"), "bad value `…`");
    assert_eq!(
        redact_values("missing field `width_mhz`"),
        "missing field `width_mhz`"
    );
}

// ------------------------------------------------------ review fixes: secrets

#[test]
fn the_redaction_placeholder_is_rejected_for_every_secret() {
    let want = |cfg: &Config, path: &str| {
        let found = issues(cfg);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, path);
        assert!(
            found[0].message.contains("redacted placeholder"),
            "{found:?}"
        );
    };
    want(
        &mutated(|c| user(c).password_hash = Secret::from(Secret::REDACTED)),
        "users[0].password_hash",
    );
    for security in [
        Security::Wpa2Psk {
            passphrase: Secret::from(Secret::REDACTED),
        },
        Security::Wpa3Sae {
            passphrase: Secret::from(Secret::REDACTED),
        },
        Security::Wpa2Wpa3Mixed {
            passphrase: Secret::from(Secret::REDACTED),
        },
    ] {
        want(
            &mutated(|c| ap(c).security = security),
            "wireless.aps[0].security.passphrase",
        );
    }
    want(
        &mutated(|c| {
            c.network.wan.proto = WanProto::Pppoe {
                username: "isp-user".into(),
                password: Secret::from(Secret::REDACTED),
                service: None,
            };
        }),
        "network.wan.proto.password",
    );
    // A redacted copy of a real config (what an API client sends back) never validates.
    let round_trip = issues(&redact(&base()));
    assert_eq!(round_trip.len(), 2, "{round_trip:?}");
    assert!(
        round_trip
            .iter()
            .all(|i| i.message.contains("redacted placeholder"))
    );
}

#[test]
fn secret_equality_compares_contents() {
    assert_eq!(Secret::from("abc"), Secret::from(String::from("abc")));
    assert_ne!(Secret::from("abc"), Secret::from("abd"));
    assert_ne!(Secret::from("abc"), Secret::from("abcd"));
    assert_ne!(Secret::from(""), Secret::from("a"));
    assert!(Secret::from(Secret::REDACTED).is_redacted());
    assert!(!Secret::from("abc").is_redacted());
}

// ------------------------------------------------------ review fixes: PPPoE

#[test]
fn pppoe_credentials_use_a_conservative_charset() {
    let pppoe = |user: &str, password: &str, service: Option<&str>| {
        mutated(|c| {
            c.network.wan.proto = WanProto::Pppoe {
                username: user.into(),
                password: Secret::from(password),
                service: service.map(Into::into),
            };
        })
    };
    pppoe(
        "user@isp.example",
        "p@ss w0rd!#$%&'()*+,-./:;<=>?[]^_`{|}~",
        None,
    )
    .validate()
    .unwrap();
    pppoe("a+b_c.d:e/f-g@h", "x", Some("My-ISP.1"))
        .validate()
        .unwrap();
    for bad in [
        "",
        "bad name",
        "us\"er",
        "us\\er",
        "semi;colon",
        "tab\t",
        "caf\u{e9}",
        &"u".repeat(65),
    ] {
        assert_only(&pppoe(bad, "x", None), "network.wan.proto.username");
        assert_only(&pppoe("u", "x", Some(bad)), "network.wan.proto.service");
    }
    for bad in [
        "",
        "has\"quote",
        "back\\slash",
        "tab\t",
        "caf\u{e9}",
        &"p".repeat(129),
    ] {
        assert_only(&pppoe("u", bad, None), "network.wan.proto.password");
    }
}

// ------------------------------------------------------ review fixes: bounds

#[test]
fn list_sizes_are_bounded() {
    let mut users = base();
    let template = users.users[0].clone();
    users.users = (0..33)
        .map(|i| User {
            name: format!("user{i}"),
            ..template.clone()
        })
        .collect();
    assert_only(&users, "users");

    let rules = mutated(|c| {
        c.firewall.rules = (0..257)
            .map(|i| Rule {
                name: format!("r{i}"),
                direction: Direction::WanIn,
                proto: RuleProto::Any,
                src: None,
                dest_port: None,
                action: Action::Drop,
                enabled: true,
            })
            .collect();
    });
    assert_only(&rules, "firewall.rules");

    let forwards = mutated(|c| {
        c.firewall.port_forwards = (0..257u16)
            .map(|i| PortForward {
                name: format!("f{i}"),
                proto: ForwardProto::Tcp,
                wan_port: PortRange::single(1000 + i),
                dest_ip: Ipv4Addr::new(192, 168, 8, 50),
                dest_port: 80,
                enabled: true,
            })
            .collect();
    });
    assert_only(&forwards, "firewall.port_forwards");

    let leases = mutated(|c| {
        c.dhcp.static_leases = (0..1025u16)
            .map(|i| StaticLease {
                mac: MacAddr([2, 0, 0, 0, i.to_be_bytes()[0], i.to_be_bytes()[1]]),
                ip: Ipv4Addr::new(192, 168, 8, 50),
                hostname: None,
            })
            .collect();
    });
    assert_only(&leases, "dhcp.static_leases");

    // The limits themselves are accepted.
    mutated(|c| {
        c.firewall.rules = (0..256)
            .map(|i| Rule {
                name: format!("r{i}"),
                direction: Direction::WanIn,
                proto: RuleProto::Any,
                src: None,
                dest_port: None,
                action: Action::Drop,
                enabled: true,
            })
            .collect();
    })
    .validate()
    .unwrap();
}

#[test]
fn ssh_keys_are_bounded_ascii_with_a_decodable_blob() {
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let keys = |list: Vec<String>| {
        mutated(|c| {
            c.services.ssh.enabled = true;
            c.services.ssh.authorized_keys = list;
        })
    };
    keys(vec![KEY.to_owned(), format!("{KEY} me@host")])
        .validate()
        .unwrap();
    for bad in [
        "ssh-ed25519 !!!!not-base64!!!!".to_owned(),
        "ssh-ed25519 A".to_owned(),
        "ssh-ed25519".to_owned(),
        format!("{KEY} caf\u{e9}"),
        format!("{KEY} {}", "c".repeat(4096)),
    ] {
        assert_only(&keys(vec![bad]), "services.ssh.authorized_keys[0]");
    }
    // Exactly 4096 characters is fine: pad the comment.
    let padded = format!("{KEY} {}", "c".repeat(4096 - KEY.len() - 1));
    assert_eq!(padded.len(), 4096);
    keys(vec![padded]).validate().unwrap();
    assert_only(
        &keys(vec![KEY.to_owned(); 33]),
        "services.ssh.authorized_keys",
    );
}

// ------------------------------------------------ review fixes: board checks

#[test]
fn board_port_roles_are_enforced() {
    // WAN must be a wan port.
    assert_board_issue(
        &mutated(|c| c.network.wan.port = "lan1".into()),
        "network.wan.port",
    );
    // LAN and VLAN ports must be lan ports.
    assert_board_issue(
        &mutated(|c| {
            c.network.lan.ports[0] = "wan".into();
            c.network.wan.port = "lan1".into();
        }),
        "network.lan.ports[0]",
    );
    assert_board_issue(
        &mutated(|c| vlan(c).ports = vec!["wan".into()]),
        "network.vlans[0].ports[0]",
    );
    // The correct assignment still passes.
    base().validate_against(&board()).unwrap();
}

#[test]
fn an_ap_on_a_disabled_radio_is_rejected() {
    let cfg = mutated(|c| radio(c, "radio1").enabled = false);
    assert_only(&cfg, "wireless.aps[0].radio");
    assert_board_issue(&cfg, "wireless.aps[0].radio");
    // Disabling a radio without APs is fine.
    mutated(|c| {
        c.wireless.aps.clear();
        radio(c, "radio1").enabled = false;
    })
    .validate_against(&board())
    .unwrap();
}

#[test]
fn fixed_5ghz_channels_must_fit_the_width() {
    let set = |width: u16, ch: u16| {
        mutated(|c| {
            let r = radio(c, "radio1");
            r.width_mhz = width;
            r.channel = Channel::Fixed(ch);
        })
        .validate_against(&board())
    };
    // 80 MHz blocks: 36-48, 52-64, 100-112, 116-128, 132-144, 149-161.
    for ok in [36, 48, 52, 64, 100, 112, 116, 128, 132, 144, 149, 161] {
        set(80, ok).unwrap();
    }
    for bad in [165, 169, 173, 177] {
        assert!(set(80, bad).is_err(), "80 MHz on {bad}");
    }
    // 160 MHz blocks: 36-64 and 100-128.
    for ok in [36, 64, 100, 128] {
        set(160, ok).unwrap();
    }
    for bad in [132, 144, 149, 161, 165] {
        let err = set(160, bad).unwrap_err();
        assert!(
            err.iter().any(|i| i.path == "wireless.radios[1].channel"),
            "160 MHz on {bad}"
        );
    }
    // 20 and 40 MHz accept any 5 GHz channel.
    for width in [20, 40] {
        set(width, 165).unwrap();
        set(width, 132).unwrap();
    }
}

#[test]
fn us_rejects_2ghz_channels_12_and_13() {
    let set = |country: &str, ch: u16| {
        mutated(|c| {
            let r = radio(c, "radio0");
            r.country = country.into();
            r.channel = Channel::Fixed(ch);
        })
        .validate_against(&board())
    };
    set("US", 11).unwrap();
    for bad in [12, 13] {
        let err = set("US", bad).unwrap_err();
        assert!(
            err.iter().any(|i| i.path == "wireless.radios[0].channel"),
            "US ch {bad}"
        );
        set("DE", bad).unwrap();
    }
}

// ------------------------------------------------- review fixes: store paths

#[test]
fn board_aware_save_and_load_reject_what_the_board_cannot_do() {
    let b = board();
    let bad = mutated(|c| c.network.lan.ports[0] = "lan9".into());
    let dir = tempfile::tempdir().unwrap();

    // save_for refuses an unknown port and writes nothing; the board-less save cannot tell.
    let store = Store::new(dir.path().join("a.toml"));
    assert!(matches!(
        store.save_for(&bad, &b),
        Err(ConfigError::Invalid(_))
    ));
    assert!(!store.path().exists());
    assert_eq!(
        store.save_for(&base(), &b).unwrap(),
        owr_common::Outcome::Written
    );
    assert_eq!(
        store.save_for(&base(), &b).unwrap(),
        owr_common::Outcome::Unchanged
    );
    assert!(matches!(
        store.save_for(&bad, &b),
        Err(ConfigError::Invalid(_))
    ));
    assert_eq!(store.load_for(&b).unwrap(), base());

    // load_for and load_or_default reject a self-consistent file the board cannot run.
    let store = Store::new(dir.path().join("b.toml"));
    store.save(&bad).unwrap();
    assert_eq!(store.load().unwrap(), bad);
    let err = store.load_for(&b).unwrap_err();
    assert!(
        err.issues()
            .iter()
            .any(|i| i.path == "network.lan.ports[0]")
    );
    assert!(matches!(
        store.load_or_default(&b),
        Err(ConfigError::Invalid(_))
    ));
    // ...and leave the file alone.
    assert_eq!(store.load().unwrap(), bad);
}

#[test]
fn oversized_config_files_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("config.toml"));
    let mut text = example_toml().to_owned();
    text.push('\n');
    let pad = 1024 * 1024 + 1 - text.len();
    text.push_str(&"#".repeat(pad));
    std::fs::write(store.path(), &text).unwrap();
    let err = store.load().unwrap_err();
    assert!(
        matches!(&err, ConfigError::Io { source, .. } if source.kind() == std::io::ErrorKind::InvalidData),
        "{err:?}"
    );
    // Exactly 1 MiB still loads.
    std::fs::write(store.path(), &text[..1024 * 1024]).unwrap();
    store.load().unwrap();
}

#[test]
fn loading_the_current_schema_does_not_rewrite_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("config.toml"));
    // Not in canonical form (comments, key order): a rewrite would change the bytes.
    let text = example_toml();
    std::fs::write(store.path(), text).unwrap();
    store.load().unwrap();
    store.load_for(&board()).unwrap();
    assert_eq!(std::fs::read_to_string(store.path()).unwrap(), text);
    assert_ne!(base().to_toml_string().unwrap(), text);
    // Nothing to migrate from yet: the current schema is the first one.
    let (_, migrated) = Config::parse_migrated(text).unwrap();
    assert!(!migrated);
}

#[cfg(unix)]
#[test]
fn config_dir_is_private_and_loose_file_modes_are_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(
        dir.path()
            .join("etc")
            .join("ferritewrt")
            .join("config.toml"),
    );
    store.save(&base()).unwrap();
    for sub in ["etc", "etc/ferritewrt"] {
        let mode = std::fs::metadata(dir.path().join(sub))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{sub}");
    }

    std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    store.load().unwrap();
    let mode = std::fs::metadata(store.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
