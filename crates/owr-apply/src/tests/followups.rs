//! Review follow-ups: step order, lease persistence, ULA, firewall/dnsmasq/wifi details.

use super::*;

fn rule_named<'a>(p: &'a Plans, name: &str) -> Option<&'a f::Rule> {
    p.fw.rules.iter().find(|r| r.name == name)
}

#[test]
fn dhcp_wan_gets_the_loose_rp_filter() {
    let p = plans(&defaults());
    assert!(
        p.net
            .sysctls
            .contains(&("net/ipv4/conf/eth1/rp_filter".to_owned(), "2".to_owned()))
    );
    assert_eq!(p.net.validate(), Ok(()));

    let mut cfg = defaults();
    cfg.network.wan.proto = c::WanProto::Static {
        ipv4: net("203.0.113.2/24"),
        gateway: Ipv4Addr::new(203, 0, 113, 1),
        dns: Vec::new(),
    };
    let p = plans(&cfg);
    assert!(
        !p.net
            .sysctls
            .iter()
            .any(|(k, _)| k.ends_with("eth1/rp_filter"))
    );
}

#[test]
fn open_vlan_cannot_reach_the_management_api_unless_bound_to_vlans() {
    let mut cfg = with_guest(false);
    cfg.services.api.port = 8443;
    let p = plans(&cfg);
    let rule = rule_named(&p, "guest-api-block").unwrap();
    assert_eq!(rule.src, Some(zone("guest")));
    assert_eq!(rule.dst, None);
    assert_eq!(rule.proto, f::Proto::Tcp);
    assert_eq!(rule.dst_port, Some(f::PortRange::single(8443)));
    assert_eq!(rule.action, f::Policy::Drop);
    // The rule is rendered before the zone's accept verdict.
    let text = f::render(&p.fw).unwrap();
    let chain = text.find("chain input_guest").unwrap();
    let block = text[chain..].find("tcp dport 8443").unwrap();
    let verdict = text[chain..].find("accept").unwrap();
    assert!(block < verdict, "{text}");

    cfg.services.api.bind = c::ApiBind::LanAndVlans;
    assert!(rule_named(&plans(&cfg), "guest-api-block").is_none());
}

#[test]
fn isolated_vlan_has_no_api_block_rule() {
    // It is dropped by the zone policy already; only dhcp/dns/icmp are accepted.
    assert!(rule_named(&plans(&with_guest(true)), "guest-api-block").is_none());
}

mod ula_mapping {
    use super::*;
    use crate::{Inputs, build_plans_with};

    fn prefix() -> ipnet::Ipv6Net {
        "fd12:3456:789a::/48".parse().unwrap()
    }

    fn with_ula(cfg: &mut c::Config) {
        cfg.network.lan.ipv6 = c::LanIpv6::Ula;
    }

    fn addrs(p: &Plans, link: &str) -> Vec<String> {
        p.net
            .addresses
            .iter()
            .filter(|a| a.link == link && a.addr.addr().is_ipv6())
            .map(|a| a.addr.to_string())
            .collect()
    }

    #[test]
    fn ula_prefix_gives_br_lan_and_every_vlan_a_slash_64() {
        let mut cfg = with_guest(true);
        with_ula(&mut cfg);
        let inputs = Inputs {
            ula_prefix: Some(prefix()),
            ..Inputs::default()
        };
        let p = build_plans_with(&board(), &cfg, &inputs).unwrap();
        assert_eq!(addrs(&p, "br-lan"), ["fd12:3456:789a::1/64"]);
        assert_eq!(addrs(&p, "br-guest"), ["fd12:3456:789a:14::1/64"]);
        assert_eq!(p.warnings, Vec::<String>::new());
        assert_eq!(p.net.validate(), Ok(()));
    }

    #[test]
    fn ula_without_a_prefix_plans_no_address_and_warns() {
        let mut cfg = defaults();
        with_ula(&mut cfg);
        let p = plans(&cfg);
        assert_eq!(addrs(&p, "br-lan"), Vec::<String>::new());
        assert_eq!(p.warnings.len(), 1);
        assert!(p.warnings[0].contains("ULA"), "{:?}", p.warnings);
    }

    #[test]
    fn a_prefix_is_ignored_when_ula_is_off() {
        let cfg = with_guest(true);
        let inputs = Inputs {
            ula_prefix: Some(prefix()),
            ..Inputs::default()
        };
        let p = build_plans_with(&board(), &cfg, &inputs).unwrap();
        assert_eq!(addrs(&p, "br-lan"), Vec::<String>::new());
        assert_eq!(p.warnings, Vec::<String>::new());
    }

    #[test]
    fn netd_advertises_the_ula_subnet_of_every_bridge_with_the_router_as_dns() {
        let mut cfg = with_guest(true);
        with_ula(&mut cfg);
        let inputs = Inputs {
            ula_prefix: Some(prefix()),
            ..Inputs::default()
        };
        let p = build_plans_with(&board(), &cfg, &inputs).unwrap();
        let ra: Vec<(&str, String, Vec<String>)> = p
            .netd
            .ra
            .iter()
            .map(|s| {
                (
                    s.link.as_str(),
                    s.prefix.to_string(),
                    s.dns.iter().map(ToString::to_string).collect(),
                )
            })
            .collect();
        assert_eq!(
            ra,
            [
                (
                    "br-lan",
                    "fd12:3456:789a::/64".to_owned(),
                    vec!["fd12:3456:789a::1".to_owned()]
                ),
                (
                    "br-guest",
                    "fd12:3456:789a:14::/64".to_owned(),
                    vec!["fd12:3456:789a:14::1".to_owned()]
                ),
            ]
        );
        assert_eq!(p.netd.dhcp.as_ref(), p.net.dhcp_clients.first());
    }

    #[test]
    fn netd_advertises_nothing_without_ula_and_runs_no_client_on_a_static_wan() {
        let p = plans(&with_guest(true));
        assert_eq!(p.netd.ra, Vec::new());
        assert_eq!(p.netd.dhcp.as_ref().map(|d| d.link.as_str()), Some("eth1"));

        let mut cfg = defaults();
        cfg.network.wan.proto = c::WanProto::Static {
            ipv4: net("203.0.113.2/24"),
            gateway: Ipv4Addr::new(203, 0, 113, 1),
            dns: Vec::new(),
        };
        assert_eq!(plans(&cfg).netd, crate::NetdPlan::default());
    }

    #[test]
    fn build_plans_is_build_plans_with_default_inputs() {
        let cfg = with_guest(true);
        assert_eq!(
            build_plans_with(&board(), &cfg, &Inputs::default()).unwrap(),
            plans(&cfg)
        );
    }
}

mod dnsmasq_follow_ups {
    use super::*;
    use crate::{Inputs, build_plans_with};

    fn static_lease_named(name: &str) -> c::Config {
        let mut cfg = defaults();
        cfg.dhcp.static_leases = vec![c::StaticLease {
            mac: c::MacAddr([2, 0, 0, 0, 0, 1]),
            ip: Ipv4Addr::new(192, 168, 8, 20),
            hostname: Some(name.to_owned()),
        }];
        cfg
    }

    #[test]
    fn reserved_static_lease_hostnames_are_rejected() {
        for name in [
            "12345", "12h", "5m", "7d", "7D", "ignore", "Ignore", "infinite", "0",
        ] {
            let err = build_plans(&board(), &static_lease_named(name)).unwrap_err();
            assert_eq!(
                err,
                MapError::ReservedName {
                    field: "dhcp.static_leases[0].hostname".to_owned()
                },
                "{name}"
            );
        }
    }

    #[test]
    fn ordinary_static_lease_hostnames_are_accepted() {
        for name in ["printer", "h", "m1", "12x", "1h2", "nas-1", "d", "ignored"] {
            if let Err(e) = build_plans(&board(), &static_lease_named(name)) {
                panic!("{name}: {e}");
            }
        }
    }

    #[test]
    fn dns_is_served_on_vlans_without_a_dhcp_pool() {
        let mut cfg = with_guest(true);
        cfg.network.vlans[0].dhcp = None;
        let conf = plans(&cfg).dnsmasq_conf;
        assert!(conf.lines().any(|l| l == "interface=br-guest"), "{conf}");
        assert!(!conf.contains("dhcp-range=set:guest"), "{conf}");
    }

    #[test]
    fn lease_and_pid_files_follow_the_run_dir() {
        let inputs = Inputs {
            run_dir: Some("/tmp/owr-run".into()),
            ..Inputs::default()
        };
        let p = build_plans_with(&board(), &defaults(), &inputs).unwrap();
        for line in [
            "dhcp-leasefile=/tmp/owr-run/dhcp.leases",
            "pid-file=/tmp/owr-run/dnsmasq.pid",
            "resolv-file=/tmp/owr-run/resolv.conf.auto",
        ] {
            assert!(p.dnsmasq_conf.lines().any(|l| l == line), "{line}");
        }
    }

    #[test]
    fn default_run_dir_is_the_well_known_one() {
        let conf = plans(&defaults()).dnsmasq_conf;
        assert!(conf.contains("dhcp-leasefile=/run/ferritewrt/dhcp.leases"));
    }

    #[test]
    fn a_hostile_run_dir_is_rejected() {
        for dir in ["relative/dir", "/run/x\nuser=root", "/run/it's", "/run/a b"] {
            let inputs = Inputs {
                run_dir: Some(dir.into()),
                ..Inputs::default()
            };
            assert!(
                matches!(
                    build_plans_with(&board(), &defaults(), &inputs),
                    Err(MapError::Injection { .. })
                ),
                "{dir:?}"
            );
        }
    }
}

#[test]
fn mt76_quirk_follows_the_driver_list() {
    let mut b = board();
    let mut cfg = c::Config::defaults_for(&b);
    cfg.wireless.aps.push(ap("radio1", "flint2", "lan"));
    let quirk = |b: &Board| build_plans(b, &cfg).unwrap().radios[0].driver_quirks.mt76;
    assert!(quirk(&b), "mt7915e is an mt76 driver");
    for driver in ["mt7996e", "mt7921e", "mt7615e", "mt7603e", "mt76x2e"] {
        driver.clone_into(&mut b.wifi.driver);
        assert!(quirk(&b), "{driver}");
    }
    // Used to match `starts_with("mt79")`: only the listed drivers count now.
    for driver in ["mt7986", "ath10k", "mt79xx"] {
        driver.clone_into(&mut b.wifi.driver);
        assert!(!quirk(&b), "{driver}");
    }
}

mod step_order {
    use std::collections::BTreeSet;

    use super::*;
    use crate::net::FORWARDING_KEYS;
    use crate::steps::{
        Step, apply_steps, bootstrap_ruleset, critical_links, forwarding_off, is_critical,
        split_forwarding,
    };
    use owr_net::Action;

    fn kinds(steps: &[Step]) -> Vec<&'static str> {
        steps
            .iter()
            .map(|s| match s {
                Step::Hostname => "hostname",
                Step::FirewallBootstrap(_) => "fw-bootstrap",
                Step::ConvergeNet(_) => "net",
                Step::FirewallFinal(_) => "fw-final",
                Step::EnableForwarding(_) => "forwarding",
                Step::DaemonFiles => "daemons",
            })
            .collect()
    }

    #[test]
    fn firewall_is_loaded_before_the_network_and_forwarding_after_it() {
        let steps = apply_steps(&plans(&defaults()));
        assert_eq!(
            kinds(&steps),
            [
                "hostname",
                "fw-bootstrap",
                "net",
                "fw-final",
                "forwarding",
                "daemons"
            ]
        );
    }

    #[test]
    fn bootstrap_is_the_final_ruleset_without_the_flowtable() {
        let p = plans(&defaults());
        assert_eq!(p.fw.options.flow_offload, f::FlowOffload::Hardware);
        let steps = apply_steps(&p);
        let (Some(Step::FirewallBootstrap(boot)), Some(Step::FirewallFinal(fin))) =
            (steps.get(1), steps.get(3))
        else {
            panic!("unexpected steps");
        };
        assert_eq!(fin, &p.fw);
        assert_eq!(boot.options.flow_offload, f::FlowOffload::Off);
        assert_eq!(boot.options.offload_devices, Vec::<String>::new());
        assert_eq!(boot.validate(), Ok(()));
        // Everything else is identical, so `policy drop` and the zones are already in force.
        assert_eq!(boot.zones, p.fw.zones);
        assert_eq!(boot.forwardings, p.fw.forwardings);
        assert_eq!(boot.rules, p.fw.rules);
        let text = f::render(boot).unwrap();
        assert!(!text.contains("flowtable") && !text.contains("flow add"));
        assert!(text.contains("policy drop"));
        assert_eq!(&bootstrap_ruleset(&p.fw), boot);
    }

    #[test]
    fn forwarding_sysctls_are_only_in_the_forwarding_step() {
        let p = plans(&defaults());
        let steps = apply_steps(&p);
        let (Some(Step::ConvergeNet(net)), Some(Step::EnableForwarding(fwd))) =
            (steps.get(2), steps.get(4))
        else {
            panic!("unexpected steps");
        };
        assert!(
            net.sysctls
                .iter()
                .all(|(k, _)| !FORWARDING_KEYS.contains(&k.as_str()))
        );
        let keys: Vec<_> = fwd.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, FORWARDING_KEYS);
        assert!(fwd.contains(&("net.ipv4.ip_forward".to_owned(), "1".to_owned())));
        // Nothing but the sysctls was dropped from the plan.
        let mut rebuilt = net.clone();
        rebuilt.sysctls.clone_from(&p.net.sysctls);
        assert_eq!(rebuilt, p.net);
        assert_eq!(split_forwarding(&p.net).0, *net);
    }

    #[test]
    fn the_fallback_switches_every_forwarding_key_off() {
        let off = forwarding_off();
        assert_eq!(off.len(), FORWARDING_KEYS.len());
        assert!(off.iter().all(|(_, v)| v == "0"));
    }

    fn crit(links: &[&str]) -> BTreeSet<String> {
        links.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn critical_links_are_wan_lan_bridge_and_its_ports() {
        let links = critical_links(&plans(&with_guest(true)));
        assert_eq!(
            links.iter().map(String::as_str).collect::<Vec<_>>(),
            ["br-lan", "eth1", "lan1", "lan2", "lan3", "lan5"]
        );
    }

    fn sysctl(key: &str) -> Action {
        Action::Sysctl {
            key: key.to_owned(),
            value: "1".to_owned(),
        }
    }

    fn set_up(link: &str) -> Action {
        Action::SetUp {
            link: link.to_owned(),
        }
    }

    fn enslave(link: &str, master: &str) -> Action {
        Action::SetMaster {
            link: link.to_owned(),
            master: Some(master.to_owned()),
        }
    }

    #[test]
    fn security_sysctls_are_fatal_other_sysctls_warn() {
        let critical = crit(&["eth1", "br-lan"]);
        for key in [
            "net.ipv4.conf.all.rp_filter",
            "net/ipv4/conf/eth1/rp_filter",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.all.send_redirects",
            "kernel.kptr_restrict",
            "kernel.dmesg_restrict",
            "kernel.unprivileged_bpf_disabled",
            "net.core.bpf_jit_harden",
            "net.ipv4.ip_forward",
        ] {
            assert!(is_critical(&sysctl(key), &critical), "{key}");
        }
        for key in [
            "net.ipv4.tcp_syncookies",
            "kernel.yama.ptrace_scope",
            "fs.protected_symlinks",
        ] {
            assert!(!is_critical(&sysctl(key), &critical), "{key}");
        }
    }

    #[test]
    fn wan_and_lan_link_and_address_actions_are_fatal_others_warn() {
        let critical = crit(&["eth1", "br-lan", "lan1"]);
        let addr = "192.168.8.1/24".parse().unwrap();
        let add_addr = |link: &str| Action::AddAddr {
            link: link.to_owned(),
            addr,
        };
        assert!(is_critical(&add_addr("br-lan"), &critical));
        assert!(is_critical(&set_up("eth1"), &critical));
        assert!(is_critical(&enslave("lan1", "br-lan"), &critical));
        assert!(is_critical(&enslave("lan2", "br-lan"), &critical));
        // A guest VLAN is neither the WAN nor the LAN.
        assert!(!is_critical(&add_addr("br-guest"), &critical));
        assert!(!is_critical(&set_up("lan4"), &critical));
        assert!(!is_critical(&enslave("lan4.20", "br-guest"), &critical));
        let vlan = Action::CreateVlan {
            name: "lan4.20".to_owned(),
            parent: "lan4".to_owned(),
            id: 20,
        };
        assert!(!is_critical(&vlan, &critical));
    }
}

mod lease_persistence {
    use std::time::{Duration, SystemTime};

    use owr_net::dhcp::{INFINITE_LEASE, Lease};

    use super::*;
    use crate::files::{RESOLV_AUTO, write_daemon_files, write_resolv};
    use crate::lease::{
        forget_lease, is_expired, lease_path, load_valid_lease, publish_lease_dns, save_lease,
        usable_dns, with_persisted_lease,
    };

    fn lease(obtained_at: SystemTime, secs: u32, dns: Vec<Ipv4Addr>) -> Lease {
        Lease {
            addr: net("100.64.0.7/24"),
            routers: vec![Ipv4Addr::new(100, 64, 0, 1)],
            dns,
            domain: None,
            classless_routes: Vec::new(),
            lease_secs: secs,
            t1: secs / 2,
            t2: secs.saturating_mul(7) / 8,
            server: Ipv4Addr::new(100, 64, 0, 1),
            obtained_at,
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn expiry_is_obtained_at_plus_lease_secs() {
        let l = lease(at(1_000), 600, Vec::new());
        assert!(!is_expired(&l, at(1_000)));
        assert!(!is_expired(&l, at(1_599)));
        assert!(is_expired(&l, at(1_600)));
        assert!(is_expired(&l, at(9_999)));
        let forever = lease(at(1_000), INFINITE_LEASE, Vec::new());
        assert!(!is_expired(&forever, at(u64::from(u32::MAX) * 10)));
    }

    #[test]
    fn a_saved_lease_is_loaded_while_valid_and_ignored_when_expired() {
        let dir = tempfile::tempdir().unwrap();
        let l = lease(at(1_000), 600, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        assert!(save_lease(dir.path(), "eth1", &l).unwrap());
        assert!(!save_lease(dir.path(), "eth1", &l).unwrap(), "idempotent");
        assert_eq!(load_valid_lease(dir.path(), "eth1", at(1_200)), Some(l));
        assert_eq!(load_valid_lease(dir.path(), "eth1", at(1_600)), None);
        assert_eq!(load_valid_lease(dir.path(), "eth2", at(1_200)), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_lease_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save_lease(dir.path(), "eth1", &lease(at(0), 60, Vec::new())).unwrap();
        let mode = std::fs::metadata(lease_path(dir.path(), "eth1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_corrupt_lease_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(lease_path(dir.path(), "eth1"), b"{not json").unwrap();
        assert_eq!(load_valid_lease(dir.path(), "eth1", at(0)), None);
    }

    #[test]
    fn link_names_cannot_escape_the_run_dir() {
        let dir = tempfile::tempdir().unwrap();
        let l = lease(at(0), 60, Vec::new());
        assert!(save_lease(dir.path(), "../evil", &l).is_err());
        assert_eq!(load_valid_lease(dir.path(), "../evil", at(0)), None);
        assert!(forget_lease(dir.path(), "../evil").is_err());
    }

    #[test]
    fn a_forgotten_lease_is_no_longer_merged() {
        let dir = tempfile::tempdir().unwrap();
        let l = lease(at(1_000), 600, Vec::new());
        save_lease(dir.path(), "eth1", &l).unwrap();
        assert!(forget_lease(dir.path(), "eth1").unwrap());
        assert!(!forget_lease(dir.path(), "eth1").unwrap(), "already gone");
        assert_eq!(load_valid_lease(dir.path(), "eth1", at(1_200)), None);
        let p = plans(&defaults());
        assert_eq!(with_persisted_lease(&p.net, dir.path(), at(1_200)), p.net);
    }

    #[test]
    fn a_valid_persisted_lease_is_merged_into_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let p = plans(&defaults());
        assert_eq!(
            with_persisted_lease(&p.net, dir.path(), at(10)),
            p.net,
            "no lease file: unchanged"
        );

        let l = lease(at(0), 600, Vec::new());
        save_lease(dir.path(), "eth1", &l).unwrap();
        let merged = with_persisted_lease(&p.net, dir.path(), at(10));
        assert!(merged.addresses.contains(&l.addr_spec("eth1")));
        assert!(
            merged
                .routes
                .iter()
                .any(|r| r.proto == RouteProto::Dhcp && r.dev.as_deref() == Some("eth1"))
        );
        // (`validate()` checks user intent and rejects a leased address on a DHCP link; the
        // planner accepts it, see `owr_net::plan`.)
        // Merging is stable, so a second apply plans the same thing.
        assert_eq!(with_persisted_lease(&p.net, dir.path(), at(20)), merged);

        assert_eq!(
            with_persisted_lease(&p.net, dir.path(), at(601)),
            p.net,
            "expired lease: unchanged"
        );
    }

    #[test]
    fn a_plan_without_a_dhcp_client_ignores_leases() {
        let dir = tempfile::tempdir().unwrap();
        save_lease(dir.path(), "eth1", &lease(at(0), 600, Vec::new())).unwrap();
        let mut cfg = defaults();
        cfg.network.wan.proto = c::WanProto::Static {
            ipv4: net("203.0.113.2/24"),
            gateway: Ipv4Addr::new(203, 0, 113, 1),
            dns: Vec::new(),
        };
        let p = plans(&cfg);
        assert_eq!(with_persisted_lease(&p.net, dir.path(), at(1)), p.net);
    }

    #[test]
    fn unusable_dns_servers_are_filtered() {
        let dns = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 1, 2, 3),
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(192, 168, 1, 1),
        ];
        assert_eq!(
            usable_dns(&dns),
            [
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
            ]
        );
    }

    #[test]
    fn a_lease_without_usable_dns_keeps_the_previous_resolv_conf() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = defaults();
        write_daemon_files(&plans(&cfg), &cfg, dir.path()).unwrap();
        write_resolv(dir.path(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))]).unwrap();
        let before = std::fs::read_to_string(dir.path().join(RESOLV_AUTO)).unwrap();

        for dns in [vec![], vec![Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST]] {
            let (changed, warning) =
                publish_lease_dns(dir.path(), &lease(at(0), 600, dns)).unwrap();
            assert!(!changed);
            assert!(warning.unwrap().contains("keeping"));
            assert_eq!(
                std::fs::read_to_string(dir.path().join(RESOLV_AUTO)).unwrap(),
                before
            );
        }
    }

    #[test]
    fn a_lease_with_dns_replaces_resolv_conf_and_reports_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let l = lease(
            at(0),
            600,
            vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(9, 9, 9, 9)],
        );
        let (changed, warning) = publish_lease_dns(dir.path(), &l).unwrap();
        assert!(changed && warning.is_none());
        let text = std::fs::read_to_string(dir.path().join(RESOLV_AUTO)).unwrap();
        assert!(text.contains("nameserver 9.9.9.9") && !text.contains("127.0.0.1"));
        assert!(!publish_lease_dns(dir.path(), &l).unwrap().0);
    }
}

mod ula_file {
    use std::io;

    use crate::ula::{UlaError, load_or_create, prefix_from_random};

    #[test]
    fn prefix_is_fd_plus_40_random_bits() {
        let p = prefix_from_random([0x12, 0x34, 0x56, 0x78, 0x9a]).unwrap();
        assert_eq!(p.to_string(), "fd12:3456:789a::/48");
    }

    #[test]
    fn created_once_then_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("ula-prefix");
        let (first, created) = load_or_create(&path, || Ok([1, 2, 3, 4, 5])).unwrap();
        assert!(created);
        assert_eq!(first.to_string(), "fd01:203:405::/48");
        // The generator must not be consulted again.
        let (again, created) = load_or_create(&path, || Err(io::Error::other("no"))).unwrap();
        assert!(!created);
        assert_eq!(again, first);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "fd01:203:405::/48\n"
        );
    }

    #[test]
    fn a_malformed_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ula-prefix");
        for bad in ["garbage", "fe80::/48", "fd00::/64", "fd00:0:0:1::/48", ""] {
            std::fs::write(&path, bad).unwrap();
            let (p, created) = load_or_create(&path, || Ok([9, 9, 9, 9, 9])).unwrap();
            assert!(created, "{bad:?}");
            assert_eq!(p.to_string(), "fd09:909:909::/48");
        }
    }

    #[test]
    fn a_failing_random_source_is_an_error_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ula-prefix");
        let err = load_or_create(&path, || Err(io::Error::other("no entropy"))).unwrap_err();
        assert!(matches!(err, UlaError::Random(_)));
        assert!(!path.exists());
    }
}
