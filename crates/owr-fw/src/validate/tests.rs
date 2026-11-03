use super::*;
use crate::fixtures::{basic, flint2, redirect, rule, zn, zone, zone_mut};
use crate::model::{Family, FlowOffload, Forwarding, Policy, PortRange, Proto};

fn messages(rs: &Ruleset) -> Vec<String> {
    rs.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn assert_single_issue(rs: &Ruleset, needle: &str) {
    let msgs = messages(rs);
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    assert!(
        msgs.iter().any(|m| m.contains(needle)),
        "{msgs:?} lacks {needle:?}"
    );
}

#[test]
fn valid_rulesets_pass() {
    assert_eq!(basic().validate(), Ok(()));
    assert_eq!(flint2(true).validate(), Ok(()));
    assert_eq!(flint2(false).validate(), Ok(()));
    assert_eq!(Ruleset::default().validate(), Ok(()));
}

#[test]
fn duplicate_zone_names_are_rejected() {
    let mut rs = basic();
    rs.zones
        .push(zone("lan", &["lan9"], Policy::Drop, Policy::Drop));
    assert_single_issue(&rs, "duplicate zone name lan");
}

#[test]
fn invalid_netdev_names_are_rejected() {
    for bad in [
        "",
        "this-name-is-too-long",
        "eth 0",
        "eth/0",
        "..",
        "eth0\"",
        "a:b",
    ] {
        let mut rs = basic();
        zone_mut(&mut rs, "lan").interfaces = vec![bad.to_owned()];
        assert_single_issue(&rs, "invalid netdev name");
    }
    assert!(is_valid_netdev_name("br-lan"));
    assert!(is_valid_netdev_name("eth0.100"));
    assert!(is_valid_netdev_name("abcdefghijklmno"));
}

#[test]
fn interface_in_two_zones_is_rejected() {
    let mut rs = basic();
    zone_mut(&mut rs, "lan").interfaces.push("eth1".to_owned());
    assert_single_issue(&rs, "already assigned");
}

#[test]
fn masquerade_zone_requires_interfaces() {
    let mut rs = basic();
    zone_mut(&mut rs, "wan").interfaces.clear();
    assert_single_issue(&rs, "requires at least one interface");
}

#[test]
fn forwardings_must_reference_existing_distinct_zones() {
    let mut rs = basic();
    rs.forwardings.push(Forwarding {
        src: zn("ghost"),
        dst: zn("wan"),
    });
    assert_single_issue(&rs, "unknown zone ghost");

    let mut rs = basic();
    rs.forwardings = vec![Forwarding {
        src: zn("lan"),
        dst: zn("lan"),
    }];
    assert_single_issue(&rs, "must differ");

    let mut rs = basic();
    rs.forwardings.push(Forwarding {
        src: zn("lan"),
        dst: zn("wan"),
    });
    assert_single_issue(&rs, "duplicate forwarding");
}

#[test]
fn rules_must_reference_existing_zones() {
    let mut rs = basic();
    let mut r = rule("x");
    r.src = Some(zn("ghost"));
    rs.rules.push(r);
    assert_single_issue(&rs, "unknown zone ghost");

    let mut rs = basic();
    let mut r = rule("x");
    r.dst = Some(zn("ghost"));
    rs.rules.push(r);
    assert_single_issue(&rs, "unknown zone ghost");
}

#[test]
fn rule_name_must_be_clean() {
    let mut rs = basic();
    rs.rules.push(rule(""));
    assert_single_issue(&rs, "must not be empty");

    let mut rs = basic();
    rs.rules.push(rule("two\nlines"));
    assert_single_issue(&rs, "name must match");
}

const BAD_NAMES: [&str; 14] = [
    "say \"hi\"",
    "back\\slash",
    "semi;colon",
    "hash#tag",
    "{brace}",
    "line\nbreak",
    "cr\rreturn",
    "tab\there",
    "caf\u{e9}",
    "\u{1f600}",
    " leading space",
    "-leading-dash",
    ".dot",
    "name\" accept; drop comment \"x",
];

#[test]
fn rule_and_redirect_names_use_an_allow_list() {
    for name in BAD_NAMES {
        let mut rs = basic();
        rs.rules.push(rule(name));
        assert_single_issue(&rs, "name must match");

        let mut rs = basic();
        rs.redirects.push(redirect(
            name,
            Proto::Tcp,
            PortRange::single(80),
            [10, 0, 0, 2],
            80,
        ));
        assert_single_issue(&rs, "name must match");
    }
    for name in ["a", "ssh from office", "Web_1.2-x", &"a".repeat(64)] {
        let mut rs = basic();
        rs.rules.push(rule(name));
        assert_eq!(rs.validate(), Ok(()), "{name:?}");
    }
    let mut rs = basic();
    rs.rules.push(rule(&"a".repeat(65)));
    assert_single_issue(&rs, "name must match");
}

#[test]
fn rule_port_requires_port_protocol_and_valid_range() {
    let mut rs = basic();
    let mut r = rule("x");
    r.proto = Proto::Icmp;
    r.dst_port = Some(PortRange::single(80));
    rs.rules.push(r);
    assert_single_issue(&rs, "requires proto");

    for range in [
        PortRange { start: 90, end: 80 },
        PortRange { start: 0, end: 80 },
    ] {
        let mut rs = basic();
        let mut r = rule("x");
        r.proto = Proto::Tcp;
        r.dst_port = Some(range);
        rs.rules.push(r);
        assert_single_issue(&rs, "1 <= start <= end");
    }
}

#[test]
fn rule_address_family_must_match() {
    let mut rs = basic();
    let mut r = rule("x");
    r.family = Family::Ipv4;
    r.src_ip = Some("2001:db8::/32".parse().expect("net"));
    rs.rules.push(r);
    assert_single_issue(&rs, "does not match rule family");

    let mut rs = basic();
    let mut r = rule("x");
    r.src_ip = Some("10.0.0.0/8".parse().expect("net"));
    r.dst_ip = Some("2001:db8::/32".parse().expect("net"));
    rs.rules.push(r);
    assert_single_issue(&rs, "different address families");
}

#[test]
fn redirects_only_support_tcp_udp() {
    for proto in [Proto::Any, Proto::Icmp] {
        let mut rs = basic();
        rs.redirects.push(redirect(
            "x",
            proto,
            PortRange::single(80),
            [10, 0, 0, 2],
            80,
        ));
        assert_single_issue(&rs, "only tcp, udp or tcp_udp");
    }
    for proto in [Proto::Tcp, Proto::Udp, Proto::TcpUdp] {
        let mut rs = basic();
        rs.redirects.push(redirect(
            "x",
            proto,
            PortRange::single(80),
            [10, 0, 0, 2],
            80,
        ));
        assert_eq!(rs.validate(), Ok(()));
    }
}

#[test]
fn redirect_zone_ports_and_name_are_checked() {
    let mut rs = basic();
    let mut r = redirect("x", Proto::Tcp, PortRange::single(80), [10, 0, 0, 2], 80);
    r.src = zn("ghost");
    rs.redirects.push(r);
    assert_single_issue(&rs, "unknown zone ghost");

    let mut rs = basic();
    rs.redirects.push(redirect(
        "x",
        Proto::Tcp,
        PortRange { start: 5, end: 1 },
        [10, 0, 0, 2],
        80,
    ));
    assert_single_issue(&rs, "1 <= start <= end");

    let mut rs = basic();
    rs.redirects.push(redirect(
        "x",
        Proto::Tcp,
        PortRange::single(80),
        [10, 0, 0, 2],
        0,
    ));
    assert_single_issue(&rs, "port must be 1-65535");

    let mut rs = basic();
    rs.redirects.push(redirect(
        "",
        Proto::Tcp,
        PortRange::single(80),
        [10, 0, 0, 2],
        80,
    ));
    assert_single_issue(&rs, "must not be empty");
}

#[test]
fn options_are_checked() {
    let mut rs = basic();
    rs.options.table_name = "Bad Name".to_owned();
    assert_single_issue(&rs, "invalid table name");

    let mut rs = basic();
    rs.options.flow_offload = FlowOffload::Hardware;
    assert_single_issue(&rs, "no devices listed");

    let mut rs = basic();
    rs.options.offload_devices = vec!["eth1".into(), "eth1".into()];
    assert_single_issue(&rs, "duplicate offload device");

    let mut rs = basic();
    rs.options.offload_devices = vec!["bad name".into()];
    assert_single_issue(&rs, "invalid netdev name");
}

#[test]
fn all_issues_are_collected() {
    let mut rs = basic();
    zone_mut(&mut rs, "lan").interfaces = vec!["bad name".into()];
    rs.options.table_name = String::new();
    rs.rules.push(rule(""));
    assert_eq!(messages(&rs).len(), 3);
}

#[test]
fn redirect_dest_ip_must_be_unicast() {
    for bad in [
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [127, 255, 255, 254],
        [224, 0, 0, 1],
        [239, 255, 255, 250],
        [255, 255, 255, 255],
    ] {
        let mut rs = basic();
        rs.redirects
            .push(redirect("x", Proto::Tcp, PortRange::single(80), bad, 80));
        assert_single_issue(&rs, "must be a unicast address");
    }
    for good in [[192, 168, 1, 10], [10, 0, 0, 2], [8, 8, 8, 8]] {
        let mut rs = basic();
        rs.redirects
            .push(redirect("x", Proto::Tcp, PortRange::single(80), good, 80));
        assert_eq!(rs.validate(), Ok(()), "{good:?}");
    }
}
