use crate::fixtures::{basic, flint2, redirect, rule, zn, zone, zone_mut};
use crate::model::{Family, FlowOffload, Forwarding, Policy, PortRange, Proto, Ruleset};
use crate::render::{RenderError, comment, comment_line, render};

fn rendered(rs: &Ruleset) -> String {
    render(rs).expect("ruleset renders")
}

fn has_line(text: &str, wanted: &str) -> bool {
    text.lines().any(|l| l.trim() == wanted)
}

fn net(s: &str) -> ipnet::IpNet {
    s.parse().expect("valid net")
}

fn scenario() -> Ruleset {
    let mut rs = flint2(true);
    rs.redirects = vec![
        redirect(
            "web",
            Proto::Tcp,
            PortRange::single(8080),
            [192, 168, 1, 10],
            80,
        ),
        redirect(
            "game",
            Proto::TcpUdp,
            "27015-27020".parse().expect("range"),
            [192, 168, 1, 20],
            27015,
        ),
    ];
    let mut v4 = rule("ssh from office");
    v4.src = Some(zn("wan"));
    v4.family = Family::Ipv4;
    v4.proto = Proto::Tcp;
    v4.src_ip = Some(net("203.0.113.0/24"));
    v4.dst_port = Some(PortRange::single(22));
    let mut v6 = rule("block v6 telnet");
    v6.src = Some(zn("lan"));
    v6.dst = Some(zn("wan"));
    v6.family = Family::Ipv6;
    v6.proto = Proto::Tcp;
    v6.dst_port = Some(PortRange::single(23));
    v6.action = Policy::Reject;
    let mut icmp = rule("ping");
    icmp.src = Some(zn("wan"));
    icmp.proto = Proto::Icmp;
    rs.rules = vec![v4, v6, icmp];
    if let Some(wan) = rs.zones.iter_mut().find(|z| z.name == zn("wan")) {
        wan.input = Policy::Reject;
    }
    rs
}

#[test]
fn snapshot_flint2_hw() {
    insta::assert_snapshot!(rendered(&flint2(true)));
}

#[test]
fn snapshot_flint2_no_offload() {
    insta::assert_snapshot!(rendered(&flint2(false)));
}

#[test]
fn snapshot_redirects_rules_and_reject() {
    insta::assert_snapshot!(rendered(&scenario()));
}

#[test]
fn render_is_deterministic() {
    let rs = scenario();
    assert_eq!(rendered(&rs), rendered(&rs));
    assert_eq!(rendered(&rs), rendered(&rs.clone()));
}

#[test]
fn script_is_idempotent_header_and_ends_with_newline() {
    let text = rendered(&basic());
    let head: Vec<&str> = text.lines().take(4).collect();
    assert_eq!(
        head,
        [
            "#!/usr/sbin/nft -f",
            "table inet owr",
            "delete table inet owr",
            "table inet owr {"
        ]
    );
    assert!(text.ends_with("}\n"));
}

#[test]
fn custom_table_name_is_used() {
    let mut rs = basic();
    rs.options.table_name = "fw_test".to_owned();
    let text = rendered(&rs);
    assert!(text.contains("delete table inet fw_test\n"));
    assert!(!text.contains("inet owr"));
}

#[test]
fn invalid_ruleset_is_rejected_with_issues() {
    let mut rs = basic();
    rs.forwardings.push(Forwarding {
        src: zn("lan"),
        dst: zn("nope"),
    });
    let err = render(&rs).expect_err("must fail");
    let RenderError::Invalid(issues) = &err;
    assert_eq!(issues.len(), 1);
    assert!(err.to_string().contains("unknown zone nope"));
}

#[test]
fn interface_sets_are_sorted_and_deduplicated() {
    let mut rs = basic();
    zone_mut(&mut rs, "lan").interfaces = vec!["lan3".into(), "br-lan".into(), "lan1".into()];
    let text = rendered(&rs);
    assert!(has_line(
        &text,
        r#"iifname { "br-lan", "lan1", "lan3" } jump input_lan"#
    ));
}

#[test]
fn drop_invalid_and_syn_flood_toggle() {
    let mut rs = basic();
    rs.options.drop_invalid = false;
    let off = rendered(&rs);
    assert!(!off.contains("ct state invalid drop"));
    assert!(!off.contains("limit rate over"));
    rs.options.drop_invalid = true;
    rs.options.syn_flood_protect = true;
    let on = rendered(&rs);
    assert_eq!(on.matches("ct state invalid drop").count(), 2);
    assert!(has_line(
        &on,
        "tcp flags syn meter synflood { ip saddr limit rate over 25/second burst 50 packets } drop"
    ));
    assert!(has_line(
        &on,
        "tcp flags syn meter synflood6 { ip6 saddr limit rate over 25/second burst 50 packets } drop"
    ));
}

fn chain_body<'a>(text: &'a str, name: &str) -> &'a str {
    let body = text
        .split(&format!("chain {name} {{"))
        .nth(1)
        .expect("chain present");
    body.split("  }").next().expect("chain body")
}

#[test]
fn syn_flood_limiter_is_per_source_and_only_on_uplink_zones() {
    let mut rs = basic();
    rs.options.syn_flood_protect = true;
    let text = rendered(&rs);
    assert!(!chain_body(&text, "input").contains("limit rate over"));
    assert!(!chain_body(&text, "input_lan").contains("synflood"));
    let wan = chain_body(&text, "input_wan");
    assert_eq!(wan.matches("meter synflood").count(), 2);
    let flood = wan.find("meter synflood ").expect("v4 limiter");
    let first_accept = wan.find("accept").expect("accept rule");
    assert!(flood < first_accept, "limiter must precede accept rules");
    rs.options.syn_flood_protect = false;
    assert!(!rendered(&rs).contains("synflood"));
}

#[test]
fn dhcp_client_accept_is_restricted_to_server_port() {
    let text = rendered(&basic());
    assert!(chain_body(&text, "input_wan").contains("udp sport 67 udp dport 68 accept"));
}

#[test]
fn flowtable_only_when_enabled_and_offload_flag_only_for_hardware() {
    let mut rs = basic();
    let off = rendered(&rs);
    assert!(!off.contains("flowtable"));
    assert!(!off.contains("flow add"));

    rs.options.offload_devices = vec!["eth1".into(), "lan1".into()];
    rs.options.flow_offload = FlowOffload::Software;
    let sw = rendered(&rs);
    assert!(sw.contains("flowtable ft {"));
    assert!(sw.contains(r#"devices = { "eth1", "lan1" };"#));
    assert!(!sw.contains("flags offload"));
    assert!(has_line(&sw, "meta l4proto { tcp, udp } flow add @ft"));

    rs.options.flow_offload = FlowOffload::Hardware;
    assert!(rendered(&rs).contains("flags offload;"));
}

#[test]
fn masquerade_is_ipv4_only_and_mss_clamp_rendered() {
    let text = rendered(&basic());
    assert!(has_line(
        &text,
        r#"meta nfproto ipv4 oifname { "eth1" } masquerade"#
    ));
    assert!(has_line(
        &text,
        r#"oifname { "eth1" } tcp flags syn tcp option maxseg size set rt mtu"#
    ));
}

#[test]
fn uplink_zone_gets_wan_housekeeping_but_lan_does_not() {
    let text = rendered(&basic());
    let wan = text.split("chain input_wan {").nth(1).expect("wan chain");
    let wan = wan.split("  }").next().expect("chain body");
    assert!(wan.contains("udp sport 67 udp dport 68 accept"));
    assert!(wan.contains("icmp type echo-request limit rate 10/second accept"));
    assert!(wan.contains("nd-neighbor-solicit"));
    assert!(wan.trim_end().ends_with("drop"));
    let lan = text.split("chain input_lan {").nth(1).expect("lan chain");
    let lan = lan.split("  }").next().expect("chain body");
    assert!(!lan.contains("udp dport 68"));
    assert!(lan.trim().ends_with("accept"));
}

#[test]
fn zone_reject_policy_uses_icmpx_port_unreachable() {
    let mut rs = basic();
    zone_mut(&mut rs, "wan").input = Policy::Reject;
    let text = rendered(&rs);
    assert!(has_line(&text, "reject with icmpx type port-unreachable"));
}

#[test]
fn user_reject_action_is_plain_reject() {
    let mut rs = basic();
    let mut r = rule("no telnet");
    r.src = Some(zn("lan"));
    r.proto = Proto::Tcp;
    r.dst_port = Some(PortRange::single(23));
    r.action = Policy::Reject;
    rs.rules.push(r);
    let text = rendered(&rs);
    assert!(has_line(
        &text,
        r#"tcp dport 23 reject comment "no telnet""#
    ));
}

#[test]
fn icmp_with_any_family_expands_to_icmp_and_icmpv6() {
    let mut rs = basic();
    let mut r = rule("ping");
    r.src = Some(zn("wan"));
    r.proto = Proto::Icmp;
    rs.rules.push(r);
    let text = rendered(&rs);
    assert!(has_line(
        &text,
        r#"meta nfproto ipv4 meta l4proto icmp accept comment "ping""#
    ));
    assert!(has_line(
        &text,
        r#"meta nfproto ipv6 meta l4proto ipv6-icmp accept comment "ping""#
    ));
}

#[test]
fn icmp_with_explicit_family_is_a_single_rule() {
    let mut rs = basic();
    let mut r = rule("ping6");
    r.proto = Proto::Icmp;
    r.family = Family::Ipv6;
    rs.rules.push(r);
    let text = rendered(&rs);
    assert_eq!(text.matches("ping6").count(), 2); // `#` line and comment
    assert!(!text.contains("meta l4proto icmp "));
}

#[test]
fn icmp_with_address_derives_family() {
    let mut rs = basic();
    let mut r = rule("ping net");
    r.proto = Proto::Icmp;
    r.src_ip = Some(net("2001:db8::/32"));
    rs.rules.push(r);
    let text = rendered(&rs);
    assert!(has_line(
        &text,
        r#"ip6 saddr 2001:db8::/32 meta l4proto ipv6-icmp accept comment "ping net""#
    ));
    assert!(!text.contains("meta l4proto icmp "));
}

#[test]
fn tcp_udp_rule_uses_l4proto_set_and_th_dport() {
    let mut rs = basic();
    let mut r = rule("dns");
    r.proto = Proto::TcpUdp;
    r.dst_port = Some(PortRange::single(53));
    rs.rules.push(r);
    assert!(has_line(
        &rendered(&rs),
        r#"meta l4proto { tcp, udp } th dport 53 accept comment "dns""#
    ));
}

#[test]
fn port_range_is_rendered_with_dash() {
    let mut rs = basic();
    let mut r = rule("high ports");
    r.proto = Proto::Udp;
    r.dst_port = Some(PortRange {
        start: 8000,
        end: 8010,
    });
    rs.rules.push(r);
    assert!(has_line(
        &rendered(&rs),
        r#"udp dport 8000-8010 accept comment "high ports""#
    ));
}

#[test]
fn address_host_bits_are_truncated() {
    let mut rs = basic();
    let mut r = rule("net");
    r.src_ip = Some(net("10.1.2.3/24"));
    rs.rules.push(r);
    assert!(has_line(
        &rendered(&rs),
        r#"ip saddr 10.1.2.0/24 accept comment "net""#
    ));
}

#[test]
fn family_only_rule_gets_nfproto_qualifier() {
    let mut rs = basic();
    let mut r = rule("v4 only");
    r.family = Family::Ipv4;
    rs.rules.push(r);
    assert!(has_line(
        &rendered(&rs),
        r#"meta nfproto ipv4 accept comment "v4 only""#
    ));
}

#[test]
fn disabled_rules_and_redirects_are_omitted() {
    let mut rs = basic();
    let mut r = rule("off");
    r.enabled = false;
    rs.rules.push(r);
    let mut rd = redirect(
        "off redirect",
        Proto::Tcp,
        PortRange::single(1),
        [10, 0, 0, 1],
        1,
    );
    rd.enabled = false;
    rs.redirects.push(rd);
    let text = rendered(&rs);
    assert!(!text.contains("# off"));
    assert!(!text.contains("off redirect"));
}

#[test]
fn rule_scopes_select_the_right_chain() {
    let mut rs = basic();
    let mut global = rule("global");
    global.proto = Proto::Udp;
    let mut fwd = rule("lan to wan");
    fwd.src = Some(zn("lan"));
    fwd.dst = Some(zn("wan"));
    let mut any_to_lan = rule("any to lan");
    any_to_lan.dst = Some(zn("lan"));
    any_to_lan.action = Policy::Drop;
    rs.rules = vec![global, fwd, any_to_lan];
    let text = rendered(&rs);

    let chain = |name: &str| -> String {
        let marker = format!("  chain {name} {{");
        let start = text.find(&marker).expect("chain exists");
        let body = text.get(start..).expect("slice");
        body.split("\n  }\n").next().expect("body").to_owned()
    };
    assert!(chain("input").contains("meta l4proto udp accept comment \"global\""));
    assert!(chain("forward_lan").contains(r#"oifname { "eth1" } accept comment "lan to wan""#));
    assert!(chain("forward").contains(r#"oifname { "br-lan" } drop comment "any to lan""#));
}

#[test]
fn redirect_renders_dnat_and_forward_accept() {
    let mut rs = basic();
    rs.redirects.push(redirect(
        "web",
        Proto::Tcp,
        PortRange {
            start: 8000,
            end: 8010,
        },
        [192, 168, 1, 10],
        80,
    ));
    let text = rendered(&rs);
    assert!(has_line(
        &text,
        r#"iifname { "eth1" } tcp dport 8000-8010 dnat ip to 192.168.1.10:80 comment "web""#
    ));
    assert!(has_line(
        &text,
        r#"ip daddr 192.168.1.10 tcp dport 80 ct status dnat accept comment "web""#
    ));
}

#[test]
fn redirect_tcp_udp_uses_th_dport() {
    let mut rs = basic();
    rs.redirects.push(redirect(
        "game",
        Proto::TcpUdp,
        PortRange::single(27015),
        [10, 0, 0, 2],
        27016,
    ));
    let text = rendered(&rs);
    assert!(text.contains("meta l4proto { tcp, udp } th dport 27015 dnat ip to 10.0.0.2:27016"));
    assert!(text.contains(
        "ip daddr 10.0.0.2 meta l4proto { tcp, udp } th dport 27016 ct status dnat accept"
    ));
}

#[test]
fn hostile_names_are_rejected_before_rendering() {
    for name in [
        "say \"hi\"",
        "a\"; drop #",
        "semi;colon",
        "x\nflush ruleset",
    ] {
        let mut rs = basic();
        rs.rules.push(rule(name));
        assert!(
            matches!(render(&rs), Err(RenderError::Invalid(_))),
            "{name:?}"
        );
        let mut rs = basic();
        rs.redirects.push(redirect(
            name,
            Proto::Tcp,
            PortRange::single(80),
            [10, 0, 0, 2],
            80,
        ));
        assert!(
            matches!(render(&rs), Err(RenderError::Invalid(_))),
            "{name:?}"
        );
    }
}

#[test]
fn valid_name_renders_exactly_one_quoted_comment_per_line() {
    let mut rs = basic();
    rs.rules.push(rule("Allow web_1.2-x"));
    let text = rendered(&rs);
    let line = text
        .lines()
        .find(|l| l.contains("Allow web_1.2-x") && l.contains("accept"))
        .expect("rule line");
    assert_eq!(line.matches("comment \"").count(), 1);
    assert_eq!(line.matches('"').count(), 2);
    assert!(line.trim_end().ends_with(r#"comment "Allow web_1.2-x""#));
}

#[test]
fn comment_helper_maps_disallowed_chars_to_underscore() {
    // Defence in depth: validation rejects these, the renderer must still never emit them.
    assert_eq!(
        comment("say \"hi\" \\o/;#{}\n\u{e9}"),
        r#"comment "say _hi_ _o_______""#
    );
    assert_eq!(comment_line("a\nflush ruleset"), "# a_flush ruleset");
}

#[test]
fn comment_is_limited_to_128_bytes_on_char_boundary() {
    // Validated names never get this long; this bounds an unvalidated one.
    assert_eq!(
        comment(&"a".repeat(300)),
        format!("comment \"{}\"", "a".repeat(128))
    );
    // Non-ASCII is mapped to `_` (one per char), so truncation happens before mapping:
    // 'é' is 2 bytes and 65 of them is 130 bytes, so only 64 chars survive.
    assert_eq!(
        comment(&"é".repeat(65)),
        format!("comment \"{}\"", "_".repeat(64))
    );
}

#[test]
fn zone_without_interfaces_renders_no_dangling_matches() {
    let mut rs = basic();
    rs.zones
        .push(zone("guest", &[], Policy::Drop, Policy::Drop));
    rs.forwardings.push(Forwarding {
        src: zn("lan"),
        dst: zn("guest"),
    });
    let text = rendered(&rs);
    assert!(!text.contains("{ }"));
    assert!(!text.contains("jump input_guest"));
    assert!(text.contains("chain input_guest {"));
}

#[test]
fn restricted_zone_output_is_filtered() {
    let mut rs = basic();
    zone_mut(&mut rs, "wan").output = Policy::Drop;
    let text = rendered(&rs);
    // output chain + intra-zone forward policy of wan
    assert_eq!(text.matches(r#"oifname { "eth1" } drop"#).count(), 2);
    assert!(has_line(&text, "oif lo accept"));
}

#[test]
fn intra_zone_forward_policy_is_rendered_per_zone() {
    let text = rendered(&basic());
    assert!(has_line(&text, r#"oifname { "br-lan" } accept"#));
    assert!(has_line(&text, r#"oifname { "eth1" } drop"#));
}
