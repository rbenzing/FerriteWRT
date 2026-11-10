use super::*;

fn plan(password: &str, service: Option<&str>) -> PppoePlan {
    PppoePlan {
        nic: "eth1".to_owned(),
        username: "user@isp".to_owned(),
        password: Zeroizing::new(password.to_owned()),
        service: service.map(str::to_owned),
        mtu: DEFAULT_MTU,
    }
}

#[test]
fn options_name_the_port_interface_credentials_and_keepalive() {
    let text = render_pppoe(&plan("s3cret pw", Some("fibre")), true);
    let lines: Vec<&str> = text.lines().collect();
    for want in [
        "plugin pppoe.so",
        "nic-eth1",
        "ifname pppoe-wan",
        "user \"user@isp\"",
        "password \"s3cret pw\"",
        "rp_pppoe_service \"fibre\"",
        "noauth",
        "defaultroute",
        "usepeerdns",
        "persist",
        "maxfail 0",
        "lcp-echo-interval 1",
        "lcp-echo-failure 5",
        "mtu 1492",
        "mru 1492",
        "nodetach",
        "logfd 2",
    ] {
        assert!(lines.contains(&want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("rp_pppoe_service") || text.contains("fibre"));
    assert!(!render_pppoe(&plan("x", None), true).contains("rp_pppoe_service"));
}

#[test]
fn the_password_is_only_in_the_file_pppd_reads() {
    let p = plan("s3cret", None);
    assert!(!render_pppoe(&p, false).contains("s3cret"));
    assert!(render_pppoe(&p, false).contains("password \"***\""));
    assert!(!format!("{p:?}").contains("s3cret"));
}

#[test]
fn quotes_and_backslashes_are_escaped_and_control_characters_refused() {
    assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
    let text = render_pppoe(&plan(r#"p"w\"#, None), true);
    assert!(text.lines().any(|l| l == r#"password "p\"w\\""#), "{text}");

    for bad in ["", "a\nnoauth", "a\rb", "a\0b", "tab\there"] {
        assert!(
            matches!(check_word("f", bad), Err(MapError::Injection { .. })),
            "{bad:?}"
        );
    }
    assert_eq!(check_word("f", "user@isp.example"), Ok(()));
}

#[test]
fn the_port_mtu_grows_only_for_baby_jumbo_frames() {
    assert_eq!(port_mtu(1492), None);
    assert_eq!(port_mtu(1400), None);
    assert_eq!(port_mtu(1500), Some(1508));
}
