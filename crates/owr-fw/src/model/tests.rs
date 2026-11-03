use super::*;

#[test]
fn zone_name_accepts_valid_and_rejects_invalid() {
    for ok in ["lan", "wan", "guest_2", "a", "abcdefghijklmno"] {
        assert!(ZoneName::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "Lan",
        "my-zone",
        "has space",
        "abcdefghijklmnop",
        "ünï",
        "a\"b",
    ] {
        assert!(ZoneName::new(bad).is_err(), "{bad}");
    }
}

#[test]
fn zone_name_deserialization_is_validated() {
    let ok: ZoneName = serde_json::from_str("\"lan\"").expect("valid");
    assert_eq!(ok.as_str(), "lan");
    assert!(serde_json::from_str::<ZoneName>("\"Bad-Name\"").is_err());
}

#[test]
fn port_range_parses_single_and_range() {
    assert_eq!("80".parse::<PortRange>(), Ok(PortRange::single(80)));
    assert_eq!(
        "8000-8010".parse::<PortRange>(),
        Ok(PortRange {
            start: 8000,
            end: 8010
        })
    );
    assert_eq!("65535".parse::<PortRange>(), Ok(PortRange::single(65535)));
}

#[test]
fn port_range_rejects_garbage() {
    for bad in [
        "", "0", "0-10", "10-5", "65536", "-5", "5-", "a", "1-2-3", " 80", "80 ",
    ] {
        assert!(bad.parse::<PortRange>().is_err(), "{bad:?}");
    }
}

#[test]
fn port_range_display_round_trips() {
    for s in ["80", "8000-8010"] {
        assert_eq!(s.parse::<PortRange>().expect("parses").to_string(), s);
    }
}

#[test]
fn ruleset_serde_round_trip() {
    let rs = crate::fixtures::basic();
    let json = serde_json::to_string(&rs).expect("serializes");
    assert_eq!(serde_json::from_str::<Ruleset>(&json).expect("parses"), rs);
}
