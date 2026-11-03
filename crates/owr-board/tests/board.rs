//! Integration tests: the shipped GL-MT6000 descriptor, plus one negative test per validation rule.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)] // test helpers: fail loudly

use std::path::Path;

use owr_board::{
    Band, Board, BoardError, ButtonAction, GL_MT6000_TOML, LedRole, PartitionRole, PortRole,
    ValidationIssue, builtin, builtin_boards,
};

fn gl() -> Board {
    Board::from_toml_str(GL_MT6000_TOML).unwrap()
}

/// Replace the first occurrence of `from`; panics if absent so stale mutations are caught.
fn mutated(from: &str, to: &str) -> String {
    assert!(
        GL_MT6000_TOML.contains(from),
        "mutation target {from:?} not in TOML"
    );
    GL_MT6000_TOML.replacen(from, to, 1)
}

fn issues_of(toml: &str) -> Vec<ValidationIssue> {
    match Board::from_toml_str(toml) {
        Err(BoardError::Invalid(issues)) => issues,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

fn assert_issue_at(issues: &[ValidationIssue], path: &str) {
    assert!(
        issues.iter().any(|i| i.path == path),
        "no issue at {path:?}; got {issues:?}"
    );
}

fn assert_toml_issue(from: &str, to: &str, path: &str) {
    assert_issue_at(&issues_of(&mutated(from, to)), path);
}

fn assert_struct_issue(mutate: impl FnOnce(&mut Board), path: &str) {
    let mut board = gl();
    mutate(&mut board);
    assert_issue_at(&board.validate().unwrap_err(), path);
}

// ---- the shipped board -------------------------------------------------------------------

#[test]
fn gl_mt6000_parses_and_validates() {
    let board = gl();
    assert_eq!(board.board.id, "glinet_gl-mt6000");
    assert_eq!(board.soc.cores, 4);
    assert!(board.validate().is_ok());
}

#[test]
fn gl_mt6000_has_five_lan_and_one_wan() {
    let board = gl();
    assert_eq!(board.lan_ports().count(), 5);
    let wans: Vec<_> = board.wan_ports().collect();
    assert_eq!(wans.len(), 1);
    assert_eq!(wans[0].name, "wan");
    assert_eq!(wans[0].role, PortRole::Wan);
}

#[test]
fn lan1_is_2500_on_switch_port_5() {
    let board = gl();
    let lan1 = board.port("lan1").unwrap();
    assert_eq!(lan1.speed_mbps, 2500);
    assert_eq!(lan1.switch_port, Some(5));
    assert!(board.port("nope").is_none());
}

#[test]
fn radio1_is_5g_160mhz() {
    let board = gl();
    let r = board.radio("radio1").unwrap();
    assert_eq!(r.band, Band::G5);
    assert_eq!(r.max_width_mhz, 160);
    assert_eq!(board.radio("radio0").unwrap().band, Band::G2);
    assert!(board.radio("radio9").is_none());
}

#[test]
fn partition_sizes_cells_and_roles_parse() {
    let board = gl();
    let parts = &board.storage.partitions;
    assert_eq!(parts[0].role, PartitionRole::Bootenv);
    assert_eq!(parts[0].size, Some(524_288));
    let factory = &parts[1];
    assert_eq!(factory.size, None);
    assert_eq!(factory.cells[1].name, "mac-base");
    assert_eq!((factory.cells[1].offset, factory.cells[1].size), (0xa, 6));
}

#[test]
fn leds_and_buttons_parse() {
    let board = gl();
    let boot: Vec<_> = board
        .leds_with_role(LedRole::Boot)
        .map(|l| l.name.as_str())
        .collect();
    assert_eq!(boot, ["blue:run"]);
    assert_eq!(board.leds_with_role(LedRole::Wan).count(), 0);
    let reset = &board.buttons[0];
    assert_eq!(reset.short_press, ButtonAction::Reboot);
    assert_eq!(reset.long_press, Some(ButtonAction::FactoryReset));
    assert_eq!(reset.long_press_secs, Some(5));
    assert_eq!(board.usb.controllers[0].vbus_gpio, Some(24));
}

#[test]
fn builtin_lookup_works() {
    assert_eq!(builtin("glinet_gl-mt6000").unwrap(), gl());
    let err = builtin("no-such-board").unwrap_err();
    assert!(
        matches!(&err, BoardError::UnknownBoard(id) if id == "no-such-board"),
        "{err:?}"
    );
}

#[test]
fn every_builtin_board_loads_and_id_matches() {
    assert_ne!(builtin_boards().len(), 0);
    for (id, toml) in builtin_boards() {
        let board = Board::from_toml_str(toml).unwrap();
        assert_eq!(&board.board.id, id);
    }
}

#[test]
fn boards_dir_file_loads_from_disk() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../boards/glinet_gl-mt6000.toml");
    if !path.exists() {
        // Cross-built test binary run on another OS (scripts/linux-tests.sh): the host's
        // manifest directory is not visible there. The host run covers this test.
        eprintln!("skipping: {} not visible from this OS", path.display());
        return;
    }
    assert_eq!(Board::load(&path).unwrap(), gl());
}

#[test]
fn json_round_trip_preserves_board() {
    let board = gl();
    let json = serde_json::to_string(&board).unwrap();
    let back: Board = serde_json::from_str(&json).unwrap();
    assert_eq!(back, board);
}

#[test]
fn other_partition_role_round_trips() {
    let toml = mutated(r#"role = "overlay""#, r#"role = "other:calibration""#);
    let board = Board::from_toml_str(&toml).unwrap();
    assert_eq!(
        board.storage.partitions[5].role,
        PartitionRole::Other("calibration".into())
    );
    let back: Board = serde_json::from_str(&serde_json::to_string(&board).unwrap()).unwrap();
    assert_eq!(back, board);
}

// ---- parse / load failures ---------------------------------------------------------------

#[test]
fn unknown_field_is_rejected() {
    let toml = mutated("baud = 115200", "baud = 115200\nbogus = 1");
    let err = Board::from_toml_str(&toml).unwrap_err();
    assert!(matches!(err, BoardError::Parse(_)), "{err:?}");
    assert!(err.to_string().contains("bogus"), "{err}");
}

#[test]
fn bad_hex_string_is_a_parse_error() {
    let err =
        Board::from_toml_str(&mutated(r#"size = "0x80000""#, r#"size = "0xnope""#)).unwrap_err();
    assert!(matches!(err, BoardError::Parse(_)), "{err:?}");
}

#[test]
fn hex_string_and_integer_sizes_are_equivalent() {
    let board = Board::from_toml_str(&mutated(r#"size = "0x80000""#, "size = 524288")).unwrap();
    assert_eq!(board.storage.partitions[0].size, Some(0x80000));
}

#[test]
fn missing_file_is_an_io_error() {
    let err = Board::load(Path::new("definitely/not/here.toml")).unwrap_err();
    assert!(matches!(err, BoardError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("here.toml"));
}

#[test]
fn invalid_error_display_lists_every_issue() {
    let toml = mutated("cores = 4", "cores = 0").replacen("ram_mib = 1024", "ram_mib = 1", 1);
    let msg = Board::from_toml_str(&toml).unwrap_err().to_string();
    assert!(msg.contains("soc.cores"), "{msg}");
    assert!(msg.contains("memory.ram_mib"), "{msg}");
}

// ---- validation rules (one negative test each) ------------------------------------------

#[test]
fn rule_schema_must_be_1() {
    assert_toml_issue("schema = 1", "schema = 2", "schema");
}

#[test]
fn rule_id_charset() {
    assert_toml_issue(r#"id = "glinet_gl-mt6000""#, r#"id = "Bad Id""#, "board.id");
    assert_struct_issue(|b| b.board.id.clear(), "board.id");
}

#[test]
fn rule_cores_at_least_one() {
    assert_toml_issue("cores = 4", "cores = 0", "soc.cores");
}

#[test]
fn rule_ram_at_least_64() {
    assert_toml_issue("ram_mib = 1024", "ram_mib = 63", "memory.ram_mib");
    assert!(Board::from_toml_str(&mutated("ram_mib = 1024", "ram_mib = 64")).is_ok());
}

#[test]
fn rule_emmc_needs_exactly_one_rootfs() {
    assert_toml_issue(
        r#"role = "rootfs""#,
        r#"role = "overlay""#,
        "storage.partitions",
    );
    assert_toml_issue(
        r#"role = "overlay""#,
        r#"role = "rootfs""#,
        "storage.partitions",
    );
}

#[test]
fn rule_rootfs_not_required_for_nand() {
    let toml = mutated(r#"kind = "emmc""#, r#"kind = "nand""#).replacen(
        r#"role = "rootfs""#,
        r#"role = "overlay""#,
        1,
    );
    assert!(Board::from_toml_str(&toml).is_ok());
}

#[test]
fn rule_partition_names_unique() {
    assert_toml_issue(
        r#"name = "kernel""#,
        r#"name = "factory""#,
        "storage.partitions[2].name",
    );
}

#[test]
fn rule_cells_inside_partition() {
    let toml = mutated(
        r#"role = "factory""#,
        "role = \"factory\"\nsize = \"0x800\"",
    );
    assert_issue_at(&issues_of(&toml), "storage.partitions[1].cells[0]");
    let fits = mutated(
        r#"role = "factory""#,
        "role = \"factory\"\nsize = \"0x1000\"",
    );
    assert!(Board::from_toml_str(&fits).is_ok());
}

#[test]
fn rule_cell_overflow_does_not_panic() {
    assert_struct_issue(
        |b| {
            let part = &mut b.storage.partitions[1];
            part.size = Some(u64::MAX);
            part.cells[0].offset = u64::MAX;
        },
        "storage.partitions[1].cells[0]",
    );
}

#[test]
fn rule_port_names_unique() {
    assert_toml_issue(
        r#"name = "lan2""#,
        r#"name = "lan1""#,
        "ethernet.ports[2].name",
    );
}

#[test]
fn rule_port_netdevs_unique() {
    assert_toml_issue(
        r#"netdev = "lan2""#,
        r#"netdev = "lan1""#,
        "ethernet.ports[2].netdev",
    );
}

#[test]
fn rule_switch_ports_unique() {
    assert_toml_issue(
        "switch_port = 0",
        "switch_port = 1",
        "ethernet.ports[3].switch_port",
    );
}

#[test]
fn rule_switch_port_not_cpu_port() {
    assert_toml_issue(
        "switch_port = 0",
        "switch_port = 6",
        "ethernet.ports[2].switch_port",
    );
}

#[test]
fn rule_switch_port_requires_switch() {
    assert_struct_issue(
        |b| b.ethernet.switch = None,
        "ethernet.ports[1].switch_port",
    );
}

#[test]
fn rule_needs_at_least_one_port() {
    assert_struct_issue(|b| b.ethernet.ports.clear(), "ethernet.ports");
}

#[test]
fn rule_needs_at_least_one_lan_port() {
    assert_struct_issue(
        |b| b.ethernet.ports.retain(|p| p.role == PortRole::Wan),
        "ethernet.ports",
    );
}

#[test]
fn rule_multiple_wan_ports_allowed() {
    let mut board = gl();
    board.ethernet.ports[2].role = PortRole::Wan;
    assert!(board.validate().is_ok());
    assert_eq!(board.wan_ports().count(), 2);
}

#[test]
fn rule_port_speed_allowed_set() {
    assert_toml_issue(
        "speed_mbps = 1000",
        "speed_mbps = 999",
        "ethernet.ports[2].speed_mbps",
    );
}

#[test]
fn rule_radio_ids_unique() {
    assert_toml_issue(r#"id = "radio1""#, r#"id = "radio0""#, "wifi.radios[1].id");
}

#[test]
fn rule_radio_phy_index_unique() {
    assert_toml_issue("phy_index = 1", "phy_index = 0", "wifi.radios[1].phy_index");
}

#[test]
fn rule_radio_width_allowed_set() {
    assert_toml_issue(
        "max_width_mhz = 160",
        "max_width_mhz = 100",
        "wifi.radios[1].max_width_mhz",
    );
}

#[test]
fn rule_2g_width_at_most_40() {
    assert_toml_issue(
        "max_width_mhz = 40",
        "max_width_mhz = 80",
        "wifi.radios[0].max_width_mhz",
    );
}

#[test]
fn rule_led_names_unique() {
    assert_toml_issue(
        r#"name = "white:system""#,
        r#"name = "blue:run""#,
        "leds[1].name",
    );
}

#[test]
fn rule_button_gpios_unique() {
    assert_struct_issue(
        |b| {
            let mut dup = b.buttons[0].clone();
            dup.name = "wps".into();
            b.buttons.push(dup);
        },
        "buttons[1].gpio",
    );
}

#[test]
fn rule_long_press_requires_secs() {
    assert_toml_issue("long_press_secs = 5\n", "", "buttons[0].long_press_secs");
}

#[test]
fn rule_openwrt_target_non_empty() {
    assert_toml_issue(r#"target = "mediatek""#, r#"target = """#, "openwrt.target");
}

#[test]
fn rule_openwrt_profile_non_empty() {
    assert_toml_issue(
        r#"profile = "glinet_gl-mt6000""#,
        r#"profile = """#,
        "openwrt.profile",
    );
}

#[test]
fn rule_wifi_driver_requires_radios() {
    assert_struct_issue(|b| b.wifi.radios.clear(), "wifi.radios");
}

#[test]
fn wifi_without_driver_may_have_no_radios() {
    let mut board = gl();
    board.wifi.driver.clear();
    board.wifi.radios.clear();
    assert!(board.validate().is_ok());
}

// ---- cross references --------------------------------------------------------------------

#[test]
fn rule_storage_root_and_overlay_must_name_a_partition() {
    assert_toml_issue(
        r#"root = "PARTLABEL=rootfs""#,
        r#"root = "PARTLABEL=nope""#,
        "storage.root",
    );
    assert_toml_issue(
        r#"overlay = "PARTLABEL=rootfs_data""#,
        r#"overlay = "PARTLABEL=nope""#,
        "storage.overlay",
    );
}

#[test]
fn rule_ethernet_mac_source_must_name_a_factory_cell() {
    assert_toml_issue(
        r#"mac_source = "factory:mac-base""#,
        r#"mac_source = "factory:nope""#,
        "ethernet.mac_source",
    );
    // The numeric-offset form is only meaningful for wifi.mac_source.
    assert_toml_issue(
        r#"mac_source = "factory:mac-base""#,
        r#"mac_source = "factory:0x04""#,
        "ethernet.mac_source",
    );
}

#[test]
fn rule_wifi_eeprom_and_mac_source_must_resolve() {
    assert_toml_issue(
        r#"eeprom = "factory:eeprom""#,
        r#"eeprom = "factory:nope""#,
        "wifi.eeprom",
    );
    assert_toml_issue(
        r#"eeprom = "factory:eeprom""#,
        r#"eeprom = "factory:0x0""#,
        "wifi.eeprom",
    );
    assert_toml_issue(
        r#"mac_source = "factory:0x04""#,
        r#"mac_source = "factory:nope""#,
        "wifi.mac_source",
    );
    // A cell name is fine for mac_source, and so is a decimal offset.
    for ok in ["factory:mac-base", "factory:4", "factory:0X4"] {
        let toml = mutated(
            r#"mac_source = "factory:0x04""#,
            &format!("mac_source = \"{ok}\""),
        );
        assert!(Board::from_toml_str(&toml).is_ok(), "{ok}");
    }
}

#[test]
fn rule_factory_reference_needs_a_factory_partition() {
    assert_struct_issue(
        |b| {
            b.storage
                .partitions
                .retain(|p| p.role != PartitionRole::Factory);
        },
        "ethernet.mac_source",
    );
}

#[test]
fn rule_cell_names_are_unique_within_a_partition() {
    assert_toml_issue(
        r#"{ name = "mac-base", offset"#,
        r#"{ name = "eeprom", offset"#,
        "storage.partitions[1].cells[1].name",
    );
}

#[test]
fn rule_cpu_netdev_must_not_be_a_port_netdev() {
    assert_toml_issue(
        r#"cpu_netdev = "eth0""#,
        r#"cpu_netdev = "eth1""#,
        "ethernet.switch.cpu_netdev",
    );
}

#[test]
fn rule_cpu_link_speed_must_be_a_known_speed() {
    assert_toml_issue(
        "cpu_link_mbps = 2500",
        "cpu_link_mbps = 3000",
        "ethernet.switch.cpu_link_mbps",
    );
}

#[test]
fn rule_led_gpios_are_unique() {
    assert_toml_issue("gpio = 37", "gpio = 38", "leds[1].gpio");
}

#[test]
fn rule_netdev_names_fit_ifnamsiz_and_charset() {
    // 16 chars, uppercase, space, slash, dot-dot, empty.
    for bad in ["this-is-sixteen-", "Eth1", "eth 1", "et/h1", "..", ""] {
        assert_toml_issue(
            r#"netdev = "eth1""#,
            &format!("netdev = \"{bad}\""),
            "ethernet.ports[0].netdev",
        );
        assert_toml_issue(
            r#"cpu_netdev = "eth0""#,
            &format!("cpu_netdev = \"{bad}\""),
            "ethernet.switch.cpu_netdev",
        );
    }
    // Exactly 15 characters is fine.
    let ok = mutated(r#"netdev = "eth1""#, r#"netdev = "abcdefghij.k_-l""#);
    assert!(Board::from_toml_str(&ok).is_ok());
}

#[test]
fn rule_radio_standards_must_not_be_empty() {
    assert_toml_issue(
        r#"standards = ["n", "ax"]"#,
        "standards = []",
        "wifi.radios[0].standards",
    );
}

// ---- partition role and numeric parsing --------------------------------------------------

#[test]
fn bare_unknown_partition_role_is_a_parse_error() {
    for bad in ["calibration", "rootfs_data", "Rootfs", "other:", "other"] {
        let err = Board::from_toml_str(&mutated(
            r#"role = "overlay""#,
            &format!("role = \"{bad}\""),
        ))
        .unwrap_err();
        assert!(matches!(err, BoardError::Parse(_)), "{bad}: {err:?}");
        assert!(err.to_string().contains("other:<name>"), "{bad}: {err}");
    }
}

#[test]
fn signed_or_padded_numbers_are_parse_errors_with_a_clear_message() {
    for (text, want) in [
        (r#"size = "-5""#, "negative"),
        ("size = -5", "negative"),
        (r#"size = "+5""#, "expected decimal digits"),
        (r#"size = " 5""#, "expected decimal digits"),
        (r#"size = "0x+5""#, "expected decimal digits"),
        (r#"size = "5 ""#, "expected decimal digits"),
        (r#"size = "0x""#, "expected decimal digits"),
    ] {
        let err = Board::from_toml_str(&mutated(r#"size = "0x80000""#, text)).unwrap_err();
        assert!(matches!(err, BoardError::Parse(_)), "{text}: {err:?}");
        assert!(err.to_string().contains(want), "{text}: {err}");
    }
    let board = Board::from_toml_str(&mutated(r#"size = "0x80000""#, r#"size = "0xA0""#)).unwrap();
    assert_eq!(board.storage.partitions[0].size, Some(0xa0));
}
