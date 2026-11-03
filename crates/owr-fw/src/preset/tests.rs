use super::*;

#[test]
fn hardware_offload_attaches_wan_and_lan_ports() {
    let rs = flint2_default("eth1", "br-lan", &["lan1", "lan2"], true);
    assert_eq!(rs.options.flow_offload, FlowOffload::Hardware);
    assert_eq!(rs.options.offload_devices, ["eth1", "lan1", "lan2"]);
    assert_eq!(rs.validate(), Ok(()));
}

#[test]
fn without_hw_offload_flowtable_is_off() {
    let rs = flint2_default("eth1", "br-lan", &["lan1"], false);
    assert_eq!(rs.options.flow_offload, FlowOffload::Off);
    assert_eq!(rs.options.offload_devices, Vec::<String>::new());
}

#[test]
fn builtin_zone_names_are_valid() {
    let rs = flint2_default("eth1", "br-lan", &[], false);
    for zone in &rs.zones {
        assert!(ZoneName::new(zone.name.as_str()).is_ok());
    }
}

#[test]
fn invalid_device_names_are_caught_by_validation() {
    let rs = flint2_default("not a dev", "br-lan", &[], false);
    assert!(rs.validate().is_err());
}
