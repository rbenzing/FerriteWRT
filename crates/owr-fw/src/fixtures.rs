//! Shared builders for unit tests.

use std::net::Ipv4Addr;

use crate::model::{
    Family, Forwarding, Policy, PortRange, Proto, Redirect, Rule, Ruleset, Zone, ZoneName,
};
use crate::preset::flint2_default;

pub(crate) fn zn(name: &str) -> ZoneName {
    ZoneName::new(name).expect("valid zone name in test")
}

pub(crate) fn zone(name: &str, interfaces: &[&str], input: Policy, forward: Policy) -> Zone {
    Zone {
        name: zn(name),
        interfaces: interfaces.iter().map(|s| (*s).to_owned()).collect(),
        input,
        output: Policy::Accept,
        forward,
        masquerade: false,
        mss_clamp: false,
    }
}

pub(crate) fn zone_mut<'a>(rs: &'a mut Ruleset, name: &str) -> &'a mut Zone {
    rs.zones
        .iter_mut()
        .find(|z| z.name.as_str() == name)
        .expect("zone present in test ruleset")
}

/// An enabled, accept-all rule matching traffic to the device from any interface.
pub(crate) fn rule(name: &str) -> Rule {
    Rule {
        name: name.to_owned(),
        src: None,
        dst: None,
        family: Family::Any,
        proto: Proto::Any,
        src_ip: None,
        dst_ip: None,
        dst_port: None,
        action: Policy::Accept,
        enabled: true,
    }
}

pub(crate) fn redirect(
    name: &str,
    proto: Proto,
    src_dport: PortRange,
    dest: [u8; 4],
    dest_port: u16,
) -> Redirect {
    Redirect {
        name: name.to_owned(),
        src: zn("wan"),
        proto,
        src_dport,
        dest_ip: Ipv4Addr::from(dest),
        dest_port,
        enabled: true,
    }
}

/// lan + wan zones with lan -> wan forwarding and default options.
pub(crate) fn basic() -> Ruleset {
    let mut wan = zone("wan", &["eth1"], Policy::Drop, Policy::Drop);
    wan.masquerade = true;
    wan.mss_clamp = true;
    Ruleset {
        zones: vec![
            zone("lan", &["br-lan"], Policy::Accept, Policy::Accept),
            wan,
        ],
        forwardings: vec![Forwarding {
            src: zn("lan"),
            dst: zn("wan"),
        }],
        ..Ruleset::default()
    }
}

pub(crate) fn flint2(hw: bool) -> Ruleset {
    flint2_default(
        "eth1",
        "br-lan",
        &["lan1", "lan2", "lan3", "lan4", "lan5"],
        hw,
    )
}
