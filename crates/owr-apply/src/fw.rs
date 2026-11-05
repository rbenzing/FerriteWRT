//! `Config` -> [`Ruleset`].

use owr_config::{Action, ApiBind, Config, Direction, ForwardProto, RuleProto, WanInput, WanProto};
use owr_fw::{
    Family, Forwarding, Policy, PortRange, Proto, Redirect, Rule, Ruleset, Zone, ZoneName,
    flint2_default,
};

use crate::error::MapError;
use crate::pppoe::PPPOE_IFNAME;
use crate::topology::{LAN_BRIDGE, Topology};

fn zone(name: &str) -> Result<ZoneName, MapError> {
    ZoneName::new(name).map_err(|_| MapError::InvalidZoneName(name.to_owned()))
}

fn policy(action: Action) -> Policy {
    match action {
        Action::Accept => Policy::Accept,
        Action::Drop => Policy::Drop,
        Action::Reject => Policy::Reject,
    }
}

fn forward_proto(proto: ForwardProto) -> Proto {
    match proto {
        ForwardProto::Tcp => Proto::Tcp,
        ForwardProto::Udp => Proto::Udp,
        ForwardProto::TcpUdp => Proto::TcpUdp,
    }
}

fn rule_proto(proto: RuleProto) -> Proto {
    match proto {
        RuleProto::Tcp => Proto::Tcp,
        RuleProto::Udp => Proto::Udp,
        RuleProto::Icmp => Proto::Icmp,
        RuleProto::Any => Proto::Any,
    }
}

fn ports(range: owr_config::PortRange) -> PortRange {
    PortRange {
        start: range.start,
        end: range.end,
    }
}

/// An accept rule for traffic from `src` to the router itself.
fn input_rule(name: String, src: &ZoneName, proto: Proto, port: Option<PortRange>) -> Rule {
    Rule {
        name,
        src: Some(src.clone()),
        dst: None,
        family: Family::Any,
        proto,
        src_ip: None,
        dst_ip: None,
        dst_port: port,
        action: Policy::Accept,
        enabled: true,
    }
}

/// Input rules of a VLAN zone. An isolated VLAN may only use the DHCP, DNS and ICMP services
/// of the router. A trusted (non-isolated) VLAN gets the full router input, except the
/// management API unless `services.api.bind` includes the VLANs.
fn vlan_input_rules(cfg: &Config, vlan_name: &str, zone: &ZoneName, isolated: bool) -> Vec<Rule> {
    let n = vlan_name;
    if isolated {
        let dhcp = PortRange { start: 67, end: 68 };
        return vec![
            input_rule(format!("{n}-dhcp"), zone, Proto::Udp, Some(dhcp)),
            input_rule(
                format!("{n}-dns"),
                zone,
                Proto::TcpUdp,
                Some(PortRange::single(53)),
            ),
            input_rule(format!("{n}-icmp"), zone, Proto::Icmp, None),
        ];
    }
    if cfg.services.api.bind == ApiBind::Lan {
        let mut block = input_rule(
            format!("{n}-api-block"),
            zone,
            Proto::Tcp,
            Some(PortRange::single(cfg.services.api.port)),
        );
        block.action = Policy::Drop;
        return vec![block];
    }
    Vec::new()
}

pub(crate) fn build_fw(cfg: &Config, topo: &Topology<'_>) -> Result<Ruleset, MapError> {
    let fwc = &cfg.firewall;
    let lan = zone("lan")?;
    let wan = zone("wan")?;
    let mut rs = flint2_default(topo.wan_dev, LAN_BRIDGE, &topo.lan_devs, fwc.hw_offload);

    if let Some(z) = rs.zones.iter_mut().find(|z| z.name == wan) {
        z.input = match fwc.default_wan_input {
            WanInput::Drop => Policy::Drop,
            WanInput::Reject => Policy::Reject,
        };
        // On PPPoE all WAN IP traffic is on pppd's interface (input, NAT, MSS clamp, port
        // forwards). The port stays in the zone: it carries only PPPoE frames, but anything
        // else arriving on it is still WAN. The flowtable keeps the port, which is where
        // the kernel offloads PPPoE flows.
        if matches!(cfg.network.wan.proto, WanProto::Pppoe { .. }) {
            z.interfaces.insert(0, PPPOE_IFNAME.to_owned());
        }
    }

    for vlan in &topo.vlans {
        let name = zone(&vlan.cfg.name)?;
        let isolated = vlan.cfg.isolated;
        rs.zones.push(Zone {
            name: name.clone(),
            interfaces: vec![vlan.bridge.clone()],
            // An isolated VLAN may only use the DHCP, DNS and ICMP services of the router.
            input: if isolated {
                Policy::Drop
            } else {
                Policy::Accept
            },
            output: Policy::Accept,
            forward: Policy::Accept,
            masquerade: false,
            mss_clamp: false,
        });
        rs.rules
            .extend(vlan_input_rules(cfg, &vlan.cfg.name, &name, isolated));
        rs.forwardings.push(Forwarding {
            src: name.clone(),
            dst: wan.clone(),
        });
        if !isolated {
            rs.forwardings.push(Forwarding {
                src: name.clone(),
                dst: lan.clone(),
            });
        }
        rs.forwardings.push(Forwarding {
            src: lan.clone(),
            dst: name,
        });
    }

    if fwc.hw_offload {
        rs.options
            .offload_devices
            .extend(topo.vlan_netdevs().map(str::to_owned));
    }

    for pf in &fwc.port_forwards {
        rs.redirects.push(Redirect {
            name: pf.name.clone(),
            src: wan.clone(),
            proto: forward_proto(pf.proto),
            src_dport: ports(pf.wan_port),
            dest_ip: pf.dest_ip,
            dest_port: pf.dest_port,
            enabled: pf.enabled,
        });
    }

    for rule in &fwc.rules {
        let (src, dst) = match rule.direction {
            Direction::WanIn => (wan.clone(), None),
            Direction::LanOut => (lan.clone(), Some(wan.clone())),
        };
        rs.rules.push(Rule {
            name: rule.name.clone(),
            src: Some(src),
            dst,
            family: Family::Any,
            proto: rule_proto(rule.proto),
            src_ip: rule.src,
            dst_ip: None,
            dst_port: rule.dest_port.map(ports),
            action: policy(rule.action),
            enabled: rule.enabled,
        });
    }
    Ok(rs)
}
