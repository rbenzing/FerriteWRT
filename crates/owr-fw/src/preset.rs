//! Built-in rulesets.

use crate::model::{FlowOffload, Forwarding, Options, Policy, Ruleset, Zone, ZoneName};

#[cfg(test)]
mod tests;

/// Default Flint 2 ruleset: `lan` (bridge, everything accepted) and `wan` (input and
/// forward dropped, masquerade, MSS clamp) with `lan -> wan` forwarding.
///
/// With `hw_offload` a hardware flowtable is attached to `wan` and `lan_ports`;
/// otherwise flow offloading is off.
pub fn flint2_default(
    wan: &str,
    lan_bridge: &str,
    lan_ports: &[&str],
    hw_offload: bool,
) -> Ruleset {
    let lan = ZoneName::builtin("lan");
    let wan_zone = ZoneName::builtin("wan");
    let offload_devices = if hw_offload {
        std::iter::once(wan)
            .chain(lan_ports.iter().copied())
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    Ruleset {
        zones: vec![
            Zone {
                name: lan.clone(),
                interfaces: vec![lan_bridge.to_owned()],
                input: Policy::Accept,
                output: Policy::Accept,
                forward: Policy::Accept,
                masquerade: false,
                mss_clamp: false,
            },
            Zone {
                name: wan_zone.clone(),
                interfaces: vec![wan.to_owned()],
                input: Policy::Drop,
                output: Policy::Accept,
                forward: Policy::Drop,
                masquerade: true,
                mss_clamp: true,
            },
        ],
        forwardings: vec![Forwarding {
            src: lan,
            dst: wan_zone,
        }],
        rules: Vec::new(),
        redirects: Vec::new(),
        options: Options {
            flow_offload: if hw_offload {
                FlowOffload::Hardware
            } else {
                FlowOffload::Off
            },
            offload_devices,
            drop_invalid: true,
            syn_flood_protect: true,
            table_name: "owr".to_owned(),
        },
    }
}
