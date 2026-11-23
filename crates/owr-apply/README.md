# owr-apply

Turns `(Board, Config)` into the domain plans of `owr-net`, `owr-fw` and `owr-wifi`, renders
the configs of the kept daemons (dnsmasq, hostapd) and, on Linux, drives the appliers and runs
the network daemon (`netd`: WAN DHCPv4 and DHCPv6 prefix-delegation clients, IPv6 router
advertisements).
`build_plans` is pure and deterministic (host-tested); `run` is Linux only.

```
owr-apply boot|apply [--board P] [--config P]   # Linux; prints the JSON ApplyOutcome
owr-apply render --what net|fw|wifi|dnsmasq|netd|pppoe [--board P] [--config P]   # any OS
owr-apply check [--board P] [--config P]        # validate_against(board) + mapping
owr-apply --log info netd [--board P] [--config P]   # Linux; runs until SIGTERM (service owr-netd)
```

`boot` creates the default config on first start, `apply` never does; both validate the config against
the board (`Store::load_for`). `render` and `check` are strictly read-only: they read the file
(or use the board defaults when it does not exist),
parse it with `Config::from_toml_str` (migration happens in memory), run `validate_against(board)`
and never write anything back (`Store::load` would chmod and rewrite the file). On other OSes
`boot`, `apply` and `netd` exit 2. `render --what wifi` prints the plan as JSON with passphrases replaced
by `***`.

Exit codes: 0 on success, also when there are warnings (printed to stderr as `warning: ...`);
1 on any error. A failed `apply` that got part-way still prints the JSON outcome reached so far
on stdout, so the supervisor can restart the daemons whose files changed.

## Mapping

| config | plan |
|---|---|
| every board port | `Physical{up}` (DSA user ports must be up) |
| `network.lan.ports` | `br-lan` (`vlan_filtering=false`) + `ipv4` as address; fw zone `lan` |
| `network.wan` port, `mac_override`, `mtu` | `Physical` on the port netdev; fw zone `wan` |
| wan `dhcp` | `DhcpClientSpec` (hostname, DNS, default route metric 10) and `owr_net::dhcp::dhcp_link_sysctls` (loose `rp_filter` on the WAN netdev) |
| wan `static` | address + default route via gateway (metric 10, proto static) |
| `network.vlans[]` | `br-<name>` + `Vlan{<port netdev>.<id>}` per port, bridged; zone `<name>` |
| vlan `isolated` | input drop except udp 67-68, tcp/udp 53, icmp; no `vlan -> lan` forwarding |
| vlan not `isolated` | **trusted**: full router input and `vlan -> lan` forwarding. The one exception: tcp to `services.api.port` is dropped (rule `<vlan>-api-block`) unless `services.api.bind = lan_and_vlans` |
| (always) | `lan -> wan`, `<vlan> -> wan`, `lan -> <vlan>` |
| `firewall.*` | `default_wan_input`, `hw_offload` (wan + lan ports + vlan netdevs), port forwards -> `Redirect` from `wan`, `wan_in` rule -> input rule, `lan_out` rule -> lan to wan |
| `wireless` radio + AP | `RadioPlan` per enabled radio with APs: `phy<N>`, `wlan<N>`, `wlan<N>-<k>`, bridge `br-lan` or `br-<vlan>` |
| `dhcp`, pools, leases | `dnsmasq.conf`; pool = network + `start` .. + `limit`, must fit and exclude the router |
| `network.wan.ipv6 = dhcpv6` | `NetdPlan.dhcp6` (`Dhcp6ClientSpec`: on the WAN port, or on `pppoe-wan` identified by the port's hardware address), `NetdPlan.pd_links` (`br-lan` is subnet 0 of the delegated prefix, a VLAN bridge the subnet of its VLAN id, as with the ULA), `accept_ra = 2` on the WAN port so the kernel uses the ISP's router advertisements (WAN address, default route) although it forwards; on `PPPoE` `default.accept_ra = 2` and `0` on every LAN-side bridge (the interface does not exist yet), and `+ipv6` in pppd's options |
| `network.lan.ipv6 = ula` | with a ULA prefix (below) `<prefix>::1/64` on `br-lan` and `<prefix>:<vlan id>::1/64` on every VLAN bridge, each advertised by `netd` (`NetdPlan.ra`: the /64, the router address as RDNSS) |
| fixed list | sysctls (forwarding, rp_filter, syncookies, kptr/dmesg/bpf/ptrace hardening) |

## ULA prefix

`build_plans` is pure and has no ULA prefix: with `lan.ipv6 = ula` it plans no IPv6 address and
records a warning in `Plans.warnings`. `build_plans_with(board, cfg, &Inputs)` takes the prefix
(`Inputs.ula_prefix`, a /48) and `Inputs.run_dir` (where dnsmasq keeps its lease and pid
files, default `/run/ferritewrt`). `run::apply_all` and `on_dhcp_lease` load the prefix from
`Paths.ula_file` (`/etc/ferritewrt/ula-prefix`, persistent) or create it: `fd00::/8` plus 40 random
bits from `/dev/urandom` (`ula::load_or_create`); a malformed file is replaced with a warning.

Values that reach dnsmasq (hostnames, domain, interface names) must match `[A-Za-z0-9._-]+`,
otherwise `MapError::Injection` (the value is never echoed). Static-lease hostnames that dnsmasq would
read as something else in a `dhcp-host` line (digits only, `[0-9]+[hmd]`, `ignore`, `infinite`;
case-insensitive) are rejected with `MapError::ReservedName`. The run directory written into the
configs must be an absolute path of `[A-Za-z0-9._/-]`. dnsmasq serves DNS on every VLAN bridge;
`dhcp-range` only for those with DHCP. No `user=` line is emitted, so
dnsmasq runs as its compiled-in default user, which the image must contain; `conf-dir` is unused.

## Files in `/run/ferritewrt` and restart semantics

| file | daemon | on change |
|---|---|---|
| `hostapd-<phy>.conf` (0600) | hostapd per radio | restart that radio's hostapd |
| `pppoe-wan.conf` (0600, PPPoE WAN only) | pppd | restart `pppoe-wan`; removed when the WAN is no longer PPPoE, which stops pppd |
| `resolv.conf.ppp` | written by pppd (`/etc/ppp/resolv.conf` links here), created empty first | none, dnsmasq re-reads it |
| `dnsmasq.conf` | dnsmasq | restart dnsmasq |
| `netd.json` | `owr-apply netd` (a view: the daemon derives the same plan from the config) | restart `owr-netd` |
| `resolv.conf.auto` | dnsmasq `resolv-file` | none, dnsmasq re-reads it |

## `apply_all` sequence

The pure list is `steps::apply_steps(plans)`; `run` only executes it:

1. hostname
2. **bootstrap firewall**: the final ruleset with `flow_offload = Off` (no flowtable, the only part
   that needs the devices to exist; `iifname { ... }` set literals do not), loaded from
   `<run_dir>/fw-bootstrap/` so its script and marker do not disturb the final ruleset's
   "already loaded" check. From here on `forward` has `policy drop`.
3. network converge (links, addresses, routes, every sysctl **except forwarding**)
4. final firewall (`nft -f`, with offload)
5. forwarding sysctls (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`), written directly
6. hostapd and dnsmasq configs, `netd.json`

Forwarding is never switched on before a ruleset with `policy drop` on forward is loaded. If a
firewall step fails, both forwarding sysctls are set to 0, the error is logged, whatever ruleset is
loaded (the bootstrap one at worst) stays loaded, and `apply_all` returns `ApplyError::Fw`.
`on_dhcp_lease` never touches forwarding.

Failed network actions are warnings, except security-relevant sysctls (`rp_filter`,
`accept_redirects`, `send_redirects`, `kptr_restrict`, `dmesg_restrict`,
`unprivileged_bpf_disabled`, `bpf_jit_harden`, `ip_forward`) and link/address actions on the WAN
netdev, `br-lan` and its ports: those return `ApplyError::CriticalNet`. Sysctls missing from the
running kernel are skipped with a warning (they could never converge); per-interface keys of links
that do not exist yet are kept.

An error while applying is `ApplyError::Partial { outcome, source }`: `outcome` is what had been
changed (`ApplyError::partial_outcome()`), so a caller can still restart daemons whose files
changed. It returns which pieces changed (`hostapd_changed`, `dnsmasq_changed`, ...).


## WAN IPv6 (DHCPv6 prefix delegation)

With `network.wan.ipv6 = dhcpv6` the network daemon runs the `owr-net` `DHCPv6` client
(`NetdPlan.dhcp6`) and a router advertisement sender for every bridge with a share
(`NetdPlan.pd_links`: `br-lan` is /64 number 0 of the delegation, a VLAN bridge the /64 whose
number is its VLAN id; a delegation too small leaves later bridges without, see `pd::assign`).

- **Lease**: `on_dhcp6_lease` persists the delegation as `<run_dir>/lease6-<link>.json` (0600,
  tmpfs), merges it with the `DHCPv4` lease (`net_with_leases`: a converge for one never removes
  what the other set) so every bridge gets `<its /64>::1/64`, converges, and publishes the DNS
  servers of both leases to `resolv.conf.auto` (IPv4 ones first; a lease without any keeps the
  file). `apply_all` merges a persisted delegation that has not expired (the shortest valid
  lifetime). `on_dhcp6_lost` forgets it and converges without the addresses.
- **Advertisements**: after the addresses are in, each sender is given its share
  (`pd::ra_dynamic`: the /64 with the lifetimes left, the router address on it as RDNSS), so
  hosts get a global address and the router as IPv6 default gateway. A renewal only refreshes
  the lifetimes the sender counts down from; a new or lost prefix wakes it
  (`pd::needs_advertising`). A lost delegation is advertised once with lifetimes of 0
  (`pd::ra_withdrawn`). A persisted delegation seeds the senders when the daemon starts, so a
  restart does not withdraw the router.
- **WAN side**: the kernel does SLAAC and the default route from the ISP's router advertisement
  (`accept_ra = 2`, see the mapping table). The client uses the WAN port; over `PPPoE` it uses
  `pppoe-wan` and takes its DUID from the physical port (PPP has no hardware address).
## Idempotence and DHCP leases

`apply_all` twice with the same config reports nothing changed. That includes a DHCP WAN:
`on_dhcp_lease` persists the lease as JSON in `<run_dir>/lease-<link>.json` (0600, tmpfs) before
converging, and `apply_all` merges a persisted lease that has not expired
(`obtained_at + lease_secs > now`, infinite leases never expire) into the plan with
`owr_net::dhcp::merge_lease`; without that the second run would delete the lease's address and
routes. `on_dhcp_lease` publishes only usable DNS servers (not `0.0.0.0`, loopback, multicast,
broadcast) to `resolv.conf.auto`; a lease without any keeps the previous file (warning).

## Known gaps

- **Trusted VLANs**: a VLAN with `isolated = false` is trusted (full router input, forwarding to the
  LAN). Only the management API port is blocked from it (see Mapping).
- **Hostname enumeration**: dnsmasq is one resolver for all networks, so a client in an isolated
  guest VLAN can query the names of LAN hosts. Per-network views need owr-dns (phase 2).
- **mt76 quirk**: chosen by `board.wifi.driver` in a fixed list (`mt7915e`, `mt7996e`, `mt7921e`,
  `mt7615e`, `mt7603e`, `mt76x2e`); a field in the board descriptor is the later improvement.
- **Without `wan.ipv6 = dhcpv6` IPv6 is LAN-only (ULA)**: router advertisements carry router
  lifetime 0, so hosts do not use the router as IPv6 default gateway. No `DHCPv6`
  server: DNS is announced with RDNSS only.
- **netd and apply race**: a lease converge in `netd` and an `apply` from the API can overlap.
  `netd` reloads the config for every lease event, and the API restarts `owr-netd` when
  `netd.json` changes, so both converge toward the saved config.
- **WAN IPv6 needs the firewall rules** that are still to come: the `DHCPv6` replies and the ISP's
  router advertisements arrive on the WAN as input, and forwarding between the LAN and the WAN
  is IPv4 only in the rulesets, so until then the prefix is delegated and advertised but not
  usable end to end. Not run against an ISP yet (also not over `PPPoE`).
- The WAN address is the kernel's SLAAC address from the ISP's advertisement (no `IA_NA`); an ISP
  that requires a `DHCPv6` address is not served.
- Hostapd configs of radios removed from the config stay in `/run` until reboot; the supervisor
  starts only the radios listed in `hostapd_changed`.
