# owr-apply

Turns `(Board, Config)` into the domain plans of `owr-net`, `owr-fw` and `owr-wifi`, renders
the configs of the kept daemons (dnsmasq, odhcpd) and, on Linux, drives the appliers.
`build_plans` is pure and deterministic (host-tested); `run` is Linux only.

```
owr-apply boot|apply [--board P] [--config P]   # Linux; prints the JSON ApplyOutcome
owr-apply render --what net|fw|wifi|dnsmasq|odhcpd [--board P] [--config P]   # any OS
owr-apply check [--board P] [--config P]        # validate_against(board) + mapping
```

`boot` creates the default config on first start, `apply` never does; both validate the config against
the board (`Store::load_for`). `render` and `check` are strictly read-only: they read the file,
parse it with `Config::from_toml_str` (migration happens in memory), run `validate_against(board)`
and never write anything back (`Store::load` would chmod and rewrite the file). On other OSes
`boot` and `apply` exit 2. `render --what wifi` prints the plan as JSON with passphrases replaced
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
| `network.lan.ipv6 = ula` | odhcpd UCI file (RA + DHCPv6 on `br-lan`); with a ULA prefix (below) `<prefix>::1/64` on `br-lan` and `<prefix>:<vlan id>::1/64` on every VLAN bridge |
| fixed list | sysctls (forwarding, rp_filter, syncookies, kptr/dmesg/bpf/ptrace hardening) |

## ULA prefix

`build_plans` is pure and has no ULA prefix: with `lan.ipv6 = ula` it plans no IPv6 address and
records a warning in `Plans.warnings`. `build_plans_with(board, cfg, &Inputs)` takes the prefix
(`Inputs.ula_prefix`, a /48) and `Inputs.run_dir` (where dnsmasq and odhcpd keep lease and pid
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
| `dnsmasq.conf` | dnsmasq | restart dnsmasq |
| `dhcp` (UCI) | odhcpd | restart odhcpd; `owr-init` must link `/etc/config/dhcp` to it |
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
6. hostapd, dnsmasq and odhcpd configs

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
- **odhcpd** reads UCI through libuci and resolves interfaces over ubus, which does not exist
  here. The file carries `interface 'lan'` and `ifname 'br-lan'`; whether the stock daemon binds
  is unverified. Phase 2: replace odhcpd with router advertisements in `owr-net`.
- **PPPoE**: `MapError::Unsupported("pppoe")` (phase 2). `wan.ipv6 = dhcpv6` is ignored (warning).
- Hostapd configs of radios removed from the config stay in `/run` until reboot; the supervisor
  starts only the radios listed in `hostapd_changed`.
