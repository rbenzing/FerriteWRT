# owr-net

Declarative network configuration for FerriteWRT (replaces netifd). Pure planner on
any host; rtnetlink applier and `DHCPv4` client on Linux only.

## Model

- `NetPlan` (desired): `links` (`Bridge`, `Vlan`, `Physical`), `addresses`, `routes`,
  `dhcp_clients`, `sysctls`. `NetPlan::validate()` checks names, bridge/vlan rules,
  port uniqueness, address/route/dhcp references and sysctl keys.
- `Observed` (kernel): links, permanent addresses, main-table unicast routes, and the
  current value of each desired sysctl.
- `plan(&desired, &observed) -> Vec<Action>` is pure and deterministic.
- `owr-net` does not depend on `owr-config`; `owr-apply` maps config into `NetPlan`.

## Planner guarantees

- **Idempotent**: applying the actions and planning again yields `[]` (property-tested
  with an in-memory kernel simulator, including arbitrary plan-to-plan transitions).
- **Never deletes** physical links, foreign bridges / VLANs (a docker `br-<hex>` or a
  dotted VLAN made by someone else), kernel-protocol routes, IPv6 link-local
  addresses, routes of other protocols (e.g. RA), or anything on unmanaged links.
  Only bridges / VLANs carrying the interface alias `owr` (`IFLA_IFALIAS`, set by
  `Action::SetAlias` right after the planner creates a link, and on adoption of an
  existing link named in the plan) that are absent from the plan are deleted.
- Order: global sysctls (`conf/all` before anything per-interface), VLAN re-creation,
  bridges (+ alias), VLANs (+ alias), masters, MTU/MAC (link down for MAC; routes of a
  link set down count as flushed and are re-added), up/down, per-interface sysctls
  (`conf/<if>/...` need the link), addresses (delete then add), routes (delete then
  add), link deletion. A per-interface sysctl for a link that is being deleted is not
  an action.
- A missing physical link or bridge port is `PlanError::MissingLink`, not a guess; a
  port / VLAN parent that the plan deletes is `PlanError::ReferencesObsolete`.
- Route destinations must be network addresses (no host bits). MTU / MAC are not set
  on links that report none (MTU 0, no hardware address).
- Sysctl keys are allow-listed: `net/`, `vm/`, and a few kernel / fs hardening keys.
- `linux::apply` re-checks that a link is a bridge or VLAN right before deleting it,
  and reports `EEXIST` on a route add as a failure (never as success).

## DHCP client (`dhcp`, `wire`; socket in `linux::dhcp`)

```text
 INIT --DISCOVER (bcast, backoff 4..64s)--> SELECTING --OFFER--> REQUESTING
  ^                                                                 | ACK
  |  NAK / timeout                                                  v
  +-----------------------------------------------------------------+--> BOUND
  |  (emit Lost on NAK / expiry)        T1: unicast REQUEST to server  |
  +<---- REBINDING <--T2, no reply-- RENEWING <------------------------+
          (bcast, until expiry)         ACK -> BOUND, emit Renewed
```

`wire` is a hand-written, bounds-checked codec (messages up to 1500 bytes, repeated
options concatenated per RFC 3396, option 121 supported, fuzzed with proptest). `dhcp::run_with` is generic over `Transport`, so the
state machine is tested with a fake network and paused tokio time.
Replies are accepted only for our xid / MAC; in REQUESTING and RENEWING also only from
the selected server (REBINDING: any server, but a server id is required), an ACK must
confirm the requested address, and a NAK needs a server id. Leases with a prefix
outside /8../30 or an unusable address are rejected; an unusable router is dropped.
Events are never dropped: the client waits for the consumer (or shutdown).

`dhcp::dhcp_link_sysctls(link)` returns `net/ipv4/conf/<link>/rp_filter = 2`: before
the lease the link has no address, and strict reverse-path filtering can drop the
server's reply to the broadcast DISCOVER. The owner (owr-apply) adds it to
`NetPlan::sysctls` for every DHCP link.

## Single-writer rule

Only `linux::apply` / `linux::converge` mutate links, addresses, routes and sysctls.
The DHCP client never touches the interface: it emits `DhcpEvent::{Bound, Renewed,
Lost}`. The owner merges the lease (`dhcp::merge_lease`, which adds the address and
`proto dhcp` routes to a copy of the plan) and calls `converge`, which is
observe, plan, apply, observe, verify-empty (`NetError::NotConverged` otherwise).
`plan` accepts such merged plans; only the user-intent `validate()` rejects a static
IPv4 address on a DHCP link.

## Limits

Every netlink request, dump and procfs access has a 5s timeout; dumps stop at 4096
entries. Gateways outside the leased subnet (needs `onlink`) and DHCP option overload
are not supported. No ARP probe is done before binding.
