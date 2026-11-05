# owr-fw

Firewall domain model for FerriteWRT that renders to nftables text. It replaces OpenWrt's
firewall4. It does not depend on `owr-config`; `owr-apply` maps configuration into
`Ruleset`.

## Model

`Ruleset { zones, forwardings, rules, redirects, options }` (all serde types).

- `Zone`: validated name (`[a-z0-9_]{1,15}`), netdev interfaces, `input`/`output`/`forward`
  policies, `masquerade`, `mss_clamp`. `forward` is the *intra-zone* policy; inter-zone
  traffic needs a `Forwarding`.
- `Rule`: `src: None` = any interface, `dst: None` = this device (input chain).
- `Redirect`: IPv4 DNAT for tcp/udp, plus the matching `ct status dnat accept`.
- `flint2_default(wan, lan_bridge, lan_ports, hw_offload)` builds the stock layout.

`Ruleset::validate()` returns every `Issue` (unknown zones, duplicate names or
interfaces, bad netdev names, bad port ranges, family mismatches, ...).

## Rendering guarantees

`render(&Ruleset) -> Result<String, RenderError>` validates first, so invalid input never
produces a script. The result is a complete `nft -f` script that starts with
`table inet T` / `delete table inet T`, so loading it replaces only that table, in one
transaction, any number of times. Output is deterministic: interface sets are sorted and
deduplicated, everything else keeps model order. Rule names appear as `# name` lines and
`comment "..."`. Names must match `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$` (nft quoted strings have no
escapes, so anything else is rejected). The per-source SYN-flood meter is rendered only in the
uplink zones' `input_<zone>` chains. Masquerade is IPv4 only.

## Apply (Linux only)

`apply::apply(rs, nft_bin, run_dir)` writes `<run_dir>/firewall.nft` (0600, atomic) and
runs `nft -f` directly (no shell, 10 s timeout, stderr capped at 4 KiB). After success it
stores the script's SHA-256 in `<run_dir>/firewall.applied`. If the script file is
unchanged, the marker matches and `nft list table` confirms the table is still loaded (5 s
timeout), nothing is reloaded and `changed = false`; a table that was flushed meanwhile is
reloaded. The marker lives on tmpfs, so after a reboot the ruleset is always loaded again.
`apply::check` runs `nft -c -f -`.

## Snapshots

Rendering is covered by `insta` snapshots in `src/render/snapshots/`. After an intended
change, regenerate and review the diff:

    INSTA_UPDATE=always cargo test -p owr-fw
