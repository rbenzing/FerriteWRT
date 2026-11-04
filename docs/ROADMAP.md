# Roadmap

Current state and the next hardware step are in [STATUS.md](STATUS.md).

## Phase 1: Rust control plane, OpenWrt kernel
- Done: board descriptor + validation, typed config, planners/renderers for network,
  firewall and Wi-Fi, PID 1 supervisor, HTTPS API + UI, OpenWrt image build.
- Done: tag-driven releases (CI-built images, `SHA256SUMS` signed with ed25519, build
  provenance attestations); first published release v0.2.0.
- Done: porting path for other OpenWrt routers (`docs/PORTING.md`,
  `scripts/openwrt-device-facts.sh`, `/ferrite-forge`, per-board CI config check).
- Kept C daemons: hostapd, nft, dnsmasq, odhcp6c, ppp, busybox (rescue),
  e2fsprogs/f2fs-tools, uboot-envtools, fitblk.
- **Open exit criteria:** initramfs image boots on a Flint 2 via U-Boot TFTP, LAN bridge +
  DHCP + NAT + both radios work, UI reachable at https://192.168.8.1.

## Phase 2: shrink the C surface, finish upgrade path
- Done (untested on hardware): `owr-upgrade` verifies the signed release bundle, init
  writes kernel and rootfs with read-back and keeps `/etc/ferritewrt`; `owr upgrade` and
  the web UI start it. Single slot: the reference board has one kernel and one rootfs
  partition, so recovery from a failed write is the bootloader's. A/B with a U-Boot boot
  counter needs a repartitioned layout and is not planned for the Flint 2.
- Done (untested on hardware): odhcpd replaced by the network daemon `owr-apply netd`
  (service `owr-netd`): router advertisements in `owr-net` (SLAAC prefix + RDNSS on every
  LAN-side bridge with a ULA /64) and the WAN DHCPv4 client, which until then no process
  started. No DHCPv6 server: RDNSS covers DNS for current Windows, macOS, iOS, Android and
  Linux clients.
- WAN IPv6: a DHCPv6 client with prefix delegation (replaces the unused `odhcp6c`), global
  /64s on the LAN bridges, the router as IPv6 default gateway, forward rules for IPv6.
- Replace dnsmasq with a Rust DHCPv4 server + forwarding resolver (`owr-dns`, hickory-based).
- Render PPPoE WAN (modelled in the config, not rendered).
- Position-independent Rust binaries: rustc does not link static-PIE for
  `aarch64-unknown-linux-musl`, so build them inside the image build as dynamic PIEs against
  the image's musl (see STATUS.md).
- Drop busybox from the production image (rescue shell only in initramfs image).
- Optional SSH via `russh`, key-only.
- Patch OpenWrt `base-files` so procd/ubus/uci are not installed at all.
- Done (untested on hardware): Landlock + seccomp + capability bounding for dnsmasq and
  hostapd, applied by `owr-init --sandbox`. Next: confine `owr-api`, `owr-apply` and the
  network daemon `owr-netd` (need network administration and config writes; best done
  with a separate uid and narrower socket permissions).

## Phase 3: nf_tables over netlink, more boards
- Pure-Rust nf_tables netlink applier (remove the `nft` binary).
- nl80211 client for radio status/survey (remove dependence on hostapd ctrl for RF info).
- Lift the porting limits in `docs/PORTING.md`: NAND/UBI storage, 32-bit ARM, non-`.bin`
  images; a release matrix that builds every board in `boards/`.
- Second board in the tree to prove the porting path on hardware.
