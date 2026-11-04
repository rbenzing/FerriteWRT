# Roadmap

Current state and the next hardware step are in [STATUS.md](STATUS.md).

## Phase 1: Rust control plane, OpenWrt kernel
- Done: board descriptor + validation, typed config, planners/renderers for network,
  firewall and Wi-Fi, PID 1 supervisor, HTTPS API + UI, OpenWrt image build.
- Done: tag-driven releases (CI-built images, `SHA256SUMS` signed with ed25519, build
  provenance attestations); first published release v0.2.0.
- Done: porting path for other OpenWrt routers (`docs/PORTING.md`,
  `scripts/openwrt-device-facts.sh`, `/ferrite-forge`, per-board CI config check).
- Kept C daemons: hostapd, nft, dnsmasq, odhcpd, odhcp6c, ppp, busybox (rescue),
  e2fsprogs/f2fs-tools, uboot-envtools, fitblk.
- **Open exit criteria:** initramfs image boots on a Flint 2 via U-Boot TFTP, LAN bridge +
  DHCP + NAT + both radios work, UI reachable at https://192.168.8.1.

## Phase 2: shrink the C surface, finish upgrade path
- `owr-upgrade`: verify signed sysupgrade images (ed25519), write kernel/rootfs eMMC
  partitions, preserve `/etc/ferritewrt`, A/B boot counter via U-Boot env.
- Replace odhcpd with Rust RA/DHCPv6 (in `owr-net`), which also makes IPv6 on the LAN work;
  replace dnsmasq with a Rust DHCPv4 server + forwarding resolver (`owr-dns`, hickory-based).
- Render PPPoE WAN (modelled in the config, not rendered).
- Position-independent Rust binaries: rustc does not link static-PIE for
  `aarch64-unknown-linux-musl`, so build them inside the image build as dynamic PIEs against
  the image's musl (see STATUS.md).
- Drop busybox from the production image (rescue shell only in initramfs image).
- Optional SSH via `russh`, key-only.
- Patch OpenWrt `base-files` so procd/ubus/uci are not installed at all.
- Landlock + seccomp sandboxes for the kept daemons, applied by `owr-init`.

## Phase 3: nf_tables over netlink, more boards
- Pure-Rust nf_tables netlink applier (remove the `nft` binary).
- nl80211 client for radio status/survey (remove dependence on hostapd ctrl for RF info).
- Lift the porting limits in `docs/PORTING.md`: NAND/UBI storage, 32-bit ARM, non-`.bin`
  images; a release matrix that builds every board in `boards/`.
- Second board in the tree to prove the porting path on hardware.
