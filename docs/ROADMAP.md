# Roadmap

## Phase 1 (this repository state): Rust control plane, OpenWrt kernel
- Board descriptor + validation, typed config, planners/renderers for network, firewall
  and Wi-Fi, PID 1 supervisor, HTTPS API + UI, image build definitions.
- Kept C daemons: hostapd, nft, dnsmasq, odhcpd, odhcp6c, ppp, busybox (rescue),
  e2fsprogs/f2fs-tools, uboot-envtools, fitblk.
- Exit criteria: initramfs image boots on a Flint 2 via U-Boot TFTP, LAN bridge +
  DHCP + NAT + both radios work, UI reachable at https://192.168.8.1.

## Phase 2: shrink the C surface, finish upgrade path
- `owr-upgrade`: verify signed sysupgrade images (ed25519), write kernel/rootfs eMMC
  partitions, preserve `/etc/ferritewrt`, A/B boot counter via U-Boot env.
- Replace odhcpd with Rust RA/DHCPv6 (in `owr-net`); replace dnsmasq with a Rust
  DHCPv4 server + forwarding resolver (`owr-dns`, hickory-based).
- Drop busybox from the production image (rescue shell only in initramfs image).
- Optional SSH via `russh`, key-only.
- Patch OpenWrt `base-files` so procd/ubus/uci are not installed at all.
- Landlock + seccomp sandboxes for the kept daemons, applied by `owr-init`.

## Phase 3: nf_tables over netlink, more boards
- Pure-Rust nf_tables netlink applier (remove the `nft` binary).
- nl80211 client for radio status/survey (remove dependence on hostapd ctrl for RF info).
- Second board descriptor (another Filogic 830/880 device) to prove the porting path.
