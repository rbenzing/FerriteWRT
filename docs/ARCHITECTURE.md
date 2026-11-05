# FerriteWRT architecture

FerriteWRT is router firmware for devices that OpenWrt supports. It reuses the OpenWrt
tree only for what cannot sensibly be rewritten (the Linux kernel, its drivers, the boot
chain and image packaging) and replaces OpenWrt's entire C userspace control plane with
Rust. Hardware differences live in data (`boards/<id>.toml` plus a short build config),
not in code; the reference board is the GL.iNet Flint 2 (GL-MT6000, MediaTek MT7986A).
Adding a router is described in [PORTING.md](PORTING.md).

## Scope boundary (what is Rust, what is kept)

| Layer | OpenWrt component | FerriteWRT | Reason |
|---|---|---|---|
| Kernel + drivers (per board: Wi-Fi, Ethernet, DSA switch, crypto engine) | Linux 6.18 (C) | kept, built from pinned OpenWrt tree with hardened diffconfig | not portable |
| Boot chain | vendor bootloader (BL2 / BL31 / U-Boot on the reference board) | kept, unmodified | not portable |
| PID 1 / service supervision / hotplug | procd, ujail | **owr-init** | |
| IPC bus | ubus, ubusd, libubox, rpcd | removed: single process, typed in-process API | less attack surface |
| Configuration | uci (/etc/config/*) | **owr-config** (TOML, typed, versioned, atomic) | |
| Network | netifd | **owr-net** (rtnetlink, declarative plan/diff/apply) | |
| Firewall | firewall4 + ucode templates | **owr-fw** (typed ruleset -> nft text); `nft` CLI kept to load it | pure-Rust nf_tables is phase 3 |
| Wi-Fi | wifi-scripts + hostapd | **owr-wifi** renders hostapd.conf; hostapd (C) kept and supervised | hostapd rewrite is out of scope |
| DHCPv4/DNS | dnsmasq | kept, config rendered by Rust; owr-dns (phase 2) | |
| PPPoE WAN | netifd ppp proto + pppd | pppd (C) kept, options rendered by **owr-apply**, supervised and confined by owr-init | IPv4 only |
| IPv6 RA/DHCPv6 | odhcpd | **owr-apply netd** (router advertisements: SLAAC prefix + RDNSS; no DHCPv6 server), also runs the WAN DHCPv4 client of **owr-net** | DHCPv6-PD client for WAN IPv6 is phase 2 |
| Web UI + API | uhttpd + LuCI (Lua/JS) + rpcd ACLs | **owr-api** (axum, rustls, argon2id, RBAC, CSRF) + embedded static UI | |
| Logging | logd/ubox | owr-init journal (bounded ring buffer + persistent) | |
| Storage/mounts | fstools (block, mount_root) | owr-init mounts (squashfs rootfs + f2fs/ext4 overlay on a GPT partition) | UBI is planned |
| Upgrade | sysupgrade + fwtool | **owr-upgrade** (verify the signed release bundle, write kernel + rootfs, keep settings); run by owr-init | single slot: the reference board has no second kernel/rootfs partition |
| Shell | busybox ash | busybox kept for rescue console only; no shell in the control plane | phase 2 removal |
| SSH | dropbear | optional, off by default; phase 2: russh | |
| Package manager | opkg/apk | none: immutable, signed image | security |

## Crate map

```
crates/
  owr-common   atomic file writes, well-known paths                                 (pure)
  owr-board    board descriptor schema (boards/*.toml), loader, validation          (pure)
  owr-config   typed system config, defaults derived from board, atomic store       (pure)
  owr-fw       firewall domain model -> nft ruleset text; applier (nft -f)          (pure + linux)
  owr-wifi     wifi domain model -> hostapd.conf; radio/phy discovery               (pure + linux)
  owr-net      network plan model; planner (desired vs. observed); rtnetlink apply;
               DHCPv4 client; IPv6 router advertisements                            (pure + linux)
  owr-init     PID 1: mounts, uevent, services, sandbox launcher, reaping, journal,
               watchdog, upgrade writes, shutdown                                   (pure + linux)
  owr-api      HTTPS API + embedded UI, auth, sessions, RBAC, audit log             (pure + linux)
  owr-apply    maps owr-config -> fw/wifi/net plans and drives appliers; the
               network daemon `owr-apply netd` (WAN DHCP client, router adverts)    (pure + linux)
  owr-upgrade  release signature contract, sysupgrade reader, verify + write plan   (pure)
  owr-cli      `owr` binary: board, config, render, check, status, upgrade, release (bin)
build/
  openwrt/common.diffconfig    OpenWrt config shared by every board (hardening, removed services)
  openwrt/<board>.diffconfig   the board's device selection, drivers and firmware
  openwrt/kernel-*.fragment    kernel hardening (shared) and per-OpenWrt-target options
  rootfs-overlay/              files synced into <openwrt>/files, i.e. into the image
  Dockerfile, build-image.sh   reproducible Linux build (Windows host uses Docker)
boards/<profile>.toml          one file per supported router, named by OpenWrt profile
scripts/openwrt-device-facts.sh  everything OpenWrt knows about one device, for porting
```

Dependency direction is strictly downward: the programs (`owr-cli`, `owr-api`, `owr-init`)
-> `owr-apply`, `owr-upgrade` -> `{fw,wifi,net,config}` -> `board` -> `common`. `owr-api`
and `owr-cli` also use `owr-init` as a library, for the client side of its control socket.
Domain crates (fw, wifi, net) do **not** depend on owr-config; they expose their own
plan types and owr-apply does the mapping. This keeps each crate locally reasonable
and independently testable.

## Non-negotiable engineering rules

1. `#![forbid(unsafe_code)]` in every crate (workspace lint). No C or asm in the
   dependency graph of target binaries (deny.toml bans ring, aws-lc, openssl, cc).
2. Everything that mutates system state is **declarative and idempotent**: build the
   desired state, observe current state, compute a diff, apply only the diff. Running
   apply twice is a no-op the second time. Appliers return the diff they applied.
3. **Atomic persistence**: write to a temp file in the same directory, fsync, rename,
   fsync the directory (`owr_common::atomic_write`). Config carries a `schema` version
   and migrations are explicit.
4. **Fail observable**: typed errors (`thiserror`), `tracing` spans on every apply step,
   never `unwrap`/`expect`/`panic` outside tests (clippy deny). Release builds keep
   overflow checks on and abort on panic.
5. Linux-only code lives behind `#[cfg(target_os = "linux")]` modules so that all pure
   logic compiles and is tested on any host. Pure logic is the majority by design.
6. Memory: no unbounded buffers from untrusted input (request body limits, bounded
   journal ring, bounded netlink dumps). Secrets in `Zeroizing<_>`. Constant-time
   comparisons for tokens (`subtle`).
7. Security defaults: WAN input dropped, management API bound to LAN only, HTTPS only
   (self-signed cert generated on first boot, pinnable), argon2id passwords, session
   cookies `Secure; HttpOnly; SameSite=Strict`, CSRF double-submit token, rate limiting
   on auth, audit log for every mutating call, no default password (first-boot setup
   forces one, enforced strength).

## Board model (owr-board)

`boards/<id>.toml` is the single source of truth about the hardware (see
`boards/glinet_gl-mt6000.toml`). The runtime reads `/etc/ferritewrt/board.toml`
(installed from the same file). Adding a router = new TOML + new diffconfig + one
registration line, plus a `kernel-<target>.fragment` for the first board of a new OpenWrt
target; no Rust logic changes for an aarch64 board with eMMC/SD storage. Repository
tests keep the board files, their registration and their build configs consistent.
Procedure and field sources: [PORTING.md](PORTING.md).

## Config model (owr-config)

`/etc/ferritewrt/config.toml`, schema-versioned. Sections: `system` (hostname, timezone,
ntp, log), `users` (argon2id hashes, roles), `network` (ports -> bridges/VLANs, WAN
proto dhcp/static/pppoe, LAN static + DHCP pool, IPv6), `wireless` (per radio: channel,
width, country; per AP: ssid, WPA2/WPA3-SAE, isolation), `firewall` (zones, policies,
forwardings, port forwards, rules), `dhcp` (static leases, DNS options), `services`
(ssh, api bind). Defaults are derived from the board (e.g. every `role = "lan"` port
joins `br-lan`). Validation is total: a config is either fully valid or rejected with
field-path errors.

## Runtime (owr-init)

Boot: the kernel runs `/sbin/init`, a symlink to `owr-init` that replaces procd's ->
mount proc/sys/dev/run -> mount overlay (`PARTLABEL=rootfs_data`, f2fs, create on first
boot; skipped when `/` is a RAM filesystem, i.e. the initramfs test image) -> load board +
config -> start journal -> netlink uevent listener (coldplug) -> `owr-apply boot`
(network, firewall, wifi, daemon configs) -> supervise services (hostapd per radio and
dnsmasq, both confined by `owr-init --sandbox`; `owr-netd`; `owr-api`) with exponential
backoff -> pet `/dev/watchdog`. Buttons/LEDs are driven from board roles. Shutdown:
SIGTERM services, sync, unmount, reboot/poweroff; a firmware upgrade is written at this
point, after every service has stopped.

## Build/image

The OpenWrt tree at the pinned commit builds kernel + modules + kept C daemons from
`build/openwrt/common.diffconfig` followed by `build/openwrt/<board>.diffconfig`, with the
kernel fragments merged last (hardening on: STACKPROTECTOR_STRONG, ARM64_PTR_AUTH,
ARM64_BTI for userspace, INIT_ON_ALLOC, SECCOMP, SECURITY+LANDLOCK+YAMA, DEBUG_LIST, no
DEVMEM/KCORE/KEXEC).
Every line of both is verified against the expanded configs. The Rust binaries are
cross-built for `aarch64-unknown-linux-musl` (static) and staged into `<openwrt>/files`.
Output per board: the `.bin` images OpenWrt builds for it (factory, sysupgrade,
initramfs). Details: [BUILD.md](BUILD.md).

Convention: any test that uses `insta` must have `snapshot` in its name; `scripts/linux-tests.sh`
skips those on Linux because snapshot paths are compiled in from the host.
