# Project status (2026-11-23)

Where FerriteWRT stands and what the next hardware session must do. Read this before
touching a router.

## Resume here

- **Released:** v0.2.1 (latest stable) and **v0.3.0-rc.1** (GitHub pre-release, the image
  for the first hardware boot: signed upgrades, confined daemons, the Rust network daemon,
  the `/sbin/owr-api` fix). Its downloads were checked with `owr release verify` and
  `owr upgrade --check`.
- **On `main` since rc.1** (see `CHANGELOG.md` `[Unreleased]`): firewall rulesets loaded
  into a real kernel in CI; PPPoE WAN (pppd options, confined `pppoe-wan` service); init
  fixes for sandboxed device ioctls and for restarting a service whose config is gone.
  Dependency updates through Dependabot (`.github/dependabot.yml`, netlink crates grouped) and
  CodeQL on GitHub's default setup. WAN IPv6 is built: the DHCPv6
  prefix-delegation client, the advertisements that carry the prefix, the `owr-apply`
  integration and a firewall that already served IPv6 are in and tested (virtual time, veth
  pairs, a real-kernel ruleset load in CI); nothing has run against an ISP. CI had been red
  since Rust 1.100 (new clippy lint) and a `cargo deny` advisory, both fixed.
- **Waiting on the owner:** boot the v0.3.0-rc.1 initramfs image on the Flint 2 with the
  checklist below. If it works, release v0.3.0 (`docs/VERSIONING.md`); anything that
  fails is fixed and shipped as the next `-rc.N`. Optionally cut an rc.2 first so the
  boot also covers PPPoE.
- **Next work without hardware**: little is left that can be proven without a router. Confining
  `owr-api` needs privilege separation first (ROADMAP, phase 2); the rest of the open list is
  large (a Rust DHCP/DNS server, dropping busybox) or hardware-bound.
- **Housekeeping:** delete the dead tags `v0.1.0`/`v0.1.1` (no release behind them); add
  a "do not boot the initramfs image" note to the v0.2.0 release; the follow-ups below.

## What exists and is verified

| Area | Verified how |
|---|---|
| Board descriptor (`boards/glinet_gl-mt6000.toml`) | Parsed + cross-validated by `owr-board` tests; values traced to the OpenWrt DTS and image recipe |
| Typed config (`owr-config`) | Unit tests incl. proptests; secrets never echoed in parse errors; argon2 params bounded |
| Firewall renderer (`owr-fw`) | Snapshot tests of the nft ruleset; every CI run loads the rendered rulesets (board defaults plus `build/nft-check/*.toml`: VLANs, port forwards, every custom-rule kind, static WAN, offload on and off) into a real kernel with `nft -f` in a throw-away network namespace (`scripts/check-nft.sh`), after a negative control proves the kernel rejects a bad ruleset; Linux applier tested with a fake `nft`; name allow-list prevents comment injection |
| Wi-Fi renderer + hostapd control client (`owr-wifi`) | Snapshot tests of hostapd.conf; control-socket client tested on Linux against a fake hostapd |
| Network planner + DHCPv4 client (`owr-net`) | Planner proven idempotent by an in-memory kernel simulator and proptest; DHCP codec fuzzed; state machine tested with fake transport |
| PID 1 (`owr-init`) | Host tests on the pure state machines; supervisor smoke-tested in `--test-mode` on Linux (WSL) |
| Daemon sandbox (`owr-init --sandbox`) | Launcher run as root under WSL: capability bounding set, `no_new_privs`, seccomp filter mode and a denied `mount` checked from inside the confined process; Landlock refuses writes outside the profile |
| Upgrades (`owr-upgrade`, `owr upgrade`, UI) | Signature, hash, board, version and image-reader checks unit-tested, including tampered and malformed bundles; the write plan executed against files with read-back; API upload, check and install tested against the mock and the real backend |
| HTTPS API (`owr-api`) | Tests incl. real TLS 1.2/1.3 handshakes, CSRF/RBAC/rate-limit/audit behaviour |
| Web UI | Driven in Chromium via Playwright against the mock backend: setup wizard, dashboard, network, wireless pages |
| Mapping + apply orchestration (`owr-apply`) | Snapshot tests for nft/hostapd/dnsmasq output; apply step order host-tested |
| Network daemon (`owr-apply netd`) | Router advertisements checked byte for byte over a veth pair on Linux (WSL), including the rate-limited answer to a solicitation; shutdown on SIGTERM tested; the DHCP lease hand-off reuses the apply path |
| Cross-compilation | Every binary builds as a static-PIE executable for `aarch64-unknown-linux-musl` with no C toolchain; CI checks the ELF and starts each one under qemu-user (see "Binary hardening") |
| OpenWrt image build | Runs in the release workflow (Docker); kernel and package config checked line by line; every board's config checked on each push |
| Releases | v0.2.0, v0.2.1 and the pre-release v0.3.0-rc.1 published by the release workflow: factory, sysupgrade and initramfs images, `SHA256SUMS` signed with the release key, provenance attestations. Boot v0.3.0-rc.1 first (see below); v0.3.0 is tagged once it works |
| Dependency policy | `cargo deny check` clean: no C/asm crates, permissive licenses, no advisories |

Linux-only code paths are exercised by `scripts/linux-tests.sh` (builds the test
binaries for x86_64 musl and runs them as root inside the WSL `docker-desktop` distro;
a failing test fails the script).

## What is NOT verified yet

- **Nothing has booted on a Flint 2.** The netlink appliers, the nft loader, mounts,
  pivot_root, the watchdog thread, uevent/evdev readers and LED writes are
  compile-checked and reviewed but have never run against a real kernel.
- hostapd.conf has not been checked with a real hostapd (it has no dry-run mode). The nft
  rulesets load in CI, but with Ubuntu's older nft 1.0.x rather than the router's 1.1.7,
  and without `flags offload` (hardware flowtable offload needs the MT7986).
- The network daemon (`owr-netd`) has not run on the router: the WAN DHCP lease, the
  router advertisements on `br-lan` and clients taking a ULA address from them. IPv6 on
  the LAN is ULA only (`network.lan.ipv6 = ula`): hosts get an address and the router as
  DNS server but no IPv6 default route, because there is no WAN IPv6 yet (DHCPv6-PD,
  phase 2).
- PPPoE WAN has not run against an ISP: pppd with the options `owr-apply` renders, its
  sandbox profile, the ISP's DNS servers reaching dnsmasq. IPv6 over PPPoE is not set up.

## Do not boot the v0.2.0 initramfs image

`owr-init` in v0.2.0 decided "initramfs boot" from the absence of `root=` on the kernel
command line. The GL-MT6000 DTS appends `root=PARTLABEL=rootfs rootwait` to every boot,
the initramfs one included, so v0.2.0 would have mounted the router's existing
`rootfs_data` partition and overlaid it. v0.2.1 decides from the filesystem at `/`
(tmpfs after OpenWrt's initramfs `/init`, squashfs on a flash boot) and leaves storage
alone when in doubt. Use v0.2.1 or later; for the first hardware session use v0.3.0-rc.1:
in v0.2.1 owr-init starts the management API from `/usr/bin/owr-api`, which the image does
not contain, so the web UI does not come up.

## First hardware session (initramfs, nothing is written to flash)

Procedure details (U-Boot variables, addresses) are in [BUILD.md](BUILD.md).

1. Download the release, check it: `owr release verify . --pubkey keys/release.pub`
   (or `sha256sum -c SHA256SUMS`).
2. Serial console on the UART header, 115200 8N1. PC at `192.168.1.254` serving
   `ferritewrt-glinet_gl-mt6000-vX.Y.Z-initramfs-kernel.bin` over TFTP, cable in a LAN port.
3. Stop U-Boot, `tftpboot 0x46000000 <file>`, `bootm 0x46000000`.
4. On the console, confirm before anything else:
   - `root filesystem: tmpfs` and `initramfs boot (root filesystem in RAM): data partition
     untouched` in the owr-init log;
   - `grep -E 'f2fs|overlay|mmcblk' /proc/mounts` prints nothing.
   If either is wrong, power off: the next boot returns to whatever is on the eMMC.
5. Then, from the rescue shell: `owr status`, `owr check`,
   `nft -c -f /run/ferritewrt/firewall.nft`, `hostapd -t` style checks of
   `/run/ferritewrt/*.conf`, a LAN client getting a DHCP lease, NAT to the WAN, both
   radios beaconing, the UI at https://192.168.8.1.
   From v0.3.0 the WAN lease comes from `owr-netd`: `owr status` lists it running,
   `/run/ferritewrt/lease-eth1.json` holds the lease, and `/run/ferritewrt/netd.json`
   shows what it runs. With `network.lan.ipv6 = ula`, a LAN client should get an `fd..`
   address and the router's `fd..::1` as DNS server.
   With `network.wan.ipv6 = dhcpv6` on a line that delegates a prefix: `/run/ferritewrt/
   lease6-eth1.json` (`lease6-pppoe-wan.json` on PPPoE) holds the delegation, `br-lan` has
   `<prefix>::1/64`, `ip -6 route` has a default route from the ISP's advertisement, a LAN client
   gets a global address and the router as default gateway, and `ping -6` out works. The
   journal of `owr-netd` names the first thing that is missing (no Advertise, no
   advertisement from the ISP, a refused address).
   From v0.3.0 dnsmasq and hostapd (and pppd on a PPPoE WAN) run confined
   (`owr-init --sandbox`). If one of
   them keeps restarting, its journal (`owr` UI logs, or the console) names the refused
   step or file; `touch /etc/ferritewrt/sandbox.off` and restart it to confirm the sandbox
   is the cause, and report the message so the profile can be fixed.
6. Only after all of step 5 works, flash `factory.bin` (BUILD.md, "Flashing").

Record what failed (console log, `owr status` output) in an issue; each failure is a
patch release.

## Follow-ups queued

- Replace `humantime` (config duration strings, RFC 3339 in `owr release`): RUSTSEC-2026-0542
  marks it unmaintained and `deny.toml` carries the one exception. The replacement must read
  every duration the current config format accepts and write the same strings back.
- The phase 2 list in [ROADMAP.md](ROADMAP.md).
- First upgrade on hardware: from a flashed v0.3.0 or later, upgrade to the next release
  through the UI and through `owr upgrade`; watch the console for the prune, the three
  writes and the reboot, and check that settings survived. Untested so far: the partition
  writes on the eMMC, `mlockall` under the running rootfs, and the GL.iNet U-Boot accepting
  the kernel written this way.

## Binary hardening

The router binaries are **static-PIE** musl executables: no dynamic dependencies, position
independent (ASLR for the executable itself), RELRO, immediate binding and a non-executable
stack. rustc's target spec for `aarch64-unknown-linux-musl` does not enable
`static-position-independent-executables` (the x86_64 musl target does), so a plain build links
a fixed-address `ET_EXEC`. The CI "router binaries" job and `build/build-image.sh` link through
`build/pie/rust-lld`, a wrapper that gives `rust-lld` the line the x86_64 target uses
(`rcrt1.o`, `crtbeginS.o`, `-static -pie --no-dynamic-linker`; it passes through unchanged if
rustc ever does this itself). Every such build runs `scripts/check-binaries.sh`: the ELF type
and program headers, no needed libraries, RELRO and `now`, and each binary started with `--help`
under `qemu-aarch64` (the static-PIE start-up relocates the binary itself, so a wrongly linked
one dies there). The image build runs it again on the binaries inside the finished rootfs. A
plain local `cargo xbuild` is still a fixed-address executable. Not run on the router yet.
