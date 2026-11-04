# Project status (2026-11-04)

Where FerriteWRT stands and what the next hardware session must do. Read this before
touching a router.

## What exists and is verified

| Area | Verified how |
|---|---|
| Board descriptor (`boards/glinet_gl-mt6000.toml`) | Parsed + cross-validated by `owr-board` tests; values traced to the OpenWrt DTS and image recipe |
| Typed config (`owr-config`) | Unit tests incl. proptests; secrets never echoed in parse errors; argon2 params bounded |
| Firewall renderer (`owr-fw`) | Snapshot tests of the nft ruleset; Linux applier tested with a fake `nft`; name allow-list prevents comment injection |
| Wi-Fi renderer + hostapd control client (`owr-wifi`) | Snapshot tests of hostapd.conf; control-socket client tested on Linux against a fake hostapd |
| Network planner + DHCPv4 client (`owr-net`) | Planner proven idempotent by an in-memory kernel simulator and proptest; DHCP codec fuzzed; state machine tested with fake transport |
| PID 1 (`owr-init`) | Host tests on the pure state machines; supervisor smoke-tested in `--test-mode` on Linux (WSL) |
| HTTPS API (`owr-api`) | Tests incl. real TLS 1.2/1.3 handshakes, CSRF/RBAC/rate-limit/audit behaviour |
| Web UI | Driven in Chromium via Playwright against the mock backend: setup wizard, dashboard, network, wireless pages |
| Mapping + apply orchestration (`owr-apply`) | Snapshot tests for nft/hostapd/dnsmasq/odhcpd output; apply step order host-tested |
| Cross-compilation | Every binary builds as a static executable for `aarch64-unknown-linux-musl` with no C toolchain (not PIE, see below) |
| OpenWrt image build | Runs in the release workflow (Docker); kernel and package config checked line by line; every board's config checked on each push |
| Releases | v0.2.0 published: factory, sysupgrade and initramfs images, `SHA256SUMS` signed with the release key, provenance attestations |
| Dependency policy | `cargo deny check` clean: no C/asm crates, permissive licenses, no advisories |

Linux-only code paths are exercised by `scripts/linux-tests.sh` (builds the test
binaries for x86_64 musl and runs them inside the WSL `docker-desktop` distro).

## What is NOT verified yet

- **Nothing has booted on a Flint 2.** The netlink appliers, the nft loader, mounts,
  pivot_root, the watchdog thread, uevent/evdev readers and LED writes are
  compile-checked and reviewed but have never run against a real kernel.
- The nft rulesets have not been checked with a real `nft -c`, nor hostapd.conf
  with a real hostapd.
- IPv6 on the LAN relies on odhcpd, which still needs ubus and is therefore
  non-functional in this image (phase 2).
- PPPoE WAN is modelled in the config but not rendered (phase 2).

## Do not boot the v0.2.0 initramfs image

`owr-init` in v0.2.0 decided "initramfs boot" from the absence of `root=` on the kernel
command line. The GL-MT6000 DTS appends `root=PARTLABEL=rootfs rootwait` to every boot,
the initramfs one included, so v0.2.0 would have mounted the router's existing
`rootfs_data` partition and overlaid it. v0.2.1 decides from the filesystem at `/`
(tmpfs after OpenWrt's initramfs `/init`, squashfs on a flash boot) and leaves storage
alone when in doubt. Use v0.2.1 or later.

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
6. Only after all of step 5 works, flash `factory.bin` (BUILD.md, "Flashing").

Record what failed (console log, `owr status` output) in an issue; each failure is a
patch release.

## Follow-ups queued

- Unify `argon2`/`password-hash` on 0.6 (digest 0.11) to drop duplicate crate versions.
- The phase 2 list in [ROADMAP.md](ROADMAP.md), `owr-upgrade` first.

## Binary hardening note

The router binaries are static musl executables (no dynamic dependencies, RELRO/NOW
and non-executable stack flags applied) but **not** position-independent. rustc 1.99's
`aarch64-unknown-linux-musl` target spec does not enable
`static-position-independent-executables` (the x86_64 musl target does, and `rcrt1.o` is
shipped), so `-C relocation-model=pie` with `+crt-static` links a fixed-address
`ET_EXEC`. Stable rustc has no switch to override the target spec. Follow-up: build the
Rust binaries inside `build/build-image.sh` with the OpenWrt toolchain as linker,
`-C target-feature=-crt-static` and `-L <staging_dir>/lib`, so they become dynamic PIEs
linked against the image's musl like every other OpenWrt userspace binary; or switch to
static-PIE once rustc enables it for this target (the `.cargo/config.toml` flags already
ask for it).
