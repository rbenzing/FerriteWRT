# Project status (2026-11-03)

This is the hand-off state of the FerriteWRT phase-1 scaffold. Read this before
touching hardware.

## What exists and is verified

| Area | Verified how |
|---|---|
| Board descriptor (`boards/glinet_gl-mt6000.toml`) | Parsed + cross-validated by `owr-board` tests; values traced to the OpenWrt DTS and image recipe |
| Typed config (`owr-config`) | Unit tests incl. proptests; secrets never echoed in parse errors; argon2 params bounded |
| Firewall renderer (`owr-fw`) | Snapshot tests of the nft ruleset; Linux applier tested with a fake `nft`; name allow-list prevents comment injection |
| Wi-Fi renderer + hostapd control client (`owr-wifi`) | Snapshot tests of hostapd.conf; control-socket client tested on Linux against a fake hostapd |
| Network planner + DHCPv4 client (`owr-net`) | Planner proven idempotent by an in-memory kernel simulator and proptest; DHCP codec fuzzed; state machine tested with fake transport |
| PID 1 (`owr-init`) | 163 host tests on the pure state machines; supervisor smoke-tested in `--test-mode` on Linux (WSL) |
| HTTPS API (`owr-api`) | 94 tests incl. real TLS 1.2/1.3 handshakes, CSRF/RBAC/rate-limit/audit behaviour |
| Web UI | Driven in Chromium via Playwright against the mock backend: setup wizard, dashboard, network, wireless pages |
| Mapping + apply orchestration (`owr-apply`) | Snapshot tests for nft/hostapd/dnsmasq/odhcpd output; apply step order host-tested |
| Cross-compilation | Every binary builds as a static PIE for `aarch64-unknown-linux-musl` with no C toolchain |
| Dependency policy | `cargo deny check` clean: no C/asm crates, permissive licenses, no advisories |

Linux-only code paths are exercised by `scripts/linux-tests.sh` (builds the test
binaries for x86_64 musl and runs them inside the WSL `docker-desktop` distro).

## What is NOT verified yet

- **Nothing has booted on a Flint 2.** The netlink appliers, the nft loader, mounts,
  pivot_root, the watchdog thread, uevent/evdev readers and LED writes are
  compile-checked and reviewed but have never run against a real kernel.
- The nft rulesets have not been checked with a real `nft -c`, nor hostapd.conf
  with a real hostapd. Both are expected to pass but must be confirmed on a Linux
  box with the tools installed.
- The OpenWrt image build (`build/`) has not been executed: Docker Desktop's daemon
  was not running on the development host. The diffconfig symbols were verified
  against the OpenWrt tree, but the kernel's "newly visible unset symbol" check
  may require additions to `build/openwrt/kernel-config.fragment`.
- IPv6 on the LAN relies on odhcpd, which still needs ubus and is therefore
  non-functional in this image (documented phase-2 gap).
- PPPoE WAN is modelled in the config but not rendered (phase 2).

## Suggested first hardware session

1. Start Docker Desktop, run `build/run-in-docker.sh` (see `docs/BUILD.md`), fix any
   kernel config aborts by extending the fragment.
2. Boot the **initramfs** image via U-Boot TFTP (never writes eMMC). Watch the
   serial console: owr-init logs every mount and service start.
3. From the rescue shell: `nft -c -f /run/ferritewrt/firewall.nft`, then
   `owr status`, `owr check`, inspect `/run/ferritewrt/*.conf`.
4. Only after LAN DHCP + NAT + both radios work from initramfs, flash
   `factory.bin` through the GL.iNet U-Boot recovery page.

## Follow-ups queued

- Unify `argon2`/`password-hash` on 0.6 (digest 0.11) to drop duplicate crate versions.
- `owr-upgrade` (signed sysupgrade images), Rust RA/DHCPv6 to replace odhcpd,
  Rust DNS/DHCPv4 server to replace dnsmasq, drop busybox from the production image.

## Binary hardening note

The router binaries are static musl executables (no dynamic dependencies, RELRO/NOW
and non-executable stack flags applied) but **not** position-independent: stable
rustc does not emit static-PIE for `aarch64-unknown-linux-musl`, and a dynamic PIE
needs `libgcc_s` from the OpenWrt toolchain sysroot, which only exists inside the
Docker build. Follow-up: build the Rust binaries inside `build/build-image.sh` with
`-C target-feature=-crt-static` and `-L <staging_dir>/lib` so they become dynamic
PIEs linked against the image's musl, like every other OpenWrt userspace binary.
