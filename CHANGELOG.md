# Changelog

All notable changes to FerriteWRT are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org). See `docs/VERSIONING.md`.

## [Unreleased]

### Added
- CI loads every rendered firewall ruleset into a real kernel (`scripts/check-nft.sh`, job
  "firewall rulesets load in a real kernel"): the board defaults and the fixtures in
  `build/nft-check/` are loaded with `nft -f` in a throw-away network namespace, the board's
  ports as dummy links for the flowtable. A negative control must be rejected first, since
  `nft -c` alone accepts rulesets the kernel refuses at commit. All rulesets load.
- PPPoE WAN (`network.wan.proto.type = "pppoe"`), which the web UI already offered but
  apply refused. `owr-apply` writes pppd's options to `/run/ferritewrt/pppoe-wan.conf`
  (0600) and removes them when the WAN is no longer PPPoE; owr-init runs pppd (service
  `pppoe-wan`) while that file exists, confined like dnsmasq and hostapd (`NET_ADMIN`,
  `NET_RAW`, `/dev/ppp`). The firewall's WAN zone covers `pppoe-wan` (NAT, MSS clamp, port
  forwards); the ISP's DNS servers reach dnsmasq through `/etc/ppp/resolv.conf`, which the
  image links into the run directory. `wan.mtu` is pppd's (default 1492); above 1492 the
  WAN port grows to carry it (RFC 4638). `owr-apply render --what pppoe` /
  `owr render pppoe` show the options with the password hidden. IPv4 only.

### Fixed
- `restart` of a service whose config file was removed (a radio or PPPoE switched off)
  started it anyway, and it failed in a loop; init now only stops it and starts it again
  once the file exists.
- The daemon sandbox never allowed `ioctl` on the devices a profile names (Landlock
  handles device ioctls from ABI 5); they are allowed now, which pppd's `/dev/ppp` needs.

## [0.3.0-rc.1] - 2026-11-04

### Added
- Firmware upgrades from a running router (`crates/owr-upgrade`). A bundle is the release's
  `-sysupgrade.bin`, `SHA256SUMS` and `SHA256SUMS.sig`; it is verified against the release
  key the image ships (`/usr/share/ferritewrt/release.pub`), then the image's hash, its
  `BOARD=` and its version (no downgrade unless asked). `owr-init` stages and verifies the
  bundle before answering, then, with every other process stopped, keeps only
  `/etc/ferritewrt` in the overlay, locks itself in memory and writes kernel and rootfs in
  OpenWrt's order with read-back before rebooting. Single slot: recovery from a failed
  write is the bootloader's.
- `owr upgrade <dir> [--downgrade] [--wipe-settings]`, and `owr upgrade --check <dir>` to
  run the same verification anywhere.
- Control socket request `upgrade <dir> [downgrade] [wipe]`.
- Web UI and API: System -> Firmware upgrade (admin only). The three release files are
  streamed to the router (`PUT /api/v1/system/upgrade/files/{name}`, release names only,
  images up to 128 MiB), checked (`POST /api/v1/system/upgrade/check`: version, board,
  signature) and installed (`POST /api/v1/system/upgrade`) after an inline confirmation;
  "Reset all settings" is off by default, a downgrade must be ticked explicitly.
- Confined network daemons: dnsmasq, odhcpd and hostapd start through
  `owr-init --sandbox <profile>`, which reduces the capability bounding set to what each
  needs, sets `no_new_privs`, limits the file system with Landlock (no `/etc/ferritewrt`, no
  data partition, no block devices, writes only to its own state files) and denies module,
  mount, namespace, kexec, reboot, ptrace, bpf, `io_uring`, keyring and clock syscalls with
  seccomp, then execs the daemon. Fails closed; `/etc/ferritewrt/sandbox.off` turns it off.
  New dependencies: `landlock`, `seccompiler`, `libc` (pure Rust).
- Network daemon `owr-apply netd` (service `owr-netd`): runs the WAN DHCPv4 client and
  applies its leases, and sends IPv6 router advertisements (`owr-net` `ra`: SLAAC prefix and
  RDNSS, RFC 4861 timing, answers router solicitations) on every LAN-side bridge with a ULA
  /64. Router lifetime 0: LAN hosts get IPv6 addresses and the router as DNS server, not an
  IPv6 default route (no WAN IPv6 yet). `owr-apply render --what netd` / `owr render netd`
  print its plan; `<run_dir>/netd.json` changing restarts it; SIGHUP restarts it cleanly.

### Fixed
- The WAN DHCPv4 client was never started by any process, so a router on the default
  (DHCP) WAN would not have obtained a WAN address.
- `scripts/linux-tests.sh` reported success when a Linux test failed (the exit status of a
  `tail` pipe was checked) and ran crate binaries as if they were tests.
- owr-init started the management API from `/usr/bin/owr-api`, but the image installs it as
  `/sbin/owr-api`, so the web UI would not have started on the router. A test now checks
  that every program init starts is one the image build installs.
- The image build treated `owr-apply` as optional; it is required now (without it the
  router boots to the rescue console with no network configuration), and the finished
  rootfs is checked for every FerriteWRT binary.
- Documentation brought up to date with 0.3.0 (README, architecture, status, roadmap,
  crate READMEs); `keys/README.md` described the key as compiled in and the effect of
  losing the seed wrongly.

### Removed
- odhcpd: not built into the image, no service, no sandbox profile. It needed ubus and UCI,
  so IPv6 on the LAN never worked with it.

### Changed
- The release signature contract (`SHA256SUMS`, `SHA256SUMS.sig`) lives in `owr-upgrade`
  and is shared by `owr release` and the router; release versions now follow semver
  pre-release rules strictly (no empty identifiers such as `1.2.3-a..b`).
- The image build installs `keys/release.pub` and checks it in the rootfs.

## [0.2.1] - 2026-11-04

### Security
- `owr-init` no longer treats the initramfs test boot as a flash boot on the GL-MT6000.
  It decided from the absence of `root=` on the kernel command line, but the board's DTS
  appends `root=PARTLABEL=rootfs` to every boot, so the v0.2.0 initramfs image would have
  mounted and overlaid the router's existing `rootfs_data` partition. It now decides from
  the filesystem mounted at `/` (RAM-backed: tmpfs, ramfs, rootfs) and leaves storage
  untouched when that cannot be read. Do not boot the v0.2.0 initramfs image.

### Changed
- `docs/STATUS.md` and `docs/ROADMAP.md` describe the current state (image build and
  releases working, first hardware session checklist); docs no longer call the router
  binaries PIE: rustc links them as fixed-address static executables for this target.

## [0.2.0] - 2026-11-03

### Added
- Router porting: `docs/PORTING.md` (procedure, support limits, where every board field
  comes from in OpenWrt), `scripts/openwrt-device-facts.sh` (support verdict and every
  hardware fact for one OpenWrt device, plus `--search`), and the `/ferrite-forge` Claude
  Code skill that drives the same workflow.
- Repository tests (`crates/owr-board/tests/repo_boards.rs`): every board file is
  registered, its diffconfig selects the device, module lists match the diffconfig, and
  nothing repeats the shared config.
- CI checks the OpenWrt config of every board, not only the reference board.

### Changed
- OpenWrt config split into `build/openwrt/common.diffconfig` (shared policy) and a short
  per-board diffconfig; kernel options of one OpenWrt target moved to
  `kernel-<target>.fragment` (`kernel-mediatek.fragment` holds the MediaTek watchdog).
- `build-image.sh` derives the Rust target from the board's `[soc] arch` and refuses
  unsupported architectures with a pointer to the porting guide.
- `ARCHITECTURE.md` moved to `docs/ARCHITECTURE.md`; README and docs describe FerriteWRT
  as firmware for OpenWrt-supported routers, with the Flint 2 as reference board.

### Fixed
- `boards/glinet_gl-mt6000.toml` listed `kmod-fs-f2fs`, which the build never selected
  (f2fs is built into the kernel).
- Kernel fragment: `INIT_STACK_ALL_ZERO` now takes effect (OpenWrt's generic config chose
  `INIT_STACK_NONE` in the same choice, which won); `ARM64_BTI_KERNEL` is dropped because
  Linux 6.18 makes it unavailable with GCC. The 0.1.2 firmware build stopped on both.
- Release workflow saves the OpenWrt build cache even when the build fails, so a later
  attempt does not rebuild the toolchain.

## [0.1.2] - 2026-11-03

Not published: the firmware build failed at the kernel config check fixed in 0.2.0.

### Fixed
- OpenWrt diffconfig: select `input-support`, which gates `kmod-input-evdev` in the
  pinned tree; `make defconfig` silently dropped the module before.
- CI verifies the diffconfig on every push and names any setting that did not take
  effect; the firmware job frees runner disk space before building.

## [0.1.1] - 2026-11-03

Not published: the firmware build failed on the diffconfig problem fixed in 0.1.2.
The `v0.1.0` tag never produced a release either (workflow failed before signing).

### Fixed
- Release workflow: the publish job runs in the `Release` environment, one run per tag,
  and the firmware build writes its log tail to the job summary when it fails.
- Shell scripts carry the executable bit (version compliance could not run on Linux).
- Audit rate-limit integration test no longer depends on argon2 finishing four
  verifications within a second.
- CI test jobs report failing tests as annotations.

## [0.1.0] - 2026-11-03

First tagged release. Nothing in it has run on hardware yet; the images are for the
initramfs TFTP test boot described in `docs/STATUS.md`.

### Added
- Phase-1 scaffold for the GL.iNet Flint 2 (GL-MT6000): board descriptor, typed
  configuration, network planner with DHCPv4 client, nftables renderer, hostapd
  renderer and control client, PID 1 supervisor, HTTPS management API with embedded
  web UI, apply orchestration, `owr` CLI, and the OpenWrt-based image build.
- FerriteWRT branding: brand assets in `assets/brand/` (Fe tile lockup, mark, favicon),
  UI header and page titles, `ferritewrt` identifiers for runtime paths, artifact
  names, the release manifest `project` field and the signature header.
- Release tooling: `owr release {keygen,sums,manifest,sign,verify,show}`, signed
  `SHA256SUMS`, `manifest.json`, versioned artifact names, release workflow with
  build-provenance attestations, and `scripts/check-version.sh` compliance check.
- GitHub Actions CI: fmt, clippy, host and Linux tests, dependency policy, UI checks,
  static aarch64 build.

### Security
- Pure-Rust dependency graph enforced by `cargo deny`; hardened kernel fragment;
  default-deny WAN firewall; LAN-only HTTPS management with argon2id, CSRF and RBAC.
