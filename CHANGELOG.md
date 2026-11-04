# Changelog

All notable changes to FerriteWRT are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org). See `docs/VERSIONING.md`.

## [Unreleased]

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
