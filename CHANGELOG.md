# Changelog

All notable changes to FerriteWRT are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org). See `docs/VERSIONING.md`.

## [Unreleased]

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
