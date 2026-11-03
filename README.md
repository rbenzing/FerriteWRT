<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-dark.svg">
  <img src="assets/brand/lockup-light.svg" alt="FerriteWRT" width="420">
</picture>

<br>

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://openwrt.org/)
[![Board](https://img.shields.io/badge/GL--MT6000-Flint%202-2F6FEF?style=for-the-badge)](boards/glinet_gl-mt6000.toml)
[![CI](https://img.shields.io/github/actions/workflow/status/rbenzing/FerriteWRT/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/rbenzing/FerriteWRT/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rbenzing/FerriteWRT?style=for-the-badge)](https://github.com/rbenzing/FerriteWRT/releases/latest)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg?style=for-the-badge)](./LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/russellbenzing)

**Router firmware with a memory-safe userspace, built for the GL.iNet Flint 2**

🔒 **Secure by default** • 🦀 **Rust, no unsafe** • 📦 **Signed, hash-verified releases** • 🧭 **One config file**

[Features](#-features) • [Architecture](#%EF%B8%8F-architecture) • [Releases](#-releases) • [Developing](#%EF%B8%8F-developing) • [Adding a router](#-adding-another-router) • [Status](#-status)

</div>

---

**FerriteWRT** keeps the Linux kernel, drivers and boot chain from [OpenWrt](https://openwrt.org/)
and replaces the entire userspace control plane with Rust: init and service supervision,
configuration, networking, firewall rendering, Wi-Fi configuration, the management API
and the web UI. It is trimmed to one board, the **GL.iNet Flint 2 (GL-MT6000)**, and
designed so that other OpenWrt-supported boards are a descriptor file away.

> Ferrite: the iron ceramic that keeps noise off a cable. The name is the job.

Design goals, in priority order: **security**, **hardware compatibility**, **memory
integrity and performance**, then ease of use.

---

## ✨ Features

- **🔒 Default-deny firewall** — nftables ruleset rendered from a typed model and loaded before forwarding is enabled
- **🦀 Memory-safe control plane** — every daemon in Rust with `#![forbid(unsafe_code)]`; `cargo deny` enforces a pure-Rust dependency graph (rustls, no OpenSSL, no C crypto)
- **🧭 One configuration file** — typed, versioned TOML replaces `uci`; unknown keys are rejected, writes are atomic
- **♻️ Idempotent apply** — observe, plan, apply, verify; re-running an apply never flaps a working link
- **🌐 Management over HTTPS only** — argon2id passwords, CSRF, admin and viewer roles, audit log, strict CSP
- **📦 Signed releases** — every firmware release ships `SHA256SUMS`, an ed25519 signature and GitHub build-provenance attestations
- **🖥️ Web UI without a framework** — vanilla ES modules, no inline code, verified in Chromium
- **🔧 Data-driven boards** — ports, radios, LEDs and buttons come from `boards/<board>.toml`

---

## 🏗️ Architecture

| Layer | OpenWrt | FerriteWRT |
|---|---|---|
| Kernel, drivers, U-Boot, image packaging | C, from the pinned OpenWrt tree | unchanged |
| Init, service supervision, logging, mounts | procd, ubox, fstools | `owr-init` |
| Configuration | uci | `owr-config` |
| Networking, DHCP client | netifd, udhcpc | `owr-net` |
| Firewall | firewall4 | `owr-fw` |
| Wi-Fi configuration | wifi-scripts | `owr-wifi` (hostapd stays) |
| Management API, web UI | uhttpd, rpcd, ubus, LuCI | `owr-api` |
| Command line | uci, ubus | `owr` |

```
boards/            one TOML descriptor per supported router (GL-MT6000 today)
assets/brand/      logo, lockup and favicon sources
crates/owr-common  atomic writes, well-known paths
crates/owr-board   board descriptor schema + validation
crates/owr-config  typed, versioned configuration
crates/owr-net     declarative network plan + rtnetlink + DHCPv4 client
crates/owr-fw      firewall model -> nftables ruleset
crates/owr-wifi    Wi-Fi model -> hostapd.conf, hostapd control client
crates/owr-init    PID 1 supervisor, journal, mounts, watchdog
crates/owr-apply   apply orchestration
crates/owr-api     HTTPS API + embedded web UI
crates/owr-cli     the owr command-line tool and release tooling
build/             OpenWrt diffconfig, kernel hardening fragment, Dockerfile, scripts
docs/              build, versioning, status and roadmap
```

The scope boundary, crate map and the non-negotiable engineering rules are in
[ARCHITECTURE.md](ARCHITECTURE.md); the threat model and hardening defaults in
[SECURITY.md](SECURITY.md).

---

## 📦 Releases

Every tag `vX.Y.Z` runs the `release` workflow: it enforces version compliance, runs the
full test and dependency-policy gate, builds the firmware in the pinned Docker image, and
publishes `ferritewrt-<board>-vX.Y.Z-{factory,sysupgrade,initramfs-kernel}.bin` together
with `manifest.json`, `SHA256SUMS`, an ed25519 `SHA256SUMS.sig` and build-provenance
attestations. Verify a download before flashing:

```bash
owr release verify <download-dir> --pubkey keys/release.pub
# or, with coreutils only:
sha256sum -c SHA256SUMS
```

How versions, signatures and hashes fit together is in [docs/VERSIONING.md](docs/VERSIONING.md).

---

## 🛠️ Developing

```bash
# Windows (Git Bash): put cargo + mingw on PATH for host builds
source scripts/env.sh

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo build --release --target aarch64-unknown-linux-musl --workspace   # router binaries

# Try the UI against a mock backend
cargo run -p owr-api -- --dev        # https://127.0.0.1:8080
```

Linux-only test paths run through `scripts/linux-tests.sh`. Firmware images are assembled
in Docker against the pinned OpenWrt tree; see [docs/BUILD.md](docs/BUILD.md).

---

## 🔌 Adding another router

1. Copy `boards/glinet_gl-mt6000.toml` to `boards/<vendor>_<model>.toml` and fill it from
   the device's OpenWrt DTS and image recipe. `cargo test -p owr-board` validates it.
2. Add `build/openwrt/<id>.diffconfig` selecting the OpenWrt target/profile and the board's
   kernel modules and firmware packages.
3. Register the board in `owr_board::builtin_boards()`.

Boards on SoC families OpenWrt already supports (MediaTek Filogic, Qualcomm IPQ, and so on)
need no Rust changes beyond that registration.

---

## 🚦 Status

Phase 1: every crate compiles for the router target (`aarch64-unknown-linux-musl`, static,
no C toolchain required), the pure logic is unit-tested on the host and the Linux paths
under WSL, and the UI is verified in a browser. **Not yet flashed to hardware.** The
hand-off state and the next hardware session are in [docs/STATUS.md](docs/STATUS.md);
what comes after in [docs/ROADMAP.md](docs/ROADMAP.md).

---

## 📄 License

GPL-2.0-only, matching the OpenWrt tree the kernel and image recipes come from. See
[LICENSE](LICENSE).

---

## 👤 Author

FerriteWRT is built by **[Russell Benzing](https://github.com/rbenzing)**.

It is developed with heavy use of AI coding assistants, for architecture, implementation,
tests and this documentation. That is a deliberate choice and worth stating plainly: the
project moves quickly, and every change still has to pass formatting, clippy at pedantic,
the dependency policy, the test suite on two platforms and a cross build before it lands.
The history is public; judge the code, not the tooling.

---

## ❤️ Support

Found a bug or have a feature request? Open an
[issue](https://github.com/rbenzing/FerriteWRT/issues). For anything security related,
follow [SECURITY.md](SECURITY.md) rather than filing a public issue.

If FerriteWRT is useful to you, you can support the work:

<div align="center">

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/russellbenzing)

</div>

---

<div align="center">

**🔒 Secure by default • 🦀 Memory-safe • 📦 Verifiable releases**

*For people who want to read, audit and own the firmware on their router.*

</div>
