# FerriteWRT: working notes for Claude Code sessions

Router firmware: a Rust control plane (`crates/owr-*`) on the Linux kernel and drivers built
from a pinned OpenWrt tree. Reference board: GL.iNet Flint 2 (`boards/glinet_gl-mt6000.toml`).

## Start here

1. `docs/STATUS.md`: "Resume here" (what is released, what is on `main` since, what to
   do next), what is verified and how, and the first-hardware-session checklist.
2. `docs/ROADMAP.md`: done vs open work per phase.
3. `CHANGELOG.md`: `[Unreleased]` holds everything on `main` since the last tag.
4. `docs/ARCHITECTURE.md` (crate map, rules), `SECURITY.md` (threat model), and each
   crate's `README.md` (its contracts and limits).

## Commands (Git Bash on the Windows host)

```bash
source scripts/env.sh                     # cargo + mingw on PATH; every session, first
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings          # host (x86_64-pc-windows-gnu)
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-musl -- -D warnings
cargo clippy --workspace --all-targets --target aarch64-unknown-linux-musl -- -D warnings
cargo test --workspace
bash scripts/linux-tests.sh [-p crate]    # Linux paths: musl test binaries run as root in WSL
cargo deny check
bash scripts/check-version.sh [--tag vX.Y.Z]
cargo xbuild                              # release router binaries (aarch64 musl, static)
cargo run -p owr-apply -- render --what fw|net|wifi|dnsmasq|netd|pppoe --board boards/glinet_gl-mt6000.toml --config <file>
```

`linux-tests.sh` runs inside the `docker-desktop` WSL distro (BusyBox userland, no `nft`,
no Docker daemon needed). Its output can be long: redirect it to a file in the scratchpad.

## The gate (before every commit)

fmt, clippy with zero warnings on all three targets, host tests, Linux tests, `cargo deny`,
version compliance. CI (`.github/workflows/ci.yml`) runs the same plus the OpenWrt config
check of every board and `scripts/check-nft.sh` (every rendered firewall ruleset is loaded
into a real kernel in a network namespace; fixtures in `build/nft-check/`).

## Rules the code follows

- `#![forbid(unsafe_code)]`; clippy pedantic; `unwrap`/`expect`/`panic`/`print*` denied,
  tests included (`unwrap`/`expect` allowed in tests by `clippy.toml`, `panic!` never).
  `arithmetic_side_effects` and `indexing_slicing` warn: use checked/saturating ops.
- Pure-Rust dependency graph only (`deny.toml`); Linux-only code behind
  `#[cfg(target_os = "linux")]` so pure logic is tested on any host.
- Every path lives once in `owr_common::paths`; when a shell script must repeat one
  (`build/build-image.sh`), a test ties the two (see `owr-init` `services` tests).
- insta snapshot tests need `snapshot` in their name (`linux-tests.sh` skips them).
- Root-only Linux tests return early when not root; tests that read repository files return
  early when the repository is not visible (cross-built binaries in WSL).
- Docs: public docs mention OpenWrt only for hardware support or where FerriteWRT goes
  beyond it. Update STATUS/ROADMAP/CHANGELOG `[Unreleased]` and the crate README with every
  behaviour change.

## Releases

Procedure in `docs/VERSIONING.md`: set the version in `Cargo.toml` (`cargo update -w`),
rename/date the changelog section, `check-version.sh --tag`, commit `release: vX.Y.Z`,
annotated tag, push the tag. A `-rc.N` tag publishes a GitHub pre-release. Firmware images
are built only by the release workflow. Never move or force-push a published tag; fix with a
new version. Ask the user before tagging.

## GitHub without `gh`

`gh` is not installed; use `curl` against api.github.com. Anonymous limit: 60 requests per
hour, so check a run once after a delay instead of polling. Job logs need a token (403);
`scripts/check-nft.sh` reports its results as annotations, readable without one:
`/repos/rbenzing/FerriteWRT/commits/<sha>/check-runs` then
`/repos/rbenzing/FerriteWRT/check-runs/<id>/annotations`.
