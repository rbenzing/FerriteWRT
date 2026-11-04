# Versioning and release policy

## One version, one place

The firmware version is `workspace.package.version` in the root `Cargo.toml`. Nothing
else may carry its own version: every crate uses `version.workspace = true`, the
binaries embed it via `CARGO_PKG_VERSION`, the UI shows it from `/system/status`, and
the image build reads it to name artifacts. `scripts/check-version.sh` enforces this
and runs in CI on every pull request and on every release tag.

## Scheme

[Semantic Versioning 2.0.0](https://semver.org): `MAJOR.MINOR.PATCH[-PRERELEASE]`.

| Bump | When |
|---|---|
| MAJOR | the config schema changes incompatibly (requires a migration that can lose settings), or the image partition layout changes |
| MINOR | new features, new boards, kernel version bumps, kept-C-daemon upgrades |
| PATCH | security and bug fixes only; config schema unchanged |
| `-rc.N` | release candidate; published as a GitHub pre-release and never auto-installed |

Security fixes always ship as a PATCH release of the current MINOR line, so an
upgrade never changes behaviour beyond the fix.

## Release procedure

1. Update `CHANGELOG.md`: move entries from `## [Unreleased]` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section. Security fixes go under `### Security` with
   the CVE or advisory id.
2. Set `version = "X.Y.Z"` in the root `Cargo.toml` and run `cargo update -w` so
   `Cargo.lock` follows.
3. Run `scripts/check-version.sh --tag vX.Y.Z`; it must pass.
4. Commit as `release: vX.Y.Z`, create an annotated tag `vX.Y.Z` on that commit, push
   the tag. The `release` workflow does the rest.

Tags that do not match the Cargo version, or that lack a changelog section, fail
the workflow before anything is built.

## What a release contains

All files are produced by `build/build-image.sh` inside the pinned Docker image and
uploaded by `.github/workflows/release.yml`:

| File | Purpose |
|---|---|
| `ferritewrt-<board>-vX.Y.Z-factory.bin` | first install via the vendor U-Boot recovery |
| `ferritewrt-<board>-vX.Y.Z-sysupgrade.bin` | upgrade from a running ferritewrt |
| `ferritewrt-<board>-vX.Y.Z-initramfs-kernel.bin` | RAM-only test boot via TFTP |
| `ferritewrt-<board>-vX.Y.Z-binaries.tar.gz` | the Rust binaries alone |
| `manifest.json` | version, board, both git commits, kernel, per-artifact sha256 and size |
| `SHA256SUMS` | sha256 of every artifact including `manifest.json` |
| `SHA256SUMS.sig` | ed25519 signature over `SHA256SUMS` (see below) |
| `build-info.txt` | toolchain and timestamps, informational |

Additionally the workflow attaches a GitHub build-provenance attestation (SLSA) to
every artifact, which ties the file hashes to the exact workflow run and commit.

## Integrity and signing

- Hashes: every artifact is listed in `SHA256SUMS`; `manifest.json` repeats the hash
  and size and is itself hashed, so a manifest cannot be swapped.
- Signature: `SHA256SUMS.sig` is an ed25519 signature over the exact bytes of
  `SHA256SUMS`, produced by `owr release sign` in the release workflow. The private
  key lives only in the `OWR_RELEASE_KEY` GitHub secret (32-byte seed as hex). The
  public key is committed at `keys/release.pub` and compiled into the firmware so
  the router (`owr-upgrade`) refuses unsigned or tampered images.
- Verify a download on any machine:

  ```bash
  owr release verify ./downloaded-dir --pubkey keys/release.pub
  ```

  or, without `owr`, check the hash list with `sha256sum -c SHA256SUMS` and the
  signature with any ed25519 tool using the key in `keys/release.pub`
  (format in `crates/owr-cli/README.md`).

- Key rotation: generate a new pair with `owr release keygen`, commit the new
  `keys/release.pub` in a MINOR release signed with the **old** key, then switch the
  secret. Devices accept either key during that release line.

## Reproducibility

The OpenWrt tree is pinned by commit in `build/build-image.sh`, the Rust toolchain by
`rust-toolchain.toml`, Rust dependencies by `Cargo.lock` (`--locked` in CI), and the
build container by its base image tag. The same tag built twice should produce
byte-identical Rust binaries; the OpenWrt image embeds timestamps and is therefore
compared by content, not byte-for-byte, until the image recipe is made reproducible.
