#!/usr/bin/env bash
# Version compliance check (docs/VERSIONING.md). Runs in CI on pull requests and tags.
#
#   scripts/check-version.sh            # consistency checks only
#   scripts/check-version.sh --tag vX.Y.Z   # additionally require tag == Cargo version
#                                           # and a matching CHANGELOG section
set -euo pipefail
cd "$(dirname "$0")/.."

tag=""
while [ $# -gt 0 ]; do
  case $1 in
    --tag) tag=${2:?--tag needs a value}; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail=0
err() { echo "FAIL: $*" >&2; fail=1; }
ok()  { echo "ok:   $*"; }

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

# 1. Single source of truth.
version=$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *=/{gsub(/.*= *"|".*/,""); print; exit}' Cargo.toml)
[ -n "$version" ] || { err "no [workspace.package] version in Cargo.toml"; exit 1; }
if [[ $version =~ $semver ]]; then ok "workspace version $version is semver"; else err "workspace version '$version' is not semver"; fi

# 2. Every crate inherits the version and the shared metadata; no private versions.
for m in crates/*/Cargo.toml; do
  grep -qE '^version\.workspace *= *true' "$m" || err "$m does not use version.workspace = true"
  if grep -qE '^version *= *"' "$m"; then err "$m declares its own version"; fi
  grep -qE '^\[lints\]' "$m" && grep -qE '^workspace *= *true' "$m" || err "$m does not inherit workspace lints"
done
ok "all crates inherit the workspace version"

# 3. Internal dependencies go through the workspace table, never ad-hoc paths.
if grep -nE '^owr-[a-z]+ *= *\{ *path' crates/*/Cargo.toml; then
  err "internal path dependencies must use '<crate>.workspace = true'"
else
  ok "internal dependencies use the workspace table"
fi

# 4. Lock file matches the manifests (CI builds with --locked).
if command -v cargo >/dev/null 2>&1; then
  if cargo metadata --locked --format-version 1 >/dev/null 2>&1; then ok "Cargo.lock is in sync"; else err "Cargo.lock is out of date (run: cargo update -w)"; fi
fi

# 5. Changelog has an Unreleased section and, for a tag, a dated section for it.
grep -qE '^## \[Unreleased\]' CHANGELOG.md || err "CHANGELOG.md lacks '## [Unreleased]'"
if [ -n "$tag" ]; then
  [[ $tag =~ ^v${semver#^} ]] || err "tag '$tag' must look like vX.Y.Z"
  tv=${tag#v}
  [ "$tv" = "$version" ] || err "tag $tag does not match Cargo version $version"
  if grep -qE "^## \[${tv//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md; then
    ok "CHANGELOG.md has a dated section for $tv"
  else
    err "CHANGELOG.md has no '## [$tv] - YYYY-MM-DD' section"
  fi
  if [[ $tv == *-* ]]; then ok "$tv is a pre-release"; fi
fi

# 6. The release public key, when present, is a single 64-hex line.
if [ -f keys/release.pub ]; then
  if grep -qE '^[0-9a-f]{64}$' keys/release.pub && [ "$(wc -l < keys/release.pub)" -eq 1 ]; then
    ok "keys/release.pub is well formed"
  else
    err "keys/release.pub must be exactly one line of 64 lowercase hex characters"
  fi
fi

[ "$fail" -eq 0 ] && echo "version compliance: PASS ($version)" || { echo "version compliance: FAIL" >&2; exit 1; }
