#!/usr/bin/env bash
# Load every rendered firewall ruleset into a real kernel in check mode (`nft -c`).
#
# The snapshot tests prove the renderer's output is stable; this proves nft and the kernel
# accept it. Each ruleset (board defaults plus build/nft-check/*.toml) is rendered by
# `owr-apply render --what fw` and checked inside a throw-away network namespace, so the
# host's own ruleset is never touched. The flowtable binds to the board's ports, so they
# are created there as dummy links. A dummy link cannot bind a hardware-offloaded
# flowtable, so `flags offload` is removed before the check; that flag is a hardware test.
#
# Linux, root (network namespaces), nftables installed.
# Usage: sudo scripts/check-nft.sh <owr-apply binary> [board file]
set -euo pipefail
cd "$(dirname "$0")/.."

apply=${1:?usage: check-nft.sh <owr-apply binary> [board file]}
board=${2:-boards/glinet_gl-mt6000.toml}
ns="owr-nft-check-$$"
work=$(mktemp -d)
cleanup() {
  ip netns del "$ns" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

command -v nft >/dev/null || { echo "nft not found (install nftables)" >&2; exit 1; }
nft --version
ip netns add "$ns"

fail=0
# check <name> [owr-apply render options...]
check() {
  local name=$1 script rendered devices d out
  shift
  rendered="$work/$name.nft"
  script="$work/$name.check.nft"
  if ! "$apply" render --what fw --board "$board" "$@" >"$rendered"; then
    echo "FAIL $name: rendering failed"
    fail=1
    return
  fi
  devices=$(grep -o 'devices = {[^}]*}' "$rendered" | grep -o '"[^"]*"' | tr -d '"' || true)
  for d in $devices; do
    ip -n "$ns" link show "$d" >/dev/null 2>&1 || ip -n "$ns" link add "$d" type dummy
  done
  grep -vE '^[[:space:]]*flags offload;$' "$rendered" >"$script"
  if out=$(ip netns exec "$ns" nft -c -f "$script" 2>&1); then
    echo "ok   $name ($(grep -c . "$rendered") lines)"
  else
    echo "FAIL $name"
    printf '%s\n' "$out"
    echo "--- rendered ruleset ---"
    cat -n "$rendered"
    fail=1
  fi
}

# No --config and no installed config: owr-apply renders the board defaults.
[ -e /etc/ferritewrt/config.toml ] && { echo "/etc/ferritewrt/config.toml exists; refusing to guess" >&2; exit 1; }
check defaults
for f in build/nft-check/*.toml; do
  check "$(basename "$f" .toml)" --config "$f"
done
exit "$fail"
