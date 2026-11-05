#!/usr/bin/env bash
# Load every rendered firewall ruleset into a real kernel.
#
# The snapshot tests prove the renderer's output is stable; this proves nft and the kernel
# accept it. Each ruleset (board defaults plus build/nft-check/*.toml) is rendered by
# `owr-apply render --what fw` and loaded with `nft -f` inside a throw-away network
# namespace, which has its own nftables state, so the host's ruleset is never touched.
# A real load rather than `nft -c`: check mode skips the kernel's commit-time validation
# (a dnat in a filter chain passes `nft -c`), which the negative control below proves.
#
# The flowtable binds to the board's ports, so they are created in the namespace as dummy
# links. A dummy link cannot bind a hardware-offloaded flowtable, so `flags offload` is
# removed before loading; that one flag is a hardware test.
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
nsnft() { ip netns exec "$ns" nft "$@"; }

fail=0
# report <ok|FAIL> <message>: stdout, plus a GitHub annotation under Actions so the result
# can be read from the run without its log.
report() {
  echo "$1 $2"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    if [ "$1" = ok ]; then echo "::notice title=nft load::$2"; else echo "::error title=nft load::$2"; fi
  fi
}

# Negative control: a ruleset nft parses but the kernel refuses at commit (dnat belongs in
# a nat chain). If it loads, this check is not reaching the kernel and proves nothing.
printf '%s\n' 'table inet owr_selftest {' \
  '  chain c { type filter hook input priority filter; policy accept; tcp dport 22 dnat ip to 192.0.2.1; }' \
  '}' >"$work/selftest.nft"
if nsnft -f "$work/selftest.nft" >/dev/null 2>&1; then
  report FAIL "self-test: the kernel loaded a ruleset it must reject"
  exit 1
fi
report ok "self-test: the kernel rejects an invalid ruleset"

# check <name> [owr-apply render options...]
check() {
  local name=$1 script rendered devices d out chains
  shift
  rendered="$work/$name.nft"
  script="$work/$name.load.nft"
  if ! "$apply" render --what fw --board "$board" "$@" >"$rendered"; then
    report FAIL "$name: rendering failed"
    fail=1
    return
  fi
  devices=$(grep -o 'devices = {[^}]*}' "$rendered" | grep -o '"[^"]*"' | tr -d '"' || true)
  for d in $devices; do
    ip -n "$ns" link show "$d" >/dev/null 2>&1 || ip -n "$ns" link add "$d" type dummy
  done
  grep -vE '^[[:space:]]*flags offload;$' "$rendered" >"$script"
  if out=$(nsnft -f "$script" 2>&1) && chains=$(nsnft list table inet owr 2>&1 | grep -c '^[[:space:]]*chain '); then
    report ok "$name: $(grep -c . "$rendered") lines loaded, $chains chains, flowtable on: $(echo $devices)"
  else
    report FAIL "$name: $(printf '%s' "$out" | head -n 3 | tr '\n' ' ')"
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
