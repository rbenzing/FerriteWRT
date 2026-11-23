#!/usr/bin/env bash
# Check the router binaries (aarch64, static-PIE, hardened) and, with --run, start each one.
#
#   scripts/check-binaries.sh <dir> [--run]
#
# Used by CI (the "router binaries" job) and by build/build-image.sh (on the freshly built
# binaries and again on the ones in the image's rootfs), so there is one definition of
# "a good router binary". For each of owr-init, owr-api, owr-apply and owr:
#
#   * an aarch64 ELF, linked as a static-PIE (ASLR for the executable itself): file type DYN,
#     a dynamic section but no interpreter and no needed libraries;
#   * a non-executable stack, RELRO and immediate binding (-z now);
#   * with --run: `<binary> --help` exits 0 under qemu-aarch64. That runs the static-PIE
#     start-up code, which relocates the binary itself; a PIE that is linked wrongly dies
#     there, not at link time.
#
# Needs file, readelf (any binutils reads aarch64 ELF) and, for --run, qemu-aarch64.
set -u

dir=${1:?usage: check-binaries.sh <dir> [--run]}
run=0
[ "${2:-}" = --run ] && run=1

BINS=(owr-init owr-api owr-apply owr)
readelf_bin=$(command -v aarch64-linux-gnu-readelf || command -v readelf || true)
[ -n "$readelf_bin" ] || { echo "check-binaries: readelf not found" >&2; exit 2; }
if [ "$run" -eq 1 ]; then
  qemu=$(command -v qemu-aarch64 || command -v qemu-aarch64-static || true)
  [ -n "$qemu" ] || { echo "check-binaries: --run needs qemu-aarch64 (package qemu-user)" >&2; exit 2; }
fi

bad=0
fail() { # <binary> <message>
  printf 'FAIL %s: %s\n' "$1" "$2" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ]; then printf '::error title=router binary %s::%s\n' "$1" "$2"; fi
  bad=$((bad + 1))
}

for b in "${BINS[@]}"; do
  f="$dir/$b"
  before=$bad
  if [ ! -f "$f" ]; then fail "$b" "missing: $f"; continue; fi
  desc=$(file -b "$f")
  case $desc in *"ARM aarch64"*) ;; *) fail "$b" "not an aarch64 binary: $desc"; continue ;; esac
  case $desc in
    *"static-pie linked"*) ;;
    *) fail "$b" "not a static-PIE: $desc" ;;
  esac
  header=$("$readelf_bin" -h "$f" 2>&1)
  phdrs=$("$readelf_bin" -lW "$f" 2>&1)
  dyn=$("$readelf_bin" -dW "$f" 2>&1)
  case $header in *"Type:"*"DYN"*) ;; *) fail "$b" "ELF type is not DYN (fixed-address executable?)" ;; esac
  if printf '%s\n' "$phdrs" | grep -qE '^[[:space:]]*INTERP'; then fail "$b" "has a program interpreter (not static)"; fi
  if ! printf '%s\n' "$phdrs" | grep -qE '^[[:space:]]*DYNAMIC'; then fail "$b" "no dynamic section (not position-independent)"; fi
  if printf '%s\n' "$dyn" | grep -q '(NEEDED)'; then fail "$b" "needs shared libraries: $(printf '%s\n' "$dyn" | grep '(NEEDED)' | tr -s ' ' | tr '\n' ';')"; fi
  if printf '%s\n' "$phdrs" | grep -E 'GNU_STACK' | grep -q 'RWE'; then fail "$b" "executable stack"; fi
  if ! printf '%s\n' "$phdrs" | grep -q 'GNU_RELRO'; then fail "$b" "no RELRO segment"; fi
  if ! printf '%s\n' "$dyn" | grep -qE '\((FLAGS|FLAGS_1)\).*(BIND_NOW|NOW)'; then fail "$b" "not linked with -z now"; fi
  started=""
  if [ "$run" -eq 1 ]; then
    if out=$(timeout 60 "$qemu" "$f" --help 2>&1); then
      started=", starts under qemu"
    else
      fail "$b" "--help failed under qemu (exit $?): $(printf '%s' "$out" | head -c 300)"
    fi
  fi
  [ "$bad" -ne "$before" ] || printf 'ok   %s: static-PIE%s\n' "$b" "$started"
done

[ "$bad" -eq 0 ] || { echo "check-binaries: $bad problem(s)" >&2; exit 1; }
echo "check-binaries: ${#BINS[@]} binaries ok"
