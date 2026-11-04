#!/usr/bin/env bash
# Run the workspace test suite as Linux binaries from a Windows host.
#
# Builds every test executable for x86_64-unknown-linux-musl (static, rust-lld, no C
# toolchain needed) and executes each one inside the WSL distro named by $WSL_DISTRO
# (default: docker-desktop, which exists wherever Docker Desktop is installed).
# This exercises the `#[cfg(target_os = "linux")]` / `cfg(unix)` code paths that are
# only type-checked on the host. insta snapshot tests are skipped here (their paths are
# compiled in from the Windows host) and run on the host instead. Usage: scripts/linux-tests.sh [-p crate]...
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source scripts/env.sh

WSL_DISTRO="${WSL_DISTRO:-docker-desktop}"
TARGET=x86_64-unknown-linux-musl
if [ "$#" -eq 0 ]; then sel=(--workspace); else sel=("$@"); fi
rustup target list --installed | grep -q "$TARGET" || rustup target add "$TARGET"

# Build first, with errors visible: a test binary that does not compile must fail the run,
# not silently drop out of the list below.
cargo test "${sel[@]}" --target "$TARGET" --no-run --quiet || { echo "test build failed" >&2; exit 1; }
# Test harnesses only (`profile.test`): integration tests also build the crate's binaries,
# which are not tests and reject the test flags.
mapfile -t exes < <(cargo test "${sel[@]}" --target "$TARGET" --no-run --message-format=json 2>/dev/null \
  | grep -E '"profile":\{[^}]*"test":true' \
  | grep -o '"executable":"[^"]*"' | sed 's/"executable":"//; s/"$//' | sed 's#\\\\#/#g')

if [ "${#exes[@]}" -eq 0 ]; then echo "no test executables built" >&2; exit 1; fi

# Translate C:/GIT/openwrtr/... to the path WSL sees. docker-desktop mounts the host at
# /mnt/host/<drive>; stock distros use /mnt/<drive>.
to_wsl() {
  local p="$1"
  p="${p//\\//}"
  local drive="${p:0:1}"; drive="${drive,,}"
  local rest="${p:2}"
  if wsl.exe -d "$WSL_DISTRO" -e /bin/sh -c "test -d /mnt/host/$drive" 2>/dev/null; then
    echo "/mnt/host/$drive$rest"
  else
    echo "/mnt/$drive$rest"
  fi
}

fail=0
for exe in "${exes[@]}"; do
  wexe="$(to_wsl "$exe")"
  echo "== $(basename "$exe")"
  # The binary's own exit status decides (a pipe into tail would report tail's); a failing
  # binary prints its whole output so the failure messages are visible.
  if ! wsl.exe -d "$WSL_DISTRO" -e /bin/sh -c \
    "out=\$('$wexe' --test-threads=4 --skip snapshot 2>&1); rc=\$?; \
     if [ \$rc -eq 0 ]; then printf '%s\n' \"\$out\" | tail -n 3; else printf '%s\n' \"\$out\"; fi; exit \$rc"; then
    fail=1
  fi
done
exit "$fail"
