#!/usr/bin/env bash
# Build the images inside Docker from a Windows (Git Bash) or Linux host.
#
#   build/run-in-docker.sh [--rebuild-image] [--shell] [build-image.sh arguments...]
#
# Defaults to "--board glinet_gl-mt6000" when no --board is given. Output lands in
# build/out/images/ of this checkout.
#
# State kept between runs in named Docker volumes (the OpenWrt tree must NOT live on a
# Windows bind mount: case-insensitive, no real symlinks, very slow):
#   ferritewrt-openwrt  /work/openwrt      OpenWrt checkout, dl/, build_dir, staging_dir
#   ferritewrt-cargo    /work/cargo-home   cargo registry and git checkouts
#   ferritewrt-target   /work/cargo-target Rust build artefacts
# ccache is intentionally not used: OpenWrt only offers it under CONFIG_DEVEL, and the
# persistent ferritewrt-openwrt volume already makes rebuilds incremental.
# Reset everything with: docker volume rm ferritewrt-openwrt ferritewrt-cargo ferritewrt-target
set -euo pipefail

IMAGE=ferritewrt-build:1
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Docker Desktop on Windows wants C:/path; "pwd -W" exists only in Git Bash/MSYS.
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && { pwd -W 2>/dev/null || pwd; })

# Git Bash rewrites arguments that look like POSIX paths (/work/...); turn that off.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

command -v docker >/dev/null || { echo 'ERROR: docker not found (install Docker Desktop)' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'ERROR: the Docker daemon is not running' >&2; exit 1; }

rebuild=0
shell=0
args=()
for a in "$@"; do
  case $a in
    --rebuild-image) rebuild=1 ;;
    --shell)         shell=1 ;;
    *)               args+=("$a") ;;
  esac
done

if [ "$rebuild" -eq 1 ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  # Bind-mounted files keep the host owner on Linux, so build as the same uid/gid there.
  # Docker Desktop (Windows/macOS) maps ownership itself; 1000 is fine.
  uid=1000 gid=1000
  if [ "$(uname -s)" = Linux ]; then uid=$(id -u); gid=$(id -g); fi
  echo "==> building $IMAGE (uid=$uid gid=$gid)" >&2
  docker build -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" \
    --build-arg "BUILDER_UID=$uid" --build-arg "BUILDER_GID=$gid" "$SCRIPT_DIR"
fi

have_board=0
for a in ${args[@]+"${args[@]}"}; do [ "$a" = --board ] && have_board=1; done
[ "$have_board" -eq 1 ] || args=(--board glinet_gl-mt6000 ${args[@]+"${args[@]}"})

tty=()
if [ -t 0 ] && [ -t 1 ]; then tty=(-it); fi

run=(docker run --rm --init ${tty[@]+"${tty[@]}"}
  -v "$REPO_ROOT:/work/ferritewrt"
  -v ferritewrt-openwrt:/work/openwrt
  -v ferritewrt-cargo:/work/cargo-home
  -v ferritewrt-target:/work/cargo-target)

if [ "$shell" -eq 1 ]; then
  exec "${run[@]}" --entrypoint bash "$IMAGE"
fi
exec "${run[@]}" "$IMAGE" "${args[@]}"
