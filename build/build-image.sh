#!/usr/bin/env bash
# Build the ferritewrt firmware images for one board. Runs inside the build container
# (see run-in-docker.sh) but works on any Linux host with the Dockerfile's packages.
#
#   build-image.sh --board glinet_gl-mt6000 [--openwrt-dir /work/openwrt]
#                  [--openwrt-rev c1bd42c934] [--openwrt-repo URL] [--jobs N]
#                  [--skip-rust] [--version <semver>] [--config-only]
#
# Idempotent: every step converges on the same state when re-run, and unchanged
# inputs do not trigger rebuilds (the OpenWrt tree keeps dl/, staging_dir, build_dir).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
OUT_DIR="$SCRIPT_DIR/out"
LOG="$OUT_DIR/build.log"

BOARD=""
OPENWRT_DIR=/work/openwrt
OPENWRT_REV=c1bd42c934            # pinned OpenWrt commit (kernel 6.18)
OPENWRT_REPO=https://github.com/openwrt/openwrt.git
JOBS=$(nproc)
SKIP_RUST=0
CONFIG_ONLY=0                     # stop after .config + kernel fragment (CI diffconfig check)
VERSION=""                        # default: [workspace.package] version of Cargo.toml
RUST_TARGET=""                    # from [soc] arch of the board file, below
REQUIRED_BINS=(owr-init owr-api owr)   # the build fails if one is missing
OPTIONAL_BINS=(owr-apply)              # copied when the workspace builds it

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

retry() { # retry <attempts> <command...>
  local attempts=$1 i; shift
  for ((i = 1; i <= attempts; i++)); do
    if "$@"; then return 0; fi
    log "attempt $i/$attempts failed: $*"
    if [ "$i" -lt "$attempts" ]; then sleep 5; fi
  done
  return 1
}

# --- arguments -------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case $1 in
    --board)        BOARD=${2:?--board needs a value}; shift 2 ;;
    --openwrt-dir)  OPENWRT_DIR=${2:?--openwrt-dir needs a value}; shift 2 ;;
    --openwrt-rev)  OPENWRT_REV=${2:?--openwrt-rev needs a value}; shift 2 ;;
    --openwrt-repo) OPENWRT_REPO=${2:?--openwrt-repo needs a value}; shift 2 ;;
    --jobs)         JOBS=${2:?--jobs needs a value}; shift 2 ;;
    --skip-rust)    SKIP_RUST=1; shift ;;
    --config-only)  CONFIG_ONLY=1; shift ;;
    --version)      VERSION=${2:?--version needs a value}; shift 2 ;;
    -h|--help)      usage 0 ;;
    *)              printf 'unknown argument: %s\n' "$1" >&2; usage 2 ;;
  esac
done

[ -n "$BOARD" ] || { printf '--board is required\n' >&2; usage 2; }
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer, got '$JOBS'"
[ "$(id -u)" -ne 0 ] || die "OpenWrt refuses to build as root; run as an unprivileged user"

# [workspace.package] version of the root Cargo.toml (first match inside that table).
workspace_version() {
  sed -n '/^\[workspace\.package\]/,/^\[/{s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*$/\1/p}' \
    "$REPO_ROOT/Cargo.toml" | head -n1
}
[ -n "$VERSION" ] || VERSION=$(workspace_version)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || die "version '$VERSION' is not MAJOR.MINOR.PATCH[-pre] (no leading 'v'); pass --version"

# git on the ferritewrt checkout. The container user may not own the bind-mounted repo.
repo_git() { git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" "$@"; }
# Full ferritewrt revision ("unknown" outside a checkout) and the short "<sha>[-dirty]" build id.
FERRITEWRT_SHA=$(repo_git rev-parse --verify --quiet HEAD 2>/dev/null) || FERRITEWRT_SHA=unknown
FERRITEWRT_DIRTY=""
if [ "$FERRITEWRT_SHA" != unknown ] && ! repo_git diff --quiet HEAD 2>/dev/null; then FERRITEWRT_DIRTY=-dirty; fi
OWR_BUILD_ID="${FERRITEWRT_SHA:0:10}$FERRITEWRT_DIRTY"

BOARD_TOML="$REPO_ROOT/boards/$BOARD.toml"
# The OpenWrt .config is common.diffconfig (project policy) followed by the board's
# diffconfig; the kernel fragment is kernel-config.fragment followed by the target's
# kernel-<target>.fragment when there is one. See docs/PORTING.md.
COMMON_DIFFCONFIG="$SCRIPT_DIR/openwrt/common.diffconfig"
BOARD_DIFFCONFIG="$SCRIPT_DIR/openwrt/$BOARD.diffconfig"
FRAGMENT="$SCRIPT_DIR/openwrt/kernel-config.fragment"
for f in "$BOARD_TOML" "$COMMON_DIFFCONFIG" "$BOARD_DIFFCONFIG" "$FRAGMENT"; do
  [ -f "$f" ] || die "missing $f (new board? see docs/PORTING.md)"
done

# Value of KEY in the [TABLE] table of the board file. Single-line values only.
toml_value() { # <table> <key>
  awk -v table="$1" -v key="$2" '
    /^\[/ { in_sec = ($0 ~ "^\\[" table "\\][[:space:]]*(#.*)?$"); next }
    in_sec && $0 ~ "^" key "[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*#.*$/, ""); print; exit
    }' "$BOARD_TOML" | tr -d '"[],' | xargs
}
TARGET=$(toml_value openwrt target)
SUBTARGET=$(toml_value openwrt subtarget)
PROFILE=$(toml_value openwrt profile)
IMAGES=$(toml_value openwrt images)
ARCH=$(toml_value soc arch)
for v in TARGET SUBTARGET PROFILE IMAGES; do
  [ -n "${!v}" ] || die "boards/$BOARD.toml: [openwrt] is missing a single-line '${v,,}' value"
done
grep -qxF "CONFIG_TARGET_${TARGET}_${SUBTARGET}_DEVICE_${PROFILE}=y" "$BOARD_DIFFCONFIG" \
  || die "$BOARD_DIFFCONFIG does not select CONFIG_TARGET_${TARGET}_${SUBTARGET}_DEVICE_${PROFILE}=y (boards/$BOARD.toml [openwrt])"

# The Rust userspace and kernel-config.fragment are aarch64-only today. Other
# architectures need a Rust target here and an arch-specific fragment split; MIPS has
# no tier-2 Rust std for musl at all. docs/PORTING.md, "What can be supported".
case $ARCH in
  aarch64) RUST_TARGET=aarch64-unknown-linux-musl ;;
  *) die "boards/$BOARD.toml: [soc] arch '$ARCH' is not supported yet (aarch64 only; see docs/PORTING.md)" ;;
esac

TARGET_FRAGMENT="$SCRIPT_DIR/openwrt/kernel-$TARGET.fragment"
mkdir -p "$OUT_DIR"
# The two files every later step reads: the combined diffconfig and kernel fragment.
DIFFCONFIG="$OUT_DIR/$BOARD.combined.diffconfig"
KERNEL_FRAGMENT="$OUT_DIR/$BOARD.kernel.fragment"
cat "$COMMON_DIFFCONFIG" "$BOARD_DIFFCONFIG" > "$DIFFCONFIG"
if [ -f "$TARGET_FRAGMENT" ]; then
  cat "$FRAGMENT" "$TARGET_FRAGMENT" > "$KERNEL_FRAGMENT"
else
  cp "$FRAGMENT" "$KERNEL_FRAGMENT"
fi
trap 'rc=$?; [ "$rc" -eq 0 ] || log "build failed (exit $rc); log: $LOG"' EXIT

# --- (a) OpenWrt checkout at the pinned revision ---------------------------------
checkout_openwrt() {
  if [ ! -d "$OPENWRT_DIR/.git" ]; then
    if [ -n "$(ls -A "$OPENWRT_DIR" 2>/dev/null)" ]; then
      die "$OPENWRT_DIR exists, is not empty and is not a git checkout"
    fi
    log "cloning $OPENWRT_REPO into $OPENWRT_DIR"
    retry 3 git clone --filter=blob:none --no-checkout "$OPENWRT_REPO" "$OPENWRT_DIR"
  fi
  local want have
  want=$(git -C "$OPENWRT_DIR" rev-parse --verify --quiet "${OPENWRT_REV}^{commit}" || true)
  if [ -z "$want" ]; then
    log "fetching $OPENWRT_REV"
    retry 3 git -C "$OPENWRT_DIR" fetch --tags origin
    want=$(git -C "$OPENWRT_DIR" rev-parse --verify --quiet "${OPENWRT_REV}^{commit}" || true)
    [ -n "$want" ] || die "revision $OPENWRT_REV not found in $OPENWRT_REPO"
  fi
  have=$(git -C "$OPENWRT_DIR" rev-parse --verify --quiet HEAD || true)
  if [ "$have" != "$want" ] || [ ! -f "$OPENWRT_DIR/rules.mk" ]; then
    log "checking out $want"
    git -C "$OPENWRT_DIR" checkout --detach "$want"
  else
    log "OpenWrt already at $want"
  fi
}

# --- (b) feeds -------------------------------------------------------------------
# Deliberately no "scripts/feeds update": everything in the diffconfig (kernel, hostapd,
# nftables, dnsmasq, odhcpd, ppp, firmware, busybox) is in-tree, and no LuCI is built.
# A package that is not in-tree would not survive "make defconfig", and the .config
# check below then fails naming it.
check_no_feeds() {
  [ -d "$OPENWRT_DIR/package/base-files" ] || die "$OPENWRT_DIR does not look like an OpenWrt tree"
  log "feeds: not used (in-tree packages only)"
}

# --- (c) Rust binaries -----------------------------------------------------------
build_rust() {
  command -v cargo >/dev/null || die "cargo not found (run inside the build container)"
  log "cross-building the Rust workspace for $RUST_TARGET (version $VERSION, build $OWR_BUILD_ID)"
  # OWR_BUILD is read with option_env! (owr-api reports it); cargo tracks it, so a new
  # revision rebuilds the crates that embed it and nothing else.
  # The 'xbuild' alias in .cargo/config.toml is: build --release --target
  # aarch64-unknown-linux-musl --workspace --exclude owr-xtask
  (cd "$REPO_ROOT" && OWR_VERSION="$VERSION" OWR_BUILD="$OWR_BUILD_ID" cargo xbuild --locked)
  # Release tooling (owr release manifest/sums) runs on the build host, not on the router.
  log "building the host owr (release tooling)"
  (cd "$REPO_ROOT" && OWR_VERSION="$VERSION" OWR_BUILD="$OWR_BUILD_ID" cargo build --release --locked -p owr-cli)
  rm -rf "${OUT_DIR:?}/bin-host"
  install -d -m 0755 "$OUT_DIR/bin-host"
  install -m 0755 "${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/owr" "$OUT_DIR/bin-host/owr"
  local rel="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/$RUST_TARGET/release" b
  rm -rf "${OUT_DIR:?}/bin"
  install -d -m 0755 "$OUT_DIR/bin"
  for b in "${REQUIRED_BINS[@]}"; do
    [ -f "$rel/$b" ] || die "workspace did not produce $rel/$b"
    install -m 0755 "$rel/$b" "$OUT_DIR/bin/$b"
  done
  for b in "${OPTIONAL_BINS[@]}"; do
    if [ -f "$rel/$b" ]; then install -m 0755 "$rel/$b" "$OUT_DIR/bin/$b"; fi
  done
  for b in "$OUT_DIR"/bin/*; do
    file -b "$b" | grep -q 'ARM aarch64' || die "$b is not an aarch64 binary: $(file -b "$b")"
    file -b "$b" | grep -Eq 'statically linked|static-pie' || die "$b is not statically linked: $(file -b "$b")"
  done
}

# Staged tree = overlay + binaries + sbin/init symlink + board descriptor. Rebuilt from
# scratch each run, then synced into <openwrt>/files (the directory OpenWrt overlays on
# the rootfs: include/rootfs.mk prepare_rootfs with $(TOPDIR)/files; there is no FILES=
# make variable in this tree).
stage_rootfs() {
  local stage="$OUT_DIR/rootfs" b
  for b in "${REQUIRED_BINS[@]}"; do
    [ -x "$OUT_DIR/bin/$b" ] || die "$OUT_DIR/bin/$b is missing: run once without --skip-rust"
  done
  rm -rf "${stage:?}"
  install -d -m 0755 "$stage"
  rsync -a --chmod=D0755,F0644 --exclude README.md --exclude .gitkeep \
    "$SCRIPT_DIR/rootfs-overlay/" "$stage/"
  install -d -m 0755 "$stage/sbin" "$stage/etc/ferritewrt"
  for b in "$OUT_DIR"/bin/*; do install -m 0755 "$b" "$stage/sbin/$(basename "$b")"; done
  ln -sfn owr-init "$stage/sbin/init"
  install -m 0644 "$BOARD_TOML" "$stage/etc/ferritewrt/board.toml"
  # Upgrades verify against this key (owr_common::paths::RELEASE_KEY_FILE).
  grep -Eqx '[0-9a-f]{64}' "$REPO_ROOT/keys/release.pub" \
    || die "keys/release.pub is not a 64-hex-digit public key"
  install -D -m 0644 "$REPO_ROOT/keys/release.pub" "$stage/usr/share/ferritewrt/release.pub"
  install -d -m 0755 "$OPENWRT_DIR/files"
  rsync -a --delete --checksum "$stage/" "$OPENWRT_DIR/files/"
  log "staged rootfs overlay: $(find "$stage" \( -type f -o -type l \) | wc -l) entries -> $OPENWRT_DIR/files"
}

# --- (d) .config -----------------------------------------------------------------
# check_config <expectations> <config> <label>: every "CONFIG_X=v" line must appear
# verbatim in <config>; every "# CONFIG_X is not set" line must not be "=y/m/..." there.
# Checked against the expanded config, not scripts/diffconfig.sh output, because
# diffconfig omits symbols that merely equal their default.
# A setting that did not survive expansion. Under GitHub Actions it is also an error
# annotation, so the run page names it without opening the log.
config_mismatch() { # <label> <wanted> <got>
  printf '  %s: wanted "%s", got "%s"\n' "$1" "$2" "$3" >&2
  if [ "${GITHUB_ACTIONS:-}" = true ]; then printf '::error title=%s::wanted %s, got %s\n' "$1" "$2" "$3"; fi
}

check_config() {
  local expect=$1 cfg=$2 label=$3 line sym actual bad=0
  local re_set='^CONFIG_([A-Za-z0-9_+.-]+)=' re_unset='^# CONFIG_([A-Za-z0-9_+.-]+) is not set$'
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    if [[ $line =~ $re_set ]]; then
      if ! grep -qxF -- "$line" "$cfg"; then
        sym=${BASH_REMATCH[1]}
        actual=$(grep -E -- "^(# )?CONFIG_${sym}[= ]" "$cfg" || true)
        config_mismatch "$label" "$line" "${actual:-<absent>}"
        bad=$((bad + 1))
      fi
    elif [[ $line =~ $re_unset ]]; then
      sym=${BASH_REMATCH[1]}
      actual=$(grep -E -- "^CONFIG_${sym}=" "$cfg" || true)
      if [ -n "$actual" ]; then
        config_mismatch "$label" "$line" "$actual"
        bad=$((bad + 1))
      fi
    fi
  done < "$expect"
  [ "$bad" -eq 0 ] || die "$bad $label setting(s) did not take effect (listed above). A dependency re-enabled or hid them; fix the diffconfig/fragment instead of ignoring this."
  log "$label: all settings verified"
}

configure_openwrt() {
  local stamp="$OPENWRT_DIR/.ferritewrt-config.sha256" sum
  sum=$( (sha256sum "$DIFFCONFIG"; git -C "$OPENWRT_DIR" rev-parse HEAD) | sha256sum | cut -d' ' -f1)
  if [ -f "$stamp" ] && [ -f "$OPENWRT_DIR/.config" ] && [ "$(cat "$stamp")" = "$sum" ]; then
    log ".config unchanged since last run"
  else
    log "expanding $(basename "$DIFFCONFIG") with make defconfig"
    cp "$DIFFCONFIG" "$OPENWRT_DIR/.config"
    make -C "$OPENWRT_DIR" defconfig
  fi
  check_config "$DIFFCONFIG" "$OPENWRT_DIR/.config" ".config"
  # Diagnostic only: what the build really selected relative to OpenWrt's defaults.
  (cd "$OPENWRT_DIR" && ./scripts/diffconfig.sh > "$OUT_DIR/resolved.diffconfig" 2>/dev/null) \
    || log "warning: scripts/diffconfig.sh failed; resolved.diffconfig not updated"
  echo "$sum" > "$stamp"
}

# --- (e) kernel fragment ---------------------------------------------------------
# $(TOPDIR)/env/kernel-config is the last file merged into the kernel config
# (include/target.mk:178). A plain directory is enough; scripts/env is not needed.
install_kernel_fragment() {
  install -d -m 0755 "$OPENWRT_DIR/env"
  cmp -s "$KERNEL_FRAGMENT" "$OPENWRT_DIR/env/kernel-config" || cp "$KERNEL_FRAGMENT" "$OPENWRT_DIR/env/kernel-config"
  log "kernel fragment installed at $OPENWRT_DIR/env/kernel-config"
}

# Kernel options to verify: the fragment, plus the diffconfig's CONFIG_KERNEL_* knobs
# translated to kernel names (CONFIG_KERNEL_FOO -> CONFIG_FOO, as kernel-defaults.mk does).
# KERNEL_CC_* are choice symbols with no kernel counterpart; the fragment states
# STACKPROTECTOR/STACKPROTECTOR_STRONG for them.
verify_kernel_config() {
  local cfg expect="$OUT_DIR/kernel-expect.txt"
  cfg=$(find "$OPENWRT_DIR/build_dir" -type f \
          -path "*/linux-${TARGET}_${SUBTARGET}/linux-[0-9]*/.config" -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | sed -n '1s/^[^ ]* //p' || true)
  [ -n "$cfg" ] || die "kernel .config not found under $OPENWRT_DIR/build_dir"
  { cat "$KERNEL_FRAGMENT"
    sed -n -E 's/^(# )?CONFIG_KERNEL_(.*)$/\1CONFIG_\2/p' "$DIFFCONFIG" | grep -v '^\(# \)\?CONFIG_CC_' || true
  } > "$expect"
  check_config "$expect" "$cfg" "kernel config ($cfg)"
}

# --- (f) build -------------------------------------------------------------------
run_make() { make -C "$OPENWRT_DIR" -j"$JOBS" V=s "$@" 2>&1 | tee -a "$LOG"; }

build_openwrt() {
  : >> "$LOG"
  log "downloading sources (log: $LOG)"
  retry 3 run_make download
  log "host tools and toolchain"
  run_make tools/install toolchain/install
  log "kernel and modules"
  run_make target/linux/compile
  verify_kernel_config
  log "packages and images"
  run_make
}

# The rootfs the images were cut from must boot owr-init, not procd.
verify_rootfs() {
  local root
  root=$(find "$OPENWRT_DIR/build_dir" -maxdepth 2 -type d -name "root-${TARGET}" -print -quit 2>/dev/null || true)
  [ -n "$root" ] || die "target rootfs root-${TARGET} not found under $OPENWRT_DIR/build_dir"
  [ "$(readlink "$root/sbin/init" || true)" = owr-init ] \
    || die "$root/sbin/init is not a symlink to owr-init (found: $(ls -l "$root/sbin/init" 2>&1)); the overlay did not replace procd's init"
  [ -x "$root/sbin/owr-init" ] || die "$root/sbin/owr-init missing"
  [ -f "$root/etc/ferritewrt/board.toml" ] || die "$root/etc/ferritewrt/board.toml missing"
  cmp -s "$root/usr/share/ferritewrt/release.pub" "$REPO_ROOT/keys/release.pub" \
    || die "$root/usr/share/ferritewrt/release.pub missing or not keys/release.pub"
  log "rootfs check: /sbin/init -> owr-init, board.toml and release.pub present"
}

# --- (g)(h) collect and summarise ------------------------------------------------
# Kernel version the images were built with: CONFIG_LINUX_<maj>_<min>=y from .config, patch
# level from target/linux/generic/kernel-<maj>.<min> ("LINUX_VERSION-6.18 = .60"). "unknown"
# when either is missing (e.g. a layout change in a newer OpenWrt).
kernel_version() {
  local ver sub f
  ver=$(sed -n 's/^CONFIG_LINUX_\([0-9][0-9]*\)_\([0-9][0-9]*\)=y$/\1.\2/p' "$OPENWRT_DIR/.config" 2>/dev/null | head -n1 || true)
  [ -n "$ver" ] || { echo unknown; return 0; }
  for f in "$OPENWRT_DIR/target/linux/generic/kernel-$ver" "$OPENWRT_DIR/include/kernel-$ver"; do
    [ -f "$f" ] || continue
    sub=$(sed -n "s/^LINUX_VERSION-${ver//./\.}[[:space:]]*=[[:space:]]*\.\([0-9][0-9]*\)\$/\1/p" "$f" | head -n1 || true)
    if [ -n "$sub" ]; then echo "$ver.$sub"; return 0; fi
  done
  echo unknown
}

# Release artifacts, named ferritewrt-<board>-v<version>-<type>.bin (OpenWrt's own file names
# are kept in build-info.txt), the four Rust binaries as one reproducible tarball, then
# manifest.json and SHA256SUMS written by the host owr. Signing is CI's job (needs the secret).
collect_images() {
  local bindir="$OPENWRT_DIR/bin/targets/$TARGET/$SUBTARGET" dest="$OUT_DIR/images" want img src type name
  local prefix="ferritewrt-${BOARD}-v${VERSION}" host_owr="$OUT_DIR/bin-host/owr" built kernel openwrt_sha b
  local -a wanted=() sources=() bins=()
  [ -x "$host_owr" ] || die "$host_owr is missing: run once without --skip-rust"
  for img in $IMAGES; do
    [[ $img == *.bin ]] || die "boards/$BOARD.toml: image '$img' does not end in .bin"
    wanted+=("squashfs-$img")
  done
  wanted+=("initramfs-kernel.bin")
  rm -rf "${dest:?}"
  install -d -m 0755 "$dest"
  for want in "${wanted[@]}"; do
    # Name is openwrt[-<version>]-<target>-<subtarget>-<profile>-<type>; match the tail.
    src=$(find "$bindir" -maxdepth 1 -type f -name "*-${PROFILE}-${want}" -print 2>/dev/null || true)
    [ -n "$src" ] && [ "$(printf '%s\n' "$src" | wc -l)" -eq 1 ] \
      || die "expected exactly one '*-${PROFILE}-${want}' in $bindir, found: ${src:-none}"
    type=${want#squashfs-}; type=${type%.bin}   # factory, sysupgrade, initramfs-kernel
    name="$prefix-$type.bin"
    cp "$src" "$dest/$name"
    sources+=("$(basename "$src") -> $name")
  done
  for b in "$OUT_DIR"/bin/*; do bins+=("$(basename "$b")"); done
  # Deterministic: sorted names, fixed mtime/owner, no gzip timestamp.
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$OUT_DIR/bin" -cf - "${bins[@]}" \
    | gzip -n -9 > "$dest/$prefix-binaries.tar.gz"
  built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kernel=$(kernel_version)
  openwrt_sha=$(git -C "$OPENWRT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
  {
    echo "board:       $BOARD"
    echo "version:     $VERSION"
    echo "openwrt:     $openwrt_sha"
    echo "ferritewrt:    $FERRITEWRT_SHA$([ -z "$FERRITEWRT_DIRTY" ] || echo ' (dirty)')"
    echo "kernel:      $kernel"
    echo "rustc:       $(rustc --version 2>/dev/null || echo unavailable)"
    echo "built (UTC): $built"
    for img in "${sources[@]}"; do echo "image:       $img"; done
  } > "$dest/build-info.txt"
  # manifest.json first: SHA256SUMS (and so the signature) must cover it.
  local -a manifest_args=(--version "$VERSION" --board "$BOARD" --kernel "$kernel" --built-utc "$built"
    --openwrt-rev "$openwrt_sha")
  if [ "$FERRITEWRT_SHA" != unknown ]; then manifest_args+=(--ferritewrt-rev "$FERRITEWRT_SHA$FERRITEWRT_DIRTY"); fi
  "$host_owr" release manifest "$dest" "${manifest_args[@]}"
  "$host_owr" release sums "$dest" > /dev/null
}

summarise() {
  local f
  printf '\n%-72s %12s\n' "ARTIFACT (build/out/images)" "SIZE"
  for f in "$OUT_DIR"/images/*; do
    printf '%-72s %12s\n' "$(basename "$f")" "$(numfmt --to=iec --suffix=B "$(stat -c %s "$f")")"
  done
  printf '\nmanifest:  %s\nchecksums: %s\nfull log:  %s\n' \
    "$OUT_DIR/images/manifest.json" "$OUT_DIR/images/SHA256SUMS" "$LOG"
  printf '\nNOT signed. CI signs SHA256SUMS with the release key:\n  OWR_RELEASE_KEY=<seed> %s release sign %s\n  %s release verify %s --pubkey keys/release.pub\n' \
    "$OUT_DIR/bin-host/owr" "$OUT_DIR/images" "$OUT_DIR/bin-host/owr" "$OUT_DIR/images"
}

checkout_openwrt
check_no_feeds
if [ "$CONFIG_ONLY" -eq 1 ]; then
  log "--config-only: skipping the Rust build and rootfs staging"
else
  if [ "$SKIP_RUST" -eq 0 ]; then build_rust; else log "skipping Rust build (--skip-rust); reusing $OUT_DIR/bin"; fi
  stage_rootfs
fi
configure_openwrt
install_kernel_fragment
if [ "$CONFIG_ONLY" -eq 1 ]; then log "--config-only: .config verified; stopping before the build"; exit 0; fi
build_openwrt
verify_rootfs
collect_images
summarise
