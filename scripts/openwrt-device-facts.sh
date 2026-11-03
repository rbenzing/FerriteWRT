#!/usr/bin/env bash
# openwrt-device-facts.sh: everything the pinned OpenWrt tree says about one device, in
# one report, so boards/<id>.toml and build/openwrt/<id>.diffconfig can be written from
# it. Read-only. See docs/PORTING.md.
#
#   scripts/openwrt-device-facts.sh [--openwrt-dir DIR] <profile>
#   scripts/openwrt-device-facts.sh [--openwrt-dir DIR] --search <word>...
#
# <profile> is the OpenWrt device name, the X of "define Device/X" in
# target/linux/<target>/image/*.mk (for example glinet_gl-mt6000). --search lists the
# profiles whose name, vendor or model contain every word (case-insensitive).
# DIR defaults to $OPENWRT_DIR, then ../openwrt next to this repository.
#
# Exit status: 0 report printed and the device is portable; 3 report printed but the
# verdict has a BLOCKED line (the device cannot run FerriteWRT yet); 1 --search found
# nothing; 2 usage error or device not found.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OPENWRT_DIR=${OPENWRT_DIR:-$REPO_ROOT/../openwrt}
PINNED_REV=$(sed -n 's/^OPENWRT_REV=\([0-9a-f]*\).*/\1/p' "$REPO_ROOT/build/build-image.sh")

usage() { sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

SEARCH=0
args=()
while [ $# -gt 0 ]; do
  case $1 in
    --openwrt-dir) OPENWRT_DIR=${2:?--openwrt-dir needs a value}; shift 2 ;;
    --search) SEARCH=1; shift ;;
    -h|--help) usage ;;
    *) args+=("$1"); shift ;;
  esac
done
[ ${#args[@]} -gt 0 ] || usage
[ -d "$OPENWRT_DIR/target/linux" ] || {
  echo "no OpenWrt tree at $OPENWRT_DIR (pass --openwrt-dir, or clone it:" >&2
  echo "  git clone https://github.com/openwrt/openwrt.git $OPENWRT_DIR && git -C $OPENWRT_DIR checkout $PINNED_REV)" >&2
  exit 2
}
cd "$OPENWRT_DIR" || exit 2

# Make variables are often continued with a trailing backslash; join those lines.
join_lines() { awk '{ if (sub(/\\[[:space:]]*$/, "")) { buf = buf $0 " "; next } print buf $0; buf = "" }' "$@"; }

# --- search mode ---------------------------------------------------------------------
if [ "$SEARCH" -eq 1 ]; then
  words=$(printf '%s\n' "${args[@]}" | tr 'A-Z' 'a-z' | tr '\n' ' ')
  for f in target/linux/*/image/*.mk target/linux/*/image/Makefile; do
    [ -f "$f" ] && join_lines "$f" | awk -v f="$f" -v words="$words" '
      /^define Device\// { dev = substr($2, 8); vendor = ""; model = ""; variant = ""; next }
      dev != "" && /^[[:space:]]*DEVICE_VENDOR[[:space:]]*:?=/  { sub(/^[^=]*=[[:space:]]*/, ""); vendor = $0 }
      dev != "" && /^[[:space:]]*DEVICE_MODEL[[:space:]]*:?=/   { sub(/^[^=]*=[[:space:]]*/, ""); model = $0 }
      dev != "" && /^[[:space:]]*DEVICE_VARIANT[[:space:]]*:?=/ { sub(/^[^=]*=[[:space:]]*/, ""); variant = $0 }
      /^endef/ && dev != "" {
        hay = tolower(dev " " vendor " " model " " variant); n = split(words, w, " "); ok = 1
        for (i = 1; i <= n; i++) if (w[i] != "" && index(hay, w[i]) == 0) ok = 0
        if (ok) hit[dev] = sprintf("%-44s %s %s %s  (%s)", dev, vendor, model, variant, f)
        dev = ""
      }
      # Only buildable devices: templates (Device/*-common, ...) are never in TARGET_DEVICES.
      /^TARGET_DEVICES[[:space:]]*\+=/ { for (i = 3; i <= NF; i++) buildable[$i] = 1 }
      END { for (d in hit) if (d in buildable) print hit[d] }'
  done | sort -u | head -60 > "${TMPDIR:-/tmp}/owr-search.$$"
  if [ -s "${TMPDIR:-/tmp}/owr-search.$$" ]; then
    cat "${TMPDIR:-/tmp}/owr-search.$$"; rm -f "${TMPDIR:-/tmp}/owr-search.$$"; exit 0
  fi
  rm -f "${TMPDIR:-/tmp}/owr-search.$$"
  echo "no device matches '${words% }'. OpenWrt rarely uses marketing names: search the model code (e.g. mt3000, ax3000t) or the vendor alone." >&2
  exit 1
fi

PROFILE=${args[0]}
mapfile -t defs < <(grep -rlx "define Device/$PROFILE" target/linux/*/image/ 2>/dev/null)
if [ ${#defs[@]} -eq 0 ]; then
  echo "no 'define Device/$PROFILE' in $OPENWRT_DIR/target/linux/*/image. Try: $0 --search <words>" >&2
  exit 2
fi
IMG_FILE=${defs[0]}
T=$(echo "$IMG_FILE" | cut -d/ -f3)
TDIR=target/linux/$T

# A "define Device/NAME" block, as text.
device_block() { # <name>
  local f
  for f in "$TDIR"/image/*.mk "$TDIR"/image/Makefile include/image.mk; do
    [ -f "$f" ] || continue
    if grep -qx "define Device/$1" "$f"; then
      awk -v d="define Device/$1" '$0 == d { on = 1 } on { print } on && /^endef/ { exit }' "$f"
      return 0
    fi
  done
  return 1
}

# The device block and the templates it inherits ($(call Device/X) or $(Device/X)),
# depth-first, each once. Later lines win for ":=", so print the templates first.
declare -A SEEN=()
BLOCKS=""
collect() { # <name> <depth>
  local name=$1 depth=$2 text parent
  [ -n "${SEEN[$name]:-}" ] && return
  SEEN[$name]=1
  text=$(device_block "$name") || return
  [ "$depth" -lt 4 ] || return
  for parent in $(printf '%s\n' "$text" | grep -oE '\$\((call )?Device/[A-Za-z0-9_.+-]+' | sed 's/.*Device\///'); do
    collect "$parent" $((depth + 1))
  done
  BLOCKS+="# --- Device/$name"$'\n'"$text"$'\n'
}
collect "$PROFILE" 0
JOINED=$(printf '%s\n' "$BLOCKS" | join_lines)

# Value(s) of a make variable in the joined blocks. "last" = last := wins; "all" = every
# := and += value concatenated (for list variables such as DEVICE_PACKAGES).
mkvar() { # <name> <last|all>
  printf '%s\n' "$JOINED" | awk -v n="$1" -v mode="$2" '
    $0 ~ "^[[:space:]]*" n "[[:space:]]*(:|\\+|\\?)?=" {
      op = $0; sub(/^[^=]*/, "", op); v = $0; sub(/^[^=]*=[[:space:]]*/, "", v)
      if (mode == "last") { if ($0 ~ "\\+=") out = out " " v; else out = v }
      else out = out " " v
    }
    END { gsub(/^[[:space:]]+|[[:space:]]+$/, "", out); print out }'
}

# --- subtarget, arch, features, default packages ---------------------------------------
SUB=$(basename "$IMG_FILE" .mk)
if [ ! -f "$TDIR/$SUB/target.mk" ]; then
  # Files like generic-tp-link.mk belong to the subtarget named before the first "-".
  [ -f "$TDIR/${SUB%%-*}/target.mk" ] && SUB=${SUB%%-*}
fi
SUBTARGETS=$(sed -n 's/^SUBTARGETS:=//p' "$TDIR/Makefile")
if [ ! -f "$TDIR/$SUB/target.mk" ]; then
  if [ "$(echo "$SUBTARGETS" | wc -w)" -eq 1 ]; then SUB=$(echo "$SUBTARGETS" | xargs); else SUB="UNRESOLVED (one of: $SUBTARGETS)"; fi
fi
mkget() { # <file> <var>: the := value (joined), or empty
  [ -f "$1" ] && join_lines "$1" | sed -n "s/^$2[[:space:]]*:=[[:space:]]*//p" | tail -1
}
mkadd() { # <file> <var>: every += value (joined)
  [ -f "$1" ] && join_lines "$1" | sed -n "s/^$2[[:space:]]*+=[[:space:]]*//p" | tr '\n' ' '
}
ARCH=$(mkget "$TDIR/$SUB/target.mk" ARCH); [ -n "$ARCH" ] || ARCH=$(mkget "$TDIR/Makefile" ARCH)
CPU_TYPE=$(mkget "$TDIR/$SUB/target.mk" CPU_TYPE); [ -n "$CPU_TYPE" ] || CPU_TYPE=$(mkget "$TDIR/Makefile" CPU_TYPE)
FEATURES="$(mkget "$TDIR/Makefile" FEATURES) $(mkget "$TDIR/$SUB/target.mk" FEATURES) $(mkadd "$TDIR/$SUB/target.mk" FEATURES)"
DEFAULT_PKGS="$(mkadd "$TDIR/Makefile" DEFAULT_PACKAGES) $(mkadd "$TDIR/$SUB/target.mk" DEFAULT_PACKAGES)"
KERNEL_PATCHVER=$(mkget "$TDIR/Makefile" KERNEL_PATCHVER)

VENDOR=$(mkvar DEVICE_VENDOR last); MODEL=$(mkvar DEVICE_MODEL last); VARIANT=$(mkvar DEVICE_VARIANT last)
SOC=$(mkvar SOC last)
DEVICE_PKGS=$(mkvar DEVICE_PACKAGES all)
IMAGES_VAR=$(mkvar IMAGES last)
DTS_NAMES=$(mkvar DEVICE_DTS last | sed "s/\\\$\\\$\\?(SOC)/$SOC/g; s/\\\$(SOC)/$SOC/g")

# --- DTS -------------------------------------------------------------------------------
find_dts() { # <basename without extension> <ext>
  find "$TDIR" -path '*/build_dir' -prune -o -type f -name "$1.$2" -print 2>/dev/null | head -1
}
DTS_FILE=""
for d in $DTS_NAMES; do f=$(find_dts "$d" dts); [ -n "$f" ] && { DTS_FILE=$f; break; }; done
COMPAT=""
if [ -n "$DTS_FILE" ]; then
  # First compatible of the root node "/ {".
  COMPAT=$(awk '
    { line = $0 }
    depth == 0 && line ~ /^[[:space:]]*\/[[:space:]]*\{/ { inroot = 1 }
    inroot && depth == 1 && line ~ /^[[:space:]]*compatible[[:space:]]*=/ {
      sub(/^[^"]*"/, "", line); sub(/".*/, "", line); print line; exit }
    { o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c; if (depth == 0) inroot = 0 }
  ' "$DTS_FILE")
fi
# Fallback: board_name is usually the profile with its first "_" turned into ",".
[ -n "$COMPAT" ] || COMPAT=$(echo "$PROFILE" | sed 's/_/,/')

# --- base-files: board.d, upgrade, wifi MAC and caldata scripts ---------------------------
BASEDIRS=$(ls -d "$TDIR/base-files" "$TDIR/$SUB/base-files" 2>/dev/null)
case_branch() { # <file> <needle>: the case label group containing needle and its body up to ;;
  awk -v needle="$2" '
    { line[NR] = $0 }
    END {
      printed = 0
      for (i = 1; i <= NR; i++) {
        if (index(line[i], needle) == 0) continue
        s = i; while (s > 1 && line[s-1] ~ /\|[[:space:]]*\\?[[:space:]]*$/) s--
        e = i; while (e < NR && line[e] !~ /;;/ && e - i < 40) e++
        if (s <= printed) continue
        for (j = s; j <= e; j++) printf "%5d  %s\n", j, line[j]
        print "      ..."; printed = e
      }
    }' "$1"
}
UPGRADE=""
for b in $BASEDIRS; do
  p="$b/lib/upgrade/platform.sh"
  [ -f "$p" ] && grep -qF "$COMPAT" "$p" && UPGRADE+=$(case_branch "$p" "$COMPAT")$'\n'
done

# --- package definitions (one index, then lookups) --------------------------------------
PKG_INDEX=$(mktemp)
trap 'rm -f "$PKG_INDEX"' EXIT
# Packages are declared either as "define Package/X" blocks or, for firmware built from a
# shared template, as "Package/X = $(call ...)" one-liners.
grep -rnE '^(define (KernelPackage|Package)/[A-Za-z0-9_.+-]+$|Package/[A-Za-z0-9_.+-]+[[:space:]]*=)' \
  package "$TDIR" --include=Makefile --include='*.mk' 2>/dev/null > "$PKG_INDEX"
pkg_def() { # <package>: "file:line" of its declaration
  local name=$1 kname=${1#kmod-}
  if [ "$name" != "$kname" ]; then
    grep -m1 "define KernelPackage/$kname\$" "$PKG_INDEX" | cut -d: -f1,2
  else
    grep -m1 -E "define Package/$name\$|:Package/$name[[:space:]]*=" "$PKG_INDEX" | cut -d: -f1,2
  fi
}
pkg_depends() { # <file> <line>
  # DEPENDS lines, plus the arguments of $(call AddDepends/<group>,<deps>) macros.
  sed -n "$2,\$p" "$1" | join_lines | awk '
    NR > 1 && /^(endef|define |Package\/)/ { exit }
    /^[[:space:]]*DEPENDS[[:space:]]*(:|\+)?=/ { sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]+/, " "); printf "%s ", $0 }
    /\$\(call AddDepends\/[A-Za-z0-9_-]+,/ { s = $0; sub(/.*AddDepends\/[A-Za-z0-9_-]+,/, "", s); sub(/\)[[:space:]]*$/, "", s); gsub(/[[:space:]]+/, " ", s); printf "%s ", s }'
}
pkg_files() { # <file> <package>: firmware files its install block copies (basenames)
  local block="define Package/$2/install"
  case $2 in kmod-*) block="define KernelPackage/${2#kmod-}/install" ;; esac
  join_lines "$1" | awk -v b="$block" '$0 == b { on = 1; next } on && /^endef/ { exit } on' \
    | grep -oE '[A-Za-z0-9_.+-]+\.(bin|fw|ucode|dat|mbn|elf)' | sort -u | tr '\n' ' '
}
# Target features select <FEATURE>_SUPPORT symbols (scripts/target-metadata.pl). A plain
# "@X_SUPPORT" dependency on a symbol only a feature selects is unmeetable when the target
# lacks that feature: make defconfig would silently drop the package.
declare -A FEATURE_OF=()
while read -r feat sym; do [ -n "$sym" ] && FEATURE_OF[$sym]=$feat; done < <(
  awk 'index($0, "and $ret .= ") && index($0, "tselect ") {
         s = $0; sub(/^[ \t]*\/\^/, "", s); f = s; sub(/\$\/.*/, "", f)
         sym = s; sub(/.*tselect /, "", sym); sub(/[^A-Z0-9_].*/, "", sym)
         if (f ~ /^[a-z0-9-]+$/) print f, sym }' scripts/target-metadata.pl)
unmet_gates() { # <depends...>: gates the target's FEATURES cannot satisfy
  local tok sym out=""
  for tok in "$@"; do
    case $tok in @[A-Z]*) sym=${tok#@} ;; *) continue ;; esac
    [ -n "${FEATURE_OF[$sym]:-}" ] || continue
    case " $(echo "$FEATURES" | xargs) " in *" ${FEATURE_OF[$sym]} "*) ;; *) out+="$tok(target lacks '${FEATURE_OF[$sym]}') " ;; esac
  done
  printf '%s' "$out"
}

# --- verdict ------------------------------------------------------------------------------
verdict=()
blockers=0
case $ARCH in
  aarch64) verdict+=("OK       arch aarch64 (Rust target aarch64-unknown-linux-musl)") ;;
  arm) verdict+=("BLOCKED  arch arm (32-bit): needs an armv7 Rust target and an arch split of kernel-config.fragment; not supported yet"); blockers=1 ;;
  mips*|"") verdict+=("BLOCKED  arch '${ARCH:-unknown}': no tier-2 Rust std for musl on this architecture; not supported"); blockers=1 ;;
  *) verdict+=("BLOCKED  arch $ARCH: not supported yet"); blockers=1 ;;
esac
# Strong sign of a UBI rootfs on raw NAND vs. a mere mention of NAND (boards that can
# boot from several media list NAND bootloader artifacts too).
ubi_layout=$(printf '%s\n' "$JOINED" | grep -cE 'KERNEL_IN_UBI|UBINIZE_OPTS|Device/UbiFit' || true)
nand_mention=$(printf '%s\n' "$JOINED" | grep -ciE 'nand' || true)
if printf '%s' "$UPGRADE" | grep -q emmc_do_upgrade; then
  verdict+=("OK       storage eMMC (platform.sh: emmc_do_upgrade); overlay on a GPT partition (PARTLABEL=...)")
elif printf '%s' "$UPGRADE" | grep -qiE 'mmc' && printf '%s' "$UPGRADE" | grep -qiE 'ubi|nand'; then
  verdict+=("CHECK    storage: the board boots from several media (eMMC/SD and NAND); FerriteWRT can only use the eMMC/SD layout with GPT partitions, so the board file must describe that one")
elif printf '%s' "$UPGRADE" | grep -qE 'nand_do_upgrade|ubi' || [ "$ubi_layout" -gt 0 ]; then
  evidence=$( { printf '%s\n' "$JOINED" | grep -oE 'KERNEL_IN_UBI|UBINIZE_OPTS|Device/UbiFit'
                printf '%s\n' "$UPGRADE" | grep -oE 'nand_do_upgrade'; } | sort -u | tr '\n' ' ')
  verdict+=("BLOCKED  storage NAND/UBI (evidence: ${evidence:-platform.sh mentions ubi}): owr-init mounts block-device overlays only (f2fs/ext4); UBI overlay support is not written yet"); blockers=1
elif [ "$nand_mention" -gt 0 ]; then
  verdict+=("CHECK    storage: the image recipe mentions NAND and the upgrade path is not plain eMMC; FerriteWRT needs the board's eMMC/SD layout with GPT partitions")
elif [ -n "$UPGRADE" ]; then
  verdict+=("CHECK    storage: platform.sh has a custom branch for this board (shown below); confirm it is a block device with GPT")
else
  verdict+=("BLOCKED  storage: platform.sh has no branch for '$COMPAT' (default_do_upgrade = raw NOR/mtd): not supported"); blockers=1
fi
for img in $IMAGES_VAR; do
  case $img in *.bin) ;; *) verdict+=("CHECK    image '$img' does not end in .bin; the build collects only *.bin (squashfs-<image>)") ;; esac
done
if [ -f "$REPO_ROOT/build/openwrt/kernel-$T.fragment" ]; then
  verdict+=("OK       kernel fragment for target '$T' exists (build/openwrt/kernel-$T.fragment)")
else
  verdict+=("TODO     new OpenWrt target '$T': add build/openwrt/kernel-$T.fragment (watchdog driver at least, see below)")
fi
[ -f "$REPO_ROOT/boards/$PROFILE.toml" ] && verdict+=("NOTE     boards/$PROFILE.toml already exists in this repository")
[ -n "$DTS_FILE" ] || verdict+=("CHECK    DTS not in the OpenWrt tree: it ships with the kernel source (read it from the kernel, or from build_dir after 'make target/linux/prepare')")
head_rev=$(git rev-parse --short=10 HEAD 2>/dev/null || echo unknown)
case $head_rev in "$PINNED_REV"*) ;; *) verdict+=("WARN     OpenWrt tree is at $head_rev, the build pins $PINNED_REV: facts may differ") ;; esac

# --- report -------------------------------------------------------------------------------
echo "# $PROFILE: ${VENDOR:-?} ${MODEL:-?} ${VARIANT}"
echo
echo "## Support verdict"
printf '  %s\n' "${verdict[@]}"
if [ "$blockers" -eq 0 ]; then echo "  => portable with the current tree"; else echo "  => NOT portable yet: stop and report the BLOCKED lines"; fi
echo
echo "## Identity"
cat <<EOF
  profile            $PROFILE
  target / subtarget $T / $SUB   (kernel $KERNEL_PATCHVER)
  arch / cpu         ${ARCH:-?} / ${CPU_TYPE:-?}
  soc (image var)    ${SOC:-not set}
  board_name         $COMPAT   (first root compatible; base-files match on this)
  device block       $IMG_FILE
  target features    $(echo "$FEATURES" | xargs)   (target-wide, NOT this device's hardware)
  images (IMAGES)    ${IMAGES_VAR:-not set} (sysupgrade.bin comes from Device/Default unless IMAGES := replaces it)
EOF
echo
echo "## Device definition (templates first, then the device)"
printf '%s\n' "$BLOCKS" | sed 's/^/  /'
echo "## Packages"
echo "  DEVICE_PACKAGES : $(echo "$DEVICE_PKGS" | xargs)"
echo "  DEFAULT_PACKAGES: $(echo "$DEFAULT_PKGS" | xargs)   (target + subtarget)"
echo
echo "  package definitions. GATES: bare DEPENDS words, select them explicitly. UNMET: the"
echo "  target can never satisfy this, so make defconfig drops the package: leave it out."
for p in $DEVICE_PKGS $DEFAULT_PKGS; do
  case $p in -*) echo "    $p  (removed by the device)"; continue ;; esac
  loc=$(pkg_def "$p")
  if [ -z "$loc" ]; then echo "    $p  (definition not found: generated by a macro, e.g. ipq-wifi)"; continue; fi
  deps=$(pkg_depends "${loc%%:*}" "${loc##*:}")
  gates=$(printf '%s\n' $deps | grep -vE '^[+@]|^$|^\$|^\(' | tr '\n' ' ')
  # shellcheck disable=SC2086 # split DEPENDS into tokens on purpose
  unmet=$(unmet_gates $deps)
  files=""
  case $p in *firmware*) files=$(pkg_files "${loc%%:*}" "$p") ;; esac
  printf '    %-32s %s\n' "$p" "$loc"
  [ -n "$deps" ] && printf '    %-32s DEPENDS: %s\n' "" "$deps"
  [ -n "$gates" ] && printf '    %-32s GATES  : %s\n' "" "$gates"
  [ -n "$unmet" ] && printf '    %-32s UNMET  : %s\n' "" "$unmet"
  [ -n "$files" ] && printf '    %-32s FILES  : %s\n' "" "$files"
done | awk '!seen[$0]++'
echo
# Print a DTS or in-tree dtsi without its pin-mux blocks.
print_dts() { # <file>
  awk '
    depth == 0 && /^&(pio|pinctrl|tlmm|iomuxc|gpio[0-9]*) *\{/ { skip = 1; skipped = 0 }
    { if (!skip) printf "  %4d  %s\n", NR, $0; else skipped++ }
    { o = gsub(/\{/, "{"); c = gsub(/\}/, "}"); depth += o - c
      if (skip && depth == 0) { printf "  %4d  [pin-mux block, %d lines omitted]\n", NR, skipped; skip = 0 } }
  ' "$1"
}
# In-tree includes shorter than this are board/family files and are printed in full;
# longer ones are SoC files and are only listed.
MAX_FAMILY_DTSI_LINES=800
echo "## DTS"
if [ -z "$DTS_FILE" ]; then
  echo "  DEVICE_DTS = '${DTS_NAMES:-not set (target default)}': not found under $TDIR"
  device_block Default 2>/dev/null | grep -E 'DEVICE_DTS' | sed 's/^/  Device\/Default: /'
else
  echo "  $DTS_FILE ($(wc -l < "$DTS_FILE") lines)"
  family=()
  while read -r _ inc; do
    inc=$(echo "$inc" | tr -d '"<>'); f=$(find_dts "${inc%.dtsi}" dtsi)
    if [ -z "$f" ]; then echo "    includes $inc (kernel-provided SoC/bindings file)"
    elif [ "$(wc -l < "$f")" -le "$MAX_FAMILY_DTSI_LINES" ]; then
      echo "    includes $inc -> $f (board family file: printed below; most nodes may live here)"; family+=("$f")
    else echo "    includes $inc -> $f ($(wc -l < "$f") lines, SoC level: read only if needed)"; fi
  done < <(grep -E '^#include' "$DTS_FILE")
  echo
  echo "  Board DTS without pin-mux blocks:"
  print_dts "$DTS_FILE"
  for f in ${family[@]+"${family[@]}"}; do
    echo
    echo "  Included $f without pin-mux blocks:"
    print_dts "$f"
  done
fi
echo
echo "## base-files matching '$COMPAT' (board.d network/LEDs, Wi-Fi MAC and caldata, upgrade)"
found=0
for b in $BASEDIRS; do
  for f in $(grep -rlF "$COMPAT" "$b" 2>/dev/null); do
    found=1; echo "  --- $f"; case_branch "$f" "$COMPAT"
  done
done
[ "$found" -eq 1 ] || echo "  none (the target's defaults apply)"
echo
echo "## Kernel: watchdog and storage drivers built in by the target config (target-wide)"
for f in "$TDIR/config-$KERNEL_PATCHVER" "$TDIR/$SUB/config-$KERNEL_PATCHVER"; do
  [ -f "$f" ] && grep -hE '^CONFIG_[A-Z0-9_]*(WATCHDOG|_WDT|MMC|F2FS)[A-Z0-9_]*=y' "$f" | sed "s|^|  $(basename "$(dirname "$f")")/$(basename "$f"): |"
done

# Exit 3 when the verdict has a BLOCKED line, so callers need not parse the report.
[ "$blockers" -eq 0 ] || exit 3
