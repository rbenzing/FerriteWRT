# Building FerriteWRT images

Everything is built in a Linux container; the Windows host only needs Docker. Nothing here
has run on hardware yet: the flashing sections are procedures to confirm, not verified ones.

## Prerequisites

* Docker Desktop (WSL2 backend on Windows) with at least 8 GB RAM (16 GB is comfortable),
  60 GB free disk and network access. The first build compiles OpenWrt's toolchain and
  kernel from source (hours); later builds reuse the volumes and are incremental.
* Git Bash on Windows (not WSL bash: the script relies on Git Bash path handling) or a Linux shell.

## One command

```
build/run-in-docker.sh                # = --board glinet_gl-mt6000
build/run-in-docker.sh --board glinet_gl-mt6000 --jobs 8 --skip-rust --version 0.1.0
build/run-in-docker.sh --shell        # interactive shell in the build image
```

`run-in-docker.sh` builds `ferritewrt-build:1` if missing (`--rebuild-image` forces it) and
mounts this checkout plus named volumes `ferritewrt-openwrt` (OpenWrt tree, `dl/`, build
dirs), `ferritewrt-cargo` and `ferritewrt-target`. The OpenWrt revision is pinned in
`build/build-image.sh` (`OPENWRT_REV`, currently `c1bd42c934`, kernel 6.18); override with
`--openwrt-rev`/`--openwrt-repo`. `docker volume rm` the three volumes to start clean.

`build/build-image.sh` then: checks out OpenWrt at the pin; cross-builds the Rust workspace
(`cargo xbuild`, aarch64-unknown-linux-musl, static, not PIE: see `STATUS.md`); stages `build/rootfs-overlay/` +
binaries + `sbin/init -> owr-init` + `boards/<board>.toml`; expands
`build/openwrt/common.diffconfig` followed by `build/openwrt/<board>.diffconfig` and **fails
if any line did not stick**; installs the kernel fragments (`kernel-config.fragment`, then
`kernel-<target>.fragment` if present); builds; then verifies the kernel `.config` and that
the rootfs `/sbin/init` is `owr-init`. No feeds are used. `--config-only` stops after the
config checks (CI runs that for every board on every push).

## Outputs (`build/out/`)

Version `V` is `--version` (default: `[workspace.package] version` of `Cargo.toml`, form
`MAJOR.MINOR.PATCH[-pre]`, no leading `v`) and `B` the board id. The script also exports
`OWR_VERSION=V` and `OWR_BUILD=<short FerriteWRT sha>[-dirty]` to cargo, so `owr-api` reports
the build it came from.

| Path | Content |
|---|---|
| `images/ferritewrt-B-vV-factory.bin` | full image for U-Boot recovery / TFTP flashing (OpenWrt's `*-squashfs-factory.bin`) |
| `images/ferritewrt-B-vV-sysupgrade.bin` | upgrade image (OpenWrt's `*-squashfs-sysupgrade.bin`), installed on a running router by `owr upgrade` or the web UI (`crates/owr-upgrade`) |
| `images/ferritewrt-B-vV-initramfs-kernel.bin` | RAM-only image for the safe first boot |
| `images/ferritewrt-B-vV-binaries.tar.gz` | the static aarch64 Rust binaries (`owr`, `owr-api`, `owr-apply`, `owr-init`); reproducible tar (`--sort=name --mtime=@0 --owner=0 --group=0`, `gzip -n`) |
| `images/build-info.txt` | version, OpenWrt/repo revisions, kernel, rustc, UTC time, and OpenWrt's original file names (`image:` lines) |
| `images/manifest.json` | schema 1: version, board, git revisions, kernel, build time, every other file with kind, size, sha256 |
| `images/SHA256SUMS` | `sha256sum` lines for every file above except itself; covers `manifest.json` |
| `bin/`, `bin-host/owr` | target binaries staged into the rootfs; host `owr` used for `owr release manifest|sums` |
| `build.log`, `resolved.diffconfig` | full `make V=s` log; what OpenWrt really selected |

The build does **not** sign. The release workflow (CI, which holds `OWR_RELEASE_KEY`) runs
`owr release sign` to create `SHA256SUMS.sig`; the script prints the commands. Anyone can check
a download with `owr release verify <dir> --pubkey keys/release.pub`; the formats are in
`crates/owr-cli/README.md` ("Release signing"). `--skip-rust` reuses `bin/` and `bin-host/` and
fails if either is missing.

## Flashing

BL2 and the FIP (U-Boot) are never touched. The build also produces `preloader.bin` and
`bl31-uboot.fip` (ARTIFACTS in `filogic.mk`); they stay in the OpenWrt volume and are not
collected.

**Stock GL.iNet U-Boot recovery (factory.bin).** This is the vendor's procedure and is not
described in the OpenWrt tree; check GL.iNet's current instructions for the exact LED
behaviour. Power off, hold Reset while powering on until the LED pattern GL.iNet documents,
give the PC a static IP in `192.168.1.0/24` (e.g. `192.168.1.2`), open `http://192.168.1.1`
and upload `ferritewrt-*-factory.bin`. Whether the stock page accepts our image is unconfirmed.

**OpenWrt U-Boot (only if you flashed OpenWrt's FIP).** `package/boot/uboot-mediatek/patches/
436-add-glinet-mt6000.patch` (`defenvs/glinet_gl-mt6000_env`) sets `ipaddr=192.168.1.1`,
`serverip=192.168.1.254`, `loadaddr=0x46000000` and
`bootfile_firmware=openwrt-mediatek-filogic-glinet_gl-mt6000-squashfs-factory.bin`. Boot menu
entry 1, "Load Firmware via TFTP then write to eMMC", serves `factory.bin` that way (serve our
`ferritewrt-*-factory.bin` under that file name, or change `bootfile_firmware`). The patch
does not describe a web recovery; that belongs to the stock U-Boot.

## Safe first test: initramfs over TFTP (nothing is written)

1. Serial console on the UART header, 115200 8N1 (`stdout-path` in the DTS). Stop U-Boot.
2. PC at `192.168.1.254`, TFTP server serving `ferritewrt-*-initramfs-kernel.bin`, LAN cable in a LAN port.
3. At the prompt (variable names from the patch env above; set `serverip`/`ipaddr` first if
   your U-Boot differs):
   `tftpboot 0x46000000 <initramfs-kernel.bin>` then `bootm 0x46000000`.
4. A power cycle returns to whatever is on the eMMC.

`owr-init` does not mount, format or write `rootfs_data` when `/` is RAM-backed (OpenWrt's
initramfs `/init` switches to a tmpfs and runs `/sbin/init`); it logs `root filesystem: tmpfs`
and `data partition untouched`. Check both lines on the console, and that
`grep -E 'f2fs|overlay|mmcblk' /proc/mounts` prints nothing, before testing anything else.
v0.2.0 did not have this check right; boot v0.2.1 or later (see `STATUS.md`).

## C components in the image

| Component | Why it stays |
|---|---|
| Linux 6.18 + kmods (mt7915e, mt7986 firmware, safexcel, nft-*, usb3, leds-gpio) | not portable; drivers |
| kernel gpio-keys + evdev (built in) | reset/mode buttons read by `owr-init` from `/dev/input` |
| wpad-basic-mbedtls (hostapd) | WPA2/WPA3 AP; owr-wifi renders `hostapd.conf` |
| nftables-nojson (`nft`) | loads the ruleset owr-fw renders |
| dnsmasq, odhcp6c | DHCPv4 server/DNS; DHCPv6 client, not used yet (Rust replacements are phase 2) |
| ppp, ppp-mod-pppoe | PPPoE WAN |
| busybox (custom, lightly trimmed) | rescue console; the initramfs `/init` needs ash, mount, cp, switch_root |
| e2fsprogs, f2fsck, mkf2fs | overlay creation/repair; kmod f2fs is built in |
| uboot-envtools, fitblk | bootloader env access; fitblk is inert on this board (phase 2 removal candidate) |

**Present but inert** (`package/base-files/Makefile:45-50` hard-depends on `+netifd +fstools
+fwtool +procd +jsonfilter +ucode`; netifd pulls `ubus`/`ubusd`): procd, netifd, ubus, ubusd,
ubox, fstools, uci libs, ucode, libubox/libubus. The kept daemons also link
`libubus`/`libubox`/`libuci` (dnsmasq, odhcp6c, hostapd). They do nothing because
`owr-init` is the kernel's default init and `/sbin/init`. `owr-init` must still run
`/sbin/kmodloader` (from ubox) to load the kmods. Removed outright: dropbear, logd, urngd,
urandom-seed, uci CLI, uclient-fetch, libustream, ca-bundle, mtd, firewall4, procd-ujail, apk,
odhcpd (router advertisements come from `owr-apply netd`).

**Phase 2 removals:** patch base-files so procd/netifd/ubus/ubox/ucode are not installed and
build the daemons without ubus; trim busybox to the rescue set; drop fitblk; signed kernel
modules (or all drivers built in and `MODULES=n`; see `kernel-config.fragment`).

## Hardening switches

Userspace: stack protector strong, `_FORTIFY_SOURCE=2` (little effect on musl), full RELRO,
PIE for all packages. Kernel: see `build/openwrt/kernel-config.fragment` (one comment per
option, `[perf]` marks costly ones), `kernel-<target>.fragment` for options of one OpenWrt
target, and the `CONFIG_KERNEL_*` lines of `common.diffconfig`. The fragments are merged
through `<openwrt>/env/kernel-config` (`include/target.mk:178`), after the generic and target
configs; there is no `FILES=` make variable, so the overlay is synced into `<openwrt>/files`
instead. Pointer authentication (kernel and user) and userspace BTI are enabled, but the
reference board's Cortex-A53 has neither; kernel BTI is impossible with GCC in Linux 6.18.

## Adding another board

See [PORTING.md](PORTING.md). In short: `boards/<profile>.toml`,
`build/openwrt/<profile>.diffconfig`, a `kernel-<target>.fragment` for a new OpenWrt target,
and one line in `crates/owr-board/src/lib.rs`; `scripts/openwrt-device-facts.sh <profile>`
collects the facts, and `build/run-in-docker.sh --board <profile>` builds the image. The
build refuses a board whose diffconfig does not select its device or whose architecture is
not supported.
