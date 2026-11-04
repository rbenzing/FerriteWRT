# rootfs-overlay

Static files merged into the root filesystem of every image, after all OpenWrt
packages are installed. Almost everything here is generated at build time, so this
tree is mostly placeholders.

## How it reaches the image

OpenWrt copies `<openwrt>/files/` over the target rootfs (`include/rootfs.mk`
`prepare_rootfs`, called with `$(TOPDIR)/files` from `package/Makefile` and
`include/image.mk`). There is no `FILES=` make variable in this tree. `build-image.sh`
therefore stages the overlay in `build/out/rootfs/` and rsyncs it to `<openwrt>/files/`.

## What the build puts in the staged tree

| Path in image | Source | Notes |
|---|---|---|
| `/sbin/owr-init`, `/sbin/owr-api`, `/sbin/owr` | `cargo xbuild` (aarch64-unknown-linux-musl, static; not PIE, see `docs/STATUS.md`) | mode 0755. `/sbin/owr-apply` is copied too if the workspace builds it. |
| `/sbin/init` | symlink to `owr-init`, created by the script | Replaces procd's `/sbin/init`. `cp -f` is expected to replace the old file; the build verifies the result and fails if `/sbin/init` is not this symlink. |
| `/etc/ferritewrt/board.toml` | `boards/<board>.toml` | copied by the script so the descriptor has one source of truth |
| `/usr/share/ferritewrt/release.pub` | `keys/release.pub` | release signing public key; upgrades verify against it. Outside `/etc/ferritewrt` on purpose: settings survive an upgrade, the key comes from the new image |
| everything else in this directory | this directory | rsynced as is; `README.md` and `.gitkeep` are skipped |

Add a file here only for static content that is identical on every board and every
build (for example a banner or a CA bundle). Board-specific content belongs in
`boards/<board>.toml`; configuration belongs in `/etc/ferritewrt/config.toml`, which
owr-init creates on first boot on the writable overlay.

## Not needed here

* `/etc/preinit`: with owr-init as PID 1 (kernel `CONFIG_DEFAULT_INIT`, plus the
  `/sbin/init` symlink) OpenWrt's preinit never runs. Procd's init is what executes
  `/etc/preinit`, and procd is installed but inert.
* `/lib/firmware`: provided by the `kmod-mt7986-firmware` and `mt7986-wo-firmware`
  packages.

## Mount points required by owr-init
`/mnt`, `/overlay` and `/rom` must exist in the read-only squashfs root: owr-init stages the
data partition at `/overlay`, builds the overlayfs root at `/mnt` and pivots the old root to `/rom`.
The empty directories here (with `.gitkeep`) make `files/` carry them into the image.
