# Adding a router to FerriteWRT

FerriteWRT runs on routers that OpenWrt already supports. OpenWrt brings the kernel, the
drivers, the device tree and the image recipe for thousands of devices; FerriteWRT adds a
small, typed description of the hardware and a short build config on top. A new router is
three files and one line of Rust, and most of the work is reading what OpenWrt already
knows about the device.

This guide is for anyone who wants to add a router, with or without Rust experience. If
you use [Claude Code](https://claude.com/claude-code), run `/ferrite-forge <router>` in this
repository and it walks the same steps for you; this page is what it follows.

- [What can be supported](#what-can-be-supported) and [lifting a limit](#lifting-a-limit)
- [What you need](#what-you-need)
- [Step 1: gather the facts](#step-1-gather-the-facts)
- [Step 2: the board descriptor](#step-2-the-board-descriptor)
- [Step 3: the build config](#step-3-the-build-config)
- [Step 4: a kernel fragment for a new OpenWrt target](#step-4-a-kernel-fragment-for-a-new-openwrt-target)
- [Step 5: register the board](#step-5-register-the-board)
- [Step 6: check it](#step-6-check-it)
- [Step 7: open a pull request](#step-7-open-a-pull-request)
- [Field reference](#field-reference)
- [Common mistakes](#common-mistakes)

## What can be supported

FerriteWRT replaces OpenWrt's userspace with Rust programs. That puts two limits on which
OpenWrt devices can run it today:

| Router has | Today | Why |
|---|---|---|
| 64-bit ARM SoC (`aarch64`: MediaTek Filogic, Qualcomm IPQ807x/IPQ60xx/IPQ50xx, Marvell Armada 3720/7k/8k, Rockchip, ...) | **supported** | The Rust programs are built for `aarch64-unknown-linux-musl`. |
| 32-bit ARM SoC (`arm`: IPQ40xx, IPQ806x, Armada 38x, ...) | not yet | Needs an `armv7` Rust target in the build and a split of the kernel fragment. Planned. |
| MIPS SoC (`mips`/`mipsel`: ath79, ramips) | no | Rust has no tier-2 standard library for MIPS on musl. |
| eMMC or SD storage with a GPT partition table | **supported** | `owr-init` keeps settings on an f2fs or ext4 partition it finds by name. |
| Raw NAND (UBI) or NOR flash only | not yet | Needs UBI support in `owr-init`. Planned. |

Boards that can boot from several media (eMMC, SD and NAND) are supported in their eMMC/SD
layout. `scripts/openwrt-device-facts.sh` checks all of this for you and prints a verdict
before anything is written.

### Lifting a limit

Each limit is a contained piece of work, and a good first contribution if you own such a
router. Open an issue first so the design can be agreed.

- **NAND/UBI storage:** `owr-init` plans its mounts in `crates/owr-init/src/mounts.rs`
  (`storage_plan`, `overlay_fstype`); it needs a UBI attach step and a `ubifs` overlay. The
  board schema already accepts `storage.kind = "nand"`.
- **32-bit ARM:** `build/build-image.sh` maps `[soc] arch` to a Rust target (only `aarch64`
  today); `armv7-unknown-linux-musleabihf` is tier 2. The arm64-only lines of
  `build/openwrt/kernel-config.fragment` (pointer authentication, BTI) move to an
  arch-specific fragment, and the repository test that requires `aarch64` is relaxed.
- **Images other than `.bin`** (`.itb`, `.ubi`): `collect_images` in `build/build-image.sh`.

## What you need

- A checkout of this repository.
- The OpenWrt source tree at the revision FerriteWRT pins (`OPENWRT_REV` in
  `build/build-image.sh`), next to this repository or anywhere you like:

  ```bash
  git clone https://github.com/openwrt/openwrt.git ../openwrt
  git -C ../openwrt checkout "$(sed -n 's/^OPENWRT_REV=\([0-9a-f]*\).*/\1/p' build/build-image.sh)"
  ```

- The router's **OpenWrt profile name**: the name OpenWrt's firmware selector and image
  file names use, such as `glinet_gl-mt6000`. If you only know the model, search:

  ```bash
  scripts/openwrt-device-facts.sh --search gl.inet mt6000
  ```

- A Rust toolchain (`rustup`, stable) to run the checks. Building a firmware image needs
  Docker, but you can leave that to CI.

## Step 1: gather the facts

```bash
scripts/openwrt-device-facts.sh glinet_gl-mt6000 > /tmp/facts.md
```

Use `--openwrt-dir DIR` or `OPENWRT_DIR=DIR` if the tree is not at `../openwrt`. The exit
status is 0 for a portable device and 3 when the verdict has a `BLOCKED` line. The report
contains:

- **Support verdict.** `OK`, `CHECK` (read and confirm), `TODO` (a file to add) or `BLOCKED`.
  Any `BLOCKED` line means the router cannot run FerriteWRT yet; stop there, and see
  [Lifting a limit](#lifting-a-limit).
- **Identity:** target, subtarget, architecture, CPU, the board name OpenWrt's scripts match
  on, and which images OpenWrt builds. The "target features" line is what the whole OpenWrt
  target supports (it lists both `emmc` and `nand` on MediaTek), not what this router has.
- **Device definition** from `target/linux/<target>/image/*.mk`, with the templates it
  inherits.
- **Packages:** the device's `DEVICE_PACKAGES`, the target's `DEFAULT_PACKAGES`, and each
  package's dependencies. `GATES` are dependency words without `+` or `@`: select them
  explicitly in the build config. `UNMET` are `@` dependencies the target can never satisfy
  (it lacks the feature): leave that package out. `FILES` are the firmware files a package
  installs, for `wifi.firmware`.
- **DTS:** the device tree source and any board-family `.dtsi` it includes, without pin-mux
  blocks. Ports, LEDs, buttons, partitions, MAC address cells and Wi-Fi calibration all come
  from here; on many boards most nodes live in the family file.
- **base-files:** OpenWrt's board scripts for this device: which ports are LAN and WAN
  (`board.d/02_network`), how Wi-Fi MACs are derived, how upgrades are written.
- **Kernel:** the watchdog and storage drivers the target builds in.

## Step 2: the board descriptor

Create `boards/<profile>.toml`. The file name, `board.id` and the OpenWrt profile are the
same string. Start from `boards/glinet_gl-mt6000.toml`, which is a complete example with a
comment on every value that is not obvious, and fill every section from the facts report
using the [field reference](#field-reference) below. Put the source of a value in a comment
next to it when it is not obvious, as the example does: the next person will thank you.

Some values are not in OpenWrt at all (RAM size without a DTS `memory` node, the core count
when the SoC file comes from the kernel, the widest channel a radio supports, an overlay
partition name nothing references). Fill them from the vendor's specifications and mark
each with `# VERIFY: <why>`, on the value's line or, for a multi-line value or a whole
table, on the line above it, so whoever has the hardware knows what to check.

Hardware the schema has no field for yet (cellular modems and their power or reset GPIOs,
fans, extra status LEDs driven by vendor software) is left out of the board file; say so in
your pull request, since the router then works without it.

The descriptor is strict on purpose. Unknown keys are errors, and
`crates/owr-board/README.md` lists every validation rule (unique port names, 2.4 GHz radios
at most 40 MHz wide, MAC cells inside their partition, and so on).

## Step 3: the build config

Create `build/openwrt/<profile>.diffconfig`. The build writes
`build/openwrt/common.diffconfig` (project policy: hardening, removed OpenWrt services, the
kept C daemons, firewall and input modules) followed by this file, then runs OpenWrt's
`make defconfig`. So this file holds only what is specific to the device:

```
CONFIG_TARGET_<target>=y
CONFIG_TARGET_<target>_<subtarget>=y
CONFIG_TARGET_<target>_<subtarget>_DEVICE_<profile>=y

# device drivers and firmware: the kmod-* and *-firmware entries of DEVICE_PACKAGES
CONFIG_PACKAGE_kmod-...=y

# overlay tools: mkf2fs + f2fsck for f2fs, e2fsprogs for ext4
CONFIG_PACKAGE_mkf2fs=y
```

Rules, each checked automatically:

- Every `kmod-*` and `*-firmware` package selected here is listed in the board file's
  `[openwrt] kernel_modules` or `firmware_packages`, and every listed one is selected here
  or in `common.diffconfig`.
- Do not repeat or contradict a line of `common.diffconfig`.
- Hidden gates from the facts report (`GATES`, for example `input-support`) must be
  selected, or `make defconfig` silently drops the package. A package with an `UNMET` gate
  cannot be built for this target at all: leave it out.
- A comment must never start with `CONFIG_`: kconfig reads `# CONFIG_X is not set` as a
  setting.

Leave out what FerriteWRT replaces or does not drive: OpenWrt's `DEVICE_PACKAGES` sometimes
include LuCI helpers, `gpio-button-hotplug`, modem tools (`uqmi`, USB serial and QMI
drivers), USB storage, or a `kmod-fs-*` for a filesystem the kernel fragment builds in.

The target's `DEFAULT_PACKAGES` are selected without your help. Select and list the kernel
modules among them that drive this board's hardware (a crypto engine such as
`kmod-crypto-hw-safexcel`, `kmod-leds-gpio`), so the board file documents what it relies on.

## Step 4: a kernel fragment for a new OpenWrt target

`build/openwrt/kernel-config.fragment` holds kernel hardening shared by every board. Options
that only exist on one OpenWrt target live in `build/openwrt/kernel-<target>.fragment`
(today: `kernel-mediatek.fragment`). The first board of a new target adds that file with at
least the SoC's **watchdog driver**, because `owr-init` relies on the hardware watchdog to
reboot a hung router. The facts report lists the watchdog symbols the target already builds
in; pin the right one:

```
# Hardware watchdog driver for <SoC family>; owr-init pets /dev/watchdog.
CONFIG_QCOM_WDT=y
```

The build checks every line of the fragments against the final kernel config and fails on
any that did not take effect.

## Step 5: register the board

The firmware embeds every board file. In `crates/owr-board/src/lib.rs` add the file to
`BUILTIN_BOARDS`:

```rust
const BUILTIN_BOARDS: &[(&str, &str)] = &[
    ("glinet_gl-mt6000", GL_MT6000_TOML),
    ("vendor_model", include_str!("../../../boards/vendor_model.toml")),
];
```

## Step 6: check it

From fastest to slowest; each step catches what the previous cannot.

1. **Descriptor:** `cargo run -p owr-cli -- board validate boards/<profile>.toml`
2. **Repository consistency:** `cargo test -p owr-board`. It checks that the board is
   registered, that its build config selects the device, that the module lists match, and
   that nothing repeats `common.diffconfig`.
3. **Whole workspace:** `cargo test --workspace`, so nothing else broke.
4. **OpenWrt config:** CI runs `make defconfig` for every board on every push and names any
   setting that did not stick. Locally, on Linux:
   `build/build-image.sh --board <profile> --openwrt-dir ../openwrt --config-only`
5. **Firmware image:** `build/run-in-docker.sh --board <profile>` (hours the first time), or
   the `release` workflow run by hand with your board id (builds everything, publishes
   nothing).
6. **Hardware:** boot the `initramfs-kernel.bin` image over TFTP first; it runs from RAM and
   writes nothing. `docs/BUILD.md` describes it for the reference board. Then check that
   every port has link and the right role, both radios come up, LEDs and the reset button
   work, and the settings survive a reboot.

## Step 7: open a pull request

- Add a line under `## [Unreleased]` in `CHANGELOG.md`:
  `- Board: <Vendor> <Model> (<profile>), untested on hardware` (or say how you tested it).
- Add the board to the "Supported hardware" table in `README.md` with its status.
- In the pull request, paste the facts report's verdict and say which steps of
  [Step 6](#step-6-check-it) you ran. A board that has only passed steps 1 to 4 is welcome;
  say so, and someone with the hardware can finish it.

## Field reference

Where each value of `boards/<profile>.toml` comes from. "DTS" is the device tree in the
facts report; "image" is the device definition.

| Field | Source | Notes |
|---|---|---|
| `schema` | always `1` | |
| `board.id` | the OpenWrt profile | also the file name |
| `board.vendor`, `board.model` | image `DEVICE_VENDOR`, `DEVICE_MODEL` (+ `DEVICE_VARIANT`) | the model may add the marketing name, e.g. `Flint 2 (GL-MT6000)` |
| `board.compatible` | DTS root `compatible` | all entries, board first |
| `soc.family` | last DTS root `compatible`, without the vendor (`mediatek,mt7986a` -> `mt7986a`) | |
| `soc.arch`, `soc.cpu` | facts report Identity (`ARCH`, `CPU_TYPE`) | `arch` must be `aarch64` |
| `soc.cores` | the SoC's `cpus` node (kernel SoC dtsi) or datasheet | |
| `soc.features` | free-form tags: crypto engine (`kmod-crypto-hw-*`), offload engines, watchdog | informational |
| `memory.ram_mib` | DTS `memory` node, else the vendor specification | at least 64 |
| `storage.kind`, `device` | `emmc`, `/dev/mmcblk0` (the `mmc` alias/index in the DTS) | eMMC/SD only today |
| `storage.root` | DTS `chosen` `bootargs` `root=`, or `CI_ROOTPART` in platform.sh | `PARTLABEL=<name>` |
| `storage.overlay`, `overlay_fs` | the GPT data partition (`CI_DATAPART`, usually `rootfs_data`); `f2fs` or `ext4` | `owr-init` formats it if blank |
| `[[storage.partitions]]` | GPT partitions named in the DTS (`partname`/`label`) and platform.sh (`CI_KERNPART`, `CI_ROOTPART`, `CI_DATAPART`) | roles: `bootenv`, `factory`, `kernel`, `bootloader`, `rootfs`, `overlay`, `other:<name>`. List only partitions with evidence, plus the overlay (with `# VERIFY:` if nothing names it); give `size` only when a source states it |
| `cells` | DTS `nvmem-layout` cells of the factory/art partition: Wi-Fi `eeprom`, `mac-base` | offsets and sizes as `0x...` strings |
| `console.device`, `baud` | DTS `chosen` `stdout-path` / `aliases` `serial0` (`ttyS0` on MediaTek, `ttyMSM0` on Qualcomm) | |
| `ethernet.mac_source` | the nvmem cell the MACs derive from, as `factory:<cell>` | |
| `[ethernet.switch]` | DTS DSA switch node: driver from `compatible`, `cpu_port` = the CPU port's `reg`, `cpu_netdev` = the GMAC it is wired to, `cpu_link_mbps` from its `fixed-link`/`phy-mode` | omit for boards without a switch |
| `[[ethernet.ports]]` `name`, `netdev` | DTS port `label` (switch ports) or the GMAC's netdev (`eth1`) | the names users see on the case. Without a switch: one port per GMAC, `netdev` from `02_network` (`eth0`, `eth1`), `name` from the case labels, else `wan`/`lan` |
| `role` | `board.d/02_network`: `ucidef_set_interfaces_lan_wan "<lan ports>" <wan>` | |
| `speed_mbps` | DTS `phy-mode` (`2500base-x` 2500, `rgmii`/`gmii`/`sgmii` 1000 unless the PHY says more) | |
| `switch_port` | the switch port's `reg` | never the CPU port |
| `phy` | the port's `phy-handle` target in the `mdio` bus: `mdio_addr` from its `reg` | `kind` is informational today (nothing reads it): the PHY family if the DTS or vendor names it (`realtek-c45`, `aquantia`), else the generic `c45` or `c22` from its `compatible` |
| `mac_offset` | the `N` in `nvmem-cells = <&<mac cell> N>` on the port's GMAC (switch ports share the CPU GMAC's offset) | the reference board's LAN ports all use 2 because they sit behind gmac0 |
| `wifi.driver` | the Wi-Fi `kmod-*` package without `kmod-` (`mt7915e`, `ath11k`, ...) | mt76 drivers get hostapd quirks automatically |
| `wifi.eeprom`, `mac_source` | Wi-Fi node `nvmem-cells`; the MAC script under `hotplug.d/ieee80211` | `factory:<cell>` or `factory:0x<offset>` |
| `wifi.firmware` | files the firmware packages install under `/lib/firmware` | |
| `[[wifi.radios]]` | one per `phy`: `phy_index` in kernel order, `band`, widest channel the chip supports (2.4 GHz at most 40), `standards`, `mac_offset` from the MAC script | |
| `[[leds]]` `name` | the name the kernel gives the LED: DTS `label`, else `<color>:<function>` | `owr-init` finds it in `/sys/class/leds` by this name |
| `gpio`, `active_low` | DTS `gpios = <&pio N GPIO_ACTIVE_LOW>` | |
| `roles` | DTS `aliases`: `led-boot`, `led-failsafe`, `led-running`, `led-upgrade`; plus `wan`, `lan`, `wifi` if the case labels say so | |
| `[[buttons]]` | DTS `gpio-keys` children: `label`, `gpios`, `linux,code` | keycodes `owr-init` knows: `KEY_RESTART`, `KEY_WPS_BUTTON`, `KEY_WLAN`, `KEY_RFKILL`, or a number |
| `short_press`, `long_press` | reset: `reboot`, long `factory-reset` after 5 s; WPS: `wps`; Wi-Fi switch: `wifi-toggle` | |
| `[usb]` | DTS USB controller nodes: `version` `"3.0"`, or `"2.0"` when USB 3 is absent or disabled (`mediatek,u3p-dis-msk`); `vbus_gpio` only when the VBUS regulator is switched by a GPIO | omit if none |
| `[openwrt]` `target`, `subtarget`, `profile` | facts report Identity | single-line values |
| `kernel_modules`, `firmware_packages` | what the board's diffconfig selects | kept in sync by `cargo test -p owr-board` |
| `images` | image `IMAGES` plus `sysupgrade.bin` | `.bin` names only, one line |

## Common mistakes

- **A package vanishes after `make defconfig`.** A dependency gate is missing (the facts
  report lists it under `GATES`), or the target cannot build it (`UNMET`, for example a fan
  driver needing `PWM_SUPPORT` on a target without the `pwm` feature). CI names the setting.
- **LED does nothing.** The `name` must be what the kernel exposes in `/sys/class/leds`; a DTS
  `label` overrides the `color:function` form.
- **Ports swapped.** Use the case labels from the DTS `label` properties, and the roles from
  `02_network`, not the order of the `reg` values.
- **Wi-Fi MAC collisions.** Follow OpenWrt's MAC script for the device exactly; it often adds
  an offset per radio.
- **The image is an `.itb` or `.ubi`.** The build collects `*.bin` images only. A board whose
  only image is something else needs the image collection in `build/build-image.sh`
  extended first.
- **The DTS is not in the OpenWrt tree.** Some boards use a device tree that ships with the
  kernel. Read it from the kernel source at the version OpenWrt uses, or from
  `build_dir/target-*/linux-*/linux-*/arch/arm64/boot/dts/` after a build has prepared it.
