---
name: ferrite-forge
description: Add FerriteWRT support for a router that OpenWrt already supports. Creates boards/<profile>.toml, build/openwrt/<profile>.diffconfig, a kernel-<target>.fragment when the OpenWrt target is new, and registers the board, then validates everything. Use whenever someone wants to add, port, support or bring up a new router, board or device in FerriteWRT, names a router model or an OpenWrt profile (like glinet_gl-mt6000 or xiaomi_ax3000t) in that context, or asks whether a router can run FerriteWRT, even if they never say "board".
argument-hint: "[router model or OpenWrt profile]"
---

# FerriteWRT board forge

Request: $ARGUMENTS

A board in FerriteWRT is three files plus one registration line, and the facts for all of
them already exist in the pinned OpenWrt tree. Your job is to read those facts, translate
them faithfully, and prove the result with the repository's checks. The human-facing
procedure, the rules and the field-by-field source table are in `docs/PORTING.md`; read it
before writing anything, and treat it as the authority where this file is brief.

## 1. Pin down the router

- **No router in the request:** ask which router to add (model name or OpenWrt profile),
  and nothing else yet. If `../openwrt` does not exist, also ask where the OpenWrt tree is
  (or offer to clone it at the pinned revision, as `docs/PORTING.md` shows).
- **A model name rather than a profile** ("Flint 2", "Xiaomi AX3000T"): find the profile with
  `scripts/openwrt-device-facts.sh --search <words>` (search on the model code, such as
  `mt6000`, since OpenWrt rarely uses marketing names). One match: use it and say so. Several
  (hardware revisions, NAND vs eMMC variants): ask which, listing them. None (exit status
  1): retry with just the model code, then just the vendor; ask the user only if those fail
  too.
- **The board already exists** in `boards/`: ask whether to review or update it before
  touching it.

On Windows run the script from Git Bash, and `source scripts/env.sh` before cargo.

## 2. Gather facts and respect the verdict

```bash
scripts/openwrt-device-facts.sh [--openwrt-dir DIR] <profile> > <scratch>/facts-<profile>.md
```

Exit status 3 means the verdict has a `BLOCKED` line; 0 means portable. Read the verdict
first, then the whole report (in ranges if it is long); it is the evidence for every value
you write. Target-wide lines (target features, kernel config) describe what the OpenWrt
target supports, not this device; the device's own facts are its definition, DTS and
base-files.

- **Any `BLOCKED` line:** stop. Create no board, build-config, fragment or registration
  files (the scratch facts report is fine). Tell the user, in plain words, which limit the
  router hits, quoting the verdict's evidence, and what work in FerriteWRT would lift it
  (`docs/PORTING.md`, "What can be supported" and "Lifting a limit"). A board file that
  validates but can never boot is worse than none, because it looks supported. Then offer
  one useful next step: checking a sibling model (an eMMC variant of the same router, or the
  vendor's other models via `--search <vendor>`), without running it unasked.
- **`CHECK` lines:** resolve each one from the report or the DTS before writing, and mention
  how in the final summary.
- **`TODO` lines:** they become files in the steps below.

## 3. Write the files

Follow `docs/PORTING.md` steps 2 to 5, using `boards/glinet_gl-mt6000.toml` and
`build/openwrt/glinet_gl-mt6000.diffconfig` as the worked example:

1. `boards/<profile>.toml`: every value from the facts report, mapped with the field
   reference table. Header comment: which OpenWrt files the values came from.
2. `build/openwrt/<profile>.diffconfig`: device selection, drivers and firmware, overlay
   tools. Only what `common.diffconfig` does not already say.
3. `build/openwrt/kernel-<target>.fragment`, only when the verdict says the target is new:
   at least the SoC watchdog driver, chosen from the report's kernel section.
4. One entry in `BUILTIN_BOARDS` in `crates/owr-board/src/lib.rs`.

Some values are not in OpenWrt at all: RAM size when the DTS has no `memory` node, core
count when the SoC dtsi is kernel-provided, the widest channel a radio supports, an overlay
partition name nothing references. Fill them from what you know about the SoC, and mark
each with `# VERIFY: <why>` (on the line, or on the line above for a multi-line value or a
whole table). Never let an inferred value look like a sourced one; the porter checks these
against the hardware, and an unmarked guess becomes a bug report months later.

Packages: drop any with an `UNMET` line in the report (the target can never build them, so
the config check would fail), select every `GATES` word, and leave out what FerriteWRT
replaces or does not drive (LuCI, `gpio-button-hotplug`, modem tools, USB storage, a
`kmod-fs-*` the kernel already builds in). Hardware the schema has no field for (modem
power GPIOs, fans) stays out of the board file and goes in the summary as "not driven". If
a `DEVICE_PACKAGES` entry is unclear, keep it out and say so.

## 4. Prove it

Run each and fix what fails before moving on; do not report success on an unrun check.

```bash
cargo run -q -p owr-cli -- board validate boards/<profile>.toml
cargo fmt --all --check
cargo clippy -p owr-board --all-targets -- -D warnings
cargo test -p owr-board          # registration, device selection, module lists, no repeats of common
cargo test --workspace
```

The OpenWrt config check (`make defconfig` and every line verified) needs Linux and the
OpenWrt build prerequisites: `build/build-image.sh --board <profile> --openwrt-dir DIR
--config-only`. If you cannot run it here, say that CI runs it for every board on the next
push, and that its annotations will name any setting that did not stick.

## 5. Record it

- `CHANGELOG.md`, under `## [Unreleased]`, `### Added`:
  `- Board: <Vendor> <Model> (<profile>), not yet tested on hardware.`
- `README.md`, "Supported hardware" table: one row with the same status.

Do not commit or push unless the user asks.

## 6. Report

Keep it short and factual:

- the verdict line by line, and how each `CHECK` was resolved;
- the files created or changed;
- every `# VERIFY:` value, with what to check on the hardware;
- packages left out and hardware not driven, each with the reason;
- which checks ran and passed, and which did not run (config check, image build, boot);
- next steps from `docs/PORTING.md` step 6: CI config check, image build, TFTP initramfs boot.
