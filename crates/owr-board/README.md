# owr-board

Board descriptor schema, loader, validation and queries. Pure Rust (no Linux-only code).
`boards/<vendor>_<model>.toml` is the single source of truth about a router's hardware.

```rust
let board = owr_board::Board::load(std::path::Path::new("/etc/ferritewrt/board.toml"))?;
for port in board.lan_ports() { /* ... */ }
let embedded = owr_board::builtin("glinet_gl-mt6000")?; // Result<Board, BoardError>
```

## Adding a board

1. Copy `boards/glinet_gl-mt6000.toml` to `boards/<vendor>_<model>.toml` and fill in every
   section from the OpenWrt DTS, image recipe and base-files for the device.
2. Add `build/openwrt/<id>.diffconfig` for the OpenWrt kernel/image build.
3. In `src/lib.rs` add a `pub const <NAME>_TOML: &str = include_str!(...)` and an entry
   `("<id>", <NAME>_TOML)` to `BUILTIN_BOARDS`.
4. Add a test in `tests/` for the new board (port counts, speeds, radios) and run
   `cargo test -p owr-board`. The `every_builtin_board_loads_and_id_matches` test checks that
   the file validates and that its `board.id` equals the list key.

Sizes and offsets (`partitions.size`, `cells.offset`, `cells.size`) are integers or strings
such as `"0x80000"` (exactly `[0-9]+` or `0x[0-9a-fA-F]+`: no sign, no whitespace). Unknown keys are
errors, so typos fail loudly. Partition roles are `bootenv`, `factory`, `kernel`, `bootloader`,
`rootfs`, `overlay`, or `other:<name>`; a bare unknown word is a parse error.

## Validation rules

Each failure is reported with a path such as `ethernet.ports[2].switch_port`; all issues are
collected and listed together.

- `schema` is 1.
- `board.id` matches `^[a-z0-9_-]+$`.
- `soc.cores` >= 1; `memory.ram_mib` >= 64.
- eMMC storage has exactly one partition with role `rootfs`.
- Partition names are unique; cell names are unique within a partition.
- `storage.root` / `storage.overlay` of the form `PARTLABEL=<name>` name an existing partition.
- `factory:<cell>` in `ethernet.mac_source` and `wifi.eeprom` names a cell of the factory partition;
  `wifi.mac_source` may also be a numeric offset (`factory:0x04`).
- Cells lie inside their partition (checked when the partition `size` is known).
- At least one ethernet port, and at least one `lan` port (several `wan` ports are allowed).
- Port names are unique; port netdevs are unique, at most 15 characters of `[a-z0-9._-]`, and
  differ from `switch.cpu_netdev` (same charset); `switch.cpu_link_mbps` is an allowed speed.
- `switch_port` values are unique and never equal the switch `cpu_port`.
- Any `switch_port` requires an `[ethernet.switch]` section.
- `speed_mbps` is one of 10, 100, 1000, 2500, 5000, 10000.
- Radio ids are unique; radio `phy_index` values are unique.
- Radio `max_width_mhz` is one of 20, 40, 80, 160, 320; 2g radios are at most 40.
- `wifi.radios` is non-empty when `wifi.driver` is non-empty.
- LED names and GPIOs are unique; button GPIOs are unique.
- Every radio lists at least one standard.
- A button with `long_press` must set `long_press_secs`.
- `openwrt.target` and `openwrt.profile` are non-empty.
