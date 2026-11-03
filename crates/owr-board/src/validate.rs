//! Semantic validation of a parsed [`Board`]. Collects every issue instead of stopping at the first.

use std::collections::HashSet;
use std::fmt::Display;
use std::hash::Hash;

use crate::error::ValidationIssue;
use crate::hex;
use crate::schema::{Band, Board, PartitionRole, PortRole, StorageKind};

const SPEEDS_MBPS: [u32; 6] = [10, 100, 1000, 2500, 5000, 10_000];
const WIDTHS_MHZ: [u16; 5] = [20, 40, 80, 160, 320];
const MAX_WIDTH_2G_MHZ: u16 = 40;
const MIN_RAM_MIB: u32 = 64;
/// `IFNAMSIZ` is 16 including the trailing NUL.
const MAX_NETDEV_LEN: usize = 15;

#[derive(Default)]
struct Issues(Vec<ValidationIssue>);

impl Issues {
    fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(ValidationIssue {
            path: path.into(),
            message: message.into(),
        });
    }

    /// Report every item whose value was already seen; `items` yields `(path, value)`.
    fn unique<T: Hash + Eq + Display>(
        &mut self,
        what: &str,
        items: impl IntoIterator<Item = (String, T)>,
    ) {
        let mut seen = HashSet::new();
        for (path, value) in items {
            let message = format!("duplicate {what} {value}");
            if !seen.insert(value) {
                self.add(path, message);
            }
        }
    }

    fn non_empty(&mut self, path: &str, value: &str) {
        if value.is_empty() {
            self.add(path, "must not be empty");
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Linux interface name as used for `netdev`: 1..=15 of `[a-z0-9._-]`, not `.` or `..`.
fn valid_netdev(name: &str) -> bool {
    (1..=MAX_NETDEV_LEN).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
        && name != "."
        && name != ".."
}

fn check_netdev(issues: &mut Issues, path: &str, name: &str) {
    if !valid_netdev(name) {
        issues.add(
            path,
            format!("{name:?} must be 1..={MAX_NETDEV_LEN} characters of [a-z0-9._-]"),
        );
    }
}

/// `PARTLABEL=<name>` must name a partition of this board; other forms are not checked.
fn check_partlabel(board: &Board, issues: &mut Issues, path: &str, value: &str) {
    if let Some(name) = value.strip_prefix("PARTLABEL=")
        && !board.storage.partitions.iter().any(|p| p.name == name)
    {
        issues.add(path, format!("no partition named {name:?}"));
    }
}

/// `factory:<cell>` must name a cell of the factory partition. With `allow_offset` the
/// target may instead be a numeric byte offset (`factory:0x04`).
fn check_factory_ref(
    board: &Board,
    issues: &mut Issues,
    path: &str,
    value: &str,
    allow_offset: bool,
) {
    let Some(target) = value.strip_prefix("factory:") else {
        return;
    };
    if allow_offset && hex::parse_u64(target).is_ok() {
        return;
    }
    let factory = board
        .storage
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Factory);
    match factory {
        None => issues.add(
            path,
            "refers to the factory partition, but the board has none",
        ),
        Some(part) if !part.cells.iter().any(|c| c.name == target) => issues.add(
            path,
            format!("no cell named {target:?} in partition {:?}", part.name),
        ),
        Some(_) => {}
    }
}

pub(crate) fn validate(board: &Board) -> Result<(), Vec<ValidationIssue>> {
    let mut issues = Issues::default();
    identity(board, &mut issues);
    storage(board, &mut issues);
    ethernet(board, &mut issues);
    wifi(board, &mut issues);
    leds_and_buttons(board, &mut issues);
    if board.openwrt.target.is_empty() {
        issues.add("openwrt.target", "must not be empty");
    }
    issues.non_empty("openwrt.profile", &board.openwrt.profile);
    if issues.0.is_empty() {
        Ok(())
    } else {
        Err(issues.0)
    }
}

fn identity(board: &Board, issues: &mut Issues) {
    if board.schema != 1 {
        issues.add(
            "schema",
            format!("unsupported schema version {} (expected 1)", board.schema),
        );
    }
    if !valid_id(&board.board.id) {
        issues.add(
            "board.id",
            format!("{:?} must match ^[a-z0-9_-]+$", board.board.id),
        );
    }
    if board.soc.cores < 1 {
        issues.add("soc.cores", "must be at least 1");
    }
    if board.memory.ram_mib < MIN_RAM_MIB {
        issues.add(
            "memory.ram_mib",
            format!(
                "{} is below the minimum of {MIN_RAM_MIB}",
                board.memory.ram_mib
            ),
        );
    }
}

fn storage(board: &Board, issues: &mut Issues) {
    let storage = &board.storage;
    if storage.kind == StorageKind::Emmc {
        let rootfs = storage
            .partitions
            .iter()
            .filter(|p| p.role == PartitionRole::Rootfs)
            .count();
        if rootfs != 1 {
            issues.add(
                "storage.partitions",
                format!(
                    "emmc storage needs exactly one partition with role rootfs, found {rootfs}"
                ),
            );
        }
    }
    issues.unique(
        "partition name",
        storage
            .partitions
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("storage.partitions[{i}].name"), p.name.as_str())),
    );
    check_partlabel(board, issues, "storage.root", &storage.root);
    if let Some(overlay) = &storage.overlay {
        check_partlabel(board, issues, "storage.overlay", overlay);
    }
    for (i, part) in storage.partitions.iter().enumerate() {
        issues.unique(
            "cell name",
            part.cells.iter().enumerate().map(|(j, c)| {
                (
                    format!("storage.partitions[{i}].cells[{j}].name"),
                    c.name.as_str(),
                )
            }),
        );
    }
    for (i, part) in storage.partitions.iter().enumerate() {
        let Some(part_size) = part.size else { continue };
        for (j, cell) in part.cells.iter().enumerate() {
            let fits = cell
                .offset
                .checked_add(cell.size)
                .is_some_and(|end| end <= part_size);
            if !fits {
                issues.add(
                    format!("storage.partitions[{i}].cells[{j}]"),
                    format!(
                        "cell {:?} (offset {:#x}, size {:#x}) exceeds partition {:?} size {part_size:#x}",
                        cell.name, cell.offset, cell.size, part.name
                    ),
                );
            }
        }
    }
}

fn ethernet(board: &Board, issues: &mut Issues) {
    let eth = &board.ethernet;
    if eth.ports.is_empty() {
        issues.add("ethernet.ports", "at least one port is required");
    } else if !eth.ports.iter().any(|p| p.role == PortRole::Lan) {
        issues.add("ethernet.ports", "at least one lan port is required");
    }
    issues.unique(
        "port name",
        eth.ports
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("ethernet.ports[{i}].name"), p.name.as_str())),
    );
    issues.unique(
        "netdev",
        eth.ports
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("ethernet.ports[{i}].netdev"), p.netdev.as_str())),
    );
    issues.unique(
        "switch_port",
        eth.ports.iter().enumerate().filter_map(|(i, p)| {
            p.switch_port
                .map(|sp| (format!("ethernet.ports[{i}].switch_port"), sp))
        }),
    );
    check_factory_ref(board, issues, "ethernet.mac_source", &eth.mac_source, false);
    for (i, port) in eth.ports.iter().enumerate() {
        check_netdev(issues, &format!("ethernet.ports[{i}].netdev"), &port.netdev);
    }
    if let Some(sw) = &eth.switch {
        check_netdev(issues, "ethernet.switch.cpu_netdev", &sw.cpu_netdev);
        if eth.ports.iter().any(|p| p.netdev == sw.cpu_netdev) {
            issues.add(
                "ethernet.switch.cpu_netdev",
                format!("{:?} is also the netdev of a port", sw.cpu_netdev),
            );
        }
        if !SPEEDS_MBPS.contains(&sw.cpu_link_mbps) {
            issues.add(
                "ethernet.switch.cpu_link_mbps",
                format!("{} is not one of {SPEEDS_MBPS:?}", sw.cpu_link_mbps),
            );
        }
    }
    for (i, port) in eth.ports.iter().enumerate() {
        if !SPEEDS_MBPS.contains(&port.speed_mbps) {
            issues.add(
                format!("ethernet.ports[{i}].speed_mbps"),
                format!("{} is not one of {SPEEDS_MBPS:?}", port.speed_mbps),
            );
        }
        let Some(sp) = port.switch_port else { continue };
        let path = format!("ethernet.ports[{i}].switch_port");
        match &eth.switch {
            None => issues.add(path, "switch_port requires an [ethernet.switch] section"),
            Some(sw) if sw.cpu_port == sp => {
                issues.add(path, format!("{sp} is the switch cpu_port"));
            }
            Some(_) => {}
        }
    }
}

fn wifi(board: &Board, issues: &mut Issues) {
    let wifi = &board.wifi;
    if !wifi.driver.is_empty() && wifi.radios.is_empty() {
        issues.add("wifi.radios", "must not be empty when wifi.driver is set");
    }
    issues.unique(
        "radio id",
        wifi.radios
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("wifi.radios[{i}].id"), r.id.as_str())),
    );
    issues.unique(
        "phy_index",
        wifi.radios
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("wifi.radios[{i}].phy_index"), r.phy_index)),
    );
    if let Some(eeprom) = &wifi.eeprom {
        check_factory_ref(board, issues, "wifi.eeprom", eeprom, false);
    }
    if let Some(mac_source) = &wifi.mac_source {
        check_factory_ref(board, issues, "wifi.mac_source", mac_source, true);
    }
    for (i, radio) in wifi.radios.iter().enumerate() {
        if radio.standards.is_empty() {
            issues.add(format!("wifi.radios[{i}].standards"), "must not be empty");
        }
        let path = format!("wifi.radios[{i}].max_width_mhz");
        if !WIDTHS_MHZ.contains(&radio.max_width_mhz) {
            issues.add(
                path,
                format!("{} is not one of {WIDTHS_MHZ:?}", radio.max_width_mhz),
            );
        } else if radio.band == Band::G2 && radio.max_width_mhz > MAX_WIDTH_2G_MHZ {
            issues.add(
                path,
                format!(
                    "{} MHz is not possible on 2g (max {MAX_WIDTH_2G_MHZ})",
                    radio.max_width_mhz
                ),
            );
        }
    }
}

fn leds_and_buttons(board: &Board, issues: &mut Issues) {
    issues.unique(
        "led name",
        board
            .leds
            .iter()
            .enumerate()
            .map(|(i, l)| (format!("leds[{i}].name"), l.name.as_str())),
    );
    issues.unique(
        "led gpio",
        board
            .leds
            .iter()
            .enumerate()
            .map(|(i, l)| (format!("leds[{i}].gpio"), l.gpio)),
    );
    issues.unique(
        "button gpio",
        board
            .buttons
            .iter()
            .enumerate()
            .map(|(i, b)| (format!("buttons[{i}].gpio"), b.gpio)),
    );
    for (i, button) in board.buttons.iter().enumerate() {
        if button.long_press.is_some() && button.long_press_secs.is_none() {
            issues.add(
                format!("buttons[{i}].long_press_secs"),
                "required when long_press is set",
            );
        }
    }
}
