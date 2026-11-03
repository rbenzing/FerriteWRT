//! Board descriptor schema, loader, validation and queries.
//!
//! `boards/<id>.toml` is the single source of truth about the hardware. Parsing rejects unknown
//! fields; [`Board::validate`] checks cross-field invariants and reports every issue at once.

mod error;
mod hex;
mod schema;
mod validate;

use std::path::Path;

pub use error::{BoardError, ValidationIssue};
pub use schema::{
    Band, Board, Button, ButtonAction, Cell, Console, Ethernet, EthernetPort, Identity, Led,
    LedRole, Memory, OpenWrt, Partition, PartitionRole, Phy, PortRole, Radio, Soc, Storage,
    StorageKind, Switch, Usb, UsbController, Wifi, WifiStandard,
};

/// The GL.iNet Flint 2 descriptor, embedded at compile time.
pub const GL_MT6000_TOML: &str = include_str!("../../../boards/glinet_gl-mt6000.toml");

const BUILTIN_BOARDS: &[(&str, &str)] = &[("glinet_gl-mt6000", GL_MT6000_TOML)];

/// All embedded board descriptors as `(id, toml)`.
pub fn builtin_boards() -> &'static [(&'static str, &'static str)] {
    BUILTIN_BOARDS
}

/// Load an embedded board by id. Fails with [`BoardError::UnknownBoard`] for an unknown id, or
/// with the parse/validation error of the descriptor (prevented by this crate's tests, but never
/// swallowed).
pub fn builtin(id: &str) -> Result<Board, BoardError> {
    let (_, toml) = BUILTIN_BOARDS
        .iter()
        .find(|(bid, _)| *bid == id)
        .ok_or_else(|| BoardError::UnknownBoard(id.to_owned()))?;
    Board::from_toml_str(toml)
}

impl Board {
    /// Parse a descriptor and validate it.
    pub fn from_toml_str(s: &str) -> Result<Board, BoardError> {
        let board: Board = toml::from_str(s)?;
        board.validate().map_err(BoardError::Invalid)?;
        Ok(board)
    }

    /// Read, parse and validate a descriptor file.
    pub fn load(path: &Path) -> Result<Board, BoardError> {
        let text = std::fs::read_to_string(path).map_err(|source| BoardError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Check cross-field invariants; returns every issue found.
    pub fn validate(&self) -> Result<(), Vec<ValidationIssue>> {
        validate::validate(self)
    }

    pub fn lan_ports(&self) -> impl Iterator<Item = &EthernetPort> {
        self.ethernet
            .ports
            .iter()
            .filter(|p| p.role == PortRole::Lan)
    }

    pub fn wan_ports(&self) -> impl Iterator<Item = &EthernetPort> {
        self.ethernet
            .ports
            .iter()
            .filter(|p| p.role == PortRole::Wan)
    }

    pub fn port(&self, name: &str) -> Option<&EthernetPort> {
        self.ethernet.ports.iter().find(|p| p.name == name)
    }

    pub fn radio(&self, id: &str) -> Option<&Radio> {
        self.wifi.radios.iter().find(|r| r.id == id)
    }

    pub fn leds_with_role(&self, role: LedRole) -> impl Iterator<Item = &Led> {
        self.leds.iter().filter(move |l| l.roles.contains(&role))
    }
}
