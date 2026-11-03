//! Well-known filesystem locations. Keep every path authoritative here.

/// Directory holding all ferritewrt configuration.
pub const CONFIG_DIR: &str = "/etc/ferritewrt";
/// Installed board descriptor (copy of `boards/<id>.toml`).
pub const BOARD_FILE: &str = "/etc/ferritewrt/board.toml";
/// Persistent, user-editable system configuration.
pub const CONFIG_FILE: &str = "/etc/ferritewrt/config.toml";
/// Runtime state (tmpfs): rendered daemon configs, sockets, pid files.
pub const RUN_DIR: &str = "/run/ferritewrt";
/// Persistent TLS material for the management API.
pub const TLS_DIR: &str = "/etc/ferritewrt/tls";
/// Append-only audit log of mutating management actions.
pub const AUDIT_LOG: &str = "/etc/ferritewrt/audit.log";
