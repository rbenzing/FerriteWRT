//! Well-known filesystem locations. Keep every path authoritative here.

/// Directory holding all ferritewrt configuration.
pub const CONFIG_DIR: &str = "/etc/ferritewrt";
/// Installed board descriptor (copy of `boards/<id>.toml`).
pub const BOARD_FILE: &str = "/etc/ferritewrt/board.toml";
/// Release signing public key (`keys/release.pub`), installed by the image build. Image
/// content, deliberately outside [`CONFIG_DIR`]: settings survive an upgrade, the key must
/// come from the new image.
pub const RELEASE_KEY_FILE: &str = "/usr/share/ferritewrt/release.pub";
/// Persistent, user-editable system configuration.
pub const CONFIG_FILE: &str = "/etc/ferritewrt/config.toml";
/// Runtime state (tmpfs): rendered daemon configs, sockets, pid files.
pub const RUN_DIR: &str = "/run/ferritewrt";
/// pppd options of a `PPPoE` WAN, inside [`RUN_DIR`] (0600: it holds the password). Written
/// by owr-apply; its presence is what makes owr-init start pppd.
pub const PPPOE_CONF: &str = "pppoe-wan.conf";
/// The ISP's DNS servers as pppd writes them, inside [`RUN_DIR`]. pppd's path is fixed at
/// `/etc/ppp/resolv.conf`; the image build makes that a symlink to this file.
pub const PPP_RESOLV: &str = "resolv.conf.ppp";
/// Persistent TLS material for the management API.
pub const TLS_DIR: &str = "/etc/ferritewrt/tls";
/// Append-only audit log of mutating management actions.
pub const AUDIT_LOG: &str = "/etc/ferritewrt/audit.log";
