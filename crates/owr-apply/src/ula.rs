//! The persistent site ULA prefix (RFC 4193): `fd00::/8` plus 40 random bits, a /48.
//!
//! [`crate::build_plans_with`] is pure, so the prefix enters through [`crate::Inputs`];
//! this module loads it from (or creates it in) a file. The file must survive reboots and
//! firmware upgrades (`/etc/ferritewrt/ula-prefix`), otherwise every boot would renumber
//! the LAN. Subnet 0 of the /48 is `br-lan`, a VLAN uses its VLAN id as subnet.

use std::io::{self, Read};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

use ipnet::Ipv6Net;
use owr_common::paths::CONFIG_DIR;
use owr_common::{AtomicWriteError, atomic_write};
use tracing::{info, warn};

/// File name of the prefix below the config directory.
pub const ULA_FILE: &str = "ula-prefix";
/// Length of the site prefix.
pub const ULA_PREFIX_LEN: u8 = 48;
/// Mode of the prefix file; the prefix is not a secret.
const ULA_MODE: u32 = 0o644;
/// Entropy source of [`os_random`].
const URANDOM: &str = "/dev/urandom";

/// Failure loading or creating the ULA prefix.
#[derive(Debug, thiserror::Error)]
pub enum UlaError {
    #[error("reading random bits: {0}")]
    Random(#[source] io::Error),
    #[error("{context}: {source}")]
    Io { context: String, source: io::Error },
    #[error(transparent)]
    Write(#[from] AtomicWriteError),
    #[error("cannot build a /{ULA_PREFIX_LEN} prefix")]
    Prefix,
}

/// Production location of the prefix file.
pub fn default_path() -> PathBuf {
    Path::new(CONFIG_DIR).join(ULA_FILE)
}

/// `fd` followed by the 40 bits in `bits`, as a /48.
pub fn prefix_from_random(bits: [u8; 5]) -> Result<Ipv6Net, UlaError> {
    let [b0, b1, b2, b3, b4] = bits;
    let addr = Ipv6Addr::from([0xfd, b0, b1, b2, b3, b4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    Ipv6Net::new(addr, ULA_PREFIX_LEN).map_err(|_| UlaError::Prefix)
}

/// Whether `prefix` is a well-formed site prefix: inside `fd00::/8`, a /48 with no host bits.
fn is_site_prefix(prefix: &Ipv6Net) -> bool {
    let [first, ..] = prefix.addr().segments();
    first >> 8 == 0xfd && prefix.prefix_len() == ULA_PREFIX_LEN && prefix.addr() == prefix.network()
}

/// 40 random bits from the kernel.
pub fn os_random() -> io::Result<[u8; 5]> {
    let mut bits = [0u8; 5];
    std::fs::File::open(URANDOM)?.read_exact(&mut bits)?;
    Ok(bits)
}

/// Load the prefix stored in `path`, or generate one with `random` and store it.
/// Returns the prefix and whether it was created. An unparsable or malformed file is
/// replaced (with a warning): the device must come up even if the file was damaged.
pub fn load_or_create(
    path: &Path,
    random: impl FnOnce() -> io::Result<[u8; 5]>,
) -> Result<(Ipv6Net, bool), UlaError> {
    match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<Ipv6Net>() {
            Ok(prefix) if is_site_prefix(&prefix) => return Ok((prefix, false)),
            _ => warn!(
                path = %path.display(),
                "ULA prefix file is malformed; generating a new prefix"
            ),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(UlaError::Io {
                context: format!("reading {}", path.display()),
                source,
            });
        }
    }
    let prefix = prefix_from_random(random().map_err(UlaError::Random)?)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| UlaError::Io {
            context: format!("creating {}", dir.display()),
            source,
        })?;
    }
    atomic_write(path, format!("{prefix}\n").as_bytes(), ULA_MODE)?;
    info!(%prefix, path = %path.display(), "generated a new ULA prefix");
    Ok((prefix, true))
}
