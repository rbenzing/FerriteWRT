//! Atomic on-disk persistence of the config.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};

use owr_board::Board;
use owr_common::{Outcome, atomic_write, paths};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{ConfigError, Issue};
use crate::model::Config;

/// File mode for the config: it holds password hashes and Wi-Fi passphrases.
const CONFIG_MODE: u32 = 0o600;
/// Directory mode for the config directory.
#[cfg(unix)]
const CONFIG_DIR_MODE: u32 = 0o700;
/// A real config is a few KiB; refuse to read anything larger into memory.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// A config file location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    path: PathBuf,
}

impl Default for Store {
    /// The production location, [`paths::CONFIG_FILE`].
    fn default() -> Self {
        Self::new(paths::CONFIG_FILE)
    }
}

/// How to validate a config on its way in or out of the store.
#[derive(Clone, Copy)]
enum Check<'a> {
    /// Self-consistency only ([`Config::validate`]).
    Own,
    /// Also against the hardware ([`Config::validate_against`]).
    Board(&'a Board),
}

impl Check<'_> {
    fn run(self, cfg: &Config) -> Result<(), ConfigError> {
        let result: Result<(), Vec<Issue>> = match self {
            Check::Own => cfg.validate(),
            Check::Board(board) => cfg.validate_against(board),
        };
        result.map_err(ConfigError::Invalid)
    }
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Store {
        Store { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read, migrate and validate the stored config for self-consistency only: ports and
    /// radios are not checked against a board. Prefer [`Store::load_for`] where the board is
    /// known.
    ///
    /// The file is capped at 1 MiB. On unix, group/other permission bits are removed with a
    /// warning. A config from an older schema is migrated and written back.
    pub fn load(&self) -> Result<Config, ConfigError> {
        self.load_checked(Check::Own)
    }

    /// Like [`Store::load`], but validates against `board` ([`Config::validate_against`]).
    pub fn load_for(&self, board: &Board) -> Result<Config, ConfigError> {
        self.load_checked(Check::Board(board))
    }

    /// Load the config, or if the file does not exist write board defaults and return
    /// them with `created = true`. The stored config is validated against `board`. Any other
    /// error (including an invalid file) is returned as-is: a broken config is never silently
    /// replaced.
    pub fn load_or_default(&self, board: &Board) -> Result<(Config, bool), ConfigError> {
        match self.load_for(board) {
            Ok(cfg) => Ok((cfg, false)),
            Err(ConfigError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
                let cfg = Config::defaults_for(board);
                self.save_for(&cfg, board)?;
                Ok((cfg, true))
            }
            Err(e) => Err(e),
        }
    }

    /// Validate for self-consistency only and atomically write the config (mode 0600).
    /// Returns [`Outcome::Unchanged`] if the file already holds identical content. Prefer
    /// [`Store::save_for`] where the board is known.
    pub fn save(&self, cfg: &Config) -> Result<Outcome, ConfigError> {
        Check::Own.run(cfg)?;
        self.persist(cfg)
    }

    /// Like [`Store::save`], but validates against `board` ([`Config::validate_against`]).
    pub fn save_for(&self, cfg: &Config, board: &Board) -> Result<Outcome, ConfigError> {
        Check::Board(board).run(cfg)?;
        self.persist(cfg)
    }

    /// SHA-256 (lowercase hex) of the canonical TOML, for idempotent-apply decisions.
    /// Covers secrets, so the digest changes when a password does: never expose this hash
    /// outside the device (it would let an observer confirm guesses of a secret-only change).
    pub fn content_hash(cfg: &Config) -> Result<String, ConfigError> {
        let canonical = Zeroizing::new(cfg.to_toml_string()?);
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(digest.iter().fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        }))
    }

    fn io_error(path: &Path, source: std::io::Error) -> ConfigError {
        ConfigError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn load_checked(&self, check: Check<'_>) -> Result<Config, ConfigError> {
        let text = self.read_text()?;
        let (cfg, migrated) = Config::parse_migrated(&text)?;
        check.run(&cfg)?;
        if migrated {
            tracing::info!(
                path = %self.path.display(),
                "config migrated to the current schema, rewriting"
            );
            self.persist(&cfg)?;
        }
        Ok(cfg)
    }

    /// Read the file (at most [`MAX_CONFIG_BYTES`]) into a zeroizing buffer.
    fn read_text(&self) -> Result<Zeroizing<String>, ConfigError> {
        let mut file = File::open(&self.path).map_err(|e| Self::io_error(&self.path, e))?;
        let meta = file.metadata().map_err(|e| Self::io_error(&self.path, e))?;
        if meta.len() > MAX_CONFIG_BYTES {
            return Err(Self::too_large(&self.path));
        }
        restrict_permissions(&self.path, &file, &meta);
        let capacity = usize::try_from(meta.len()).unwrap_or(0).saturating_add(1);
        let mut text = Zeroizing::new(String::with_capacity(capacity));
        // The file may grow between the metadata call and the read; the limit still holds.
        (&mut file)
            .take(MAX_CONFIG_BYTES.saturating_add(1))
            .read_to_string(&mut text)
            .map_err(|e| Self::io_error(&self.path, e))?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
            return Err(Self::too_large(&self.path));
        }
        Ok(text)
    }

    fn too_large(path: &Path) -> ConfigError {
        Self::io_error(
            path,
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("config file is larger than {MAX_CONFIG_BYTES} bytes"),
            ),
        )
    }

    /// Serialize and atomically write an already validated config.
    fn persist(&self, cfg: &Config) -> Result<Outcome, ConfigError> {
        let text = Zeroizing::new(cfg.to_toml_string()?);
        if let Some(dir) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(dir).map_err(|e| Self::io_error(dir, e))?;
        }
        Ok(atomic_write(&self.path, text.as_bytes(), CONFIG_MODE)?)
    }
}

/// Create `dir` and missing parents; on unix new directories get mode 0700.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(CONFIG_DIR_MODE);
    }
    builder.create(dir)
}

/// Best effort: if the config is readable by group or others, say so and chmod it to 0600.
/// Failing to chmod is logged, not fatal: the device must still boot.
#[cfg(unix)]
fn restrict_permissions(path: &Path, file: &File, meta: &std::fs::Metadata) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode() & 0o777;
    // No group/other bits: the low six bits (0o077) are all clear.
    if mode.trailing_zeros() >= 6 {
        return;
    }
    tracing::warn!(
        path = %path.display(),
        mode = format_args!("{mode:o}"),
        "config file is accessible by group/others, restricting to 0600"
    );
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(CONFIG_MODE)) {
        tracing::warn!(path = %path.display(), %error, "could not restrict config file permissions");
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _file: &File, _meta: &std::fs::Metadata) {}
