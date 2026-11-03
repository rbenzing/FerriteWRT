//! TOML encode/decode and schema migration.

use crate::error::{ConfigError, Issue};
use crate::model::{CURRENT_SCHEMA, Config};

/// One migration step rewrites a schema-N table into schema-N+1. `MIGRATIONS[0]` upgrades
/// schema 1 to 2, and so on; its length must stay `CURRENT_SCHEMA - 1`.
type Migration = fn(&mut toml::Table) -> Result<(), ConfigError>;
const MIGRATIONS: [Migration; 0] = [];

// Bumping CURRENT_SCHEMA without adding the migration must not compile.
const _: () = assert!(MIGRATIONS.len() == (CURRENT_SCHEMA as usize) - 1);

impl Config {
    /// Parse TOML text, migrate it to the current schema and validate it (no board).
    ///
    /// Parse errors name the field path but never echo the offending value, which may be a
    /// secret.
    pub fn from_toml_str(s: &str) -> Result<Config, ConfigError> {
        let (cfg, _migrated) = Self::parse_migrated(s)?;
        cfg.validate().map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// Canonical TOML: struct field order, so equal configs give identical text.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string(self)?)
    }

    /// Parse and migrate without validating. The flag is true if a migration ran, i.e. the
    /// text was an older schema than [`CURRENT_SCHEMA`].
    pub(crate) fn parse_migrated(s: &str) -> Result<(Config, bool), ConfigError> {
        let value: toml::Value = toml::from_str(s)?;
        Self::migrate(value)
    }

    /// Upgrade a parsed config document to [`CURRENT_SCHEMA`] and deserialize it. The flag
    /// is true if any migration step ran. Does not run [`Config::validate`].
    pub(crate) fn migrate(value: toml::Value) -> Result<(Config, bool), ConfigError> {
        let toml::Value::Table(mut table) = value else {
            return Err(ConfigError::Invalid(vec![Issue::new(
                "",
                "config must be a TOML table",
            )]));
        };
        let schema = match table.get("schema") {
            Some(toml::Value::Integer(n)) => u32::try_from(*n)
                .map_err(|_| ConfigError::Invalid(vec![Issue::new("schema", "out of range")]))?,
            Some(_) => {
                return Err(ConfigError::Invalid(vec![Issue::new(
                    "schema",
                    "must be an integer",
                )]));
            }
            None => return Err(ConfigError::Invalid(vec![Issue::new("schema", "missing")])),
        };
        if schema == 0 || schema > CURRENT_SCHEMA {
            return Err(ConfigError::UnsupportedSchema(schema));
        }
        for from in schema..CURRENT_SCHEMA {
            let step = usize::try_from(from.saturating_sub(1))
                .ok()
                .and_then(|i| MIGRATIONS.get(i))
                .ok_or(ConfigError::UnsupportedSchema(schema))?;
            step(&mut table)?;
            table.insert(
                "schema".to_owned(),
                toml::Value::Integer(i64::from(from.saturating_add(1))),
            );
        }
        let cfg = serde_path_to_error::deserialize(toml::Value::Table(table))
            .map_err(|e| ConfigError::from_path_error(&e))?;
        Ok((cfg, schema < CURRENT_SCHEMA))
    }
}
