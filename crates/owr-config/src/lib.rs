//! Typed, versioned system configuration for ferritewrt.
//!
//! The config file is TOML with a `schema` version. [`Config::from_toml_str`] parses,
//! migrates and validates in one step; [`Store`] persists it atomically with mode 0600.
//! Validation is total: a config is either fully valid or rejected with every
//! field-path [`Issue`] found.

#![forbid(unsafe_code)]

mod board;
mod codec;
mod error;
mod model;
mod store;
mod types;
mod validate;

pub use error::{ConfigError, Issue};
pub use model::*;
pub use store::Store;
pub use types::{MacAddr, ParseError, PortRange, Secret};

#[cfg(test)]
mod tests;
