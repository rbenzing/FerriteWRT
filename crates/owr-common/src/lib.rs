//! Shared primitives for ferritewrt.
//!
//! Deliberately tiny: atomic file persistence and well-known filesystem paths.
//! Anything domain-specific belongs in a domain crate.

#![forbid(unsafe_code)]

pub mod atomic;
pub mod paths;

pub use atomic::{AtomicWriteError, Outcome, atomic_write};
