//! Shared primitives for ferritewrt.
//!
//! Deliberately tiny: atomic file persistence, well-known filesystem paths and the text forms of
//! durations and timestamps.
//! Anything domain-specific belongs in a domain crate.

#![forbid(unsafe_code)]

pub mod atomic;
pub mod paths;
pub mod time;

pub use atomic::{AtomicWriteError, Outcome, atomic_write};
