//! `owr-api`: HTTPS management API and embedded web UI host.
//!
//! Replaces uhttpd + rpcd + the `LuCI` backend. The crate talks to the rest of the system
//! only through the [`backend::SystemBackend`] trait; `real::RealBackend` (Linux only) is the real
//! implementation on top of `owr-apply` and friends, [`mock::MockBackend`] a development/test one.

#![forbid(unsafe_code)]

mod app;
pub mod audit;
pub mod backend;
pub mod document;
pub mod dto;
mod error;
mod middleware;
pub mod mock;
pub mod password;
pub mod procfs;
#[cfg(target_os = "linux")]
pub mod real;
mod routes;
pub mod secrets;
pub mod server;
pub mod session;
pub mod tls;
pub mod ui;
mod upgrade;
pub mod view;

pub use backend::{BackendResult, BoxFuture, SystemBackend};
pub use server::{ServeError, ServerConfig, TlsConfig, router, serve, serve_on};
