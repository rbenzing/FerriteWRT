//! `owr-init`: PID 1 for ferritewrt routers.
//!
//! The library holds pure, host-testable state machines and parsers (service supervision,
//! journal, button classification, mount planning, boot decisions, uevent and control
//! protocol parsing). The Linux-only runtime that wires them to the kernel lives in
//! [`linux`] behind `#[cfg(target_os = "linux")]`.

#![forbid(unsafe_code)]
// `print!`/`eprintln!` panic when the write fails (EIO on a dead console), and a panic in PID 1
// is a kernel panic. Use `linux::console_log` (or `let _ = writeln!(..)`) instead.
#![deny(clippy::print_stderr, clippy::print_stdout)]

pub mod args;
pub mod boot;
pub mod button;
pub mod client;
pub mod coldplug;
pub mod control;
pub mod journal;
pub mod led;
pub mod manager;
pub mod mounts;
pub mod sandbox;
pub mod service;
pub mod services;
pub mod uevent;
pub mod watchdog;

#[cfg(target_os = "linux")]
pub mod linux;
