//! `owr-init` binary entry point. All logic lives in the library.

#![forbid(unsafe_code)]
// A failing `eprintln!` panics; see the library crate root.
#![deny(clippy::print_stderr, clippy::print_stdout)]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    owr_init::linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "owr-init only runs on Linux");
    std::process::ExitCode::from(1)
}
