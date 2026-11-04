//! Command line of the `owr-init` binary (pure).
//!
//! * no arguments: run as PID 1
//! * `--test-mode <dir> [--services <file>]`: run the supervisor loop as an ordinary process
//! * `--sandbox <profile> -- <argv>`: confine this process, then exec `argv` (see
//!   [`crate::sandbox`]); used by init to start the network daemons
//! * `--help`

use std::path::PathBuf;

use crate::sandbox::SANDBOX_FLAG;

pub const USAGE: &str = "usage: owr-init [--test-mode <dir> [--services <file>]]\n\
  (no arguments)        run as PID 1\n\
  --test-mode <dir>     supervisor loop only: no mounts, watchdog or PID 1 checks;\n\
                        run dir, control socket and journal live in <dir>\n\
  --services <file>     services TOML for --test-mode (default <dir>/services.toml)\n\
  --sandbox <profile> -- <program> [args]\n\
                        confine this process with <profile>, then exec <program>\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cli {
    Pid1,
    Test {
        dir: PathBuf,
        services: Option<PathBuf>,
    },
    Sandbox {
        profile: String,
        argv: Vec<String>,
    },
    Help,
}

/// `--sandbox <profile> -- <absolute program> [args]` (everything after `--` is the program).
fn parse_sandbox<'a>(mut it: impl Iterator<Item = &'a str>) -> Result<Cli, String> {
    let profile = it.next().ok_or("--sandbox needs a profile")?.to_owned();
    if it.next() != Some("--") {
        return Err("--sandbox <profile> must be followed by -- and the program".to_owned());
    }
    let argv: Vec<String> = it.map(str::to_owned).collect();
    match argv.first() {
        Some(program) if program.starts_with('/') => Ok(Cli::Sandbox { profile, argv }),
        Some(_) => Err("--sandbox: the program must be an absolute path".to_owned()),
        None => Err("--sandbox: no program after --".to_owned()),
    }
}

/// Parse arguments (without `argv[0]`).
pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<Cli, String> {
    let mut it = args.iter().map(AsRef::as_ref);
    if args.first().map(AsRef::as_ref) == Some(SANDBOX_FLAG) {
        it.next();
        return parse_sandbox(it);
    }
    let mut dir = None;
    let mut services = None;
    while let Some(arg) = it.next() {
        match arg {
            "--help" | "-h" => return Ok(Cli::Help),
            "--test-mode" => {
                let d = it.next().ok_or("--test-mode needs a directory")?;
                dir = Some(PathBuf::from(d));
            }
            "--services" => {
                let f = it.next().ok_or("--services needs a file")?;
                services = Some(PathBuf::from(f));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    match (dir, services) {
        (None, None) => Ok(Cli::Pid1),
        (Some(dir), services) => Ok(Cli::Test { dir, services }),
        (None, Some(_)) => Err("--services requires --test-mode".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_sandbox_launcher() {
        assert_eq!(
            parse_args(&[
                "--sandbox",
                "dnsmasq",
                "--",
                "/usr/sbin/dnsmasq",
                "-k",
                "--test"
            ]),
            Ok(Cli::Sandbox {
                profile: "dnsmasq".into(),
                argv: vec!["/usr/sbin/dnsmasq".into(), "-k".into(), "--test".into()],
            })
        );
        for bad in [
            &["--sandbox"][..],
            &["--sandbox", "dnsmasq"],
            &["--sandbox", "dnsmasq", "--"],
            &["--sandbox", "dnsmasq", "/usr/sbin/dnsmasq"],
            &["--sandbox", "dnsmasq", "--", "dnsmasq"],
        ] {
            assert!(parse_args(bad).is_err(), "{bad:?}");
        }
        assert!(
            parse_args(&["--test-mode", "/d", "--sandbox", "x"]).is_err(),
            "only as the first argument"
        );
    }

    #[test]
    fn parses_modes() {
        assert_eq!(parse_args::<&str>(&[]), Ok(Cli::Pid1));
        assert_eq!(parse_args(&["--help"]), Ok(Cli::Help));
        assert_eq!(
            parse_args(&["--test-mode", "/tmp/x"]),
            Ok(Cli::Test {
                dir: "/tmp/x".into(),
                services: None
            })
        );
        assert_eq!(
            parse_args(&["--test-mode", "/d", "--services", "/s.toml"]),
            Ok(Cli::Test {
                dir: "/d".into(),
                services: Some("/s.toml".into())
            })
        );
        assert_eq!(
            parse_args(&["--services", "/s.toml", "--test-mode", "/d"]),
            Ok(Cli::Test {
                dir: "/d".into(),
                services: Some("/s.toml".into())
            })
        );
    }

    #[test]
    fn rejects_bad_usage() {
        assert!(parse_args(&["--test-mode"]).is_err());
        assert!(parse_args(&["--test-mode", "/d", "--services"]).is_err());
        assert!(parse_args(&["--services", "/s"]).is_err());
        assert!(parse_args(&["--bogus"]).is_err());
        // The kernel may append unknown args after `--`; init refuses to guess.
        assert!(parse_args(&["quiet"]).is_err());
    }
}
