//! Command line of the `owr-init` binary (pure).
//!
//! * no arguments: run as PID 1
//! * `--test-mode <dir> [--services <file>]`: run the supervisor loop as an ordinary process
//! * `--help`

use std::path::PathBuf;

pub const USAGE: &str = "usage: owr-init [--test-mode <dir> [--services <file>]]\n\
  (no arguments)        run as PID 1\n\
  --test-mode <dir>     supervisor loop only: no mounts, watchdog or PID 1 checks;\n\
                        run dir, control socket and journal live in <dir>\n\
  --services <file>     services TOML for --test-mode (default <dir>/services.toml)\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cli {
    Pid1,
    Test {
        dir: PathBuf,
        services: Option<PathBuf>,
    },
    Help,
}

/// Parse arguments (without `argv[0]`).
pub fn parse_args<S: AsRef<str>>(args: &[S]) -> Result<Cli, String> {
    let mut it = args.iter().map(AsRef::as_ref);
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
