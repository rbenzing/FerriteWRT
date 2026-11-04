//! `owr-apply`: apply the configuration to the running system, or render what would be
//! applied. `render` and `check` are pure and work on any OS; `boot`, `apply` and `netd`
//! need Linux.

#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use owr_board::Board;
use owr_common::paths::{BOARD_FILE, CONFIG_FILE};
use owr_config::{Config, ConfigError, Store};

#[derive(Debug, Parser)]
#[command(
    name = "owr-apply",
    version,
    about = "Apply or render the ferritewrt configuration"
)]
struct Cli {
    /// Log verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "warn", global = true)]
    log: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// First boot: load the board, load or create the config, apply everything (Linux)
    Boot(Sources),
    /// Apply the existing config; never creates defaults (Linux)
    Apply(Sources),
    /// Print a rendered plan or daemon config without touching the system
    Render {
        #[arg(long, value_enum)]
        what: What,
        #[command(flatten)]
        sources: Sources,
    },
    /// Validate the config against the board and the mapping to plans
    Check(Sources),
    /// Run the network daemon (WAN DHCP client, IPv6 router advertisements) until
    /// SIGTERM; never creates defaults (Linux)
    Netd(Sources),
}

#[derive(Debug, Args)]
struct Sources {
    /// Board descriptor (default: the installed one)
    #[arg(long)]
    board: Option<PathBuf>,
    /// Config file (default: the installed one; `render` and `check` fall back to the
    /// board defaults when it does not exist)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum What {
    /// Network plan as JSON
    Net,
    /// nftables script
    Fw,
    /// Radio plans as JSON, passphrases redacted
    Wifi,
    /// dnsmasq.conf
    Dnsmasq,
    /// Network daemon plan as JSON (DHCP client, router advertisements)
    Netd,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Board(#[from] owr_board::BoardError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("configuration does not match the board:\n{}", .0.join("\n"))]
    Invalid(Vec<String>),
    #[error(transparent)]
    Map(#[from] owr_apply::MapError),
    #[error(transparent)]
    Render(#[from] owr_fw::RenderError),
    #[error("serializing output: {0}")]
    Json(#[from] serde_json::Error),
    #[cfg(target_os = "linux")]
    #[error("starting the async runtime: {0}")]
    Runtime(std::io::Error),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Apply(#[from] owr_apply::run::ApplyError),
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    #[error(
        "boot, apply and netd need Linux (netlink, nftables); use `render` or `check` on this host"
    )]
    NotLinux,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            if matches!(err, CliError::NotLinux) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Boot(src) => {
            ensure_linux()?;
            let board = load_board(&src)?;
            let store = Store::new(src.config.unwrap_or_else(|| PathBuf::from(CONFIG_FILE)));
            let (cfg, created) = store.load_or_default(&board)?;
            if created {
                tracing::info!(path = %store.path().display(), "first boot: wrote default config");
            }
            apply_on_system(&board, &cfg)
        }
        Command::Apply(src) => {
            ensure_linux()?;
            let (board, cfg) = load_for_apply(&src)?;
            apply_on_system(&board, &cfg)
        }
        Command::Netd(src) => {
            ensure_linux()?;
            let (board, cfg) = load_for_apply(&src)?;
            run_netd(board, cfg, &src)
        }
        Command::Render { what, sources } => {
            let (board, cfg) = load_readonly(sources)?;
            render(what, &board, &cfg)
        }
        Command::Check(sources) => {
            let (board, cfg) = load_readonly(sources)?;
            let plans = owr_apply::build_plans(&board, &cfg)?;
            for warning in &plans.warnings {
                eprintln!("warning: {warning}");
            }
            println!("ok");
            Ok(())
        }
    }
}

fn load_board(src: &Sources) -> Result<Board, CliError> {
    let path = src
        .board
        .clone()
        .unwrap_or_else(|| PathBuf::from(BOARD_FILE));
    Ok(Board::load(&path)?)
}

/// A real config is a few KiB; refuse to read anything larger into memory (same cap as
/// `owr_config::Store`).
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Read, migrate in memory and validate a config file without touching it. `Store::load`
/// would tighten permissions and write migrated configs back, which `render` and `check`
/// must never do (they run as any user, on a read-only rootfs or on someone else's file).
fn read_config_readonly(path: &Path) -> Result<Config, ConfigError> {
    let io_err = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(io_err)?
        .take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(io_err)?;
    if u64::try_from(text.len()).map_or(true, |len| len > MAX_CONFIG_BYTES) {
        return Err(io_err(std::io::Error::new(
            ErrorKind::InvalidData,
            "config file is larger than 1 MiB",
        )));
    }
    Config::from_toml_str(&text)
}

/// Board and config for the pure subcommands, validated against the board and never
/// written back. Without `--config` and without an installed config file the board
/// defaults are used.
/// Board and config for changing the system. Board-aware validation: a config that names
/// ports or radios the board does not have must not be applied.
fn load_for_apply(src: &Sources) -> Result<(Board, Config), CliError> {
    let board = load_board(src)?;
    let path = src
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILE));
    let cfg = Store::new(path).load_for(&board)?;
    Ok((board, cfg))
}

fn load_readonly(src: Sources) -> Result<(Board, Config), CliError> {
    let board = load_board(&src)?;
    let cfg = match src.config {
        Some(path) => read_config_readonly(&path)?,
        None => match read_config_readonly(Path::new(CONFIG_FILE)) {
            Err(ConfigError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
                Config::defaults_for(&board)
            }
            other => other?,
        },
    };
    cfg.validate_against(&board)
        .map_err(|issues| CliError::Invalid(issues.iter().map(ToString::to_string).collect()))?;
    Ok((board, cfg))
}

fn render(what: What, board: &Board, cfg: &Config) -> Result<(), CliError> {
    let plans = owr_apply::build_plans(board, cfg)?;
    match what {
        What::Net => println!("{}", serde_json::to_string_pretty(&plans.net)?),
        What::Fw => print!("{}", owr_fw::render(&plans.fw)?),
        What::Wifi => {
            let radios = owr_apply::redact_radios(&plans.radios);
            println!("{}", serde_json::to_string_pretty(&radios)?);
        }
        What::Dnsmasq => print!("{}", plans.dnsmasq_conf),
        What::Netd => println!("{}", serde_json::to_string_pretty(&plans.netd)?),
    }
    Ok(())
}

/// `boot`, `apply` and `netd` need netlink and nftables. (`cfg!` instead of two cfg'd functions: a
/// function that always returns `Ok` on Linux trips `clippy::unnecessary_wraps`.)
fn ensure_linux() -> Result<(), CliError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(CliError::NotLinux)
    }
}

#[cfg(target_os = "linux")]
fn apply_on_system(board: &Board, cfg: &Config) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    let paths = owr_apply::run::Paths::default();
    // Warnings go to stderr and do not change the exit code; the JSON outcome (also of a
    // failed apply, when it got that far) goes to stdout so the supervisor can still restart
    // the daemons whose files changed.
    match runtime.block_on(owr_apply::run::apply_all(board, cfg, &paths)) {
        Ok(outcome) => {
            print_outcome(&outcome)?;
            Ok(())
        }
        Err(err) => {
            if let Some(outcome) = err.partial_outcome() {
                print_outcome(outcome)?;
            }
            Err(err.into())
        }
    }
}

#[cfg(target_os = "linux")]
fn print_outcome(outcome: &owr_apply::run::ApplyOutcome) -> Result<(), CliError> {
    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    println!("{}", serde_json::to_string_pretty(outcome)?);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_on_system(_board: &Board, _cfg: &Config) -> Result<(), CliError> {
    Err(CliError::NotLinux)
}

#[cfg(target_os = "linux")]
fn run_netd(board: Board, cfg: Config, src: &Sources) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    let paths = owr_apply::run::Paths::default();
    let reload = || load_for_apply(src);
    Ok(runtime.block_on(owr_apply::daemon::run(board, cfg, reload, &paths))?)
}

#[cfg(not(target_os = "linux"))]
fn run_netd(_board: Board, _cfg: Config, _src: &Sources) -> Result<(), CliError> {
    Err(CliError::NotLinux)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Config {
        Config::defaults_for(&owr_board::builtin("glinet_gl-mt6000").unwrap())
    }

    #[test]
    fn readonly_load_parses_and_never_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = defaults().to_toml_string().unwrap();
        std::fs::write(&path, &text).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(read_config_readonly(&path).unwrap(), defaults());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        // No temp or backup files appear next to it either.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn readonly_load_reports_missing_files_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_config_readonly(&dir.path().join("absent.toml")).unwrap_err();
        assert!(
            matches!(err, ConfigError::Io { source, .. } if source.kind() == ErrorKind::NotFound)
        );
    }

    #[test]
    fn readonly_load_refuses_oversized_and_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.toml");
        std::fs::write(
            &big,
            vec![b'#'; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            read_config_readonly(&big),
            Err(ConfigError::Io { source, .. }) if source.kind() == ErrorKind::InvalidData
        ));
        let junk = dir.path().join("junk.toml");
        std::fs::write(&junk, "this is not = [valid").unwrap();
        assert!(read_config_readonly(&junk).is_err());
    }
}
