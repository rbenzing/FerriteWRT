//! `owr`: the ferritewrt command-line tool.
//!
//! Board descriptors, offline config bootstrap and validation, rendering of the plans that
//! `owr-apply` would apply, a combined `check`, and (on the router) `status` from init.
//! Command handlers live in [`commands`] and write to a `&mut dyn Write`, so they are tested
//! without spawning the binary.

#![forbid(unsafe_code)]

mod commands;
mod release;
mod status;
mod upgrade;

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand, ValueEnum};
use commands::{Env, Exit};
use owr_board::Board;
use owr_common::paths::{CONFIG_FILE, RELEASE_KEY_FILE};

#[derive(Debug, Parser)]
#[command(name = "owr", version, about = "ferritewrt router control tool")]
struct Cli {
    /// Log verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "warn", global = true)]
    log: String,
    /// Board descriptor TOML (default: /etc/ferritewrt/board.toml)
    // Not global: `owr release manifest` has its own `--board <id>`.
    #[arg(long, conflicts_with = "board_id")]
    board: Option<PathBuf>,
    /// Use the board descriptor compiled into this binary instead of a file
    #[arg(long, global = true)]
    board_id: Option<String>,
    /// Config file
    #[arg(long = "config", global = true, default_value = CONFIG_FILE)]
    config_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect and validate board descriptors
    Board {
        #[command(subcommand)]
        action: BoardAction,
    },
    /// Create, inspect and validate the system config
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Print what would be applied (nft script, daemon configs, plans)
    Render {
        what: What,
        /// JSON output (wifi, net, sysctl)
        #[arg(long)]
        json: bool,
        /// wifi: print passphrases instead of `***`
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// Validate board, config and the mapping to plans; print a summary
    Check,
    /// Build, sign and verify release artifacts
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// Service status from init (router only)
    Status {
        /// Print init's JSON reply unchanged
        #[arg(long)]
        json: bool,
    },
    /// Install a release bundle (router), or verify one with --check (anywhere)
    Upgrade {
        /// Directory holding the sysupgrade image, SHA256SUMS and SHA256SUMS.sig
        dir: PathBuf,
        /// Verify signature, hash, board and version only; change nothing
        #[arg(long)]
        check: bool,
        /// Accept a version older than the running one
        #[arg(long)]
        downgrade: bool,
        /// Reset all settings on the first boot of the new image
        #[arg(long)]
        wipe_settings: bool,
        /// Release public key (--check only; init always uses the installed one)
        #[arg(long, default_value = RELEASE_KEY_FILE)]
        pubkey: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReleaseAction {
    /// Generate a signing key pair (public key on stdout, `OWR_RELEASE_KEY=<seed>` on stderr)
    Keygen {
        /// Write release.pub and release.key (0600) into this directory instead
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Write <dir>/SHA256SUMS over all files except SHA256SUMS and SHA256SUMS.sig
    Sums { dir: PathBuf },
    /// Write <dir>/manifest.json (run before `sums`)
    Manifest {
        dir: PathBuf,
        /// Release version, MAJOR.MINOR.PATCH[-pre], no leading 'v'
        #[arg(long)]
        version: String,
        /// Board id, e.g. glinet_gl-mt6000
        #[arg(long)]
        board: String,
        /// `OpenWrt` git revision (default: unknown)
        #[arg(long)]
        openwrt_rev: Option<String>,
        /// ferritewrt git revision (default: unknown)
        #[arg(long)]
        ferritewrt_rev: Option<String>,
        /// Kernel version such as 6.18.3 (default: unknown)
        #[arg(long)]
        kernel: Option<String>,
        /// Build time, RFC 3339 (default: now, UTC)
        #[arg(long)]
        built_utc: Option<String>,
    },
    /// Sign <dir>/SHA256SUMS with the key in `OWR_RELEASE_KEY` (or `--key-file`)
    Sign {
        dir: PathBuf,
        /// File holding the 64-hex-char seed (mode 0600) instead of `OWR_RELEASE_KEY`
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Overwrite an existing SHA256SUMS.sig
        #[arg(long)]
        force: bool,
    },
    /// Verify the signature and the hashes of a release directory (or of single files in it)
    Verify {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Public key: 64 hex characters or a release.pub file
        #[arg(long)]
        pubkey: String,
        /// Do not fail when a listed file is absent
        #[arg(long)]
        allow_missing: bool,
    },
    /// Print the manifest summary of a release directory
    Show { dir: PathBuf },
}

#[derive(Debug, Subcommand)]
enum BoardAction {
    /// Print the installed (or given) board descriptor as JSON
    Show {
        /// Path to a board TOML; defaults to the installed descriptor
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Validate a board TOML file and report every issue
    Validate { file: PathBuf },
    /// List the boards compiled into this binary
    List,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Validate a config against the board; exit 1 and list every issue if invalid
    Validate {
        /// Config to validate (default: the global --config)
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Print the default config for the board as TOML (offline bootstrap)
    Defaults,
    /// Print the config with secrets redacted
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Write the default config if there is none ("created" or "exists")
    Init,
    /// Set a user's password from one line on stdin (creates the user as admin)
    SetPassword { user: String },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum What {
    Net,
    Fw,
    Wifi,
    Dnsmasq,
    Odhcpd,
    Sysctl,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error(transparent)]
    Board(#[from] owr_board::BoardError),
    #[error(transparent)]
    Config(#[from] owr_config::ConfigError),
    #[error("building plans: {0}")]
    Map(#[from] owr_apply::MapError),
    #[error(transparent)]
    Nft(#[from] owr_fw::RenderError),
    #[error(transparent)]
    Hostapd(#[from] owr_wifi::RenderError),
    #[error("serializing output: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Release(String),
    #[error(transparent)]
    Atomic(#[from] owr_common::AtomicWriteError),
    #[cfg_attr(unix, allow(dead_code))]
    #[error("this command requires the router")]
    NotRouter,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);
    match run(cli) {
        Ok(exit) => ExitCode::from(exit.code()),
        Err(CliError::NotRouter) => {
            let _ = writeln!(io::stdout(), "{}", CliError::NotRouter);
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
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

fn run(cli: Cli) -> Result<Exit, CliError> {
    let env = Env {
        board: cli.board,
        board_id: cli.board_id,
        config: cli.config_path,
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let out: &mut dyn io::Write = &mut out;
    match cli.command {
        Command::Board { action } => board(out, action).map(|()| Exit::Ok),
        Command::Config { action } => match action {
            ConfigAction::Validate { file } => {
                commands::config_validate(out, &env, file.as_deref())
            }
            ConfigAction::Defaults => commands::config_defaults(out, &env).map(|()| Exit::Ok),
            ConfigAction::Show { json } => {
                commands::config_show(out, &env, json).map(|()| Exit::Ok)
            }
            ConfigAction::Init => commands::config_init(out, &env).map(|()| Exit::Ok),
            ConfigAction::SetPassword { user } => {
                let stdin = io::stdin();
                commands::config_set_password(out, &env, &mut stdin.lock(), &user)
                    .map(|()| Exit::Ok)
            }
        },
        Command::Render {
            what,
            json,
            reveal_secrets,
        } => commands::render(out, &env, what, json, reveal_secrets).map(|()| Exit::Ok),
        Command::Check => commands::check(out, &env),
        Command::Status { json } => status::run(out, json).map(|()| Exit::Ok),
        Command::Upgrade {
            dir,
            check,
            downgrade,
            wipe_settings,
            pubkey,
        } => {
            let args = upgrade::Args {
                dir,
                allow_downgrade: downgrade,
                wipe_settings,
                pubkey,
            };
            if check {
                upgrade::check(out, &args, &env.board()?)
            } else {
                upgrade::install(out, &args)
            }
            .map(|()| Exit::Ok)
        }
        Command::Release { action } => release(out, action),
    }
}

fn release(out: &mut dyn io::Write, action: ReleaseAction) -> Result<Exit, CliError> {
    match action {
        ReleaseAction::Keygen { out: dir } => {
            let stderr = io::stderr();
            release::keygen(out, &mut stderr.lock(), dir.as_deref()).map(|()| Exit::Ok)
        }
        ReleaseAction::Sums { dir } => release::sums(out, &dir).map(|()| Exit::Ok),
        ReleaseAction::Manifest {
            dir,
            version,
            board,
            openwrt_rev,
            ferritewrt_rev,
            kernel,
            built_utc,
        } => {
            let args = release::ManifestArgs {
                version,
                board,
                openwrt_rev,
                ferritewrt_rev,
                kernel,
                built_utc,
            };
            release::manifest(out, &dir, &args, SystemTime::now()).map(|()| Exit::Ok)
        }
        ReleaseAction::Sign {
            dir,
            key_file,
            force,
        } => {
            let key =
                release::read_key_hex(key_file.as_deref(), std::env::var_os(release::KEY_ENV))?;
            release::sign(out, &dir, &key, force).map(|()| Exit::Ok)
        }
        ReleaseAction::Verify {
            paths,
            pubkey,
            allow_missing,
        } => release::verify(
            out,
            &release::VerifyArgs {
                paths,
                pubkey,
                allow_missing,
            },
        ),
        ReleaseAction::Show { dir } => release::show(out, &dir).map(|()| Exit::Ok),
    }
}

fn board(out: &mut dyn io::Write, action: BoardAction) -> Result<(), CliError> {
    match action {
        BoardAction::Show { file } => {
            let path = file.unwrap_or_else(|| PathBuf::from(owr_common::paths::BOARD_FILE));
            let board = Board::load(&path)?;
            writeln!(out, "{}", serde_json::to_string_pretty(&board)?)?;
        }
        BoardAction::Validate { file } => {
            let board = Board::load(&file)?;
            writeln!(
                out,
                "{}: valid ({} {}, {} ports, {} radios)",
                file.display(),
                board.board.vendor,
                board.board.model,
                board.ethernet.ports.len(),
                board.wifi.radios.len()
            )?;
        }
        BoardAction::List => {
            for (id, _) in owr_board::builtin_boards() {
                writeln!(out, "{id}")?;
            }
        }
    }
    Ok(())
}
