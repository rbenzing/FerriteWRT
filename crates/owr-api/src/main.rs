//! `owr-api` binary: HTTPS management API + web UI.
//!
//! Production (no `--dev`, Linux only) serves the real backend over HTTPS on the LAN
//! address. `--dev` serves the in-memory mock backend over plain HTTP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use owr_api::mock::MockBackend;
use owr_api::tls::{self, CERT_FILE, KEY_FILE};
use owr_api::{ServerConfig, TlsConfig, serve};

const DEV_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
const SESSION_TTL: Duration = Duration::from_mins(30);
/// Firmware upload directory below the run directory (production).
#[cfg(target_os = "linux")]
const UPLOAD_DIR: &str = "upgrade-upload";

/// ferritewrt management API and web UI.
#[derive(Debug, Parser)]
#[command(version, about)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Args {
    /// Listen address [default: 127.0.0.1:8080 with --dev, otherwise the LAN address from the
    /// configuration on the configured API port (443)].
    #[arg(long)]
    bind: Option<SocketAddr>,
    /// Directory holding server.key / server.crt, generated when missing
    /// [default: /etc/ferritewrt/tls]. With --dev, TLS is only used if this is given.
    #[arg(long)]
    tls_dir: Option<PathBuf>,
    /// Serve plain HTTP (only allowed together with --dev).
    #[arg(long)]
    no_tls: bool,
    /// Development mode: in-memory mock backend, plain HTTP, audit log in the temp dir.
    #[arg(long)]
    dev: bool,
    /// Serve the UI from this directory instead of the embedded copy.
    #[arg(long)]
    ui_dir: Option<PathBuf>,
    /// Run directory with daemon configs and sockets [default: /run/ferritewrt].
    #[arg(long)]
    run_dir: Option<PathBuf>,
    /// init control socket [default: <run-dir>/init.sock].
    #[arg(long)]
    init_sock: Option<PathBuf>,
    /// The nft binary [default: /usr/sbin/nft].
    #[arg(long)]
    nft: Option<PathBuf>,
    /// Board descriptor [default: /etc/ferritewrt/board.toml].
    #[arg(long)]
    board: Option<PathBuf>,
    /// Configuration file [default: /etc/ferritewrt/config.toml].
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    if args.no_tls && !args.dev {
        eprintln!("--no-tls is only allowed together with --dev");
        return ExitCode::from(2);
    }
    #[cfg(not(target_os = "linux"))]
    if !args.dev {
        eprintln!("production backend requires Linux");
        return ExitCode::from(2);
    }
    tls::install_crypto_provider();
    #[cfg(target_os = "linux")]
    let result = if args.dev {
        run_dev(args).await
    } else {
        run_production(args).await
    };
    #[cfg(not(target_os = "linux"))]
    let result = run_dev(args).await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("owr-api: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Make sure a certificate exists in `dir` (listing `sans`), print its fingerprint and
/// return where the server finds it.
fn tls_config(dir: &Path, sans: &[String]) -> Result<TlsConfig, String> {
    let (cert, _key) = tls::ensure_cert(dir, sans).map_err(|e| e.to_string())?;
    eprintln!(
        "TLS certificate SHA-256 fingerprint: {}",
        tls::fingerprint_sha256(&cert)
    );
    Ok(TlsConfig {
        cert_path: dir.join(CERT_FILE),
        key_path: dir.join(KEY_FILE),
    })
}

async fn run_server(config: ServerConfig) -> Result<(), String> {
    tokio::select! {
        result = serve(config) => result.map_err(|e| e.to_string()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

async fn run_dev(args: Args) -> Result<(), String> {
    let bind = args.bind.unwrap_or(DEV_BIND);
    let tls = match (&args.tls_dir, args.no_tls) {
        (Some(dir), false) => Some(tls_config(dir, &["127.0.0.1".to_owned()])?),
        _ => None,
    };
    let audit_log_path = std::env::temp_dir().join("owr-api-dev-audit.log");
    let upload_dir =
        std::env::temp_dir().join(format!("owr-api-dev-upgrade-{}", std::process::id()));
    eprintln!(
        "owr-api --dev: mock backend on {}://{bind}/ (audit log: {})",
        if tls.is_some() { "https" } else { "http" },
        audit_log_path.display()
    );
    run_server(ServerConfig {
        bind,
        tls,
        session_ttl: SESSION_TTL,
        backend: Arc::new(MockBackend::new()),
        ui_enabled: true,
        ui_dir: args.ui_dir,
        audit_log_path,
        upload_dir,
    })
    .await
}

#[cfg(target_os = "linux")]
async fn run_production(args: Args) -> Result<(), String> {
    use owr_api::real::{RealBackend, RealConfig};
    use owr_common::paths::{AUDIT_LOG, TLS_DIR};

    let mut real = args
        .run_dir
        .map_or_else(RealConfig::default, RealConfig::with_run_dir);
    if let Some(sock) = args.init_sock {
        real.init_sock = sock;
    }
    if let Some(nft) = args.nft {
        real.nft_bin = nft;
    }
    if let Some(board) = args.board {
        real.board_path = board;
    }
    if let Some(config) = args.config {
        real.config_path = config;
    }
    // Uploads live in RAM (tmpfs): drop whatever a previous run of the API left behind.
    let upload_dir = real.run_dir.join(UPLOAD_DIR);
    if let Err(e) = std::fs::remove_dir_all(&upload_dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(dir = %upload_dir.display(), error = %e, "removing old upgrade uploads failed");
    }
    let backend = RealBackend::new(real).map_err(|e| format!("loading the board: {e}"))?;
    let info = backend.startup();
    let (lan_ip, hostname, port, session_ttl) = match &info {
        Ok(i) => (
            Some(i.lan_ipv4),
            Some(i.hostname.clone()),
            i.api_port,
            i.session_ttl,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "configuration unusable; falling back to 0.0.0.0:443");
            (None, None, 443, SESSION_TTL)
        }
    };
    let bind = args.bind.unwrap_or_else(|| {
        SocketAddr::new(IpAddr::V4(lan_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)), port)
    });
    let tls_dir = args.tls_dir.unwrap_or_else(|| PathBuf::from(TLS_DIR));
    let sans: Vec<String> = lan_ip
        .map(|ip| ip.to_string())
        .into_iter()
        .chain(hostname)
        .collect();
    let tls = tls_config(&tls_dir, &sans)?;
    eprintln!("owr-api: listening on https://{bind}/");
    run_server(ServerConfig {
        bind,
        tls: Some(tls),
        session_ttl,
        backend: Arc::new(backend),
        ui_enabled: true,
        ui_dir: args.ui_dir,
        audit_log_path: PathBuf::from(AUDIT_LOG),
        upload_dir,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses() {
        let a = Args::try_parse_from([
            "owr-api",
            "--dev",
            "--bind",
            "127.0.0.1:9000",
            "--ui-dir",
            "x",
        ])
        .unwrap();
        assert!(a.dev && a.bind.is_some() && a.ui_dir.is_some());
        assert!(Args::try_parse_from(["owr-api", "--bogus"]).is_err());
    }

    #[test]
    fn production_overrides_parse() {
        let a = Args::try_parse_from([
            "owr-api",
            "--run-dir",
            "/tmp/r",
            "--init-sock",
            "/tmp/r/i.sock",
            "--nft",
            "/bin/nft",
            "--tls-dir",
            "/tmp/tls",
        ])
        .unwrap();
        assert!(!a.dev);
        assert_eq!(a.run_dir.as_deref(), Some(Path::new("/tmp/r")));
        assert_eq!(a.init_sock.as_deref(), Some(Path::new("/tmp/r/i.sock")));
        assert_eq!(a.nft.as_deref(), Some(Path::new("/bin/nft")));
    }
}
