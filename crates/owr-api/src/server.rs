//! Router assembly and the (optionally TLS) accept loop.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::app::{AppState, Inner, rate_limit_key, unmap_ip};
use crate::audit::AuditLog;
use crate::backend::SystemBackend;
use crate::middleware::{
    audit, is_api_path, json_errors, reject_cross_site, security_headers, trace,
};
use crate::routes;
use crate::session::{RateLimiter, SessionStore};
use crate::tls::{self, TlsError};
use crate::ui::UiSource;

/// Per-request processing deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline for the firmware upgrade routes: uploading an image of up to
/// `owr_upgrade::bundle::MAX_IMAGE` bytes over a slow link, hashing it, init staging it.
/// Below `CONNECTION_LIFETIME`, which ends the request anyway.
const UPGRADE_REQUEST_TIMEOUT: Duration = Duration::from_secs(240);
/// Paths that get `UPGRADE_REQUEST_TIMEOUT`.
const UPGRADE_PATH: &str = "/api/v1/system/upgrade";
/// Time a client gets to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a client gets to send complete request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for the lifetime of one connection. hyper has no write timeout, so a client
/// that stops reading its response would otherwise hold its slot forever; this bounds it
/// (idle keep-alive is already bounded by `HEADER_READ_TIMEOUT`, requests by
/// `REQUEST_TIMEOUT`). Browsers reconnect transparently.
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
/// Simultaneous connections per client address (IPv6: per /64), so one host cannot use up
/// all of `MAX_CONNECTIONS`.
const MAX_CONNECTIONS_PER_IP: usize = 16;
/// Simultaneous connections (bounds memory use under load).
const MAX_CONNECTIONS: usize = 128;
/// Interval of the background purge of expired sessions.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);
/// Cap for HTTP header buffers.
const MAX_HEADER_BUF: usize = 32 * 1024;

/// Locations of the PEM certificate and private key.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Everything [`serve`] needs.
pub struct ServerConfig {
    pub bind: SocketAddr,
    /// `None` serves plain HTTP (development only).
    pub tls: Option<TlsConfig>,
    /// Idle lifetime of a session.
    pub session_ttl: Duration,
    pub backend: Arc<dyn SystemBackend>,
    /// Serve the web UI; when false only `/api/v1` exists.
    pub ui_enabled: bool,
    /// Serve the UI from this directory instead of the embedded copy.
    pub ui_dir: Option<PathBuf>,
    pub audit_log_path: PathBuf,
    /// Directory owned by the API for firmware upgrade uploads (created on demand, mode
    /// 0700); production uses `<run_dir>/upgrade-upload`. Its path must be a plain absolute
    /// path (init refuses anything else).
    pub upload_dir: PathBuf,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind", &self.bind)
            .field("tls", &self.tls)
            .field("session_ttl", &self.session_ttl)
            .field("ui_enabled", &self.ui_enabled)
            .field("ui_dir", &self.ui_dir)
            .field("audit_log_path", &self.audit_log_path)
            .field("upload_dir", &self.upload_dir)
            .finish_non_exhaustive()
    }
}

/// Failure to start or run the server.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("binding {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
    #[error(transparent)]
    Tls(#[from] TlsError),
}

pub(crate) fn build(cfg: &ServerConfig) -> (Router, AppState) {
    let ui = cfg.ui_enabled.then(|| match &cfg.ui_dir {
        Some(dir) => UiSource::Disk(dir.clone()),
        None => UiSource::Embedded,
    });
    let app = AppState(Arc::new(Inner {
        backend: Arc::clone(&cfg.backend),
        sessions: SessionStore::new(cfg.session_ttl),
        limiter: RateLimiter::new(),
        audit: AuditLog::new(cfg.audit_log_path.clone()),
        secure: cfg.tls.is_some(),
        ui,
        upload_dir: cfg.upload_dir.clone(),
        admin_lock: tokio::sync::Mutex::new(()),
        login_gate: Semaphore::new(1),
    }));
    let router = Router::new()
        .nest("/api/v1", routes::api_router(&app))
        .fallback(fallback)
        .with_state(app.clone())
        .layer(from_fn(deadline))
        .layer(from_fn(reject_cross_site))
        .layer(from_fn(json_errors))
        .layer(from_fn_with_state(app.clone(), audit))
        .layer(from_fn_with_state(app.clone(), security_headers))
        .layer(from_fn(trace));
    (router, app)
}

fn request_timeout(path: &str) -> Duration {
    let upgrade = path
        .strip_prefix(UPGRADE_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    if upgrade {
        UPGRADE_REQUEST_TIMEOUT
    } else {
        REQUEST_TIMEOUT
    }
}

/// End a request that takes longer than its deadline with 408. The dropped handler future
/// cancels the request; work it handed to `detached` tasks still completes.
async fn deadline(req: Request, next: Next) -> Response {
    let limit = request_timeout(req.uri().path());
    tokio::time::timeout(limit, next.run(req))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}

/// The fully layered application router (API + UI) without any network listener.
/// Used by [`serve_on`] and for in-process testing.
pub fn router(cfg: &ServerConfig) -> Router {
    build(cfg).0
}

/// Non-API paths: the web UI. Anything under `/api` that is not a route is a 404.
async fn fallback(State(app): State<AppState>, req: Request) -> Response {
    let path = req.uri().path();
    let Some(ui) = app.ui.as_ref().filter(|_| !is_api_path(path)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    ui.respond(path, req.headers()).await
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn_purge(app: AppState) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        let mut tick = tokio::time::interval(PURGE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let dropped = app.sessions.purge();
            app.limiter.purge();
            if dropped > 0 {
                tracing::debug!(dropped, "expired sessions purged");
            }
        }
    }))
}

/// Open connections per client address.
#[derive(Debug, Default)]
struct ConnectionCounter(Mutex<HashMap<IpAddr, usize>>);

/// One counted connection; released on drop.
struct IpSlot {
    counter: Arc<ConnectionCounter>,
    key: IpAddr,
}

impl ConnectionCounter {
    fn try_acquire(self: &Arc<Self>, peer: IpAddr, limit: usize) -> Option<IpSlot> {
        let key = rate_limit_key(unmap_ip(peer));
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let open = map.entry(key).or_insert(0);
        if *open >= limit {
            return None;
        }
        *open = open.saturating_add(1);
        Some(IpSlot {
            counter: Arc::clone(self),
            key,
        })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut map = self
            .counter
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(open) = map.get_mut(&self.key) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                map.remove(&self.key);
            }
        }
    }
}

/// Bind `cfg.bind` and serve until an unrecoverable error occurs.
pub async fn serve(cfg: ServerConfig) -> Result<(), ServeError> {
    let listener = TcpListener::bind(cfg.bind)
        .await
        .map_err(|source| ServeError::Bind {
            addr: cfg.bind,
            source,
        })?;
    serve_on(listener, cfg).await
}

/// Serve on an already bound listener (`cfg.bind` is ignored).
pub async fn serve_on(listener: TcpListener, cfg: ServerConfig) -> Result<(), ServeError> {
    let acceptor = match &cfg.tls {
        Some(t) => {
            let config = tls::load_server_config_from(&t.cert_path, &t.key_path)?;
            Some(TlsAcceptor::from(Arc::new(config)))
        }
        None => None,
    };
    let (router, app) = build(&cfg);
    let _purge = spawn_purge(app);
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_ip = Arc::new(ConnectionCounter::default());
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(%addr, tls = acceptor.is_some(), "owr-api listening");
    }
    loop {
        // Waiting for a slot before accepting leaves excess clients in the kernel backlog.
        let Ok(permit) = Arc::clone(&connections).acquire_owned().await else {
            return Ok(());
        };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(slot) = per_ip.try_acquire(peer.ip(), MAX_CONNECTIONS_PER_IP) else {
            tracing::debug!(%peer, "per-address connection limit reached; closing");
            continue;
        };
        let router = router.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            handle_connection(stream, peer, acceptor, router).await;
            drop((permit, slot));
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Option<TlsAcceptor>,
    router: Router,
) {
    // Best effort: failing to set TCP_NODELAY only costs latency.
    let _ = stream.set_nodelay(true);
    match acceptor {
        Some(acceptor) => {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => serve_http(TokioIo::new(tls_stream), peer, router).await,
                Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
        }
        None => serve_http(TokioIo::new(stream), peer, router).await,
    }
}

async fn serve_http<I>(io: TokioIo<I>, peer: SocketAddr, router: Router)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let router = router.clone();
        async move {
            let mut req = req.map(Body::new);
            req.extensions_mut().insert(ConnectInfo(peer));
            router.oneshot(req).await
        }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEADER_BUF)
        .serve_connection(io, service)
        .with_upgrades();
    match tokio::time::timeout(CONNECTION_LIFETIME, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "connection ended with error"),
        Err(_) => tracing::debug!(%peer, "connection lifetime exceeded; closing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBackend;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn per_ip_cap_counts_and_releases() {
        let counter = Arc::new(ConnectionCounter::default());
        let a: IpAddr = "192.168.8.5".parse().unwrap();
        let b: IpAddr = "192.168.8.6".parse().unwrap();
        let mut held: Vec<_> = (0..MAX_CONNECTIONS_PER_IP)
            .map(|_| counter.try_acquire(a, MAX_CONNECTIONS_PER_IP).unwrap())
            .collect();
        assert!(counter.try_acquire(a, MAX_CONNECTIONS_PER_IP).is_none());
        // other clients (and the mapped form of the same client) are counted separately/equally
        assert!(counter.try_acquire(b, MAX_CONNECTIONS_PER_IP).is_some());
        let mapped: IpAddr = "::ffff:192.168.8.5".parse().unwrap();
        assert!(
            counter
                .try_acquire(mapped, MAX_CONNECTIONS_PER_IP)
                .is_none()
        );
        held.pop();
        assert!(counter.try_acquire(a, MAX_CONNECTIONS_PER_IP).is_some());
        drop(held);
        // entries do not accumulate once their connections are gone
        assert!(counter.0.lock().unwrap().is_empty());
    }

    #[test]
    fn only_upgrade_routes_get_the_long_deadline() {
        for path in [
            "/api/v1/system/upgrade",
            "/api/v1/system/upgrade/check",
            "/api/v1/system/upgrade/files/SHA256SUMS",
        ] {
            assert_eq!(request_timeout(path), UPGRADE_REQUEST_TIMEOUT, "{path}");
        }
        for path in ["/api/v1/system/upgraded", "/api/v1/system/reboot", "/"] {
            assert_eq!(request_timeout(path), REQUEST_TIMEOUT, "{path}");
        }
        assert!(UPGRADE_REQUEST_TIMEOUT < CONNECTION_LIFETIME);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_requests_end_with_408() {
        let app = Router::new()
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(REQUEST_TIMEOUT.saturating_mul(2)).await;
                }),
            )
            .layer(from_fn(deadline));
        let req = Request::builder().uri("/slow").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[test]
    fn ipv6_clients_share_their_prefix_budget() {
        let counter = Arc::new(ConnectionCounter::default());
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let _held = counter.try_acquire(a, 1).unwrap();
        assert!(counter.try_acquire(b, 1).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_cannot_hold_a_connection_forever() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            session_ttl: Duration::from_mins(30),
            backend: Arc::new(MockBackend::new()),
            ui_enabled: false,
            ui_dir: None,
            audit_log_path: dir.path().join("audit.log"),
            upload_dir: dir.path().join("upload"),
        };
        // A tiny pipe whose far end never reads: the response cannot be written out.
        let (mut client, server) = tokio::io::duplex(64);
        let task = tokio::spawn(serve_http(
            TokioIo::new(server),
            "127.0.0.1:1".parse().unwrap(),
            router(&cfg),
        ));
        client
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(
            CONNECTION_LIFETIME
                .checked_sub(Duration::from_secs(5))
                .unwrap(),
        )
        .await;
        assert!(!task.is_finished(), "closed before the lifetime elapsed");
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(task.is_finished(), "stalled connection was not closed");
        task.await.unwrap();
    }
}
