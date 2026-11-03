//! Cross-cutting request/response processing: tracing, security headers, cross-site
//! rejection, JSON error normalisation, audit logging and the session guard.

use std::net::IpAddr;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

use crate::app::{Actor, AppState, AuditSlot, CSRF_HEADER, ClientIp, client_ip, session_token};
use crate::dto::Role;
use crate::error::ApiError;
use crate::session::ct_eq;

/// True for `/api` and everything below it.
pub(crate) fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

const BACKUP_PATH: &str = "/api/v1/system/backup";

const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; \
script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// HSTS is kept short (1 day): the certificate is self-signed and regenerated on factory
/// reset, so a long-lived pin would lock browsers out of a reset router for a year.
const HSTS: &str = "max-age=86400";

fn is_read_method(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// One tracing span per request: method, path, status, latency. Cookies, tokens, query
/// strings and bodies are never recorded.
pub(crate) async fn trace(mut req: Request, next: Next) -> Response {
    let ip = client_ip(&req);
    req.extensions_mut().insert(ClientIp(ip));
    let span = tracing::info_span!(
        "request",
        method = %req.method(),
        path = %req.uri().path(),
        status = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    );
    let started = Instant::now();
    let response = next.run(req).instrument(span.clone()).await;
    span.record("status", response.status().as_u16());
    span.record(
        "latency_ms",
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    span.in_scope(|| tracing::info!("handled"));
    response
}

/// Add the security headers to every response.
pub(crate) async fn security_headers(
    State(app): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let is_api = is_api_path(req.uri().path());
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    let fixed: [(HeaderName, &'static str); 6] = [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=()",
        ),
    ];
    for (name, value) in fixed {
        h.insert(name, HeaderValue::from_static(value));
    }
    if app.secure {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        );
    }
    if is_api && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Reject state-changing requests that the browser marks as cross-site.
pub(crate) async fn reject_cross_site(req: Request, next: Next) -> Response {
    if !is_read_method(req.method()) && is_cross_site(req.headers()) {
        return ApiError::forbidden_code("cross_site", "cross-site request rejected")
            .into_response();
    }
    next.run(req).await
}

fn is_cross_site(headers: &axum::http::HeaderMap) -> bool {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = text("sec-fetch-site") {
        return !matches!(site, "same-origin" | "none");
    }
    let Some(origin) = text("origin") else {
        return false;
    };
    let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    !text("host").is_some_and(|host| host.eq_ignore_ascii_case(authority))
}

/// Replace framework-generated plain error responses under `/api/` (404, 405, 408, 413,
/// ...) with the JSON error envelope.
pub(crate) async fn json_errors(req: Request, next: Next) -> Response {
    let is_api = is_api_path(req.uri().path());
    let response = next.run(req).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !is_api || is_json || !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    let (parts, _) = response.into_parts();
    let mut replacement = ApiError::from_status(status).into_response();
    for (name, value) in &parts.headers {
        if name != header::CONTENT_LENGTH && name != header::CONTENT_TYPE {
            replacement
                .headers_mut()
                .append(name.clone(), value.clone());
        }
    }
    replacement.extensions_mut().extend(parts.extensions);
    replacement
}

fn outcome(status: StatusCode) -> &'static str {
    match status.as_u16() {
        200..=399 => "ok",
        401 | 403 | 429 => "denied",
        400..=499 => "rejected",
        _ => "error",
    }
}

const LOGIN_PATH: &str = "/api/v1/auth/login";
const SETUP_PATH: &str = "/api/v1/setup";

/// Writes the "aborted" audit line when the request future is dropped before it
/// produced a response (client disconnected, 30 s timeout fired above us).
struct AbortGuard {
    app: AppState,
    slot: AuditSlot,
    ip: IpAddr,
    method: String,
    path: String,
    armed: bool,
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Only authenticated requests are worth a line; anonymous ones are noise.
        let Some(actor) = self.slot.get() else { return };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let audit = self.app.audit.clone();
        let (ip, method, path) = (self.ip, self.method.clone(), self.path.clone());
        runtime.spawn(async move {
            audit.record(&actor, ip, &method, &path, "aborted").await;
        });
    }
}

/// Append audit records for API calls that change state (and backup downloads):
/// * authenticated requests (session valid, CSRF passed): always, outcome `aborted` when
///   the request was cancelled or timed out;
/// * login/setup: success always, failure at most once per second and client;
/// * everything else (unauthenticated, cross-site, CSRF rejections, unknown paths):
///   one `rejected` line per second and client at most.
pub(crate) async fn audit(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let relevant = is_api_path(&path) && (!is_read_method(&method) || path == BACKUP_PATH);
    if !relevant {
        return next.run(req).await;
    }
    let ip = client_ip(&req);
    let slot = AuditSlot::default();
    req.extensions_mut().insert(slot.clone());
    let mut pending = AbortGuard {
        app: app.clone(),
        slot,
        ip,
        method: method.to_string(),
        path: path.clone(),
        armed: true,
    };
    let response = next.run(req).await;
    pending.armed = false;

    let status = response.status();
    let audit = &app.audit;
    if let Some(actor) = pending.slot.get() {
        let result = if status == StatusCode::REQUEST_TIMEOUT {
            "aborted"
        } else {
            outcome(status)
        };
        audit
            .record(&actor, ip, method.as_str(), &path, result)
            .await;
    } else if path == LOGIN_PATH || path == SETUP_PATH {
        let actor = response
            .extensions()
            .get::<Actor>()
            .map_or("-", |a| a.0.as_str());
        if status.is_success() {
            audit
                .record(actor, ip, method.as_str(), &path, outcome(status))
                .await;
        } else {
            audit
                .record_limited(actor, ip, method.as_str(), &path, outcome(status))
                .await;
        }
    } else {
        audit
            .record_limited("-", ip, method.as_str(), &path, "rejected")
            .await;
    }
    response
}

/// What a route group demands from the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Any role may read; only admins may change state.
    Standard,
    /// Any role, any method (logout, own password, session info).
    SelfService,
    /// Admins only, even for reads (backup, restore).
    AdminOnly,
}

/// Authenticate the session cookie, enforce CSRF and role, expose the session to handlers.
pub(crate) async fn guard(
    State((app, access)): State<(AppState, Access)>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(session) = session_token(req.headers()).and_then(|t| app.sessions.lookup(&t)) else {
        return ApiError::unauthorized("authentication required").into_response();
    };
    let mutating = !is_read_method(req.method());

    let csrf_ok = req
        .headers()
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| ct_eq(t, &session.csrf));
    if mutating && !csrf_ok {
        // Not attributed to the session: a cross-site page can trigger this, so it is
        // audit noise (rate limited), not an action of the user.
        return ApiError::forbidden_code("csrf_invalid", "missing or invalid CSRF token")
            .into_response();
    }
    if let Some(slot) = req.extensions().get::<AuditSlot>() {
        slot.set(&session.user.name);
    }
    if session.user.role != Role::Admin
        && (access == Access::AdminOnly || (access == Access::Standard && mutating))
    {
        return ApiError::forbidden("administrator role required").into_response();
    }
    req.extensions_mut().insert(session);
    next.run(req).await
}
