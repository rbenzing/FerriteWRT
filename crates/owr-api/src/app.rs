//! Shared application state and small request helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, header};

use crate::audit::AuditLog;
use crate::backend::SystemBackend;
use crate::session::{RateLimiter, SessionStore};
use crate::ui::UiSource;

/// Name of the session cookie.
pub(crate) const SESSION_COOKIE: &str = "owr_session";
/// Longest user name (also bounds the actor recorded in the audit log).
pub(crate) const MAX_USERNAME_CHARS: usize = 32;
/// Name of the CSRF request header.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

/// Who performed a request, attached to responses for the audit middleware.
#[derive(Debug, Clone)]
pub(crate) struct Actor(pub String);

/// Filled by the session guard with the authenticated actor (once the CSRF check has
/// passed) so the audit middleware can attribute a request that never produced a
/// response of its own: client gone, 30 s timeout.
#[derive(Debug, Clone, Default)]
pub(crate) struct AuditSlot(Arc<Mutex<Option<String>>>);

impl AuditSlot {
    pub(crate) fn set(&self, actor: &str) {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = Some(actor.chars().take(MAX_USERNAME_CHARS).collect());
    }

    pub(crate) fn get(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Client address of the request, inserted by the tracing middleware.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientIp(pub IpAddr);

pub(crate) struct Inner {
    pub backend: Arc<dyn SystemBackend>,
    pub sessions: SessionStore,
    pub limiter: RateLimiter,
    pub audit: AuditLog,
    /// TLS in use: cookies get `Secure`, responses get HSTS.
    pub secure: bool,
    pub ui: Option<UiSource>,
    /// Where firmware upgrade files are uploaded to (created on demand).
    pub upload_dir: PathBuf,
    /// Serialises user-management operations (setup, create/modify/delete).
    pub admin_lock: tokio::sync::Mutex<()>,
    /// Serialises password verification so the failure limiter cannot be raced.
    pub login_gate: tokio::sync::Semaphore,
}

/// Cheaply clonable handle to the shared state.
#[derive(Clone)]
pub(crate) struct AppState(pub Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// Unwrap IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`).
pub(crate) fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Client address of a request (IPv4 loopback when the server did not record one, as in
/// in-process tests). IPv4-mapped IPv6 addresses are unwrapped.
pub(crate) fn client_ip(req: &Request) -> IpAddr {
    unmap_ip(
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |c| c.0.ip()),
    )
}

/// Address used as rate-limiting key: IPv6 clients control a whole /64, so only the
/// prefix identifies them.
pub(crate) fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o.iter_mut().skip(8).for_each(|b| *b = 0);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        IpAddr::V4(_) => ip,
    }
}

/// Extract the session token from the `Cookie` header(s).
pub(crate) fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parses_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; owr_session=tok123; b=2"),
        );
        assert_eq!(session_token(&h).as_deref(), Some("tok123"));
        assert_eq!(session_token(&HeaderMap::new()), None);
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("xowr_session=bad"));
        assert_eq!(session_token(&h), None);
    }

    #[test]
    fn ipv6_rate_limit_key_is_prefix_and_mapped_v4_unwrapped() {
        let a: IpAddr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        assert_eq!(rate_limit_key(a), rate_limit_key(b));
        assert_ne!(
            rate_limit_key(a),
            rate_limit_key("2001:db8:1:3::1".parse().unwrap())
        );
        let m: IpAddr = "::ffff:192.168.8.5".parse().unwrap();
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        assert_eq!(client_ip(&req), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut req = req;
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(m, 1)));
        assert_eq!(client_ip(&req), "192.168.8.5".parse::<IpAddr>().unwrap());
    }
}
