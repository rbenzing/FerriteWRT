//! Server-side session store and brute-force rate limiting.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::dto::UserInfo;

/// Maximum number of concurrent sessions; the least recently used is evicted beyond this.
pub const MAX_SESSIONS: usize = 64;
/// Absolute lifetime of a session regardless of activity.
const ABSOLUTE_LIFETIME: Duration = Duration::from_hours(24);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 32 random bytes, base64url without padding.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Constant-time string equality.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Sessions are indexed by the SHA-256 of the cookie token so that map lookups never
/// compare the secret itself.
pub type SessionKey = [u8; 32];

fn key_of(token: &str) -> SessionKey {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(Debug)]
struct Entry {
    user: UserInfo,
    csrf: String,
    created: Instant,
    last_seen: Instant,
}

/// What an authenticated request learns about its session.
#[derive(Debug, Clone)]
pub struct SessionView {
    pub key: SessionKey,
    pub user: UserInfo,
    pub csrf: String,
}

/// A freshly created session.
#[derive(Debug)]
pub struct NewSession {
    pub token: String,
    pub csrf: String,
}

/// In-memory session store with idle and absolute expiry and a hard size cap.
#[derive(Debug)]
pub struct SessionStore {
    inner: Mutex<HashMap<SessionKey, Entry>>,
    idle_ttl: Duration,
}

impl SessionStore {
    pub fn new(idle_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            idle_ttl,
        }
    }

    pub fn create(&self, user: UserInfo) -> NewSession {
        self.create_at(user, Instant::now())
    }

    fn create_at(&self, user: UserInfo, now: Instant) -> NewSession {
        let token = random_token();
        let csrf = random_token();
        let mut map = lock(&self.inner);
        while map.len() >= MAX_SESSIONS {
            let oldest = map.iter().min_by_key(|(_, e)| e.last_seen).map(|(k, _)| *k);
            match oldest {
                Some(k) => map.remove(&k),
                None => break,
            };
        }
        map.insert(
            key_of(&token),
            Entry {
                user,
                csrf: csrf.clone(),
                created: now,
                last_seen: now,
            },
        );
        NewSession { token, csrf }
    }

    /// Look the session up and refresh its idle timer.
    pub fn lookup(&self, token: &str) -> Option<SessionView> {
        self.lookup_at(token, Instant::now())
    }

    fn lookup_at(&self, token: &str, now: Instant) -> Option<SessionView> {
        let key = key_of(token);
        let mut map = lock(&self.inner);
        let entry = map.get_mut(&key)?;
        if self.expired(entry, now) {
            map.remove(&key);
            return None;
        }
        entry.last_seen = now;
        Some(SessionView {
            key,
            user: entry.user.clone(),
            csrf: entry.csrf.clone(),
        })
    }

    fn expired(&self, e: &Entry, now: Instant) -> bool {
        now.duration_since(e.last_seen) >= self.idle_ttl
            || now.duration_since(e.created) >= ABSOLUTE_LIFETIME
    }

    pub fn remove(&self, key: &SessionKey) {
        lock(&self.inner).remove(key);
    }

    /// Drop all sessions.
    pub fn clear(&self) {
        lock(&self.inner).clear();
    }

    /// Drop every session of `name`, except `keep` if given.
    pub fn revoke_user(&self, name: &str, keep: Option<&SessionKey>) {
        lock(&self.inner).retain(|k, e| e.user.name != name || Some(k) == keep);
    }

    /// Remove expired sessions; returns how many were dropped.
    pub fn purge(&self) -> usize {
        self.purge_at(Instant::now())
    }

    fn purge_at(&self, now: Instant) -> usize {
        let mut map = lock(&self.inner);
        let before = map.len();
        map.retain(|_, e| !self.expired(e, now));
        before.saturating_sub(map.len())
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Failed-login limiter: at most [`RateLimiter::MAX_FAILURES`] failures per key within
/// [`RateLimiter::WINDOW`]. Keys are usernames and client IPs (checked independently).
#[derive(Debug)]
pub struct RateLimiter {
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub const MAX_FAILURES: usize = 5;
    pub const WINDOW: Duration = Duration::from_secs(300);
    /// Hard bound on tracked keys (memory limit for untrusted input).
    const MAX_KEYS: usize = 4096;

    pub fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// `Some(retry_after)` when any of `keys` is currently blocked.
    pub fn blocked(&self, keys: &[&str]) -> Option<Duration> {
        self.blocked_at(keys, Instant::now())
    }

    fn blocked_at(&self, keys: &[&str], now: Instant) -> Option<Duration> {
        let mut map = lock(&self.failures);
        let mut wait: Option<Duration> = None;
        for key in keys {
            let Some(q) = map.get_mut(*key) else { continue };
            while q
                .front()
                .is_some_and(|t| now.duration_since(*t) >= Self::WINDOW)
            {
                q.pop_front();
            }
            if q.len() >= Self::MAX_FAILURES {
                let oldest = q.front().copied().unwrap_or(now);
                let remaining = Self::WINDOW.saturating_sub(now.duration_since(oldest));
                wait = Some(wait.map_or(remaining, |w| w.max(remaining)));
            }
        }
        wait
    }

    pub fn record_failure(&self, keys: &[&str]) {
        self.record_failure_at(keys, Instant::now());
    }

    fn record_failure_at(&self, keys: &[&str], now: Instant) {
        let mut map = lock(&self.failures);
        if map.len() >= Self::MAX_KEYS {
            Self::purge_map(&mut map, now);
        }
        for key in keys {
            if !map.contains_key(*key) && map.len() >= Self::MAX_KEYS {
                continue;
            }
            let q = map.entry((*key).to_owned()).or_default();
            q.push_back(now);
            while q.len() > Self::MAX_FAILURES {
                q.pop_front();
            }
        }
    }

    pub fn clear(&self, key: &str) {
        lock(&self.failures).remove(key);
    }

    pub fn purge(&self) {
        Self::purge_map(&mut lock(&self.failures), Instant::now());
    }

    fn purge_map(map: &mut HashMap<String, VecDeque<Instant>>, now: Instant) {
        map.retain(|_, q| {
            q.back()
                .is_some_and(|t| now.duration_since(*t) < Self::WINDOW)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Role;

    fn user(name: &str) -> UserInfo {
        UserInfo {
            name: name.into(),
            role: Role::Admin,
            enabled: true,
        }
    }

    #[test]
    fn tokens_are_unique_base64url_32_bytes() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_token());
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn lookup_and_expiry() {
        let store = SessionStore::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let s = store.create_at(user("a"), t0);
        assert!(store.lookup_at(&s.token, t0).is_some());
        assert!(store.lookup_at("bogus", t0).is_none());
        // activity refreshes the idle timer
        assert!(
            store
                .lookup_at(&s.token, t0 + Duration::from_secs(50))
                .is_some()
        );
        assert!(
            store
                .lookup_at(&s.token, t0 + Duration::from_secs(100))
                .is_some()
        );
        // idle expiry
        assert!(
            store
                .lookup_at(&s.token, t0 + Duration::from_secs(200))
                .is_none()
        );
        assert!(store.is_empty());
    }

    #[test]
    fn absolute_expiry_and_purge() {
        let store = SessionStore::new(Duration::from_hours(48));
        let t0 = Instant::now();
        let s = store.create_at(user("a"), t0);
        assert_eq!(store.purge_at(t0 + Duration::from_secs(60)), 0);
        assert!(store.lookup_at(&s.token, t0 + ABSOLUTE_LIFETIME).is_none());
        store.create_at(user("b"), t0);
        assert_eq!(store.purge_at(t0 + ABSOLUTE_LIFETIME), 1);
    }

    #[test]
    fn cap_evicts_least_recently_used() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let t0 = Instant::now();
        let first = store.create_at(user("first"), t0);
        let second = store.create_at(user("second"), t0 + Duration::from_secs(1));
        for i in 0..MAX_SESSIONS - 2 {
            store.create_at(
                user("u"),
                t0 + Duration::from_secs(u64::try_from(i).unwrap_or(0) + 2),
            );
        }
        assert_eq!(store.len(), MAX_SESSIONS);
        // the oldest session is in active use: it must survive, the idle one is evicted
        let busy = t0 + Duration::from_secs(100);
        assert!(store.lookup_at(&first.token, busy).is_some());
        store.create_at(user("new"), busy + Duration::from_secs(1));
        assert_eq!(store.len(), MAX_SESSIONS);
        assert!(store.lookup_at(&first.token, busy).is_some());
        assert!(store.lookup_at(&second.token, busy).is_none());
    }

    #[test]
    fn revoke_user_keeps_requested() {
        let store = SessionStore::new(Duration::from_secs(60));
        let a = store.create(user("a"));
        let b = store.create(user("a"));
        let c = store.create(user("c"));
        let keep = store.lookup(&a.token).map(|v| v.key);
        store.revoke_user("a", keep.as_ref());
        assert!(store.lookup(&a.token).is_some());
        assert!(store.lookup(&b.token).is_none());
        assert!(store.lookup(&c.token).is_some());
    }

    #[test]
    fn rate_limit_window() {
        let rl = RateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..RateLimiter::MAX_FAILURES {
            assert!(rl.blocked_at(&["u:a", "i:1"], t0).is_none());
            rl.record_failure_at(&["u:a", "i:1"], t0);
        }
        let wait = rl.blocked_at(&["u:a"], t0).unwrap();
        assert!(wait <= RateLimiter::WINDOW && wait > Duration::from_secs(290));
        // different user, same ip: still blocked via ip key
        assert!(rl.blocked_at(&["u:b", "i:1"], t0).is_some());
        assert!(rl.blocked_at(&["u:b", "i:2"], t0).is_none());
        // window passes
        assert!(rl.blocked_at(&["u:a"], t0 + RateLimiter::WINDOW).is_none());
        rl.record_failure_at(&["u:z"], t0);
        rl.clear("u:z");
        assert!(rl.blocked_at(&["u:z"], t0).is_none());
    }
}
