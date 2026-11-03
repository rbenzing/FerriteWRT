//! Append-only audit log: one JSON object per line, fsynced, size-capped.
//!
//! Records who did what from where and whether it worked. Request bodies, cookies and
//! tokens are never passed in here, so they cannot be logged.
//!
//! The log lives on flash, so growth and write volume are bounded:
//! * once the file exceeds [`MAX_LOG_BYTES`] it is renamed to `<name>.1` (replacing the
//!   previous rotation) and a fresh file is started, so at most two files exist;
//! * unauthenticated noise (unknown paths, cross-site and CSRF rejections, failed logins)
//!   goes through [`AuditLog::record_limited`], which writes at most one line per second
//!   and client. Authenticated mutations and successful logins are always written.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::app::rate_limit_key;

/// Longest request path recorded (the rest is cut off).
const MAX_PATH_CHARS: usize = 256;
/// The log is rotated once it is larger than this (512 KiB).
pub const MAX_LOG_BYTES: u64 = 512 * 1024;
/// Minimum spacing of rate-limited lines per client.
const LIMITED_INTERVAL: Duration = Duration::from_secs(1);
/// Hard bound on tracked clients (memory limit for untrusted input).
const MAX_TRACKED_CLIENTS: usize = 1024;

#[derive(Debug, Default)]
struct Shared {
    /// Serialises appends and rotation (they run on blocking threads).
    io: Mutex<()>,
    /// When each client last got a rate-limited line.
    last_limited: Mutex<HashMap<IpAddr, Instant>>,
}

/// Handle to the audit log file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    shared: Arc<Shared>,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            max_bytes: MAX_LOG_BYTES,
            shared: Arc::default(),
        }
    }

    #[cfg(test)]
    fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            max_bytes,
            ..Self::new(path)
        }
    }

    /// Append one record. Failures are logged through `tracing` and never panic.
    pub async fn record(&self, actor: &str, ip: IpAddr, method: &str, path: &str, outcome: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = serde_json::json!({
            "ts": ts,
            "actor": actor,
            "ip": ip.to_string(),
            "method": method,
            "path": path.chars().take(MAX_PATH_CHARS).collect::<String>(),
            "outcome": outcome,
        })
        .to_string();
        let target = self.path.clone();
        let max_bytes = self.max_bytes;
        let shared = Arc::clone(&self.shared);
        let result = tokio::task::spawn_blocking(move || {
            let _io = shared.io.lock().unwrap_or_else(PoisonError::into_inner);
            append_line(&target, &line, max_bytes)
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(path = %self.path.display(), error = %e, "audit write failed");
            }
            Err(e) => tracing::error!(error = %e, "audit task failed"),
        }
    }

    /// Like [`AuditLog::record`] but dropped when `ip` (its /64 for IPv6) already got a
    /// line within the last second. For events any unauthenticated client can trigger.
    pub async fn record_limited(
        &self,
        actor: &str,
        ip: IpAddr,
        method: &str,
        path: &str,
        outcome: &str,
    ) {
        if self.allow_limited_at(ip, Instant::now()) {
            self.record(actor, ip, method, path, outcome).await;
        }
    }

    fn allow_limited_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self
            .shared
            .last_limited
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if map.len() >= MAX_TRACKED_CLIENTS {
            map.retain(|_, t| now.duration_since(*t) < LIMITED_INTERVAL);
            if map.len() >= MAX_TRACKED_CLIENTS {
                return false;
            }
        }
        let key = rate_limit_key(ip);
        if map
            .get(&key)
            .is_some_and(|t| now.duration_since(*t) < LIMITED_INTERVAL)
        {
            return false;
        }
        map.insert(key, now);
        true
    }
}

/// `<path>.1`, the single previous generation kept by rotation.
fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// Move the log aside when it has outgrown `max_bytes`.
fn rotate_if_needed(path: &Path, max_bytes: u64) -> std::io::Result<()> {
    let size = match fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if size <= max_bytes {
        return Ok(());
    }
    fs::rename(path, rotated_path(path))?;
    #[cfg(unix)]
    {
        // Make the rename durable; the record itself is still fsynced below.
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
            tracing::warn!(dir = %dir.display(), error = %e, "audit directory fsync failed");
        }
    }
    Ok(())
}

fn append_line(path: &Path, line: &str, max_bytes: u64) -> std::io::Result<()> {
    rotate_if_needed(path, max_bytes)?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(format!("{line}\n").as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn appends_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.log"));
        let ip: IpAddr = "192.168.8.5".parse().unwrap();
        log.record("admin", ip, "PUT", "/api/v1/config", "ok").await;
        log.record("a\"b\n", ip, "POST", "/x", "denied").await;
        let text = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["actor"], "admin");
        assert_eq!(v["ip"], "192.168.8.5");
        assert_eq!(v["outcome"], "ok");
        assert!(v["ts"].as_u64().unwrap() > 1_700_000_000);
        let v: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v["actor"], "a\"b\n");
    }

    #[tokio::test]
    async fn rotates_keeping_one_previous_file() {
        const MAX: u64 = 600;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::with_max_bytes(path.clone(), MAX);
        let ip: IpAddr = "192.168.8.5".parse().unwrap();
        for i in 0..40 {
            log.record("admin", ip, "POST", &format!("/p/{i}"), "ok")
                .await;
        }
        let previous = rotated_path(&path);
        assert!(previous.is_file(), "no rotated file");
        assert!(!dir.path().join("audit.log.2").exists());
        let size = |p: &Path| fs::metadata(p).unwrap().len();
        // a file is only rotated once it is over the cap, and one line adds ~100 bytes
        assert!(size(&path) <= MAX + 200, "current file is {}", size(&path));
        assert!(
            size(&previous) > MAX,
            "previous file is {}",
            size(&previous)
        );
        // the newest record is in the fresh file, every line is intact JSON
        let current = fs::read_to_string(&path).unwrap();
        assert!(current.lines().last().unwrap().contains("/p/39"));
        let old = fs::read_to_string(&previous).unwrap();
        for line in current.lines().chain(old.lines()) {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }

    #[tokio::test]
    async fn limited_records_are_one_per_second_per_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let log = AuditLog::new(path.clone());
        let ip: IpAddr = "192.168.8.5".parse().unwrap();
        for _ in 0..20 {
            log.record_limited("-", ip, "POST", "/api/v1/nope", "rejected")
                .await;
        }
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        let other: IpAddr = "192.168.8.6".parse().unwrap();
        log.record_limited("-", other, "POST", "/api/v1/nope", "rejected")
            .await;
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn limiter_window_and_ipv6_prefix() {
        let log = AuditLog::new(PathBuf::from("unused"));
        let t0 = Instant::now();
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1:2::9".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1:3::9".parse().unwrap();
        assert!(log.allow_limited_at(a, t0));
        assert!(!log.allow_limited_at(same_prefix, t0 + Duration::from_millis(500)));
        assert!(log.allow_limited_at(other_prefix, t0 + Duration::from_millis(500)));
        assert!(log.allow_limited_at(a, t0 + LIMITED_INTERVAL));
    }
}
