//! Client for the control socket (`<RUN_DIR>/init.sock`, protocol in [`crate::control`]).
//!
//! Pure std and synchronous: callers on an async runtime wrap calls in `spawn_blocking`.
//! The framing (request lines, bounded reply reading, reply parsing) is pure and tested on
//! every host; only [`InitClient`], which owns the socket, needs unix.
//!
//! One request per connection: [`InitClient`] only remembers the socket path and opens a
//! fresh connection (2 s read and write timeouts) for every call.

use std::io::{self, Read};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::control::{ERR_UNKNOWN_SERVICE, MAX_JOURNAL_BYTES, MAX_JOURNAL_LIMIT};
#[cfg(unix)]
use crate::control::{UPGRADE_DEADLINE, UpgradeRequest};
use crate::manager::valid_service_name;

/// Read and write timeout of one control connection.
pub const TIMEOUT: Duration = Duration::from_secs(2);
/// Largest reply accepted (a full `journal` page is the biggest init ever sends).
pub const MAX_REPLY_BYTES: usize = MAX_JOURNAL_BYTES;
/// Longest init error text kept in a [`ClientError::Refused`].
const MAX_ERROR_CHARS: usize = 200;

/// Failure talking to init.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The service name would not survive the request line (init would refuse it too).
    #[error("invalid service name")]
    BadName,
    /// The upgrade directory is not an absolute path of plain characters.
    #[error("invalid upgrade directory (absolute path of [A-Za-z0-9._/-], no ..)")]
    BadUpgradeDir,
    #[error("init control socket: {0}")]
    Io(#[from] io::Error),
    #[error("init reply is larger than {MAX_REPLY_BYTES} bytes")]
    TooLarge,
    #[error("malformed reply from init: {0}")]
    Malformed(String),
    /// `restart` / `reload` of a service init does not supervise.
    #[error("unknown service")]
    UnknownService,
    /// init answered `{"ok":false,"error":...}`.
    #[error("init refused: {0}")]
    Refused(String),
}

/// One supervised service as reported by `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub state: String,
    pub pid: Option<u32>,
    /// Unix time at which the service entered its current state.
    pub since_unix: u64,
    pub restarts: u32,
    /// Consecutive failures in the current streak.
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub oneshot: bool,
    /// `None` when the service has no health check.
    #[serde(default)]
    pub healthy: Option<bool>,
}

/// The `status` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitStatus {
    pub uptime_ms: u64,
    pub mode: String,
    #[serde(default)]
    pub failsafe_reason: Option<String>,
    pub services: Vec<ServiceInfo>,
}

/// One `journal` entry; `ts_ms` is milliseconds since boot, `source` is `"kernel"`,
/// `"init"` or `"service:<name>"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq: u64,
    pub ts_ms: u64,
    pub prio: u8,
    pub source: String,
    pub msg: String,
}

/// Request line for `restart <name>` / `reload <name>`; the name is validated with the
/// same rule init applies, so no request can smuggle a second command.
fn service_request(verb: &str, name: &str) -> Result<String, ClientError> {
    if valid_service_name(name) {
        Ok(format!("{verb} {name}\n"))
    } else {
        Err(ClientError::BadName)
    }
}

/// Request line of `restart <name>`.
pub fn restart_request(name: &str) -> Result<String, ClientError> {
    service_request("restart", name)
}

/// Request line of `reload <name>`.
pub fn reload_request(name: &str) -> Result<String, ClientError> {
    service_request("reload", name)
}

/// Request line for `journal`; `limit` is clamped to what init serves (1..=1000).
pub fn journal_request(since_seq: u64, limit: usize) -> String {
    format!(
        "journal {since_seq} {}\n",
        limit.clamp(1, MAX_JOURNAL_LIMIT)
    )
}

/// Read a whole reply, failing with [`ClientError::TooLarge`] past [`MAX_REPLY_BYTES`].
pub fn read_reply(reader: impl Read) -> Result<Vec<u8>, ClientError> {
    let cap = u64::try_from(MAX_REPLY_BYTES).unwrap_or(u64::MAX);
    let mut buf = Vec::new();
    reader.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() > MAX_REPLY_BYTES {
        return Err(ClientError::TooLarge);
    }
    Ok(buf)
}

fn malformed(e: &serde_json::Error) -> ClientError {
    // serde_json messages name the problem, not the offending text.
    ClientError::Malformed(e.to_string())
}

fn refusal(error: &str) -> ClientError {
    if error == ERR_UNKNOWN_SERVICE {
        ClientError::UnknownService
    } else {
        ClientError::Refused(error.chars().take(MAX_ERROR_CHARS).collect())
    }
}

/// Turn `{"ok":false,"error":...}` into the matching error.
fn check_ok(value: &serde_json::Value) -> Result<(), ClientError> {
    match value.get("ok").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err(refusal(
            value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error"),
        )),
        None => Err(ClientError::Malformed("reply has no \"ok\" field".into())),
    }
}

/// Parse the reply of `restart`, `reload`, `reboot` or `poweroff`.
pub fn parse_ack(reply: &[u8]) -> Result<(), ClientError> {
    let value = serde_json::from_slice(reply).map_err(|e| malformed(&e))?;
    check_ok(&value)
}

/// Parse the reply of `status`.
pub fn parse_status(reply: &[u8]) -> Result<InitStatus, ClientError> {
    let value: serde_json::Value = serde_json::from_slice(reply).map_err(|e| malformed(&e))?;
    check_ok(&value)?;
    serde_json::from_value(value).map_err(|e| malformed(&e))
}

/// One line of a `journal` reply: an entry, or init's refusal of the whole request.
#[derive(Deserialize)]
#[serde(untagged)]
enum JournalLine {
    Entry(JournalEntry),
    Refusal { ok: bool, error: String },
}

/// Parse the NDJSON reply of `journal`. Every entry must be complete: a reply that does not
/// end in a newline was cut short and is rejected as a whole.
pub fn parse_journal(reply: &[u8]) -> Result<Vec<JournalEntry>, ClientError> {
    if !reply.is_empty() && !reply.ends_with(b"\n") {
        return Err(ClientError::Malformed("journal reply is truncated".into()));
    }
    let mut entries = Vec::new();
    for line in reply
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
    {
        match serde_json::from_slice(line) {
            Ok(JournalLine::Entry(e)) => entries.push(e),
            Ok(JournalLine::Refusal { ok: false, error }) => return Err(refusal(&error)),
            Ok(JournalLine::Refusal { ok: true, .. }) | Err(_) => {
                return Err(ClientError::Malformed("unrecognised journal line".into()));
            }
        }
    }
    Ok(entries)
}

/// Connection factory for the control socket; see the module docs.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct InitClient {
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl InitClient {
    /// Check that `path` is a unix socket (init is running) and remember it.
    pub fn connect(path: impl Into<std::path::PathBuf>) -> io::Result<Self> {
        use std::os::unix::fs::FileTypeExt as _;

        let path = path.into();
        if !std::fs::metadata(&path)?.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a socket", path.display()),
            ));
        }
        Ok(Self { path })
    }

    fn request(&self, line: &str) -> Result<Vec<u8>, ClientError> {
        self.request_within(line, TIMEOUT)
    }

    fn request_within(&self, line: &str, timeout: Duration) -> Result<Vec<u8>, ClientError> {
        use std::io::Write as _;

        let mut sock = std::os::unix::net::UnixStream::connect(&self.path)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(TIMEOUT))?;
        sock.write_all(line.as_bytes())?;
        read_reply(sock)
    }

    /// Mode, uptime and the service table.
    pub fn status_report(&self) -> Result<InitStatus, ClientError> {
        parse_status(&self.request("status\n")?)
    }

    /// The service table.
    pub fn status(&self) -> Result<Vec<ServiceInfo>, ClientError> {
        self.status_report().map(|s| s.services)
    }

    /// Entries with `seq > since_seq`, oldest first, at most `limit` (clamped to 1000).
    /// `limit == 0` asks for nothing and does not touch the socket.
    pub fn journal(&self, since_seq: u64, limit: usize) -> Result<Vec<JournalEntry>, ClientError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        parse_journal(&self.request(&journal_request(since_seq, limit))?)
    }

    pub fn restart(&self, name: &str) -> Result<(), ClientError> {
        parse_ack(&self.request(&restart_request(name)?)?)
    }

    /// Send SIGHUP to a running service.
    pub fn reload(&self, name: &str) -> Result<(), ClientError> {
        parse_ack(&self.request(&reload_request(name)?)?)
    }

    pub fn reboot(&self) -> Result<(), ClientError> {
        parse_ack(&self.request("reboot\n")?)
    }

    pub fn poweroff(&self) -> Result<(), ClientError> {
        parse_ack(&self.request("poweroff\n")?)
    }

    /// Ask init to verify and install the bundle in `req.dir`. `Ok` means init accepted it:
    /// services are stopping and the router reboots into the new image when the write is done.
    /// Verification takes seconds, so this waits up to [`UPGRADE_DEADLINE`].
    pub fn upgrade(&self, req: &UpgradeRequest) -> Result<(), ClientError> {
        let line = req.line().ok_or(ClientError::BadUpgradeDir)?;
        parse_ack(&self.request_within(&line, UPGRADE_DEADLINE)?)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const STATUS: &str = concat!(
        r#"{"ok":true,"uptime_ms":5000,"mode":"normal","failsafe_reason":null,"services":["#,
        r#"{"name":"dnsmasq","state":"running","pid":42,"failures":0,"oneshot":false,"healthy":null,"since_unix":100,"restarts":2},"#,
        r#"{"name":"owr-apply","state":"stopped","pid":null,"failures":1,"oneshot":true,"healthy":false,"since_unix":90,"restarts":0}"#,
        "]}\n"
    );

    #[test]
    fn status_reply_is_parsed() {
        let st = parse_status(STATUS.as_bytes()).unwrap();
        assert_eq!((st.uptime_ms, st.mode.as_str()), (5000, "normal"));
        assert_eq!(st.failsafe_reason, None);
        assert_eq!(st.services.len(), 2);
        let dns = &st.services[0];
        assert_eq!(
            (dns.name.as_str(), dns.pid, dns.restarts),
            ("dnsmasq", Some(42), 2)
        );
        assert_eq!(dns.healthy, None);
        assert_eq!(st.services[1].healthy, Some(false));
        assert!(st.services[1].oneshot);
    }

    #[test]
    fn status_tolerates_missing_optional_fields() {
        let st = parse_status(
            br#"{"ok":true,"uptime_ms":1,"mode":"failsafe","failsafe_reason":"button","services":[{"name":"a","state":"running","pid":1,"since_unix":1,"restarts":0}]}"#,
        )
        .unwrap();
        assert_eq!(st.failsafe_reason.as_deref(), Some("button"));
        assert_eq!(st.services[0].failures, 0);
    }

    #[test]
    fn refusals_and_garbage_are_errors() {
        let refused = parse_status(br#"{"ok":false,"error":"busy"}"#).unwrap_err();
        assert!(
            matches!(&refused, ClientError::Refused(m) if m == "busy"),
            "{refused}"
        );
        assert!(matches!(
            parse_status(b"not json"),
            Err(ClientError::Malformed(_))
        ));
        assert!(matches!(
            parse_status(br#"{"ok":true}"#),
            Err(ClientError::Malformed(_))
        ));
        assert!(matches!(parse_status(b""), Err(ClientError::Malformed(_))));
        assert!(matches!(
            parse_ack(br#"{"services":[]}"#),
            Err(ClientError::Malformed(_))
        ));
    }

    #[test]
    fn ack_distinguishes_unknown_service() {
        assert!(parse_ack(b"{\"ok\":true}\n").is_ok());
        assert!(matches!(
            parse_ack(br#"{"ok":false,"error":"unknown service"}"#),
            Err(ClientError::UnknownService)
        ));
        assert!(matches!(
            parse_ack(br#"{"ok":false,"error":"service is not running"}"#),
            Err(ClientError::Refused(m)) if m == "service is not running"
        ));
    }

    #[test]
    fn journal_reply_is_ndjson() {
        let reply = concat!(
            r#"{"seq":3,"ts_ms":10,"prio":6,"source":"init","msg":"hello"}"#,
            "\n",
            r#"{"seq":4,"ts_ms":11,"prio":3,"source":"service:dnsmasq","msg":"a \"b\""}"#,
            "\n"
        );
        let entries = parse_journal(reply.as_bytes()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 3);
        assert_eq!(entries[1].source, "service:dnsmasq");
        assert_eq!(entries[1].msg, "a \"b\"");
        assert_eq!(parse_journal(b"").unwrap(), Vec::<JournalEntry>::new());
    }

    #[test]
    fn journal_errors() {
        assert!(matches!(
            parse_journal(b"{\"ok\":false,\"error\":\"too many journal requests\"}\n"),
            Err(ClientError::Refused(m)) if m.contains("too many")
        ));
        let cut = br#"{"seq":3,"ts_ms":10,"prio":6,"source":"init","msg":"x"}"#;
        assert!(matches!(
            parse_journal(cut),
            Err(ClientError::Malformed(m)) if m.contains("truncated")
        ));
        assert!(matches!(
            parse_journal(b"{\"seq\":\"x\"}\n"),
            Err(ClientError::Malformed(_))
        ));
        assert!(matches!(
            parse_journal(b"{\"ok\":true}\n"),
            Err(ClientError::Malformed(_))
        ));
    }

    #[test]
    fn request_lines() {
        assert_eq!(
            restart_request("hostapd-phy0").unwrap(),
            "restart hostapd-phy0\n"
        );
        assert_eq!(reload_request("dnsmasq").unwrap(), "reload dnsmasq\n");
        assert_eq!(journal_request(7, 50), "journal 7 50\n");
        assert_eq!(journal_request(0, 0), "journal 0 1\n");
        assert_eq!(journal_request(0, 1_000_000), "journal 0 1000\n");
    }

    #[test]
    fn hostile_names_never_reach_the_wire() {
        let long = "a".repeat(65);
        for name in ["", "a b", "a\nreboot", "a\r", "../x", "x/y", "é", &long] {
            assert!(
                matches!(restart_request(name), Err(ClientError::BadName)),
                "{name:?}"
            );
            assert!(
                matches!(reload_request(name), Err(ClientError::BadName)),
                "{name:?}"
            );
        }
    }

    #[test]
    fn replies_are_capped() {
        let ok = vec![b'x'; MAX_REPLY_BYTES];
        assert_eq!(read_reply(Cursor::new(&ok)).unwrap().len(), MAX_REPLY_BYTES);
        let big = vec![b'x'; MAX_REPLY_BYTES + 1];
        assert!(matches!(
            read_reply(Cursor::new(&big)),
            Err(ClientError::TooLarge)
        ));
        assert_eq!(
            read_reply(Cursor::new(Vec::new())).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[cfg(unix)]
    mod socket {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::os::unix::net::UnixListener;
        use std::path::PathBuf;
        use std::thread::JoinHandle;

        use super::*;

        /// Serve `(expected request line, reply)` pairs, one connection each.
        fn serve(
            dir: &tempfile::TempDir,
            replies: Vec<(&'static str, &'static str)>,
        ) -> (PathBuf, JoinHandle<()>) {
            let path = dir.path().join("init.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let handle = std::thread::spawn(move || {
                for (expect, reply) in replies {
                    let (mut conn, _) = listener.accept().unwrap();
                    let mut line = String::new();
                    BufReader::new(&conn).read_line(&mut line).unwrap();
                    assert_eq!(line, expect);
                    conn.write_all(reply.as_bytes()).unwrap();
                }
            });
            (path, handle)
        }

        #[test]
        fn speaks_the_line_protocol() {
            let dir = tempfile::tempdir().unwrap();
            let entry = "{\"seq\":6,\"ts_ms\":1,\"prio\":6,\"source\":\"kernel\",\"msg\":\"m\"}\n";
            let (path, server) = serve(
                &dir,
                vec![
                    ("status\n", STATUS),
                    ("journal 5 20\n", entry),
                    ("restart dnsmasq\n", "{\"ok\":true}\n"),
                    (
                        "reload nope\n",
                        "{\"ok\":false,\"error\":\"unknown service\"}\n",
                    ),
                    ("reboot\n", "{\"ok\":true}\n"),
                    ("poweroff\n", "{\"ok\":true}\n"),
                ],
            );
            let client = InitClient::connect(&path).unwrap();
            assert_eq!(client.status().unwrap().len(), 2);
            let entries = client.journal(5, 20).unwrap();
            assert_eq!((entries.len(), entries[0].seq), (1, 6));
            client.restart("dnsmasq").unwrap();
            assert!(matches!(
                client.reload("nope"),
                Err(ClientError::UnknownService)
            ));
            client.reboot().unwrap();
            client.poweroff().unwrap();
            server.join().unwrap();
        }

        #[test]
        fn zero_limit_and_bad_names_skip_the_socket() {
            let dir = tempfile::tempdir().unwrap();
            let (path, server) = serve(&dir, Vec::new());
            let client = InitClient::connect(&path).unwrap();
            assert_eq!(client.journal(0, 0).unwrap(), Vec::<JournalEntry>::new());
            assert!(matches!(client.restart("a b"), Err(ClientError::BadName)));
            server.join().unwrap();
        }

        #[test]
        fn connect_rejects_missing_and_non_socket_paths() {
            let dir = tempfile::tempdir().unwrap();
            let missing = InitClient::connect(dir.path().join("nope.sock")).unwrap_err();
            assert_eq!(missing.kind(), io::ErrorKind::NotFound);
            let file = dir.path().join("plain");
            std::fs::write(&file, b"x").unwrap();
            assert_eq!(
                InitClient::connect(&file).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }

        #[test]
        fn an_empty_reply_is_an_error() {
            let dir = tempfile::tempdir().unwrap();
            let (path, server) = serve(&dir, vec![("status\n", "")]);
            let client = InitClient::connect(&path).unwrap();
            assert!(matches!(client.status(), Err(ClientError::Malformed(_))));
            server.join().unwrap();
        }
    }
}
