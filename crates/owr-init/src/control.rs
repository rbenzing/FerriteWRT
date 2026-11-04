//! Control socket protocol (pure parts): request parsing and response building.
//!
//! One request per connection, one line (max [`MAX_LINE`] bytes including the newline):
//!
//! ```text
//! status\n                    -> one JSON object
//! restart <name>\n            -> {"ok":true} | {"ok":false,"error":...}
//! reload <name>\n             -> same (SIGHUP)
//! journal <since_seq> <limit>\n -> newline-delimited JSON entries
//! reboot\n | poweroff\n       -> {"ok":true}, then the system goes down
//! upgrade <dir> [downgrade] [wipe]\n
//!                             -> {"ok":true} once the bundle in <dir> is verified, then
//!                                services stop, the image is written and the system reboots
//! ```
//!
//! This is how `owr-api` talks to init (there is no ubus).

use serde::Serialize;

use crate::journal::Entry;
use crate::manager::valid_service_name;
use crate::mounts::BootMode;
use crate::service::ServiceStatus;

/// Longest accepted request line, newline included.
pub const MAX_LINE: usize = 256;
/// How long an `upgrade` request may take to answer: staging and verifying the bundle hash
/// the whole image (seconds on the router). Well under the watchdog's stall limit.
pub const UPGRADE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
/// Longest `upgrade` directory path.
pub const MAX_UPGRADE_DIR: usize = 200;
/// Error text for a `restart` / `reload` of a service init does not know (clients match it).
pub const ERR_UNKNOWN_SERVICE: &str = "unknown service";
/// Concurrent control connections; further ones are dropped immediately.
pub const MAX_CONNECTIONS: usize = 64;
/// Largest page `journal` will return, in entries.
pub const MAX_JOURNAL_LIMIT: usize = 1000;
/// Largest `journal` reply in bytes (NDJSON lines, newlines included).
pub const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
/// Concurrent `journal` requests; each streams up to [`MAX_JOURNAL_BYTES`].
pub const MAX_JOURNAL_CONNECTIONS: usize = 4;

/// Admission control for one streamed `journal` reply: at most `entries_left` lines and
/// `bytes_left` bytes, whichever runs out first. Entries are sent whole or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalBudget {
    entries_left: usize,
    bytes_left: usize,
}

impl JournalBudget {
    /// `limit` is the requested page size (also capped at [`MAX_JOURNAL_LIMIT`]).
    pub fn new(limit: usize) -> Self {
        Self {
            entries_left: limit.min(MAX_JOURNAL_LIMIT),
            bytes_left: MAX_JOURNAL_BYTES,
        }
    }

    /// Account for a line of `len` bytes; `false` (and nothing consumed) when it does not fit.
    pub fn admit(&mut self, len: usize) -> bool {
        if self.entries_left == 0 || len > self.bytes_left {
            return false;
        }
        self.entries_left = self.entries_left.saturating_sub(1);
        self.bytes_left = self.bytes_left.saturating_sub(len);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Status,
    Restart(String),
    Reload(String),
    Journal { since: u64, limit: usize },
    Reboot,
    Poweroff,
    Upgrade(UpgradeRequest),
}

/// `upgrade <dir> [downgrade] [wipe]`: install the release bundle in `dir` (the three files
/// `owr-upgrade` verifies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    pub dir: String,
    /// Accept a version older than the running one.
    pub allow_downgrade: bool,
    /// Factory reset on the first boot of the new image instead of keeping the settings.
    pub wipe_settings: bool,
}

/// An absolute path of plain characters, no `..`: it travels on the one-line protocol, so
/// nothing in it may look like a separator or a second word.
pub fn valid_upgrade_dir(dir: &str) -> bool {
    dir.starts_with('/')
        && dir.len() <= MAX_UPGRADE_DIR
        && dir
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        && !dir.split('/').any(|c| c == "..")
}

impl UpgradeRequest {
    /// The request line, or `None` if `dir` is not a [`valid_upgrade_dir`].
    pub fn line(&self) -> Option<String> {
        valid_upgrade_dir(&self.dir).then(|| {
            let mut line = format!("upgrade {}", self.dir);
            if self.allow_downgrade {
                line.push_str(" downgrade");
            }
            if self.wipe_settings {
                line.push_str(" wipe");
            }
            line.push('\n');
            line
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("request longer than {MAX_LINE} bytes")]
    TooLong,
    #[error("request is not valid UTF-8")]
    NotUtf8,
    #[error("empty request")]
    Empty,
    #[error("unknown command {0:?}")]
    Unknown(String),
    #[error("{0}: missing argument")]
    MissingArg(&'static str),
    #[error("{0}: invalid argument")]
    BadArg(&'static str),
    #[error("{0}: unexpected extra arguments")]
    ExtraArgs(&'static str),
}

fn no_args<'a>(
    cmd: &'static str,
    mut args: impl Iterator<Item = &'a str>,
) -> Result<(), RequestError> {
    match args.next() {
        None => Ok(()),
        Some(_) => Err(RequestError::ExtraArgs(cmd)),
    }
}

fn service_arg<'a>(
    cmd: &'static str,
    mut args: impl Iterator<Item = &'a str>,
) -> Result<String, RequestError> {
    let name = args.next().ok_or(RequestError::MissingArg(cmd))?;
    if !valid_service_name(name) {
        return Err(RequestError::BadArg(cmd));
    }
    no_args(cmd, args)?;
    Ok(name.to_owned())
}

/// Parse one request line (with or without the trailing newline).
pub fn parse_request(line: &[u8]) -> Result<Request, RequestError> {
    if line.len() > MAX_LINE {
        return Err(RequestError::TooLong);
    }
    let text = std::str::from_utf8(line).map_err(|_| RequestError::NotUtf8)?;
    let text = text.trim_end_matches(['\n', '\r']);
    let mut words = text.split(' ').filter(|w| !w.is_empty());
    let cmd = words.next().ok_or(RequestError::Empty)?;
    match cmd {
        "status" => no_args("status", words).map(|()| Request::Status),
        "reboot" => no_args("reboot", words).map(|()| Request::Reboot),
        "poweroff" => no_args("poweroff", words).map(|()| Request::Poweroff),
        "restart" => service_arg("restart", words).map(Request::Restart),
        "reload" => service_arg("reload", words).map(Request::Reload),
        "journal" => {
            let since = words
                .next()
                .ok_or(RequestError::MissingArg("journal"))?
                .parse()
                .map_err(|_| RequestError::BadArg("journal"))?;
            let limit: usize = words
                .next()
                .ok_or(RequestError::MissingArg("journal"))?
                .parse()
                .map_err(|_| RequestError::BadArg("journal"))?;
            no_args("journal", words)?;
            if limit == 0 {
                return Err(RequestError::BadArg("journal"));
            }
            Ok(Request::Journal {
                since,
                limit: limit.min(MAX_JOURNAL_LIMIT),
            })
        }
        "upgrade" => {
            let dir = words.next().ok_or(RequestError::MissingArg("upgrade"))?;
            if !valid_upgrade_dir(dir) {
                return Err(RequestError::BadArg("upgrade"));
            }
            let mut req = UpgradeRequest {
                dir: dir.to_owned(),
                allow_downgrade: false,
                wipe_settings: false,
            };
            for word in words {
                let flag = match word {
                    "downgrade" => &mut req.allow_downgrade,
                    "wipe" => &mut req.wipe_settings,
                    _ => return Err(RequestError::BadArg("upgrade")),
                };
                if std::mem::replace(flag, true) {
                    return Err(RequestError::BadArg("upgrade"));
                }
            }
            Ok(Request::Upgrade(req))
        }
        other => Err(RequestError::Unknown(other.chars().take(32).collect())),
    }
}

#[derive(Serialize)]
struct StatusBody<'a> {
    ok: bool,
    uptime_ms: u64,
    mode: &'static str,
    failsafe_reason: Option<&'static str>,
    services: &'a [ServiceStatus],
}

fn json_line<T: Serialize>(value: &T) -> String {
    let mut s = serde_json::to_string(value)
        .unwrap_or_else(|_| String::from("{\"ok\":false,\"error\":\"encoding failed\"}"));
    s.push('\n');
    s
}

/// `status` response.
pub fn status_response(
    services: &[ServiceStatus],
    uptime_ms: u64,
    mode: BootMode,
    failsafe_reason: Option<&'static str>,
) -> String {
    json_line(&StatusBody {
        ok: true,
        uptime_ms,
        mode: mode.name(),
        failsafe_reason,
        services,
    })
}

/// One `journal` reply line (NDJSON): the entry as JSON plus a newline. Replies are written
/// entry by entry, oldest first, under a [`JournalBudget`].
pub fn journal_line(entry: &Entry) -> String {
    json_line(entry)
}

pub fn ok_response() -> String {
    String::from("{\"ok\":true}\n")
}

pub fn error_response(message: &str) -> String {
    #[derive(Serialize)]
    struct Err<'a> {
        ok: bool,
        error: &'a str,
    }
    json_line(&Err {
        ok: false,
        error: message,
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::journal::{Journal, Source};

    #[test]
    fn parses_upgrade_and_round_trips_the_line() {
        let req = UpgradeRequest {
            dir: "/tmp/ferritewrt-upgrade".into(),
            allow_downgrade: true,
            wipe_settings: true,
        };
        let line = req.line().unwrap();
        assert_eq!(line, "upgrade /tmp/ferritewrt-upgrade downgrade wipe\n");
        assert_eq!(parse_request(line.as_bytes()), Ok(Request::Upgrade(req)));
        assert_eq!(
            parse_request(b"upgrade /tmp/u wipe\n"),
            Ok(Request::Upgrade(UpgradeRequest {
                dir: "/tmp/u".into(),
                allow_downgrade: false,
                wipe_settings: true,
            }))
        );
        for bad in [
            "upgrade",
            "upgrade tmp/relative",
            "upgrade /tmp/../etc",
            "upgrade /tmp/a\tb",
            "upgrade /tmp/u wipe wipe",
            "upgrade /tmp/u force",
        ] {
            assert!(parse_request(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_UPGRADE_DIR));
        assert!(!valid_upgrade_dir(&long));
        assert_eq!(
            UpgradeRequest {
                dir: "/tmp/x y".into(),
                allow_downgrade: false,
                wipe_settings: false
            }
            .line(),
            None,
            "a space would split the request"
        );
    }

    #[test]
    fn parses_all_commands() {
        assert_eq!(parse_request(b"status\n"), Ok(Request::Status));
        assert_eq!(
            parse_request(b"status"),
            Ok(Request::Status),
            "newline optional"
        );
        assert_eq!(parse_request(b"status\r\n"), Ok(Request::Status));
        assert_eq!(parse_request(b"reboot\n"), Ok(Request::Reboot));
        assert_eq!(parse_request(b"poweroff\n"), Ok(Request::Poweroff));
        assert_eq!(
            parse_request(b"restart dnsmasq\n"),
            Ok(Request::Restart("dnsmasq".into()))
        );
        assert_eq!(
            parse_request(b"reload hostapd-phy0\n"),
            Ok(Request::Reload("hostapd-phy0".into()))
        );
        assert_eq!(
            parse_request(b"journal 10 50\n"),
            Ok(Request::Journal {
                since: 10,
                limit: 50
            })
        );
        assert_eq!(
            parse_request(b"  restart   a.b_c  \n"),
            Ok(Request::Restart("a.b_c".into()))
        );
    }

    #[test]
    fn journal_limit_is_clamped_and_validated() {
        assert_eq!(
            parse_request(b"journal 0 999999\n"),
            Ok(Request::Journal {
                since: 0,
                limit: MAX_JOURNAL_LIMIT
            })
        );
        assert_eq!(
            parse_request(b"journal 0 0\n"),
            Err(RequestError::BadArg("journal"))
        );
        assert_eq!(
            parse_request(b"journal -1 5\n"),
            Err(RequestError::BadArg("journal"))
        );
        assert_eq!(
            parse_request(b"journal x 5\n"),
            Err(RequestError::BadArg("journal"))
        );
        assert_eq!(
            parse_request(b"journal 1\n"),
            Err(RequestError::MissingArg("journal"))
        );
        assert_eq!(
            parse_request(b"journal\n"),
            Err(RequestError::MissingArg("journal"))
        );
        assert_eq!(
            parse_request(b"journal 1 2 3\n"),
            Err(RequestError::ExtraArgs("journal"))
        );
        assert_eq!(
            parse_request(b"journal 99999999999999999999999 5\n"),
            Err(RequestError::BadArg("journal")),
            "u64 overflow"
        );
    }

    #[test]
    fn rejects_bad_requests() {
        assert_eq!(parse_request(b""), Err(RequestError::Empty));
        assert_eq!(parse_request(b"\n"), Err(RequestError::Empty));
        assert_eq!(parse_request(b"   \n"), Err(RequestError::Empty));
        assert_eq!(
            parse_request(b"frobnicate\n"),
            Err(RequestError::Unknown("frobnicate".into()))
        );
        assert_eq!(
            parse_request(b"status now\n"),
            Err(RequestError::ExtraArgs("status"))
        );
        assert_eq!(
            parse_request(b"restart\n"),
            Err(RequestError::MissingArg("restart"))
        );
        assert_eq!(
            parse_request(b"restart a b\n"),
            Err(RequestError::ExtraArgs("restart"))
        );
        assert_eq!(
            parse_request(b"restart ../etc\n"),
            Err(RequestError::BadArg("restart"))
        );
        assert_eq!(
            parse_request(b"reload a;b\n"),
            Err(RequestError::BadArg("reload"))
        );
        assert_eq!(parse_request(b"status\xff\n"), Err(RequestError::NotUtf8));
        assert_eq!(
            parse_request(b"STATUS\n"),
            Err(RequestError::Unknown("STATUS".into())),
            "case-sensitive"
        );
    }

    #[test]
    fn line_length_limit() {
        let mut ok = b"restart ".to_vec(); // 70-char name
        ok.extend(std::iter::repeat_n(b'a', 70));
        assert!(
            matches!(parse_request(&ok), Err(RequestError::BadArg(_))),
            "name > 64 is a bad arg, not too long"
        );
        let long = vec![b'a'; MAX_LINE + 1];
        assert_eq!(parse_request(&long), Err(RequestError::TooLong));
        let mut exact = b"journal 1 ".to_vec();
        exact.resize(MAX_LINE, b'1');
        assert_ne!(parse_request(&exact), Err(RequestError::TooLong));
    }

    #[test]
    fn unknown_command_echo_is_truncated() {
        let mut line = vec![b'x'; 200];
        line.push(b'\n');
        match parse_request(&line) {
            Err(RequestError::Unknown(s)) => assert_eq!(s.len(), 32),
            other => unreachable!("{other:?}"),
        }
    }

    #[test]
    fn status_response_is_one_json_line() {
        let svc = ServiceStatus {
            name: "dnsmasq".into(),
            state: "running",
            pid: Some(42),
            failures: 0,
            oneshot: false,
            healthy: None,
            since_unix: 1_700_000_000,
            restarts: 2,
        };
        let out = status_response(&[svc], 12_345, BootMode::Normal, None);
        assert!(out.ends_with('\n') && out.matches('\n').count() == 1);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["uptime_ms"], 12_345);
        assert_eq!(v["mode"], "normal");
        assert!(v["failsafe_reason"].is_null());
        assert_eq!(v["services"][0]["name"], "dnsmasq");
        assert_eq!(v["services"][0]["state"], "running");
        assert_eq!(v["services"][0]["pid"], 42);
        assert!(v["services"][0]["healthy"].is_null());
        // The owr-api `ServiceStatus` DTO fields.
        assert_eq!(v["services"][0]["since_unix"], 1_700_000_000_u64);
        assert_eq!(v["services"][0]["restarts"], 2);

        let out = status_response(&[], 1, BootMode::Failsafe, Some("why"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            (v["mode"].as_str(), v["failsafe_reason"].as_str()),
            (Some("failsafe"), Some("why"))
        );
        assert_eq!(v["services"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn journal_lines_are_ndjson_matching_the_api_log_entry() {
        let mut j = Journal::default();
        j.push(1, 6, Source::Kernel, "hello \"world\"\tx");
        j.push(2, 3, Source::Service("a".into()), "second");
        j.push(3, 5, Source::Init, "third");
        let out: String = j.snapshot(10).iter().map(journal_line).collect();
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["msg"], "hello \"world\"\tx");
        assert_eq!(first["source"], "kernel");
        assert_eq!(first["seq"], 1);
        assert_eq!(first["ts_ms"], 1);
        assert_eq!(first["prio"], 6);
        // Exactly the owr-api `LogEntry` keys; `source` is a plain string.
        let mut keys: Vec<_> = first.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["msg", "prio", "seq", "source", "ts_ms"]);
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["source"], "service:a");
        let third: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(third["source"], "init");
    }

    #[test]
    fn journal_budget_caps_entries() {
        let mut b = JournalBudget::new(3);
        assert!(b.admit(10) && b.admit(10) && b.admit(10));
        assert!(!b.admit(1), "fourth entry exceeds the requested limit");
        // The request limit itself is capped.
        let mut b = JournalBudget::new(usize::MAX);
        let admitted = (0..MAX_JOURNAL_LIMIT + 5).filter(|_| b.admit(1)).count();
        assert_eq!(admitted, MAX_JOURNAL_LIMIT);
    }

    #[test]
    fn journal_budget_caps_bytes_and_never_splits_an_entry() {
        let mut b = JournalBudget::new(MAX_JOURNAL_LIMIT);
        let line = MAX_JOURNAL_BYTES / 4 + 1;
        assert!(b.admit(line) && b.admit(line) && b.admit(line));
        assert!(!b.admit(line), "would exceed 1 MiB");
        assert!(b.admit(1), "a smaller entry that still fits is fine");
        let mut b = JournalBudget::new(5);
        assert!(!b.admit(MAX_JOURNAL_BYTES + 1));
        assert!(b.admit(MAX_JOURNAL_BYTES), "an exactly-full reply fits");
        assert!(!b.admit(1));
    }

    #[test]
    fn ok_and_error_responses() {
        assert_eq!(ok_response(), "{\"ok\":true}\n");
        let v: serde_json::Value =
            serde_json::from_str(&error_response("no \"such\" service")).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "no \"such\" service");
    }
}
