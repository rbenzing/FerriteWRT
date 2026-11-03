//! Bounded in-memory log journal with optional on-disk persistence.
//!
//! Replaces `logd`/`logread`: kernel messages (`/dev/kmsg`), service stdout/stderr and init's
//! own `tracing` events all land in one ring, bounded both by bytes and by entry count.
//! Timestamps are milliseconds since boot (the router has no battery-backed clock).
//!
//! Persistence appends newline-delimited JSON to a rotating pair `journal.0` / `journal.1`
//! (512 KiB each) using [`owr_common::atomic_write`], so a power cut leaves either the old or
//! the new complete file. Flushes are infrequent by design (flash wear).

use std::collections::VecDeque;
use std::fmt::{self, Debug, Write as _};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Longest stored message; longer ones are truncated at a character boundary.
pub const MAX_MSG_BYTES: usize = 1024;
pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES: usize = 8192;
/// Size at which the persistent journal rotates to the other file.
pub const ROTATE_BYTES: usize = 512 * 1024;
/// Syslog level used for unparseable lines.
pub const DEFAULT_PRIO: u8 = 6;
/// Fixed per-entry overhead charged against the byte budget.
const ENTRY_OVERHEAD: usize = 48;

/// Where an entry came from. On the wire (control socket, persisted NDJSON) this is the plain
/// string `"kernel"`, `"init"` or `"service:<name>"`, matching `owr-api`'s `LogEntry.source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Kernel,
    Service(String),
    Init,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => f.write_str("kernel"),
            Self::Init => f.write_str("init"),
            Self::Service(name) => write!(f, "service:{name}"),
        }
    }
}

impl Serialize for Source {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// One journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// Monotonic, assigned by [`Journal::push`], starts at 1.
    pub seq: u64,
    /// Milliseconds since boot.
    pub ts_ms: u64,
    /// Syslog level 0 (emerg) to 7 (debug).
    pub prio: u8,
    pub source: Source,
    pub msg: String,
}

impl Entry {
    fn cost(&self) -> usize {
        let src = match &self.source {
            Source::Service(s) => s.len(),
            Source::Kernel | Source::Init => 0,
        };
        self.msg
            .len()
            .saturating_add(src)
            .saturating_add(ENTRY_OVERHEAD)
    }
}

/// Persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal I/O on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("encoding journal entry: {0}")]
    Encode(#[from] serde_json::Error),
    #[error(transparent)]
    Write(#[from] owr_common::AtomicWriteError),
}

/// The ring buffer.
#[derive(Debug)]
pub struct Journal {
    entries: VecDeque<Entry>,
    bytes: usize,
    max_bytes: usize,
    max_entries: usize,
    next_seq: u64,
    flushed_seq: u64,
    /// Which of `journal.0`/`journal.1` receives appends (decided lazily on first flush).
    slot: Option<usize>,
}

impl Default for Journal {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES)
    }
}

/// Truncate to at most `max` bytes on a UTF-8 boundary.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or("")
}

impl Journal {
    pub fn with_limits(max_bytes: usize, max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_bytes,
            max_entries: max_entries.max(1),
            next_seq: 1,
            flushed_seq: 0,
            slot: None,
        }
    }

    /// Append an entry and return its sequence number. Evicts the oldest entries when the
    /// byte or count budget is exceeded (the newest entry is always kept).
    pub fn push(&mut self, ts_ms: u64, prio: u8, source: Source, msg: &str) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = Entry {
            seq,
            ts_ms,
            prio: prio.min(7),
            source,
            msg: truncate_utf8(msg.trim_end_matches(['\n', '\r']), MAX_MSG_BYTES).to_owned(),
        };
        self.bytes = self.bytes.saturating_add(entry.cost());
        self.entries.push_back(entry);
        while self.entries.len() > 1
            && (self.bytes > self.max_bytes || self.entries.len() > self.max_entries)
        {
            if let Some(old) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.cost());
            }
        }
        seq
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes charged against the budget.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Sequence number of the newest entry (0 when nothing was ever pushed).
    pub fn last_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// Entries with `seq` strictly greater than `seq`, oldest first.
    pub fn iter_since(&self, seq: u64) -> impl Iterator<Item = &Entry> {
        let start = self.entries.partition_point(|e| e.seq <= seq);
        self.entries.range(start..)
    }

    /// Up to `limit` entries after `seq`, oldest first (for paging with the control socket).
    pub fn since(&self, seq: u64, limit: usize) -> Vec<Entry> {
        self.iter_since(seq).take(limit).cloned().collect()
    }

    /// The newest `limit` entries, oldest first.
    pub fn snapshot(&self, limit: usize) -> Vec<Entry> {
        let skip = self.entries.len().saturating_sub(limit);
        self.entries.iter().skip(skip).cloned().collect()
    }

    /// Append entries not yet persisted to `dir/journal.{0,1}` as NDJSON.
    ///
    /// Rotates to the other file when the active one would exceed [`ROTATE_BYTES`]. Tracing
    /// from inside the write is suppressed because the caller usually holds the journal lock
    /// that the tracing bridge would need. On error nothing is marked flushed.
    pub fn flush_to(&mut self, dir: &Path) -> Result<usize, JournalError> {
        let pending: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.seq > self.flushed_seq)
            .collect();
        let Some(last) = pending.last().map(|e| e.seq) else {
            return Ok(0);
        };
        let count = pending.len();
        let mut add = Vec::new();
        for e in pending {
            serde_json::to_writer(&mut add, e)?;
            add.push(b'\n');
        }
        let add = trim_front_lines(&add, ROTATE_BYTES);

        let mut slot = self.slot.unwrap_or_else(|| active_slot(dir));
        let mut content = fs::read(slot_path(dir, slot)).unwrap_or_default();
        if content.len().saturating_add(add.len()) > ROTATE_BYTES {
            slot = usize::from(slot == 0);
            content.clear();
        }
        content.extend_from_slice(add);

        fs::create_dir_all(dir).map_err(|source| JournalError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let target = slot_path(dir, slot);
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            owr_common::atomic_write(&target, &content, 0o600)
        })?;
        self.slot = Some(slot);
        self.flushed_seq = last;
        Ok(count)
    }
}

fn slot_path(dir: &Path, slot: usize) -> PathBuf {
    dir.join(format!("journal.{slot}"))
}

/// The slot most recently written (newest mtime); 0 when neither file exists.
fn active_slot(dir: &Path) -> usize {
    let mtime = |n| {
        fs::metadata(slot_path(dir, n))
            .and_then(|m| m.modified())
            .ok()
    };
    match (mtime(0), mtime(1)) {
        (Some(a), Some(b)) if b > a => 1,
        (None, Some(_)) => 1,
        _ => 0,
    }
}

/// Keep at most `max` trailing bytes, dropping whole lines from the front.
fn trim_front_lines(buf: &[u8], max: usize) -> &[u8] {
    if buf.len() <= max {
        return buf;
    }
    let cut = buf.len().saturating_sub(max);
    let tail = buf.get(cut..).unwrap_or(buf);
    match tail.iter().position(|b| *b == b'\n') {
        Some(nl) => tail.get(nl.saturating_add(1)..).unwrap_or(&[]),
        None => &[],
    }
}

/// Journal shared between the event loop, reader tasks and the tracing bridge.
pub type SharedJournal = Arc<Mutex<Journal>>;

pub fn shared(journal: Journal) -> SharedJournal {
    Arc::new(Mutex::new(journal))
}

/// Lock, recovering from poisoning (a panic elsewhere must not stop logging).
pub fn lock(journal: &SharedJournal) -> MutexGuard<'_, Journal> {
    journal.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A parsed kernel log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRecord {
    /// Syslog level 0-7 (facility bits removed).
    pub prio: u8,
    /// Kernel sequence number (`/dev/kmsg` only).
    pub seq: Option<u64>,
    /// Milliseconds since boot (`/dev/kmsg` only).
    pub ts_ms: Option<u64>,
    pub msg: String,
}

impl KmsgRecord {
    fn raw(line: &str) -> Self {
        Self {
            prio: DEFAULT_PRIO,
            seq: None,
            ts_ms: None,
            msg: line.trim_end().to_owned(),
        }
    }
}

fn level_of(code: u32) -> u8 {
    u8::try_from(code & 7).unwrap_or(DEFAULT_PRIO)
}

/// Parse one `/dev/kmsg` record: `"<prio>,<seq>,<usec>,<flags>[,...];<msg>"`, optionally
/// followed by `\n KEY=VALUE` continuation lines (ignored). Malformed input is kept verbatim
/// with priority 6.
pub fn parse_dev_kmsg(record: &str) -> KmsgRecord {
    let first = record.split('\n').next().unwrap_or_default();
    let Some((header, msg)) = first.split_once(';') else {
        return KmsgRecord::raw(first);
    };
    let mut fields = header.split(',');
    let parsed = (|| {
        let prio: u32 = fields.next()?.trim().parse().ok()?;
        let seq: u64 = fields.next()?.trim().parse().ok()?;
        let usec: u64 = fields.next()?.trim().parse().ok()?;
        fields.next()?; // flags must exist
        Some((prio, seq, usec))
    })();
    match parsed {
        Some((prio, seq, usec)) => KmsgRecord {
            prio: level_of(prio),
            seq: Some(seq),
            ts_ms: Some(usec / 1000),
            msg: msg.trim_end().to_owned(),
        },
        None => KmsgRecord::raw(first),
    }
}

/// Parse one classic `/proc/kmsg` line: `"<prio>msg"`. Malformed input is kept verbatim with
/// priority 6.
pub fn parse_proc_kmsg(line: &str) -> KmsgRecord {
    let parsed = line.strip_prefix('<').and_then(|rest| {
        let (num, msg) = rest.split_once('>')?;
        let prio: u32 = num.parse().ok()?;
        Some((prio, msg))
    });
    match parsed {
        Some((prio, msg)) => KmsgRecord {
            prio: level_of(prio),
            seq: None,
            ts_ms: None,
            msg: msg.trim_end().to_owned(),
        },
        None => KmsgRecord::raw(line),
    }
}

/// Splits a byte stream into lines with a hard cap on line length, so a daemon that never
/// prints a newline cannot grow init's memory.
#[derive(Debug)]
pub struct LineSplitter {
    buf: Vec<u8>,
    max: usize,
}

impl LineSplitter {
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max: max.max(1),
        }
    }

    fn take_line(&mut self) -> Option<String> {
        let bytes = std::mem::take(&mut self.buf);
        let text = String::from_utf8_lossy(&bytes);
        let text = text.trim_end_matches('\r');
        (!text.is_empty()).then(|| text.to_owned())
    }

    /// Feed bytes; returns every completed line.
    pub fn push(&mut self, data: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for &b in data {
            if b == b'\n' {
                lines.extend(self.take_line());
            } else {
                self.buf.push(b);
                if self.buf.len() >= self.max {
                    lines.extend(self.take_line());
                }
            }
        }
        lines
    }

    /// Flush a final unterminated line at EOF.
    pub fn finish(&mut self) -> Option<String> {
        self.take_line()
    }
}

/// Syslog level for a tracing level.
pub fn prio_of(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        _ => 7,
    }
}

/// `tracing` layer that records init's own events (and those of `owr-common`) as
/// [`Source::Init`] entries.
#[derive(Debug, Clone)]
pub struct JournalLayer {
    journal: SharedJournal,
    clock: fn() -> u64,
    max_level: Level,
}

impl JournalLayer {
    /// `clock` returns milliseconds since boot. Events more verbose than `max_level` are
    /// ignored.
    pub fn new(journal: SharedJournal, clock: fn() -> u64, max_level: Level) -> Self {
        Self {
            journal,
            clock,
            max_level,
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for JournalLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = event.metadata().level();
        if *level > self.max_level {
            return;
        }
        let mut v = MessageVisitor::default();
        event.record(&mut v);
        let msg = format!("{}{}", v.message, v.fields);
        lock(&self.journal).push((self.clock)(), prio_of(level), Source::Init, &msg);
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    fn push(j: &mut Journal, msg: &str) -> u64 {
        j.push(1, 6, Source::Init, msg)
    }

    #[test]
    fn seq_is_monotonic_and_iter_since_filters() {
        let mut j = Journal::default();
        assert_eq!(j.last_seq(), 0);
        let a = push(&mut j, "a");
        let b = push(&mut j, "b");
        let c = push(&mut j, "c");
        assert_eq!((a, b, c), (1, 2, 3));
        let msgs: Vec<_> = j.iter_since(1).map(|e| e.msg.as_str()).collect();
        assert_eq!(msgs, ["b", "c"]);
        assert_eq!(j.iter_since(3).count(), 0);
        assert_eq!(j.iter_since(0).count(), 3);
        assert_eq!(j.since(0, 2).len(), 2);
        assert_eq!(j.last_seq(), 3);
    }

    #[test]
    fn count_cap_evicts_oldest_and_seq_survives() {
        let mut j = Journal::with_limits(usize::MAX, 3);
        for i in 0..10 {
            push(&mut j, &format!("m{i}"));
        }
        assert_eq!(j.len(), 3);
        let seqs: Vec<_> = j.iter_since(0).map(|e| e.seq).collect();
        assert_eq!(seqs, [8, 9, 10]);
        assert_eq!(
            j.snapshot(2)
                .iter()
                .map(|e| e.msg.as_str())
                .collect::<Vec<_>>(),
            ["m8", "m9"]
        );
        assert_eq!(j.snapshot(100).len(), 3);
    }

    #[test]
    fn byte_cap_evicts_oldest() {
        let mut j = Journal::with_limits(1000, 10_000);
        for _ in 0..100 {
            push(&mut j, &"x".repeat(100));
        }
        assert!(j.bytes() <= 1000, "bytes={}", j.bytes());
        assert!(j.len() >= 5 && j.len() < 100);
    }

    #[test]
    fn newest_entry_is_never_evicted() {
        let mut j = Journal::with_limits(1, 1);
        push(&mut j, "only");
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn long_messages_are_truncated_on_char_boundary() {
        let mut j = Journal::default();
        let msg = "é".repeat(1000); // 2000 bytes, odd cut would split a char
        push(&mut j, &msg);
        let e = j.snapshot(1).remove(0);
        assert!(e.msg.len() <= MAX_MSG_BYTES);
        assert!(e.msg.chars().all(|c| c == 'é'));
        push(&mut j, "line\r\n");
        assert_eq!(j.snapshot(1)[0].msg, "line");
    }

    #[test]
    fn prio_is_clamped() {
        let mut j = Journal::default();
        j.push(0, 200, Source::Kernel, "x");
        assert_eq!(j.snapshot(1)[0].prio, 7);
    }

    #[test]
    fn parses_dev_kmsg() {
        let r = parse_dev_kmsg("6,339,5140900,-;NET: Registered protocol family 10\n");
        assert_eq!(r.prio, 6);
        assert_eq!(r.seq, Some(339));
        assert_eq!(r.ts_ms, Some(5140));
        assert_eq!(r.msg, "NET: Registered protocol family 10");
        // facility bits are masked: <30> is daemon.info
        assert_eq!(parse_dev_kmsg("30,1,0,-;x").prio, 6);
        assert_eq!(parse_dev_kmsg("3,1,0,-;x").prio, 3);
        // flags with extra fields, continuation lines, and ';' inside the message
        let r = parse_dev_kmsg("4,7,2000,c,caller=T1;a;b\n SUBSYSTEM=net\n DEVICE=n1");
        assert_eq!((r.prio, r.ts_ms, r.msg.as_str()), (4, Some(2), "a;b"));
    }

    #[test]
    fn malformed_dev_kmsg_kept_raw_with_prio_6() {
        for bad in ["garbage", "x,1,2,-;msg", "6,1;msg", "6,1,2;msg", ""] {
            let r = parse_dev_kmsg(bad);
            assert_eq!(r.prio, 6, "{bad:?}");
            assert_eq!(r.seq, None);
            assert_eq!(r.msg, bad.trim_end());
        }
    }

    #[test]
    fn parses_proc_kmsg() {
        let r = parse_proc_kmsg("<3>oops happened\n");
        assert_eq!((r.prio, r.msg.as_str()), (3, "oops happened"));
        assert_eq!(parse_proc_kmsg("<30>daemon").prio, 6);
        assert_eq!(parse_proc_kmsg("<7>").msg, "");
    }

    #[test]
    fn malformed_proc_kmsg_kept_raw() {
        for bad in ["no prefix", "<x>bad", "<6 missing", "<>", "<-1>neg"] {
            let r = parse_proc_kmsg(bad);
            assert_eq!(r.prio, 6, "{bad:?}");
            assert_eq!(r.msg, bad);
        }
    }

    #[test]
    fn line_splitter_handles_partial_long_and_crlf() {
        let mut s = LineSplitter::new(8);
        assert_eq!(s.push(b"hel"), Vec::<String>::new());
        assert_eq!(s.push(b"lo\r\nwor"), ["hello"]);
        assert_eq!(s.push(b"ld\n\n"), ["world"]);
        assert_eq!(s.push(b"0123456789abc\n"), ["01234567", "89abc"]);
        assert_eq!(s.push(b"tail"), Vec::<String>::new());
        assert_eq!(s.finish().as_deref(), Some("tail"));
        assert_eq!(s.finish(), None);
    }

    #[test]
    fn flush_appends_ndjson_and_only_new_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::default();
        push(&mut j, "one");
        j.push(2, 3, Source::Service("dnsmasq".into()), "two");
        assert_eq!(j.flush_to(dir.path()).unwrap(), 2);
        assert_eq!(j.flush_to(dir.path()).unwrap(), 0, "nothing new");
        push(&mut j, "three");
        assert_eq!(j.flush_to(dir.path()).unwrap(), 1);

        let text = fs::read_to_string(dir.path().join("journal.0")).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["msg"], "one");
        assert_eq!(lines[0]["source"], "init");
        assert_eq!(lines[1]["source"], "service:dnsmasq");
        assert_eq!(lines[1]["prio"], 3);
        assert_eq!(lines[2]["seq"], 3);
        assert!(!dir.path().join("journal.1").exists());
    }

    #[test]
    fn flush_rotates_between_the_pair() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::with_limits(usize::MAX, usize::MAX);
        let big = "y".repeat(MAX_MSG_BYTES);
        // ~1.1 KiB per line: 600 lines ~ 660 KiB > one 512 KiB file.
        for round in 0..3 {
            for _ in 0..250 {
                push(&mut j, &big);
            }
            j.flush_to(dir.path()).unwrap();
            for n in 0..2 {
                let len =
                    fs::metadata(dir.path().join(format!("journal.{n}"))).map_or(0, |m| m.len());
                assert!(
                    len <= ROTATE_BYTES as u64,
                    "round {round}: journal.{n} is {len}"
                );
            }
        }
        assert!(
            dir.path().join("journal.1").exists(),
            "rotation must reach the second file"
        );
        // Every persisted line is complete JSON.
        for n in 0..2 {
            let text = fs::read_to_string(dir.path().join(format!("journal.{n}"))).unwrap();
            assert!(
                text.lines()
                    .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok())
            );
        }
    }

    #[test]
    fn flush_resumes_on_most_recent_file_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("journal.0"), "{\"old\":1}\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.path().join("journal.1"), "{\"newer\":1}\n").unwrap();
        let mut j = Journal::default();
        push(&mut j, "boot2");
        j.flush_to(dir.path()).unwrap();
        let text = fs::read_to_string(dir.path().join("journal.1")).unwrap();
        assert!(text.starts_with("{\"newer\":1}\n"), "{text}");
        assert!(text.contains("boot2"));
    }

    #[test]
    fn oversized_batch_is_trimmed_to_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::with_limits(usize::MAX, usize::MAX);
        let big = "z".repeat(MAX_MSG_BYTES);
        for _ in 0..1000 {
            push(&mut j, &big);
        }
        j.flush_to(dir.path()).unwrap();
        let text = fs::read_to_string(dir.path().join("journal.0")).unwrap();
        assert!(text.len() <= ROTATE_BYTES);
        assert!(
            text.lines()
                .all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok())
        );
        assert!(text.contains("\"seq\":1000"), "newest entry must survive");
    }

    #[test]
    fn flush_failure_does_not_mark_flushed() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        fs::write(&blocker, "x").unwrap();
        let mut j = Journal::default();
        push(&mut j, "a");
        assert!(j.flush_to(&blocker.join("sub")).is_err());
        assert_eq!(j.flush_to(dir.path()).unwrap(), 1, "entry is retried");
    }

    #[test]
    fn tracing_layer_records_events() {
        let j = shared(Journal::default());
        let layer = JournalLayer::new(j.clone(), || 42, Level::INFO);
        let sub = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(path = "/x", n = 3, "disk slow");
            tracing::info!("plain");
            tracing::debug!("too verbose");
        });
        let snap = lock(&j).snapshot(10);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].prio, 4);
        assert_eq!(snap[0].ts_ms, 42);
        assert_eq!(snap[0].source, Source::Init);
        assert!(snap[0].msg.starts_with("disk slow"), "{}", snap[0].msg);
        assert!(snap[0].msg.contains("path=/x") && snap[0].msg.contains("n=3"));
        assert_eq!(snap[1].msg, "plain");
        assert_eq!(snap[1].prio, 6);
    }
}
