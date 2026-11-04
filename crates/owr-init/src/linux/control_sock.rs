//! Control socket server (protocol in [`crate::control`]).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::Mode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::timeout;

use super::runtime::{Msg, Reply};
use crate::control::{
    JournalBudget, MAX_CONNECTIONS, MAX_JOURNAL_CONNECTIONS, MAX_LINE, Request, RequestError,
    UPGRADE_DEADLINE, error_response, journal_line, parse_request,
};
use crate::journal::{SharedJournal, lock};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// A whole `journal` stream (up to 1 MiB) must finish within this, however slow the reader.
const JOURNAL_DEADLINE: Duration = Duration::from_secs(30);

/// Bind the socket with mode 0600 (the umask is tightened around `bind` so there is no window
/// in which it is more permissive).
pub(super) fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    // A stale socket from a previous run (test mode) would make bind fail.
    if path.exists() {
        fs::remove_file(path)?;
    }
    let old = rustix::process::umask(Mode::from_raw_mode(0o177));
    let listener = UnixListener::bind(path);
    rustix::process::umask(old);
    let listener = listener?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accept connections forever; at most [`MAX_CONNECTIONS`] are served concurrently, of which at
/// most [`MAX_JOURNAL_CONNECTIONS`] stream the journal.
pub(super) async fn serve(listener: UnixListener, journal: SharedJournal, tx: mpsc::Sender<Msg>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let journal_slots = Arc::new(Semaphore::new(MAX_JOURNAL_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => match Arc::clone(&slots).try_acquire_owned() {
                Ok(permit) => {
                    tokio::spawn(handle(
                        stream,
                        permit,
                        journal.clone(),
                        Arc::clone(&journal_slots),
                        tx.clone(),
                    ));
                }
                // Over the limit: closing immediately is the whole response.
                Err(_) => drop(stream),
            },
            Err(e) => {
                tracing::warn!("control accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn read_line(stream: &mut UnixStream) -> Result<Vec<u8>, RequestError> {
    let mut line = Vec::new();
    let mut reader = BufReader::new(
        stream.take(
            u64::try_from(MAX_LINE)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        ),
    );
    match timeout(IO_TIMEOUT, reader.read_until(b'\n', &mut line)).await {
        Ok(Ok(_)) if line.len() > MAX_LINE => Err(RequestError::TooLong),
        Ok(Ok(_)) => Ok(line),
        Ok(Err(_)) | Err(_) => Err(RequestError::Empty),
    }
}

/// Ask the event loop to handle `req`.
async fn forward(req: Request, tx: &mpsc::Sender<Msg>) -> Reply {
    // Verifying an upgrade bundle hashes the whole image before init can answer.
    let deadline = if matches!(req, Request::Upgrade(_)) {
        UPGRADE_DEADLINE
    } else {
        IO_TIMEOUT
    };
    let (reply, rx) = oneshot::channel();
    if tx.send(Msg::Control { req, reply }).await.is_err() {
        return Reply::text(error_response("init is shutting down"));
    }
    match timeout(deadline, rx).await {
        Ok(Ok(reply)) => reply,
        _ => Reply::text(error_response("no answer from init")),
    }
}

/// Write a complete reply and half-close, bounded by [`IO_TIMEOUT`]. The client may have gone
/// away; there is nothing to do about that.
async fn write_reply(stream: &mut UnixStream, text: &str) {
    let _ = timeout(IO_TIMEOUT, async {
        stream.write_all(text.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

/// Stream journal entries after `since` as NDJSON, one entry at a time, never more than the
/// [`JournalBudget`] allows. Memory use is one entry, however large the page.
async fn stream_journal(
    stream: &mut UnixStream,
    journal: &SharedJournal,
    since: u64,
    limit: usize,
) {
    let mut budget = JournalBudget::new(limit);
    let mut cursor = since;
    loop {
        // One entry per lock: the std mutex is never held across an await.
        let Some(entry) = lock(journal).iter_since(cursor).next().cloned() else {
            break;
        };
        let line = journal_line(&entry);
        if !budget.admit(line.len()) {
            break;
        }
        match timeout(IO_TIMEOUT, stream.write_all(line.as_bytes())).await {
            Ok(Ok(())) => {}
            // The client went away or stalled: stop, nothing else to tell it.
            Ok(Err(_)) | Err(_) => return,
        }
        cursor = entry.seq;
    }
    let _ = timeout(IO_TIMEOUT, stream.shutdown()).await;
}

async fn handle(
    mut stream: UnixStream,
    _permit: OwnedSemaphorePermit,
    journal: SharedJournal,
    journal_slots: Arc<Semaphore>,
    tx: mpsc::Sender<Msg>,
) {
    let req = match read_line(&mut stream).await.and_then(|l| parse_request(&l)) {
        Ok(req) => req,
        Err(e) => {
            write_reply(&mut stream, &error_response(&e.to_string())).await;
            return;
        }
    };
    if let Request::Journal { since, limit } = req {
        let Ok(_journal_permit) = journal_slots.try_acquire_owned() else {
            write_reply(&mut stream, &error_response("too many journal requests")).await;
            return;
        };
        let _ = timeout(
            JOURNAL_DEADLINE,
            stream_journal(&mut stream, &journal, since, limit),
        )
        .await;
        return;
    }
    let Reply { text, written } = forward(req, &tx).await;
    write_reply(&mut stream, &text).await;
    // Tell init the reply is out: a reboot/poweroff must not overtake it.
    if let Some(written) = written {
        let _ = written.send(());
    }
}
