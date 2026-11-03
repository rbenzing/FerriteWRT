//! Linux applier: render, persist, and load the ruleset with the `nft` CLI.
//!
//! `nft` is executed directly (no shell). The script is loaded as a single netlink
//! transaction, so a failed load leaves the previous ruleset untouched.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use owr_common::{AtomicWriteError, Outcome, atomic_write};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::Instrument;

use crate::model::Ruleset;
use crate::render::{RenderError, render};

/// Rendered script file inside the run dir.
const SCRIPT_FILE: &str = "firewall.nft";
/// Marker holding the hex SHA-256 of the last script nft loaded successfully.
const MARKER_FILE: &str = "firewall.applied";
/// Upper bound for one `nft` invocation.
const NFT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for the `nft list table` liveness probe.
const TABLE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Captured stderr is truncated to this many bytes.
const STDERR_LIMIT: usize = 4096;
const FILE_MODE: u32 = 0o600;

/// Result of [`apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// `false` when the identical ruleset was already loaded (confirmed with
    /// `nft list table`; no reload was performed).
    pub changed: bool,
    /// Size of the rendered script.
    pub bytes: usize,
}

/// Errors from [`apply`] and [`check`].
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Render(#[from] RenderError),
    #[error(transparent)]
    Write(#[from] AtomicWriteError),
    #[error("spawning {bin}: {source}")]
    Spawn { bin: PathBuf, source: io::Error },
    #[error("talking to nft: {0}")]
    Io(#[source] io::Error),
    #[error("nft did not finish within {0:?}")]
    Timeout(Duration),
    #[error("nft failed ({status}): {stderr}")]
    Nft { status: ExitStatus, stderr: String },
}

/// Render `rs` and load it with `nft -f`, unless that exact script is already loaded.
pub async fn apply(rs: &Ruleset, nft_bin: &Path, run_dir: &Path) -> Result<Applied, ApplyError> {
    apply_with_timeout(rs, nft_bin, run_dir, NFT_TIMEOUT).await
}

/// Validate and render `rs`, then ask nft to check it (`nft -c -f -`) without loading.
pub async fn check(rs: &Ruleset, nft_bin: &Path) -> Result<(), ApplyError> {
    let script = render(rs)?;
    run_nft(
        nft_bin,
        &["-c", "-f", "-"],
        Some(script.as_bytes()),
        NFT_TIMEOUT,
    )
    .instrument(tracing::info_span!("fw_check", bytes = script.len()))
    .await
}

async fn apply_with_timeout(
    rs: &Ruleset,
    nft_bin: &Path,
    run_dir: &Path,
    timeout: Duration,
) -> Result<Applied, ApplyError> {
    let script = render(rs)?;
    let bytes = script.len();
    let hash = hex(&Sha256::digest(script.as_bytes()));
    let script_path = run_dir.join(SCRIPT_FILE);
    let marker_path = run_dir.join(MARKER_FILE);

    async {
        let outcome = atomic_write(&script_path, script.as_bytes(), FILE_MODE)?;
        if outcome == Outcome::Unchanged
            && marker_matches(&marker_path, &hash).await
            && table_loaded(nft_bin, &rs.options.table_name).await
        {
            tracing::debug!("fw_apply: ruleset already loaded");
            return Ok(Applied {
                changed: false,
                bytes,
            });
        }
        run_nft(
            nft_bin,
            &[OsStr::new("-f"), script_path.as_os_str()],
            None,
            timeout,
        )
        .await?;
        atomic_write(&marker_path, hash.as_bytes(), FILE_MODE)?;
        tracing::info!(bytes, "fw_apply: ruleset loaded");
        Ok(Applied {
            changed: true,
            bytes,
        })
    }
    .instrument(tracing::info_span!("fw_apply", bytes, hash = %hash))
    .await
}

/// Lower-case hex (independent of whether the digest output type implements `LowerHex`).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

async fn marker_matches(path: &Path, hash: &str) -> bool {
    tokio::fs::read_to_string(path)
        .await
        .is_ok_and(|m| m.trim() == hash)
}

/// The marker only proves we loaded this script once; the table may have been flushed
/// or deleted since. Confirm with the kernel, and reload on any doubt.
async fn table_loaded(nft_bin: &Path, table: &str) -> bool {
    let args = ["list", "table", "inet", table];
    match run_nft(nft_bin, &args, None, TABLE_CHECK_TIMEOUT).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, table, "fw_apply: marker matches but table not loaded; reloading");
            false
        }
    }
}

/// Read to EOF but keep only the first `limit` bytes, so the child never blocks on a
/// full pipe while memory stays bounded.
async fn read_capped<R: AsyncReadExt + Unpin>(
    mut reader: R,
    limit: usize,
) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 1024];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok((kept, truncated));
        }
        let room = limit.saturating_sub(kept.len());
        if let Some(part) = chunk.get(..n.min(room)) {
            kept.extend_from_slice(part);
        }
        truncated |= n > room;
    }
}

/// Run `nft_bin args...`, optionally feeding `stdin_data`, under `timeout`.
async fn run_nft<S: AsRef<OsStr>>(
    nft_bin: &Path,
    args: &[S],
    stdin_data: Option<&[u8]>,
    timeout: Duration,
) -> Result<(), ApplyError> {
    let mut child = Command::new(nft_bin)
        .args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| ApplyError::Spawn {
            bin: nft_bin.to_path_buf(),
            source,
        })?;
    let stdin = child.stdin.take();
    let stderr = child.stderr.take();

    let send_script = async {
        if let (Some(mut pipe), Some(data)) = (stdin, stdin_data) {
            // A broken pipe means nft exited early; its status and stderr tell why.
            match pipe.write_all(data).await {
                Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
                _ => {}
            }
        }
        Ok(())
    };
    let capture = async {
        match stderr {
            Some(pipe) => read_capped(pipe, STDERR_LIMIT).await,
            None => Ok((Vec::new(), false)),
        }
    };
    let finished = async { tokio::join!(child.wait(), send_script, capture) };

    let (status, sent, captured) = tokio::time::timeout(timeout, finished)
        .await
        .map_err(|_| ApplyError::Timeout(timeout))?;
    let status = status.map_err(ApplyError::Io)?;
    sent.map_err(ApplyError::Io)?;
    let (raw, truncated) = captured.map_err(ApplyError::Io)?;
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::from_utf8_lossy(&raw).trim().to_owned();
    if truncated {
        stderr.push_str(" [truncated]");
    }
    Err(ApplyError::Nft { status, stderr })
}

#[cfg(test)]
mod tests;
