//! Crash-safe file replacement.
//!
//! [`atomic_write`] guarantees that a reader observes either the previous complete file
//! or the new complete file, never a partial one, even across power loss: write to a
//! temporary sibling, `fsync` it, `rename` over the target, `fsync` the directory.
//! The operation is idempotent: writing identical content again is a no-op, reported
//! via the returned [`Outcome`].

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Errors from [`atomic_write`].
#[derive(Debug, thiserror::Error)]
pub enum AtomicWriteError {
    #[error("target path has no parent directory: {0}")]
    NoParent(PathBuf),
    #[error("creating temporary file in {dir}: {source}")]
    CreateTemp { dir: PathBuf, source: io::Error },
    #[error("writing temporary file {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("renaming {from} over {to}: {source}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("syncing directory {dir}: {source}")]
    SyncDir { dir: PathBuf, source: io::Error },
}

/// What [`atomic_write`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// File content already matched; nothing was written.
    Unchanged,
    /// File was replaced (or created).
    Written,
}

/// Atomically replace `target` with `content`.
///
/// `mode` is the Unix permission mode applied to a newly created file (ignored on
/// non-Unix hosts). Sensitive files (password hashes, TLS keys) should use `0o600`.
pub fn atomic_write(target: &Path, content: &[u8], mode: u32) -> Result<Outcome, AtomicWriteError> {
    if current_content_matches(target, content) {
        tracing::debug!(path = %target.display(), "atomic_write: unchanged");
        return Ok(Outcome::Unchanged);
    }
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicWriteError::NoParent(target.to_path_buf()))?;

    let tmp_path = temp_sibling(target);
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut file = opts
            .open(&tmp_path)
            .map_err(|source| AtomicWriteError::CreateTemp {
                dir: dir.to_path_buf(),
                source,
            })?;
        let write_result = file.write_all(content).and_then(|()| file.sync_all());
        if let Err(source) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(AtomicWriteError::Write {
                path: tmp_path,
                source,
            });
        }
    }
    if let Err(source) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(AtomicWriteError::Rename {
            from: tmp_path,
            to: target.to_path_buf(),
            source,
        });
    }
    sync_dir(dir)?;
    tracing::info!(path = %target.display(), bytes = content.len(), "atomic_write: written");
    Ok(Outcome::Written)
}

fn current_content_matches(target: &Path, content: &[u8]) -> bool {
    let Ok(mut file) = File::open(target) else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    if meta.len() != content.len() as u64 {
        return false;
    }
    let mut existing = Vec::with_capacity(content.len());
    file.read_to_end(&mut existing).is_ok() && existing == content
}

fn temp_sibling(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nonce = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    target.with_file_name(format!(".{name}.{nonce}.{nanos}.tmp"))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), AtomicWriteError> {
    let d = File::open(dir).map_err(|source| AtomicWriteError::SyncDir {
        dir: dir.to_path_buf(),
        source,
    })?;
    d.sync_all().map_err(|source| AtomicWriteError::SyncDir {
        dir: dir.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "signature must match the unix implementation"
)]
fn sync_dir(_dir: &Path) -> Result<(), AtomicWriteError> {
    // Directory handles cannot be fsynced on Windows; rename is already atomic there.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_then_reports_unchanged_on_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        assert_eq!(
            atomic_write(&target, b"a = 1\n", 0o600).unwrap(),
            Outcome::Written
        );
        assert_eq!(fs::read(&target).unwrap(), b"a = 1\n");
        assert_eq!(
            atomic_write(&target, b"a = 1\n", 0o600).unwrap(),
            Outcome::Unchanged
        );
        assert_eq!(
            atomic_write(&target, b"a = 2\n", 0o600).unwrap(),
            Outcome::Written
        );
        assert_eq!(fs::read(&target).unwrap(), b"a = 2\n");
    }

    #[test]
    fn leaves_no_temp_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("f");
        atomic_write(&target, b"x", 0o644).unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("f")]);
    }

    #[test]
    fn rejects_path_without_parent() {
        let err = atomic_write(Path::new("relative-file"), b"x", 0o644);
        assert!(matches!(err, Err(AtomicWriteError::NoParent(_))));
    }

    #[cfg(unix)]
    #[test]
    fn applies_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret");
        atomic_write(&target, b"s", 0o600).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
