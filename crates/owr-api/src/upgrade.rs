//! The firmware upload area: the release files of an upgrade bundle, streamed by the API into
//! a directory it owns. The backend verifies the bundle there and init installs it from there
//! (init copies it to a staging directory of its own first).
//!
//! Only release file names are accepted, each with the size limit the verifier applies. A file
//! is received under a temporary name and renamed into place when complete, so a failed,
//! oversized or cancelled upload never leaves a partial file behind.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{Body, HttpBody as _};
use owr_upgrade::Version;
use owr_upgrade::bundle::MAX_IMAGE;
use owr_upgrade::release::{SIG_FILE, SUMS_FILE, valid_file_name};
use tokio::io::AsyncWriteExt as _;

/// Size limits of the two small files (the bounds `owr_upgrade::bundle` reads them with).
pub(crate) const MAX_SUMS: u64 = 64 * 1024;
pub(crate) const MAX_SIG: u64 = 4 * 1024;
/// Longest accepted image name (release names are well under 100 bytes).
const MAX_NAME: usize = 128;
const IMAGE_PREFIX: &str = "ferritewrt-";
const IMAGE_SUFFIX: &str = "-sysupgrade.bin";
/// Temporary files start with a dot: never a release file name, so never verified or staged.
const PART_PREFIX: &str = ".upload-";

/// The firmware this API belongs to (the version every image is compared against).
pub(crate) fn running_version() -> Option<Version> {
    Version::parse(env!("CARGO_PKG_VERSION"))
}

/// A sysupgrade image name as releases use it (`ferritewrt-<board>-v<version>-sysupgrade.bin`).
fn is_image_name(name: &str) -> bool {
    name.len() <= MAX_NAME
        && valid_file_name(name)
        && name.starts_with(IMAGE_PREFIX)
        && name.ends_with(IMAGE_SUFFIX)
}

/// The size limit for an upload called `name`, `None` if it is not a release file name.
pub(crate) fn limit_for(name: &str) -> Option<u64> {
    match name {
        SUMS_FILE => Some(MAX_SUMS),
        SIG_FILE => Some(MAX_SIG),
        _ if is_image_name(name) => Some(MAX_IMAGE),
        _ => None,
    }
}

/// Why an upload was not stored.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UploadError {
    #[error("{name} may be at most {limit} bytes")]
    TooLarge { name: String, limit: u64 },
    #[error("the file is empty")]
    Empty,
    #[error("not enough free space on the router for {0}")]
    NoSpace(String),
    #[error("the upload was interrupted")]
    Interrupted,
    #[error("storing the upload: {0}")]
    Io(#[from] io::Error),
}

fn write_error(name: &str, e: io::Error) -> UploadError {
    if e.kind() == io::ErrorKind::StorageFull {
        UploadError::NoSpace(name.to_owned())
    } else {
        UploadError::Io(e)
    }
}

/// A temporary upload file, removed on drop unless it was renamed into place.
struct PartFile(Option<PathBuf>);

impl Drop for PartFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && let Err(e) = std::fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), error = %e, "removing a partial upload failed");
        }
    }
}

fn part_name() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("{PART_PREFIX}{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Create `dir` (only the API process may use it: mode 0700 on unix) if it is missing.
async fn ensure_dir(dir: &Path) -> io::Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).await
}

/// Stream `body` into `dir/name`, at most `limit` bytes; returns the size. An image replaces
/// every other image in `dir`, so the directory holds one bundle (it is RAM on the router).
pub(crate) async fn store(
    dir: &Path,
    name: &str,
    limit: u64,
    mut body: Body,
) -> Result<u64, UploadError> {
    ensure_dir(dir).await?;
    let mut part = PartFile(Some(dir.join(part_name())));
    let part_path = part.0.clone().unwrap_or_default();
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&part_path).await?;
    let mut size = 0u64;
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| UploadError::Interrupted)?;
        let Ok(data) = frame.into_data() else {
            continue; // trailers carry no file content
        };
        size = size.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if size > limit {
            return Err(UploadError::TooLarge {
                name: name.to_owned(),
                limit,
            });
        }
        file.write_all(&data)
            .await
            .map_err(|e| write_error(name, e))?;
    }
    file.flush().await.map_err(|e| write_error(name, e))?;
    drop(file);
    if size == 0 {
        return Err(UploadError::Empty);
    }
    tokio::fs::rename(&part_path, dir.join(name)).await?;
    part.0 = None;
    if is_image_name(name) {
        remove_other_images(dir, name).await?;
    }
    Ok(size)
}

async fn remove_other_images(dir: &Path, keep: &str) -> io::Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(name) = name.to_str().filter(|n| *n != keep && is_image_name(n)) {
            tokio::fs::remove_file(dir.join(name)).await?;
        }
    }
    Ok(())
}

/// Remove every upload (a missing directory is already clear).
pub(crate) async fn clear(dir: &Path) -> io::Result<()> {
    match tokio::fs::remove_dir_all(dir).await {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "ferritewrt-glinet_gl-mt6000-v0.3.0-sysupgrade.bin";

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn only_release_file_names_are_accepted() {
        assert_eq!(limit_for(SUMS_FILE), Some(MAX_SUMS));
        assert_eq!(limit_for(SIG_FILE), Some(MAX_SIG));
        assert_eq!(limit_for(IMAGE), Some(MAX_IMAGE));
        for bad in [
            "",
            ".",
            "..",
            "config.toml",
            "sha256sums",
            "ferritewrt-x-v1.0.0-factory.bin",
            "openwrt-x-sysupgrade.bin",
            "ferritewrt-a/b-sysupgrade.bin",
            "ferritewrt-a\\b-sysupgrade.bin",
            "ferritewrt-a\nb-sysupgrade.bin",
            ".upload-0",
        ] {
            assert_eq!(limit_for(bad), None, "{bad:?}");
        }
        let long = format!("{IMAGE_PREFIX}{}{IMAGE_SUFFIX}", "x".repeat(MAX_NAME));
        assert_eq!(limit_for(&long), None);
    }

    #[tokio::test]
    async fn stores_a_file_and_replaces_older_images() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("upload");
        let old = "ferritewrt-glinet_gl-mt6000-v0.2.0-sysupgrade.bin";
        assert_eq!(store(&dir, old, 100, Body::from("old")).await.unwrap(), 3);
        assert_eq!(
            store(&dir, SUMS_FILE, 100, Body::from("sums"))
                .await
                .unwrap(),
            4
        );
        assert_eq!(
            store(&dir, IMAGE, 100, Body::from("image")).await.unwrap(),
            5
        );
        assert_eq!(names(&dir), [SUMS_FILE, IMAGE]);
        assert_eq!(std::fs::read(dir.join(IMAGE)).unwrap(), b"image");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[tokio::test]
    async fn oversized_and_empty_uploads_leave_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("upload");
        store(&dir, SUMS_FILE, 4, Body::from("good")).await.unwrap();
        let err = store(&dir, SUMS_FILE, 4, Body::from("too long"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, UploadError::TooLarge { limit: 4, .. }),
            "{err}"
        );
        let err = store(&dir, SIG_FILE, 4, Body::empty()).await.unwrap_err();
        assert!(matches!(err, UploadError::Empty), "{err}");
        // the earlier complete file is untouched, no temporary file is left
        assert_eq!(names(&dir), [SUMS_FILE]);
        assert_eq!(std::fs::read(dir.join(SUMS_FILE)).unwrap(), b"good");
    }

    #[tokio::test]
    async fn clear_removes_everything_and_tolerates_a_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("upload");
        clear(&dir).await.unwrap();
        store(&dir, SUMS_FILE, 10, Body::from("x")).await.unwrap();
        clear(&dir).await.unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn the_running_version_parses() {
        assert!(running_version().is_some());
    }
}
