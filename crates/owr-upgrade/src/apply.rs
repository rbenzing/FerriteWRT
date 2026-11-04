//! Carry out a write plan and prune the overlay. Plain `std` I/O, so it runs against regular
//! files in tests and against block devices on the router; the caller (`owr-init`) resolves
//! partition labels to devices, checks sizes with [`crate::plan::check_fit`] first, and makes
//! sure nothing else is running from the root filesystem being replaced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::plan::WriteStep;

const CHUNK: usize = 1024 * 1024;

/// The settings directory, relative to the overlay's upper layer: the only thing that
/// survives an upgrade.
pub const KEEP: [&str; 2] = ["etc", "ferritewrt"];
/// Files in [`KEEP`] that are image content, not settings: a copy in the upper layer would
/// hide the new image's version, so they are removed too.
pub const IMAGE_FILES_IN_KEEP: &[&str] = &["board.toml"];

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("{partition}: no device for this partition label")]
    NoDevice { partition: String },
    #[error("{step}: {source}")]
    Io {
        step: String,
        #[source]
        source: io::Error,
    },
    #[error("{partition}: read-back does not match what was written")]
    Verify { partition: String },
}

fn describe(step: &WriteStep) -> String {
    match step {
        WriteStep::Invalidate { partition, len } => format!("invalidate {partition} ({len} bytes)"),
        WriteStep::Copy { partition, member } => {
            format!("write {partition} ({} bytes)", member.size)
        }
    }
}

/// Copy exactly `len` bytes from `from` to `to` (or zeros when `from` is `None`), returning
/// the SHA-256 of what was written.
fn copy_hashed(from: Option<&mut File>, to: &mut File, len: u64) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    let mut from = from;
    while left > 0 {
        let n = usize::try_from(left).map_or(CHUNK, |l| l.min(CHUNK));
        let chunk = buf.get_mut(..n).unwrap_or_default();
        match from.as_deref_mut() {
            Some(f) => f.read_exact(chunk)?,
            None => chunk.fill(0),
        }
        to.write_all(chunk)?;
        hasher.update(&*chunk);
        left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok(hasher.finalize().into())
}

/// SHA-256 of the first `len` bytes of `f`.
fn hash_prefix(f: &mut File, len: u64) -> io::Result<[u8; 32]> {
    f.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(CHUNK, |l| l.min(CHUNK));
        let chunk = buf.get_mut(..n).unwrap_or_default();
        f.read_exact(chunk)?;
        hasher.update(&*chunk);
        left = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok(hasher.finalize().into())
}

/// Run `steps` in order. `device_of` maps a partition label to its device node. Each step is
/// flushed to the device and read back before the next one starts; the first failure stops
/// the sequence. `on_step` is called before each step (progress logging).
pub fn execute(
    steps: &[WriteStep],
    image: &Path,
    device_of: impl Fn(&str) -> Option<PathBuf>,
    mut on_step: impl FnMut(&WriteStep),
) -> Result<(), ApplyError> {
    for step in steps {
        on_step(step);
        let partition = step.partition();
        let device = device_of(partition).ok_or_else(|| ApplyError::NoDevice {
            partition: partition.to_owned(),
        })?;
        let io_err = |source: io::Error| ApplyError::Io {
            step: describe(step),
            source,
        };
        // Never create or truncate: the target is a device node (or, in tests, a file that
        // stands in for one).
        let mut dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device)
            .map_err(io_err)?;
        let written = match step {
            WriteStep::Invalidate { len, .. } => copy_hashed(None, &mut dev, *len),
            WriteStep::Copy { member, .. } => {
                let mut src = File::open(image).map_err(io_err)?;
                src.seek(SeekFrom::Start(member.offset)).map_err(io_err)?;
                copy_hashed(Some(&mut src), &mut dev, member.size)
            }
        }
        .map_err(io_err)?;
        dev.sync_all().map_err(io_err)?;
        let read_back = hash_prefix(&mut dev, step.write_len()).map_err(io_err)?;
        if read_back != written {
            return Err(ApplyError::Verify {
                partition: partition.to_owned(),
            });
        }
    }
    Ok(())
}

fn remove(path: &Path) -> io::Result<()> {
    // symlink_metadata: a symlink to a directory is removed, never followed.
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// Entries of `dir` other than `keep`, as full paths.
fn others(dir: &Path, keep: &str) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() != keep {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// Reduce the overlay's upper layer to the settings directory ([`KEEP`] minus
/// [`IMAGE_FILES_IN_KEEP`]), so the new image is not shadowed by files of the old one:
/// changed binaries, whiteouts of deleted files, a stale board descriptor. Returns what was
/// removed. A missing upper layer (nothing persisted yet) is not an error.
pub fn prune_upper(upper: &Path) -> io::Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    let mut dir = upper.to_path_buf();
    for keep in KEEP {
        match fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => {
                // A whiteout or file where a directory of the kept path should be.
                remove(&dir)?;
                removed.push(dir);
                return Ok(removed);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(removed),
            Err(e) => return Err(e),
        }
        for path in others(&dir, keep)? {
            remove(&path)?;
            removed.push(path);
        }
        dir.push(keep);
    }
    if fs::symlink_metadata(&dir).is_ok_and(|md| !md.is_dir()) {
        remove(&dir)?;
        removed.push(dir);
        return Ok(removed);
    }
    for name in IMAGE_FILES_IN_KEEP {
        let path = dir.join(name);
        match remove(&path) {
            Ok(()) => removed.push(path),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::image::{self, tests::image};
    use crate::plan::{INVALIDATE_LEN, write_plan};

    /// Partitions as files filled with 0xAA, the image file, and the label -> file map.
    fn setup(
        kernel: &[u8],
        root: &[u8],
    ) -> (tempfile::TempDir, PathBuf, BTreeMap<String, PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("sysupgrade.bin");
        fs::write(&img_path, image("glinet_gl-mt6000", kernel, root)).unwrap();
        let mut parts = BTreeMap::new();
        for name in ["kernel", "rootfs"] {
            let p = dir.path().join(name);
            fs::write(&p, vec![0xAAu8; 64 * 1024]).unwrap();
            parts.insert(name.to_owned(), p);
        }
        (dir, img_path, parts)
    }

    fn steps(img_path: &Path) -> Vec<WriteStep> {
        let img = image::read(&mut File::open(img_path).unwrap()).unwrap();
        let storage = owr_board::builtin("glinet_gl-mt6000").unwrap().storage;
        write_plan(&storage, &img).unwrap()
    }

    #[test]
    fn writes_members_and_keeps_the_rest_of_the_partition() {
        let kernel = vec![0x11u8; 5000];
        let root = vec![0x22u8; 9000];
        let (_dir, img_path, parts) = setup(&kernel, &root);
        let mut seen = Vec::new();
        execute(
            &steps(&img_path),
            &img_path,
            |p| parts.get(p).cloned(),
            |s| {
                seen.push(s.partition().to_owned());
            },
        )
        .unwrap();
        assert_eq!(seen, ["kernel", "rootfs", "kernel"], "OpenWrt order");
        let k = fs::read(&parts["kernel"]).unwrap();
        assert_eq!(&k[..5000], &kernel[..]);
        assert!(
            k[5000..].iter().all(|&b| b == 0xAA),
            "no truncation, no padding"
        );
        let r = fs::read(&parts["rootfs"]).unwrap();
        assert_eq!(&r[..9000], &root[..]);
        assert_eq!(r.len(), 64 * 1024);
    }

    #[test]
    fn a_failed_root_write_leaves_the_kernel_invalidated() {
        let (_dir, img_path, mut parts) = setup(&[0x11; 5000], &[0x22; 9000]);
        parts.remove("rootfs");
        let err = execute(
            &steps(&img_path),
            &img_path,
            |p| parts.get(p).cloned(),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(err, ApplyError::NoDevice { ref partition } if partition == "rootfs"));
        let k = fs::read(&parts["kernel"]).unwrap();
        let invalidated = usize::try_from(INVALIDATE_LEN).unwrap();
        assert!(k[..invalidated].iter().all(|&b| b == 0), "header destroyed");
        assert!(k[invalidated..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn a_missing_device_node_is_an_io_error_not_a_new_file() {
        let (dir, img_path, mut parts) = setup(&[1; 10], &[2; 10]);
        let ghost = dir.path().join("no-such-device");
        parts.insert("kernel".into(), ghost.clone());
        assert!(matches!(
            execute(
                &steps(&img_path),
                &img_path,
                |p| parts.get(p).cloned(),
                |_| {}
            ),
            Err(ApplyError::Io { .. })
        ));
        assert!(!ghost.exists(), "must never create the target");
    }

    #[test]
    fn prune_keeps_only_settings() {
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path();
        for (path, body) in [
            ("etc/ferritewrt/config.toml", "cfg"),
            ("etc/ferritewrt/tls/key.pem", "key"),
            ("etc/ferritewrt/board.toml", "stale board"),
            ("etc/passwd", "x"),
            ("sbin/owr-api", "old binary"),
            ("usr/share/ferritewrt/release.pub", "forged key"),
        ] {
            let p = upper.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
        let removed = prune_upper(upper).unwrap();
        assert_eq!(removed.len(), 4, "{removed:?}");
        assert!(upper.join("etc/ferritewrt/config.toml").exists());
        assert!(upper.join("etc/ferritewrt/tls/key.pem").exists());
        for gone in ["etc/ferritewrt/board.toml", "etc/passwd", "sbin", "usr"] {
            assert!(!upper.join(gone).exists(), "{gone} must be removed");
        }
    }

    #[test]
    fn prune_handles_missing_and_non_directory_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            prune_upper(&dir.path().join("absent")).unwrap(),
            Vec::<PathBuf>::new()
        );
        // A file where etc/ should be (stands in for an overlay whiteout of /etc).
        fs::write(dir.path().join("etc"), "").unwrap();
        fs::write(dir.path().join("other"), "").unwrap();
        let removed = prune_upper(dir.path()).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
