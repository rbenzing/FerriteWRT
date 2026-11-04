//! Verify an upgrade bundle: the three release files in one directory.
//!
//! Order matters: the signature is checked before anything listed in `SHA256SUMS` is trusted,
//! the image hash before its contents are parsed, and the board and version last.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::image::{self, ImageError, SysupgradeImage};
use crate::release::{SIG_FILE, SUMS_FILE, hash_reader, parse_sums, verify_signature};
use crate::version::Version;

/// Upper bounds for the two small files; a real `SHA256SUMS` is well under 1 KiB.
const MAX_SUMS: u64 = 64 * 1024;
const MAX_SIG: u64 = 4 * 1024;
/// Upper bound for an image. The reference board's image is about 30 MiB. On the router the
/// upload and init's staged copy both sit in RAM (tmpfs), so two of these must fit
/// comfortably: 128 MiB keeps the worst case at a quarter of a 1 GiB router.
pub const MAX_IMAGE: u64 = 128 * 1024 * 1024;

fn copy_capped(src: &Path, dst: &Path, cap: u64) -> Result<(), BundleError> {
    let name = src
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let err = |msg: String| BundleError::Read {
        file: name.clone(),
        msg,
    };
    let md = fs::symlink_metadata(src).map_err(|e| err(e.to_string()))?;
    if !md.is_file() {
        return Err(err("not a regular file".into()));
    }
    let mut from = File::open(src)
        .map_err(|e| err(e.to_string()))?
        .take(cap.saturating_add(1));
    let mut to = File::create(dst).map_err(|e| err(e.to_string()))?;
    let n = io::copy(&mut from, &mut to).map_err(|e| err(e.to_string()))?;
    if n > cap {
        return Err(err(format!("larger than {cap} bytes")));
    }
    to.sync_all().map_err(|e| err(e.to_string()))
}

/// Copy a bundle from `src` (a directory the caller does not control) into a fresh `dst`
/// that only the caller can write (mode 0700 on unix), so nothing can change the files
/// between [`verify`] and the write. Copies `SHA256SUMS`, its signature and the one
/// sysupgrade image named for `board` (at most [`MAX_IMAGE`] bytes); images of other boards
/// in `src` (a full multi-board release) are skipped. `dst` is replaced.
pub fn stage(src: &Path, dst: &Path, board: &str) -> Result<(), BundleError> {
    let err = |msg: String| BundleError::Read {
        file: dst.display().to_string(),
        msg,
    };
    match fs::remove_dir_all(dst) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(err(e.to_string())),
    }
    #[cfg(unix)]
    let builder = {
        let mut b = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder.create(dst).map_err(|e| err(e.to_string()))?;

    copy_capped(&src.join(SUMS_FILE), &dst.join(SUMS_FILE), MAX_SUMS)?;
    copy_capped(&src.join(SIG_FILE), &dst.join(SIG_FILE), MAX_SIG)?;
    let listing = fs::read_dir(src).map_err(|e| BundleError::Read {
        file: src.display().to_string(),
        msg: e.to_string(),
    })?;
    let mut staged = false;
    for entry in listing.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|n| image_version(n, board).is_some()) else {
            continue;
        };
        if std::mem::replace(&mut staged, true) {
            return Err(BundleError::Sums(format!(
                "more than one sysupgrade image for {board} in {}",
                src.display()
            )));
        }
        copy_capped(&entry.path(), &dst.join(name), MAX_IMAGE)?;
    }
    if staged {
        Ok(())
    } else {
        Err(BundleError::NoImage(board.to_owned()))
    }
}

/// What the running router is.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    /// `[board] id`: the board token in release file names.
    pub board_id: &'a str,
    /// `[openwrt] profile`: the `BOARD=` `OpenWrt` writes into the image.
    pub profile: &'a str,
    /// The running firmware version.
    pub current: &'a Version,
}

/// A bundle that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub version: Version,
    /// File name of the image as listed in the signed `SHA256SUMS`.
    pub image_name: String,
    pub image_path: PathBuf,
    /// Its SHA-256 (lowercase hex), as signed.
    pub sha256: String,
    pub image: SysupgradeImage,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("{file}: {msg}")]
    Read { file: String, msg: String },
    #[error("{SIG_FILE}: {0}")]
    Signature(String),
    #[error("{SUMS_FILE}: {0}")]
    Sums(String),
    #[error("the release has no sysupgrade image for board {0}")]
    NoImage(String),
    #[error("{0} does not match {SUMS_FILE}")]
    Hash(String),
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("the image is for {image}, this router is {expected}")]
    WrongBoard { image: String, expected: String },
    #[error("{to} is older than the running {from}; a downgrade must be requested explicitly")]
    Downgrade { from: String, to: String },
}

/// The release file name of the sysupgrade image for `board` at `version`.
pub fn image_name(board: &str, version: &Version) -> String {
    format!("ferritewrt-{board}-v{version}-sysupgrade.bin")
}

/// The version encoded in a sysupgrade image name for `board`, if `name` is one.
fn image_version(name: &str, board: &str) -> Option<Version> {
    let v = name
        .strip_prefix("ferritewrt-")?
        .strip_prefix(board)?
        .strip_prefix("-v")?
        .strip_suffix("-sysupgrade.bin")?;
    Version::parse(v)
}

fn read_capped(dir: &Path, file: &str, cap: u64) -> Result<Vec<u8>, BundleError> {
    let err = |msg: String| BundleError::Read {
        file: file.to_owned(),
        msg,
    };
    let f = File::open(dir.join(file)).map_err(|e| err(e.to_string()))?;
    let mut buf = Vec::new();
    f.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| err(e.to_string()))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > cap {
        return Err(err(format!("larger than {cap} bytes")));
    }
    Ok(buf)
}

/// Verify the bundle in `dir` against the release public key and the running router.
/// `allow_downgrade` permits an older version (the same version is always allowed: it
/// reinstalls).
pub fn verify(
    dir: &Path,
    pubkey: &[u8; 32],
    expect: &Expect<'_>,
    allow_downgrade: bool,
) -> Result<Verified, BundleError> {
    let sums = read_capped(dir, SUMS_FILE, MAX_SUMS)?;
    let sig = read_capped(dir, SIG_FILE, MAX_SIG)?;
    let sig = String::from_utf8(sig).map_err(|_| BundleError::Signature("not UTF-8".into()))?;
    verify_signature(&sig, &sums, pubkey).map_err(BundleError::Signature)?;
    let entries = parse_sums(&sums).map_err(BundleError::Sums)?;

    let mut images = entries
        .iter()
        .filter_map(|e| image_version(&e.name, expect.board_id).map(|v| (e, v)));
    let (entry, version) = match (images.next(), images.next()) {
        (Some(one), None) => one,
        (None, _) => return Err(BundleError::NoImage(expect.board_id.to_owned())),
        (Some(_), Some(_)) => {
            return Err(BundleError::Sums(
                "more than one sysupgrade image for this board".into(),
            ));
        }
    };

    let image_path = dir.join(&entry.name);
    let read_err = |e: io::Error| BundleError::Read {
        file: entry.name.clone(),
        msg: e.to_string(),
    };
    let md = fs::symlink_metadata(&image_path).map_err(read_err)?;
    if !md.is_file() {
        return Err(BundleError::Read {
            file: entry.name.clone(),
            msg: "not a regular file".into(),
        });
    }
    let mut file = File::open(&image_path).map_err(read_err)?;
    let (sha256, _) = hash_reader(&mut file).map_err(read_err)?;
    if sha256 != entry.hash {
        return Err(BundleError::Hash(entry.name.clone()));
    }
    let image = image::read(&mut file)?;
    if image.board != expect.profile {
        return Err(BundleError::WrongBoard {
            image: image.board,
            expected: expect.profile.to_owned(),
        });
    }
    if version < *expect.current && !allow_downgrade {
        return Err(BundleError::Downgrade {
            from: expect.current.to_string(),
            to: version.to_string(),
        });
    }
    Ok(Verified {
        version,
        image_name: entry.name.clone(),
        image_path,
        sha256,
        image,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::image::tests::image;
    use crate::release::{hash_file, signature_text};

    pub(crate) const BOARD: &str = "glinet_gl-mt6000";

    pub(crate) fn key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    /// Write `files` into `dir`, then SHA256SUMS over them and its signature by `key()`.
    pub(crate) fn release(dir: &Path, files: &[(&str, &[u8])]) {
        let mut sums = String::new();
        for (name, bytes) in files {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            for part in [hash_file(&path).unwrap().0.as_str(), "  ", name, "\n"] {
                sums.push_str(part);
            }
        }
        fs::write(dir.join(SUMS_FILE), &sums).unwrap();
        let k = key();
        let text = signature_text(
            &k.verifying_key().to_bytes(),
            &k.sign(sums.as_bytes()).to_bytes(),
        );
        fs::write(dir.join(SIG_FILE), text).unwrap();
    }

    pub(crate) fn good_image() -> Vec<u8> {
        image(BOARD, b"kernel-fit", b"squashfs-root")
    }

    fn run(dir: &Path, current: &str, allow_downgrade: bool) -> Result<Verified, BundleError> {
        let current = Version::parse(current).unwrap();
        let expect = Expect {
            board_id: BOARD,
            profile: BOARD,
            current: &current,
        };
        verify(
            dir,
            &key().verifying_key().to_bytes(),
            &expect,
            allow_downgrade,
        )
    }

    const NAME: &str = "ferritewrt-glinet_gl-mt6000-v0.3.0-sysupgrade.bin";

    #[test]
    fn accepts_a_signed_bundle() {
        let dir = tempfile::tempdir().unwrap();
        release(
            dir.path(),
            &[(NAME, &good_image()), ("manifest.json", b"{}")],
        );
        let v = run(dir.path(), "0.2.1", false).unwrap();
        assert_eq!(v.version.to_string(), "0.3.0");
        assert_eq!(v.image_name, NAME);
        assert_eq!(v.image.board, BOARD);
        // The other release files need not be present: only the image is read.
        fs::remove_file(dir.path().join("manifest.json")).unwrap();
        assert!(run(dir.path(), "0.3.0", false).is_ok(), "reinstall");
    }

    #[test]
    fn rejects_a_modified_image_or_sums() {
        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &good_image())]);
        let mut bytes = good_image();
        bytes.push(0);
        fs::write(dir.path().join(NAME), &bytes).unwrap();
        assert_eq!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::Hash(NAME.into()))
        );

        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &good_image())]);
        let sums = fs::read_to_string(dir.path().join(SUMS_FILE)).unwrap();
        fs::write(dir.path().join(SUMS_FILE), sums.replace("v0.3.0", "v9.0.0")).unwrap();
        assert!(matches!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::Signature(_))
        ));
    }

    #[test]
    fn rejects_other_keys_boards_and_downgrades() {
        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &good_image())]);
        let current = Version::parse("0.2.1").unwrap();
        let expect = Expect {
            board_id: BOARD,
            profile: BOARD,
            current: &current,
        };
        let other = SigningKey::from_bytes(&[4u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            verify(dir.path(), &other, &expect, false),
            Err(BundleError::Signature(_))
        ));

        // Name says our board, image says another one: the signed name is not enough.
        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &image("other_board", b"k", b"r"))]);
        assert!(matches!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::WrongBoard { .. })
        ));

        // A release for another board only.
        let dir = tempfile::tempdir().unwrap();
        release(
            dir.path(),
            &[("ferritewrt-other-v0.3.0-sysupgrade.bin", &good_image())],
        );
        assert_eq!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::NoImage(BOARD.into()))
        );

        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &good_image())]);
        assert!(matches!(
            run(dir.path(), "0.4.0", false),
            Err(BundleError::Downgrade { .. })
        ));
        assert!(run(dir.path(), "0.4.0", true).is_ok());
    }

    #[test]
    fn missing_files_are_named() {
        let dir = tempfile::tempdir().unwrap();
        release(dir.path(), &[(NAME, &good_image())]);
        fs::remove_file(dir.path().join(NAME)).unwrap();
        assert!(matches!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::Read { file, .. }) if file == NAME
        ));
        fs::remove_file(dir.path().join(SIG_FILE)).unwrap();
        assert!(matches!(
            run(dir.path(), "0.2.1", false),
            Err(BundleError::Read { file, .. }) if file == SIG_FILE
        ));
    }

    #[test]
    fn staged_copy_verifies_and_ignores_unrelated_files() {
        let src = tempfile::tempdir().unwrap();
        release(
            src.path(),
            &[
                (NAME, &good_image()),
                ("ferritewrt-other-v0.3.0-sysupgrade.bin", b"another board"),
                ("notes.txt", b"x"),
            ],
        );
        let dst = tempfile::tempdir().unwrap();
        let staged = dst.path().join("upgrade");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("leftover"), b"old").unwrap();
        stage(src.path(), &staged, BOARD).unwrap();
        let mut names: Vec<String> = fs::read_dir(&staged)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [SUMS_FILE, SIG_FILE, NAME],
            "replaced, only bundle files"
        );
        assert!(run(&staged, "0.2.1", false).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn staging_requires_sums_and_signature() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join(NAME), good_image()).unwrap();
        let dst = tempfile::tempdir().unwrap();
        assert!(matches!(
            stage(src.path(), &dst.path().join("u"), BOARD),
            Err(BundleError::Read { file, .. }) if file == SUMS_FILE
        ));
    }

    #[test]
    fn image_names_round_trip() {
        let v = Version::parse("1.2.3-rc.1").unwrap();
        let name = image_name(BOARD, &v);
        assert_eq!(image_version(&name, BOARD), Some(v));
        assert_eq!(
            image_version(&name, "glinet"),
            None,
            "board must match exactly"
        );
        assert_eq!(
            image_version("ferritewrt-glinet_gl-mt6000-v1.2.3-factory.bin", BOARD),
            None
        );
    }
}
