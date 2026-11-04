//! `owr upgrade <dir>`: install a release bundle on the router, or `--check` one anywhere.
//!
//! The bundle is the release's `ferritewrt-<board>-v<version>-sysupgrade.bin` with
//! `SHA256SUMS` and `SHA256SUMS.sig` in one directory. On the router the directory is handed
//! to init, which verifies it again on its own, stops everything and writes the image;
//! `--check` runs the same verification here and changes nothing.

use std::io::Write;
use std::path::{Path, PathBuf};

use owr_board::Board;
use owr_upgrade::{Expect, Version, bundle, release};

use crate::CliError;

#[derive(Debug, Clone)]
pub(crate) struct Args {
    pub dir: PathBuf,
    pub allow_downgrade: bool,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub wipe_settings: bool,
    /// Release public key file (64 hex digits).
    pub pubkey: PathBuf,
}

/// The firmware version this binary belongs to.
fn running_version() -> Result<Version, CliError> {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| CliError::Usage("this build's version is not MAJOR.MINOR.PATCH".into()))
}

/// `--check`: verify `args.dir` for `board` and print what would be installed.
pub(crate) fn check(out: &mut dyn Write, args: &Args, board: &Board) -> Result<(), CliError> {
    let text = std::fs::read_to_string(&args.pubkey)
        .map_err(|e| CliError::Usage(format!("{}: {e}", args.pubkey.display())))?;
    let pubkey = release::parse_pubkey(&text)
        .ok_or_else(|| CliError::Usage(format!("{}: not a public key", args.pubkey.display())))?;
    let current = running_version()?;
    let expect = Expect {
        board_id: &board.board.id,
        profile: &board.openwrt.profile,
        current: &current,
    };
    let v = bundle::verify(&args.dir, &pubkey, &expect, args.allow_downgrade)
        .map_err(|e| CliError::Usage(format!("{}: {e}", args.dir.display())))?;
    writeln!(
        out,
        "ok: {} is FerriteWRT {} for {} (running {current})",
        v.image_name, v.version, board.board.id
    )?;
    Ok(())
}

/// Hand the bundle to init (router only).
pub(crate) fn install(out: &mut dyn Write, args: &Args) -> Result<(), CliError> {
    let dir = std::path::absolute(&args.dir)
        .map_err(|e| CliError::Usage(format!("{}: {e}", args.dir.display())))?;
    send(out, &dir, args)
}

#[cfg(unix)]
fn send(out: &mut dyn Write, dir: &Path, args: &Args) -> Result<(), CliError> {
    use owr_init::client::{ClientError, InitClient};
    use owr_init::control::{UpgradeRequest, valid_upgrade_dir};

    let req = UpgradeRequest {
        dir: dir.to_string_lossy().into_owned(),
        allow_downgrade: args.allow_downgrade,
        wipe_settings: args.wipe_settings,
    };
    if !valid_upgrade_dir(&req.dir) {
        return Err(CliError::Usage(format!(
            "{}: {}",
            dir.display(),
            ClientError::BadUpgradeDir
        )));
    }
    let sock = Path::new(owr_common::paths::RUN_DIR).join("init.sock");
    let client = InitClient::connect(&sock)
        .map_err(|e| CliError::Usage(format!("connecting to {}: {e}", sock.display())))?;
    writeln!(out, "verifying {} ...", dir.display())?;
    client
        .upgrade(&req)
        .map_err(|e| CliError::Usage(format!("upgrade: {e}")))?;
    writeln!(
        out,
        "accepted: services are stopping; the router reboots into the new image once it is \
         written (follow the serial console for progress)"
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn send(_out: &mut dyn Write, _dir: &Path, _args: &Args) -> Result<(), CliError> {
    Err(CliError::NotRouter)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ed25519_dalek::{Signer as _, SigningKey};
    use owr_upgrade::release::{SIG_FILE, SUMS_FILE, hash_file, signature_text};

    use super::*;

    /// A one-member-each sysupgrade tar is built by `owr-upgrade`'s own tests; here only the
    /// CLI wiring matters, so a bundle whose image is not a tar is enough to see the board
    /// and signature checks run in order.
    fn bundle(dir: &Path, name: &str, image: &[u8], key: &SigningKey) {
        fs::write(dir.join(name), image).unwrap();
        let sums = format!("{}  {name}\n", hash_file(&dir.join(name)).unwrap().0);
        fs::write(dir.join(SUMS_FILE), &sums).unwrap();
        let text = signature_text(
            &key.verifying_key().to_bytes(),
            &key.sign(sums.as_bytes()).to_bytes(),
        );
        fs::write(dir.join(SIG_FILE), text).unwrap();
        fs::write(
            dir.join("release.pub"),
            format!("{}\n", hex::encode(key.verifying_key().to_bytes())),
        )
        .unwrap();
    }

    fn args(dir: &Path) -> Args {
        Args {
            dir: dir.to_path_buf(),
            allow_downgrade: false,
            wipe_settings: false,
            pubkey: dir.join("release.pub"),
        }
    }

    #[test]
    fn check_reports_the_first_failing_verification_step() {
        let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let name = "ferritewrt-glinet_gl-mt6000-v99.0.0-sysupgrade.bin";
        bundle(dir.path(), name, b"not a tar", &key);
        let err = check(&mut Vec::new(), &args(dir.path()), &board).unwrap_err();
        assert!(
            err.to_string().contains("not a sysupgrade image"),
            "signature and hash passed, image parse failed: {err}"
        );

        let other = SigningKey::from_bytes(&[6u8; 32]);
        fs::write(
            dir.path().join("release.pub"),
            hex::encode(other.verifying_key().to_bytes()),
        )
        .unwrap();
        let err = check(&mut Vec::new(), &args(dir.path()), &board).unwrap_err();
        assert!(err.to_string().contains(SIG_FILE), "{err}");
    }

    #[test]
    fn check_needs_a_readable_key() {
        let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = check(&mut Vec::new(), &args(dir.path()), &board).unwrap_err();
        assert!(err.to_string().contains("release.pub"), "{err}");
    }
}
