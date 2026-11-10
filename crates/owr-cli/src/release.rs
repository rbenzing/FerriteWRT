//! `owr release ...`: build, sign and verify release artifacts.
//!
//! The byte-exact signature contract is documented in the crate README ("Release signing").
//! Handlers write to a `&mut dyn Write` and are tested without spawning the binary. The
//! private key is only ever a 32-byte ed25519 seed (64 hex chars) in `OWR_RELEASE_KEY` or a
//! `0600` key file; it is held in `Zeroizing` buffers and never printed except by `keygen`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ed25519_dalek::{Signer as _, SigningKey};
use owr_common::atomic_write;
use rand::TryRng as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use owr_upgrade::release::{self, SIG_FILE, SUMS_FILE, decode32, parse_sums, valid_file_name};
use owr_upgrade::version::valid_version;

use crate::CliError;
use crate::commands::{Exit, io_error};

pub(crate) const MANIFEST_FILE: &str = "manifest.json";
/// Environment variable holding the signing seed (64 hex chars).
pub(crate) const KEY_ENV: &str = "OWR_RELEASE_KEY";
const PUBLIC_MODE: u32 = 0o644;
const SECRET_MODE: u32 = 0o600;

fn fail(msg: impl Into<String>) -> CliError {
    CliError::Release(msg.into())
}

// --- manifest model ------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    project: String,
    version: String,
    board: String,
    git: GitRevs,
    kernel: String,
    built_utc: String,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitRevs {
    ferritewrt: String,
    openwrt: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    kind: String,
    size: u64,
    sha256: String,
}

/// Options of `owr release manifest`.
#[derive(Debug, Clone)]
pub(crate) struct ManifestArgs {
    pub version: String,
    pub board: String,
    pub openwrt_rev: Option<String>,
    pub ferritewrt_rev: Option<String>,
    pub kernel: Option<String>,
    pub built_utc: Option<String>,
}

// --- validation helpers --------------------------------------------------------------

/// `unknown` or dotted numbers such as `6.18.3`.
fn valid_kernel(s: &str) -> bool {
    s == "unknown"
        || (!s.is_empty()
            && s.split('.')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
}

/// Board ids and git revisions: `[A-Za-z0-9._-]{1,64}`.
fn valid_token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

// --- files and hashing ---------------------------------------------------------------

/// Streaming SHA-256 and size of a file (images are hundreds of MB).
fn hash_file(path: &Path) -> Result<(String, u64), CliError> {
    release::hash_file(path).map_err(|e| io_error(path, &e))
}

/// Names of the regular files in `dir` (symlinks and directories are skipped), sorted
/// bytewise, minus `exclude`.
fn regular_files(dir: &Path, exclude: &[&str]) -> Result<Vec<String>, CliError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| io_error(dir, &e))? {
        let entry = entry.map_err(|e| io_error(dir, &e))?;
        if !entry.file_type().map_err(|e| io_error(dir, &e))?.is_file() {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|n| {
            fail(format!(
                "{}: non-UTF-8 file name {}",
                dir.display(),
                n.display()
            ))
        })?;
        if exclude.contains(&name.as_str()) {
            continue;
        }
        if !valid_file_name(&name) {
            return Err(fail(format!(
                "{}: file name {name:?} contains control or path characters",
                dir.display()
            )));
        }
        names.push(name);
    }
    names.sort_unstable();
    Ok(names)
}

// --- keygen --------------------------------------------------------------------------

/// Generate a key pair. Without `out_dir`: public key hex on `out`, `OWR_RELEASE_KEY=<seed>`
/// on `err`. With `out_dir`: `release.pub` and `release.key` (0600) are written there.
pub(crate) fn keygen(
    out: &mut dyn Write,
    err: &mut dyn Write,
    out_dir: Option<&Path>,
) -> Result<(), CliError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut *seed)
        .map_err(|e| fail(format!("OS random source failed: {e}")))?;
    let key = SigningKey::from_bytes(&seed);
    let pub_hex = hex::encode(key.verifying_key().to_bytes());
    let seed_hex = Zeroizing::new(hex::encode(*seed));
    let Some(dir) = out_dir else {
        writeln!(err, "{KEY_ENV}={}", seed_hex.as_str())?;
        writeln!(
            err,
            "# WARNING: this is the release SIGNING key. Store it only as a CI secret; never commit it."
        )?;
        writeln!(out, "{pub_hex}")?;
        return Ok(());
    };
    fs::create_dir_all(dir).map_err(|e| io_error(dir, &e))?;
    let pub_path = dir.join("release.pub");
    let key_path = dir.join("release.key");
    for p in [&pub_path, &key_path] {
        if p.exists() {
            return Err(fail(format!(
                "{} exists; refusing to overwrite",
                p.display()
            )));
        }
    }
    let key_line = Zeroizing::new(format!("{}\n", seed_hex.as_str()));
    atomic_write(&key_path, key_line.as_bytes(), SECRET_MODE)?;
    atomic_write(&pub_path, format!("{pub_hex}\n").as_bytes(), PUBLIC_MODE)?;
    writeln!(out, "wrote {}", pub_path.display())?;
    writeln!(out, "wrote {}", key_path.display())?;
    writeln!(
        err,
        "WARNING: {} is the release SIGNING key (mode 0600). Never commit it. Move it into the CI \
         secret {KEY_ENV} and delete the file.",
        key_path.display()
    )?;
    Ok(())
}

// --- sums ----------------------------------------------------------------------------

/// Write `<dir>/SHA256SUMS` over every regular file except `SHA256SUMS` and its signature.
pub(crate) fn sums(out: &mut dyn Write, dir: &Path) -> Result<(), CliError> {
    let names = regular_files(dir, &[SUMS_FILE, SIG_FILE])?;
    if names.is_empty() {
        return Err(fail(format!("{}: no files to checksum", dir.display())));
    }
    let mut text = String::new();
    for name in &names {
        let (hash, _) = hash_file(&dir.join(name))?;
        for part in [hash.as_str(), "  ", name.as_str(), "\n"] {
            text.push_str(part);
        }
    }
    let path = dir.join(SUMS_FILE);
    atomic_write(&path, text.as_bytes(), PUBLIC_MODE)?;
    out.write_all(text.as_bytes())?;
    Ok(())
}

// --- manifest ------------------------------------------------------------------------

fn kind_of(name: &str) -> &'static str {
    if name.ends_with("-factory.bin") {
        "factory"
    } else if name.ends_with("-sysupgrade.bin") {
        "sysupgrade"
    } else if name.ends_with("-initramfs-kernel.bin") || name.contains("initramfs") {
        "initramfs"
    } else if name.ends_with(".tar.gz") || name.ends_with(".tar.zst") {
        "binaries"
    } else {
        "other"
    }
}

/// Write `<dir>/manifest.json` describing every file in `dir` except the manifest itself and
/// the sums/signature files. Run it before `sums` so the signature covers the manifest.
pub(crate) fn manifest(
    out: &mut dyn Write,
    dir: &Path,
    args: &ManifestArgs,
    now: SystemTime,
) -> Result<(), CliError> {
    if !valid_version(&args.version) {
        return Err(fail(format!(
            "--version must be MAJOR.MINOR.PATCH[-pre] without a leading 'v', got {:?}",
            args.version
        )));
    }
    if !valid_token(&args.board) {
        return Err(fail("--board must match [A-Za-z0-9._-]{1,64}"));
    }
    let unknown = || "unknown".to_owned();
    let openwrt = args.openwrt_rev.clone().unwrap_or_else(unknown);
    let ferritewrt = args.ferritewrt_rev.clone().unwrap_or_else(unknown);
    if !valid_token(&openwrt) || !valid_token(&ferritewrt) {
        return Err(fail(
            "--openwrt-rev and --ferritewrt-rev must match [A-Za-z0-9._-]{1,64}",
        ));
    }
    let kernel = args.kernel.clone().unwrap_or_else(unknown);
    if !valid_kernel(&kernel) {
        return Err(fail(format!(
            "--kernel must be 'unknown' or a dotted version such as 6.18.3, got {kernel:?}"
        )));
    }
    let built_utc = match &args.built_utc {
        Some(t) => {
            humantime::parse_rfc3339(t)
                .map_err(|e| fail(format!("--built-utc is not RFC 3339: {e}")))?;
            t.clone()
        }
        None => humantime::format_rfc3339_seconds(now).to_string(),
    };

    let names = regular_files(dir, &[SUMS_FILE, SIG_FILE, MANIFEST_FILE])?;
    if names.is_empty() {
        return Err(fail(format!("{}: no artifacts found", dir.display())));
    }
    let mut artifacts = Vec::with_capacity(names.len());
    for name in names {
        let (sha256, size) = hash_file(&dir.join(&name))?;
        artifacts.push(Artifact {
            kind: kind_of(&name).to_owned(),
            name,
            size,
            sha256,
        });
    }
    let doc = Manifest {
        schema: 1,
        project: "ferritewrt".to_owned(),
        version: args.version.clone(),
        board: args.board.clone(),
        git: GitRevs {
            ferritewrt,
            openwrt,
        },
        kernel,
        built_utc,
        artifacts,
    };
    let mut json = serde_json::to_string_pretty(&doc)?;
    json.push('\n');
    let path = dir.join(MANIFEST_FILE);
    atomic_write(&path, json.as_bytes(), PUBLIC_MODE)?;
    writeln!(
        out,
        "wrote {} ({} artifacts)",
        path.display(),
        doc.artifacts.len()
    )?;
    Ok(())
}

fn read_manifest(path: &Path) -> Result<Manifest, CliError> {
    let bytes = fs::read(path).map_err(|e| io_error(path, &e))?;
    parse_manifest(&bytes).map_err(|e| fail(format!("{}: {e}", path.display())))
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    let doc: Manifest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if doc.schema != 1 {
        return Err(format!("unsupported schema {}", doc.schema));
    }
    if doc.project != "ferritewrt" {
        return Err(format!("unexpected project {:?}", doc.project));
    }
    Ok(doc)
}

/// Print a manifest summary.
pub(crate) fn show(out: &mut dyn Write, dir: &Path) -> Result<(), CliError> {
    let doc = read_manifest(&dir.join(MANIFEST_FILE))?;
    writeln!(out, "{} v{} ({})", doc.project, doc.version, doc.board)?;
    writeln!(out, "kernel:   {}", doc.kernel)?;
    writeln!(out, "built:    {}", doc.built_utc)?;
    writeln!(out, "ferritewrt: {}", doc.git.ferritewrt)?;
    writeln!(out, "openwrt:  {}", doc.git.openwrt)?;
    writeln!(out)?;
    writeln!(
        out,
        "{:<56} {:<10} {:>12}  SHA256",
        "ARTIFACT", "KIND", "SIZE"
    )?;
    for a in &doc.artifacts {
        let short = a.sha256.get(..16).unwrap_or(&a.sha256);
        writeln!(
            out,
            "{:<56} {:<10} {:>12}  {short}...",
            a.name, a.kind, a.size
        )?;
    }
    Ok(())
}

// --- sign ----------------------------------------------------------------------------

/// The signing seed from `--key-file` (must not be group/world accessible on unix) or, if no
/// file was given, from the `OWR_RELEASE_KEY` value.
pub(crate) fn read_key_hex(
    key_file: Option<&Path>,
    env_value: Option<OsString>,
) -> Result<Zeroizing<String>, CliError> {
    if let Some(path) = key_file {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .map_err(|e| io_error(path, &e))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(fail(format!(
                    "{}: key file is accessible by group/others (mode {:04o}); chmod 600 it",
                    path.display(),
                    mode & 0o7777
                )));
            }
        }
        let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| io_error(path, &e))?);
        return Ok(Zeroizing::new(text.trim().to_owned()));
    }
    match env_value {
        Some(v) => {
            let s = v
                .into_string()
                .map_err(|_| fail(format!("{KEY_ENV} is not valid UTF-8")))?;
            Ok(Zeroizing::new(s.trim().to_owned()))
        }
        None => Err(fail(format!(
            "no signing key: set {KEY_ENV} or pass --key-file"
        ))),
    }
}

fn signing_key(key_hex: &str) -> Result<SigningKey, CliError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    if key_hex.len() != 64 || hex::decode_to_slice(key_hex, &mut *seed).is_err() {
        // Never echo the value: it is a secret.
        return Err(fail(format!(
            "signing key must be the 32-byte seed as 64 hex characters ({KEY_ENV})"
        )));
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Sign `<dir>/SHA256SUMS`, writing `<dir>/SHA256SUMS.sig`.
pub(crate) fn sign(
    out: &mut dyn Write,
    dir: &Path,
    key_hex: &str,
    force: bool,
) -> Result<(), CliError> {
    let sums_path = dir.join(SUMS_FILE);
    let sig_path = dir.join(SIG_FILE);
    let bytes = fs::read(&sums_path).map_err(|e| {
        let hint = if e.kind() == io::ErrorKind::NotFound {
            " (run `owr release sums` first)"
        } else {
            ""
        };
        fail(format!("{}: {e}{hint}", sums_path.display()))
    })?;
    parse_sums(&bytes).map_err(|e| fail(format!("{}: {e}", sums_path.display())))?;
    if sig_path.exists() && !force {
        return Err(fail(format!(
            "{} exists; use --force to overwrite",
            sig_path.display()
        )));
    }
    let key = signing_key(key_hex)?;
    let signature = key.sign(&bytes);
    let pubkey = key.verifying_key().to_bytes();
    let pub_hex = hex::encode(pubkey);
    let text = release::signature_text(&pubkey, &signature.to_bytes());
    atomic_write(&sig_path, text.as_bytes(), PUBLIC_MODE)?;
    writeln!(out, "signed {} with key {pub_hex}", sums_path.display())?;
    Ok(())
}

// --- verify --------------------------------------------------------------------------

/// Options of `owr release verify`.
#[derive(Debug, Clone)]
pub(crate) struct VerifyArgs {
    pub paths: Vec<PathBuf>,
    /// 64 hex characters, or the path of a `release.pub` file.
    pub pubkey: String,
    pub allow_missing: bool,
}

fn resolve_pubkey(spec: &str) -> Result<[u8; 32], CliError> {
    if let Some(k) = decode32(spec.trim()) {
        return Ok(k);
    }
    let text = fs::read_to_string(spec).map_err(|e| {
        fail(format!(
            "--pubkey is neither 64 hex characters nor a readable file: {e}"
        ))
    })?;
    decode32(text.trim()).ok_or_else(|| {
        fail(format!(
            "{spec}: not a public key (expected 64 hex characters)"
        ))
    })
}

/// The directory holding `SHA256SUMS`, and the file names to check (`None` = all listed).
fn resolve_targets(paths: &[PathBuf]) -> Result<(PathBuf, Option<BTreeSet<String>>), CliError> {
    let mut dir: Option<PathBuf> = None;
    let mut canonical: Option<PathBuf> = None;
    let mut names = BTreeSet::new();
    let mut whole_dir = false;
    for p in paths {
        let md = fs::metadata(p).map_err(|e| io_error(p, &e))?;
        let d = if md.is_dir() {
            whole_dir = true;
            p.clone()
        } else {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| fail(format!("{}: not a usable file name", p.display())))?;
            names.insert(name.to_owned());
            match p.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
                _ => PathBuf::from("."),
            }
        };
        let c = fs::canonicalize(&d).map_err(|e| io_error(&d, &e))?;
        match &canonical {
            Some(prev) if *prev != c => {
                return Err(fail("all paths must be in the same directory"));
            }
            Some(_) => {}
            None => {
                canonical = Some(c);
                dir = Some(d);
            }
        }
    }
    let dir = dir.ok_or_else(|| fail("nothing to verify"))?;
    Ok((dir, if whole_dir { None } else { Some(names) }))
}

/// Check `SHA256SUMS.sig` against `sums` and the expected public key.
fn check_signature(dir: &Path, sums: &[u8], pubkey: &[u8; 32]) -> Result<(), String> {
    let text = fs::read_to_string(dir.join(SIG_FILE))
        .map_err(|e| format!("cannot read {SIG_FILE}: {e}"))?;
    release::verify_signature(&text, sums, pubkey)
}

/// Checks the manifest's artifacts against the (already verified) sums. Returns `false`
/// after printing a `FAIL` line for each inconsistency.
fn check_manifest(
    out: &mut dyn Write,
    bytes: &[u8],
    listed: &BTreeMap<&str, &str>,
    sizes: &BTreeMap<String, u64>,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<bool, CliError> {
    let doc = match parse_manifest(bytes) {
        Ok(doc) => doc,
        Err(why) => {
            writeln!(out, "FAIL {MANIFEST_FILE}: {why}")?;
            return Ok(false);
        }
    };
    let mut ok = true;
    for a in doc.artifacts.iter().filter(|a| wanted(&a.name)) {
        let problem = match (listed.get(a.name.as_str()), sizes.get(&a.name)) {
            (None, _) => Some("not in SHA256SUMS".to_owned()),
            (Some(hash), _) if **hash != a.sha256 => {
                Some("sha256 differs from SHA256SUMS".to_owned())
            }
            (Some(_), Some(actual)) if *actual != a.size => {
                Some(format!("size {} != file size {actual}", a.size))
            }
            _ => None,
        };
        if let Some(problem) = problem {
            writeln!(out, "FAIL {} (manifest: {problem})", a.name)?;
            ok = false;
        }
    }
    Ok(ok)
}

/// Verify the signature, then every listed file that exists. Exit `Ok` only when the
/// signature and every checked hash match (and nothing is missing, unless allowed).
pub(crate) fn verify(out: &mut dyn Write, args: &VerifyArgs) -> Result<Exit, CliError> {
    let pubkey = resolve_pubkey(&args.pubkey)?;
    let (dir, only) = resolve_targets(&args.paths)?;
    let sums_path = dir.join(SUMS_FILE);
    let sums_bytes = fs::read(&sums_path).map_err(|e| io_error(&sums_path, &e))?;
    if let Err(why) = check_signature(&dir, &sums_bytes, &pubkey) {
        writeln!(out, "FAIL {SIG_FILE}: {why}")?;
        return Ok(Exit::Issues);
    }
    writeln!(out, "ok  {SIG_FILE}")?;
    let entries = match parse_sums(&sums_bytes) {
        Ok(entries) => entries,
        Err(why) => {
            writeln!(out, "FAIL {SUMS_FILE}: {why}")?;
            return Ok(Exit::Issues);
        }
    };
    let wanted = |name: &str| only.as_ref().is_none_or(|set| set.contains(name));
    let listed: BTreeMap<&str, &str> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.hash.as_str()))
        .collect();

    let mut bad = false;
    let mut missing = false;
    let mut sizes: BTreeMap<String, u64> = BTreeMap::new();
    for entry in entries.iter().filter(|e| wanted(&e.name)) {
        let path = dir.join(&entry.name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                writeln!(out, "missing {}", entry.name)?;
                missing = true;
                continue;
            }
            Ok(md) if md.is_file() => {}
            Ok(_) | Err(_) => {
                writeln!(out, "FAIL {} (not a readable regular file)", entry.name)?;
                bad = true;
                continue;
            }
        }
        match hash_file(&path) {
            Ok((hash, size)) if hash == entry.hash => {
                writeln!(out, "ok  {}", entry.name)?;
                sizes.insert(entry.name.clone(), size);
            }
            Ok(_) => {
                writeln!(out, "FAIL {}", entry.name)?;
                bad = true;
            }
            Err(e) => {
                writeln!(out, "FAIL {} ({e})", entry.name)?;
                bad = true;
            }
        }
    }
    if let Some(only) = &only {
        for name in only.iter().filter(|n| {
            ![SUMS_FILE, SIG_FILE].contains(&n.as_str()) && !listed.contains_key(n.as_str())
        }) {
            writeln!(out, "FAIL {name} (not listed in {SUMS_FILE})")?;
            bad = true;
        }
    } else {
        for name in regular_files(&dir, &[SUMS_FILE, SIG_FILE])? {
            if !listed.contains_key(name.as_str()) {
                writeln!(out, "extra {name} (not listed in {SUMS_FILE}; ignored)")?;
            }
        }
    }
    // The manifest is only trusted once its own hash matched the signed sums.
    if sizes.contains_key(MANIFEST_FILE) {
        let path = dir.join(MANIFEST_FILE);
        let bytes = fs::read(&path).map_err(|e| io_error(&path, &e))?;
        if !check_manifest(out, &bytes, &listed, &sizes, &wanted)? {
            bad = true;
        }
    }
    Ok(if bad || (missing && !args.allow_missing) {
        Exit::Issues
    } else {
        Exit::Ok
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use owr_upgrade::release::lower_hex;

    use super::*;

    const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn out_str(buf: Vec<u8>) -> String {
        String::from_utf8(buf).unwrap()
    }

    fn pub_of(key_hex: &str) -> String {
        hex::encode(signing_key(key_hex).unwrap().verifying_key().to_bytes())
    }

    fn manifest_args() -> ManifestArgs {
        ManifestArgs {
            version: "1.2.3".to_owned(),
            board: "test_board".to_owned(),
            openwrt_rev: Some("abc1234".to_owned()),
            ferritewrt_rev: Some("def5678-dirty".to_owned()),
            kernel: Some("6.18.3".to_owned()),
            built_utc: Some("2026-01-02T03:04:05Z".to_owned()),
        }
    }

    /// A signed release directory: files, manifest, sums and signature.
    fn signed_release(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        manifest(
            &mut Vec::new(),
            dir.path(),
            &manifest_args(),
            SystemTime::now(),
        )
        .unwrap();
        sums(&mut Vec::new(), dir.path()).unwrap();
        sign(&mut Vec::new(), dir.path(), KEY_A, false).unwrap();
        dir
    }

    const FILES: &[(&str, &[u8])] = &[
        ("ferritewrt-b-v1.2.3-factory.bin", b"factory image"),
        ("ferritewrt-b-v1.2.3-sysupgrade.bin", b"sysupgrade image"),
    ];

    fn verify_with(dir: &Path, pubkey: &str, allow_missing: bool) -> (Exit, String) {
        verify_paths(&[dir.to_path_buf()], pubkey, allow_missing)
    }

    fn verify_paths(paths: &[PathBuf], pubkey: &str, allow_missing: bool) -> (Exit, String) {
        let mut out = Vec::new();
        let args = VerifyArgs {
            paths: paths.to_vec(),
            pubkey: pubkey.to_owned(),
            allow_missing,
        };
        let exit = verify(&mut out, &args).unwrap();
        (exit, out_str(out))
    }

    #[test]
    fn keygen_prints_public_key_on_stdout_and_seed_on_stderr() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        keygen(&mut out, &mut err, None).unwrap();
        let out = out_str(out);
        let err = out_str(err);
        let pub_hex = out.strip_suffix('\n').unwrap();
        assert!(lower_hex(pub_hex, 64), "{out:?}");
        let seed = err
            .lines()
            .next()
            .unwrap()
            .strip_prefix("OWR_RELEASE_KEY=")
            .unwrap();
        assert!(lower_hex(seed, 64));
        assert_eq!(pub_of(seed), pub_hex);
        assert!(!out.contains(seed), "seed must not reach stdout");
    }

    #[test]
    fn keygen_out_dir_writes_files_warns_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("keys");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        keygen(&mut out, &mut err, Some(&target)).unwrap();
        let seed = fs::read_to_string(target.join("release.key")).unwrap();
        let pubkey = fs::read_to_string(target.join("release.pub")).unwrap();
        assert_eq!(pub_of(seed.trim_end()), pubkey.trim_end());
        assert!(pubkey.ends_with('\n') && pubkey.len() == 65);
        assert!(out_str(err).contains("WARNING"));
        assert!(!out_str(out).contains(seed.trim_end()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(target.join("release.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let again = keygen(&mut Vec::new(), &mut Vec::new(), Some(&target)).unwrap_err();
        assert!(
            again.to_string().contains("refusing to overwrite"),
            "{again}"
        );
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in FILES {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        keygen(&mut out, &mut err, None).unwrap();
        let pubkey = out_str(out);
        let err = out_str(err);
        let seed = err
            .lines()
            .next()
            .unwrap()
            .strip_prefix("OWR_RELEASE_KEY=")
            .unwrap();
        manifest(
            &mut Vec::new(),
            dir.path(),
            &manifest_args(),
            SystemTime::now(),
        )
        .unwrap();
        sums(&mut Vec::new(), dir.path()).unwrap();
        sign(&mut Vec::new(), dir.path(), seed, false).unwrap();
        let (exit, text) = verify_with(dir.path(), pubkey.trim(), false);
        assert_eq!(exit, Exit::Ok, "{text}");
        assert!(
            text.contains("ok  ferritewrt-b-v1.2.3-factory.bin"),
            "{text}"
        );
        assert!(text.contains("ok  manifest.json"), "{text}");
        assert!(!text.contains("FAIL"), "{text}");
    }

    #[test]
    fn tampered_file_fails() {
        let dir = signed_release(FILES);
        fs::write(dir.path().join(FILES[0].0), b"evil image").unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(
            text.contains("FAIL ferritewrt-b-v1.2.3-factory.bin"),
            "{text}"
        );
        assert!(
            text.contains("ok  ferritewrt-b-v1.2.3-sysupgrade.bin"),
            "{text}"
        );
    }

    #[test]
    fn tampered_sums_fails_signature_and_checks_nothing_else() {
        let dir = signed_release(FILES);
        let path = dir.path().join(SUMS_FILE);
        let mut text = fs::read_to_string(&path).unwrap();
        text = text.replacen("factory", "factorx", 1);
        fs::write(&path, text).unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(text.starts_with("FAIL SHA256SUMS.sig"), "{text}");
        assert_eq!(text.lines().count(), 1, "files must not be trusted: {text}");
    }

    #[test]
    fn wrong_pubkey_fails() {
        let dir = signed_release(FILES);
        let other = pub_of(&"02".repeat(32));
        let (exit, text) = verify_with(dir.path(), &other, false);
        assert_eq!(exit, Exit::Issues);
        assert!(text.contains("signed by key"), "{text}");
        assert!(!text.contains("ok  "), "{text}");
    }

    #[test]
    fn forged_signature_with_matching_key_line_fails() {
        let dir = signed_release(FILES);
        let sig_path = dir.path().join(SIG_FILE);
        let forged = signing_key(&"02".repeat(32)).unwrap().sign(b"other bytes");
        let key_a = signing_key(KEY_A).unwrap().verifying_key().to_bytes();
        let text = release::signature_text(&key_a, &forged.to_bytes());
        fs::write(&sig_path, text).unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(text.contains("signature does not match"), "{text}");
    }

    #[test]
    fn missing_file_is_reported_and_fails_unless_allowed() {
        let dir = signed_release(FILES);
        fs::remove_file(dir.path().join(FILES[1].0)).unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(
            text.contains("missing ferritewrt-b-v1.2.3-sysupgrade.bin"),
            "{text}"
        );
        assert!(
            text.contains("ok  ferritewrt-b-v1.2.3-factory.bin"),
            "{text}"
        );

        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), true);
        assert_eq!(exit, Exit::Ok, "--allow-missing: {text}");
        assert!(
            text.contains("missing ferritewrt-b-v1.2.3-sysupgrade.bin"),
            "{text}"
        );
    }

    #[test]
    fn allow_missing_still_fails_on_a_bad_hash() {
        let dir = signed_release(FILES);
        fs::remove_file(dir.path().join(FILES[1].0)).unwrap();
        fs::write(dir.path().join(FILES[0].0), b"evil").unwrap();
        let (exit, _) = verify_with(dir.path(), &pub_of(KEY_A), true);
        assert_eq!(exit, Exit::Issues);
    }

    #[test]
    fn manifest_size_mismatch_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in FILES {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        manifest(
            &mut Vec::new(),
            dir.path(),
            &manifest_args(),
            SystemTime::now(),
        )
        .unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        let mut doc = parse_manifest(&fs::read(&path).unwrap()).unwrap();
        doc.artifacts[0].size = doc.artifacts[0].size.saturating_add(1);
        fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        // Sums and signature are made over the doctored manifest: only the consistency check
        // can notice.
        sums(&mut Vec::new(), dir.path()).unwrap();
        sign(&mut Vec::new(), dir.path(), KEY_A, false).unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(
            text.contains("FAIL ferritewrt-b-v1.2.3-factory.bin (manifest: size"),
            "{text}"
        );
    }

    #[test]
    fn manifest_hash_mismatch_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in FILES {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        manifest(
            &mut Vec::new(),
            dir.path(),
            &manifest_args(),
            SystemTime::now(),
        )
        .unwrap();
        let path = dir.path().join(MANIFEST_FILE);
        let mut doc = parse_manifest(&fs::read(&path).unwrap()).unwrap();
        doc.artifacts[1].sha256 = "0".repeat(64);
        fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        sums(&mut Vec::new(), dir.path()).unwrap();
        sign(&mut Vec::new(), dir.path(), KEY_A, false).unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(text.contains("sha256 differs"), "{text}");
    }

    #[test]
    fn sums_are_bytewise_sorted_exclude_signature_files_and_match_sha256sum_format() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["b1", "a.bin", "B", "a-b", "Z", "a"] {
            fs::write(dir.path().join(name), b"abc").unwrap();
        }
        fs::write(dir.path().join(SUMS_FILE), b"stale").unwrap();
        fs::write(dir.path().join(SIG_FILE), b"stale").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        let mut out = Vec::new();
        sums(&mut out, dir.path()).unwrap();
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let mut want = String::new();
        for name in ["B", "Z", "a", "a-b", "a.bin", "b1"] {
            for part in [abc, "  ", name, "\n"] {
                want.push_str(part);
            }
        }
        assert_eq!(out_str(out), want);
        assert_eq!(
            fs::read_to_string(dir.path().join(SUMS_FILE)).unwrap(),
            want
        );
    }

    #[test]
    fn sums_are_idempotent_when_rerun() {
        let dir = signed_release(FILES);
        let before = fs::read(dir.path().join(SUMS_FILE)).unwrap();
        sums(&mut Vec::new(), dir.path()).unwrap();
        assert_eq!(fs::read(dir.path().join(SUMS_FILE)).unwrap(), before);
    }

    #[test]
    fn signature_file_has_exactly_three_lines() {
        let dir = signed_release(FILES);
        let text = fs::read_to_string(dir.path().join(SIG_FILE)).unwrap();
        assert!(text.ends_with('\n') && !text.contains('\r'));
        let lines: Vec<&str> = text.strip_suffix('\n').unwrap().split('\n').collect();
        assert_eq!(lines.len(), 3, "{text:?}");
        assert_eq!(lines[0], "ferritewrt-sig/1");
        assert_eq!(lines[1], format!("key: {}", pub_of(KEY_A)));
        let sig = lines[2].strip_prefix("sig: ").unwrap();
        assert_eq!(STANDARD.decode(sig).unwrap().len(), 64);
        assert!(sig.ends_with('='), "standard base64 with padding: {sig}");
    }

    #[test]
    fn sign_refuses_to_overwrite_without_force() {
        let dir = signed_release(FILES);
        let err = sign(&mut Vec::new(), dir.path(), KEY_A, false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        sign(&mut Vec::new(), dir.path(), &"03".repeat(32), true).unwrap();
        let (exit, _) = verify_with(dir.path(), &pub_of(&"03".repeat(32)), false);
        assert_eq!(exit, Exit::Ok);
    }

    #[test]
    fn sign_needs_sums_and_a_well_formed_key_and_never_echoes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let err = sign(&mut Vec::new(), dir.path(), KEY_A, false).unwrap_err();
        assert!(err.to_string().contains("owr release sums"), "{err}");
        fs::write(dir.path().join("f"), b"x").unwrap();
        sums(&mut Vec::new(), dir.path()).unwrap();
        let err = sign(&mut Vec::new(), dir.path(), "not-a-key-zzz", false).unwrap_err();
        assert!(!err.to_string().contains("not-a-key-zzz"), "{err}");
        assert!(!dir.path().join(SIG_FILE).exists());
    }

    #[test]
    fn key_source_prefers_file_then_env_and_reports_absence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("release.key");
        fs::write(&file, format!("{KEY_A}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            let err = read_key_hex(Some(&file), None).unwrap_err();
            assert!(err.to_string().contains("chmod 600"), "{err}");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_key_hex(Some(&file), None).unwrap().as_str(), KEY_A);
        let env = Some(OsString::from(format!(" {KEY_A}\n")));
        assert_eq!(read_key_hex(None, env).unwrap().as_str(), KEY_A);
        let err = read_key_hex(None, None).unwrap_err();
        assert!(err.to_string().contains(KEY_ENV), "{err}");
    }

    #[test]
    fn unlisted_extra_files_are_reported_and_ignored() {
        let dir = signed_release(FILES);
        fs::write(dir.path().join("README.txt"), b"hello").unwrap();
        let (exit, text) = verify_with(dir.path(), &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Ok, "{text}");
        assert!(text.contains("extra README.txt"), "{text}");
    }

    #[test]
    fn verifying_a_single_file_checks_only_that_file() {
        let dir = signed_release(FILES);
        fs::write(dir.path().join(FILES[1].0), b"tampered").unwrap();
        let good = dir.path().join(FILES[0].0);
        let (exit, text) = verify_paths(&[good], &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Ok, "{text}");
        assert!(
            text.contains("ok  ferritewrt-b-v1.2.3-factory.bin"),
            "{text}"
        );
        assert!(!text.contains("sysupgrade"), "{text}");

        let bad = dir.path().join(FILES[1].0);
        let (exit, _) = verify_paths(&[bad], &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);

        let unlisted = dir.path().join("new.bin");
        fs::write(&unlisted, b"x").unwrap();
        let (exit, text) = verify_paths(&[unlisted], &pub_of(KEY_A), false);
        assert_eq!(exit, Exit::Issues);
        assert!(text.contains("FAIL new.bin (not listed"), "{text}");
    }

    #[test]
    fn pubkey_can_be_a_file() {
        let dir = signed_release(FILES);
        let key_file = dir.path().join("release.pub");
        fs::write(&key_file, format!("{}\n", pub_of(KEY_A))).unwrap();
        let (exit, text) = verify_with(dir.path(), key_file.to_str().unwrap(), false);
        assert_eq!(exit, Exit::Ok, "{text}");
        let err = verify(
            &mut Vec::new(),
            &VerifyArgs {
                paths: vec![dir.path().to_path_buf()],
                pubkey: "zz".to_owned(),
                allow_missing: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("--pubkey"), "{err}");
    }

    #[test]
    fn manifest_contents_kinds_and_ordering() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "z-sysupgrade.bin",
            "a-binaries.tar.gz",
            "m-factory.bin",
            "n-initramfs-kernel.bin",
            "build-info.txt",
        ] {
            fs::write(dir.path().join(name), name.as_bytes()).unwrap();
        }
        fs::write(dir.path().join(SUMS_FILE), b"x").unwrap();
        fs::write(dir.path().join(SIG_FILE), b"x").unwrap();
        manifest(
            &mut Vec::new(),
            dir.path(),
            &manifest_args(),
            SystemTime::now(),
        )
        .unwrap();
        let text = fs::read_to_string(dir.path().join(MANIFEST_FILE)).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["schema"], 1);
        assert_eq!(doc["project"], "ferritewrt");
        assert_eq!(doc["version"], "1.2.3");
        assert_eq!(doc["board"], "test_board");
        assert_eq!(doc["git"]["ferritewrt"], "def5678-dirty");
        assert_eq!(doc["git"]["openwrt"], "abc1234");
        assert_eq!(doc["kernel"], "6.18.3");
        assert_eq!(doc["built_utc"], "2026-01-02T03:04:05Z");
        let arts: Vec<(&str, &str)> = doc["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["name"].as_str().unwrap(), a["kind"].as_str().unwrap()))
            .collect();
        assert_eq!(
            arts,
            [
                ("a-binaries.tar.gz", "binaries"),
                ("build-info.txt", "other"),
                ("m-factory.bin", "factory"),
                ("n-initramfs-kernel.bin", "initramfs"),
                ("z-sysupgrade.bin", "sysupgrade"),
            ]
        );
        assert_eq!(doc["artifacts"][0]["size"], "a-binaries.tar.gz".len());
        assert!(text.find("\"schema\"").unwrap() < text.find("\"artifacts\"").unwrap());
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn manifest_defaults_unknowns_and_rejects_bad_input() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("f.bin"), b"x").unwrap();
        let mut args = manifest_args();
        args.openwrt_rev = None;
        args.ferritewrt_rev = None;
        args.kernel = None;
        args.built_utc = None;
        let now = SystemTime::UNIX_EPOCH;
        manifest(&mut Vec::new(), dir.path(), &args, now).unwrap();
        let doc = read_manifest(&dir.path().join(MANIFEST_FILE)).unwrap();
        assert_eq!(doc.kernel, "unknown");
        assert_eq!(doc.git.openwrt, "unknown");
        assert_eq!(doc.built_utc, "1970-01-01T00:00:00Z");

        for (field, bad) in [
            ("version", "v1.2.3"),
            ("version", "1.2"),
            ("kernel", "6.x"),
            ("board", "a b"),
            ("built_utc", "yesterday"),
        ] {
            let mut a = manifest_args();
            match field {
                "version" => a.version = bad.to_owned(),
                "kernel" => a.kernel = Some(bad.to_owned()),
                "board" => a.board = bad.to_owned(),
                _ => a.built_utc = Some(bad.to_owned()),
            }
            assert!(
                manifest(&mut Vec::new(), dir.path(), &a, now).is_err(),
                "{field}={bad}"
            );
        }
    }

    #[test]
    fn version_and_kernel_validation() {
        for ok in ["0.1.0", "10.20.30", "1.0.0-rc.1", "1.0.0-alpha-2"] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in [
            "",
            "1.0",
            "1.0.0.0",
            "v1.0.0",
            "1.0.0-",
            "1.0.x",
            "1.0.0-a_b",
        ] {
            assert!(!valid_version(bad), "{bad}");
        }
        assert!(valid_kernel("6.18.3") && valid_kernel("unknown") && !valid_kernel("6..3"));
    }

    #[test]
    fn show_prints_summary_table() {
        let dir = signed_release(FILES);
        let mut out = Vec::new();
        show(&mut out, dir.path()).unwrap();
        let text = out_str(out);
        assert!(
            text.starts_with("ferritewrt v1.2.3 (test_board)\n"),
            "{text}"
        );
        assert!(text.contains("kernel:   6.18.3"), "{text}");
        assert!(text.contains("ferritewrt-b-v1.2.3-factory.bin"), "{text}");
        assert!(text.contains("factory"), "{text}");
        let err = show(&mut Vec::new(), &dir.path().join("nope")).unwrap_err();
        assert!(err.to_string().contains("manifest.json"), "{err}");
    }

    #[test]
    fn parse_sums_is_strict() {
        let h = "a".repeat(64);
        assert!(parse_sums(format!("{h}  x\n").as_bytes()).is_ok());
        for bad in [
            format!("{h}  x"),
            format!("{h} x\n"),
            format!("{h} *x\n"),
            format!("{}  x\n", "A".repeat(64)),
            format!("{h}  dir/x\n"),
            format!("{h}  x\n{h}  x\n"),
            format!("{h}  x\r\n"),
            String::new(),
        ] {
            assert!(parse_sums(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }
}
