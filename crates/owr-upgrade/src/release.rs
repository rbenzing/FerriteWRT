//! The release signature contract, shared by `owr release` (which writes it) and the
//! upgrade path (which checks it). Documented byte for byte in the `owr-cli` README
//! ("Release signing").
//!
//! * `SHA256SUMS`: `sha256sum` text mode, one `<64 lowercase hex>  <name>\n` line per file.
//! * `SHA256SUMS.sig`: exactly three lines, `ferritewrt-sig/1`, `key: <public key hex>`,
//!   `sig: <base64 of the 64-byte ed25519 signature over the SHA256SUMS bytes>`.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

pub const SUMS_FILE: &str = "SHA256SUMS";
pub const SIG_FILE: &str = "SHA256SUMS.sig";
pub const SIG_MAGIC: &str = "ferritewrt-sig/1";
const HASH_BUF: usize = 1024 * 1024;

/// One line of `SHA256SUMS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumEntry {
    /// 64 lowercase hex digits.
    pub hash: String,
    pub name: String,
}

/// `s` is exactly `len` lowercase hex digits.
pub fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// File names that can live in `SHA256SUMS` unambiguously (no directories, no escapes).
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}

/// 32 bytes from 64 hex digits (either case); `None` otherwise.
pub fn decode32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// The contents of a `release.pub` file: the public key as 64 hex digits, surrounding
/// whitespace ignored.
pub fn parse_pubkey(text: &str) -> Option<[u8; 32]> {
    decode32(text.trim())
}

/// Strict `sha256sum` text-mode parser: `<64 lowercase hex>  <name>\n` per line, names
/// unique.
pub fn parse_sums(bytes: &[u8]) -> Result<Vec<SumEntry>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_owned())?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| "missing final newline".to_owned())?;
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for (i, line) in body.split('\n').enumerate() {
        let lineno = i.saturating_add(1);
        let (Some(hash), Some("  "), Some(name)) =
            (line.get(..64), line.get(64..66), line.get(66..))
        else {
            return Err(format!("line {lineno}: expected '<sha256>  <name>'"));
        };
        if !lower_hex(hash, 64) {
            return Err(format!(
                "line {lineno}: hash is not 64 lowercase hex digits"
            ));
        }
        if !valid_file_name(name) {
            return Err(format!("line {lineno}: invalid file name {name:?}"));
        }
        if !seen.insert(name) {
            return Err(format!("line {lineno}: duplicate entry {name:?}"));
        }
        entries.push(SumEntry {
            hash: hash.to_owned(),
            name: name.to_owned(),
        });
    }
    Ok(entries)
}

/// SHA-256 (lowercase hex) and length of everything `r` yields.
pub fn hash_reader(r: &mut impl Read) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    let mut len = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(buf.get(..n).unwrap_or(&[]));
        len = len.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok((hex::encode(hasher.finalize()), len))
}

/// SHA-256 (lowercase hex) and length of a file.
pub fn hash_file(path: &Path) -> io::Result<(String, u64)> {
    hash_reader(&mut File::open(path)?)
}

/// The text of `SHA256SUMS.sig` for a signature by `pubkey`.
pub fn signature_text(pubkey: &[u8; 32], signature: &[u8; 64]) -> String {
    format!(
        "{SIG_MAGIC}\nkey: {}\nsig: {}\n",
        hex::encode(pubkey),
        STANDARD.encode(signature)
    )
}

/// Check the text of `SHA256SUMS.sig` against the `SHA256SUMS` bytes and the expected
/// public key. The error names what is wrong, never secret material.
pub fn verify_signature(sig_text: &str, sums: &[u8], pubkey: &[u8; 32]) -> Result<(), String> {
    let body = sig_text
        .strip_suffix('\n')
        .ok_or("malformed signature file: missing final newline")?;
    let mut lines = body.split('\n');
    let (Some(magic), Some(key_line), Some(sig_line), None) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Err("malformed signature file: expected exactly three lines".to_owned());
    };
    if magic != SIG_MAGIC {
        return Err(format!("unsupported signature format {magic:?}"));
    }
    let key_hex = key_line
        .strip_prefix("key: ")
        .filter(|k| lower_hex(k, 64))
        .ok_or("malformed key line")?;
    let expected_hex = hex::encode(pubkey);
    if !bool::from(key_hex.as_bytes().ct_eq(expected_hex.as_bytes())) {
        return Err(format!("signed by key {key_hex}, expected {expected_hex}"));
    }
    let sig_bytes = sig_line
        .strip_prefix("sig: ")
        .and_then(|s| STANDARD.decode(s).ok())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or("malformed sig line (expected base64 of 64 bytes)")?;
    VerifyingKey::from_bytes(pubkey)
        .map_err(|_| "invalid public key".to_owned())?
        .verify_strict(sums, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| "signature does not match SHA256SUMS".to_owned())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const SUMS: &[u8] =
        b"0000000000000000000000000000000000000000000000000000000000000000  a.bin\n";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed(sums: &[u8]) -> (String, [u8; 32]) {
        let k = key();
        let pubkey = k.verifying_key().to_bytes();
        (signature_text(&pubkey, &k.sign(sums).to_bytes()), pubkey)
    }

    #[test]
    fn signature_round_trips() {
        let (text, pubkey) = signed(SUMS);
        assert!(text.starts_with("ferritewrt-sig/1\nkey: "));
        assert_eq!(verify_signature(&text, SUMS, &pubkey), Ok(()));
    }

    #[test]
    fn signature_rejects_tampering_and_wrong_key() {
        let (text, pubkey) = signed(SUMS);
        let mut tampered = SUMS.to_vec();
        tampered[0] = b'1';
        assert_eq!(
            verify_signature(&text, &tampered, &pubkey),
            Err("signature does not match SHA256SUMS".to_owned())
        );
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            verify_signature(&text, SUMS, &other)
                .unwrap_err()
                .starts_with("signed by key ")
        );
        assert!(verify_signature(text.trim_end(), SUMS, &pubkey).is_err());
        assert!(verify_signature(&text.replace("sig/1", "sig/2"), SUMS, &pubkey).is_err());
        assert!(verify_signature(&format!("{text}extra\n"), SUMS, &pubkey).is_err());
    }

    #[test]
    fn sums_parser_is_strict() {
        assert_eq!(parse_sums(SUMS).unwrap()[0].name, "a.bin");
        let h = "0".repeat(64);
        for bad in [
            format!("{h}  a.bin"),                  // no final newline
            format!("{h} a.bin\n"),                 // one space
            format!("{}  a.bin\n", "A".repeat(64)), // uppercase
            format!("{h}  ../a\n"),                 // directory
            format!("{h}  a\n{h}  a\n"),            // duplicate
        ] {
            assert!(parse_sums(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hash_streams_across_buffer_boundaries() {
        let data = vec![7u8; HASH_BUF * 2 + 13];
        let (hash, len) = hash_reader(&mut data.as_slice()).unwrap();
        assert_eq!(len, u64::try_from(data.len()).unwrap());
        assert_eq!(hash, hex::encode(Sha256::digest(&data)));
    }

    #[test]
    fn pubkey_parses_with_whitespace_only() {
        let hexkey = "ab".repeat(32);
        assert_eq!(parse_pubkey(&format!("{hexkey}\n")), Some([0xab; 32]));
        assert_eq!(parse_pubkey("ab"), None);
        assert_eq!(parse_pubkey(&format!("x{}", &hexkey[1..])), None);
    }
}
