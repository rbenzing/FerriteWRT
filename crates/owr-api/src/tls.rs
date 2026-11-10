//! Self-signed certificate management and rustls server configuration.
//!
//! On first boot [`ensure_cert`] generates a P-256 key and a 10-year self-signed
//! certificate (CN `ferritewrt`, SAN `ferritewrt.lan`, `ferritewrt` + the caller's extra names or
//! addresses, e.g. the LAN IP) and stores them
//! atomically under the TLS directory. The SHA-256 [`fingerprint_sha256`] lets the UI
//! show what to pin. Crypto comes from the pure-Rust graviola provider (no ring/aws-lc).

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::RngExt;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::der::asn1::{Ia5String, OctetString};
use x509_cert::der::oid::db::rfc5280::ID_KP_SERVER_AUTH;
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};

/// File name of the PEM private key inside the TLS directory.
pub const KEY_FILE: &str = "server.key";
/// File name of the PEM certificate inside the TLS directory.
pub const CERT_FILE: &str = "server.crt";

/// DNS names always placed in the certificate.
const SAN_DNS: [&str; 2] = ["ferritewrt.lan", "ferritewrt"];
/// Bound on caller-supplied names (the list comes from configuration).
const MAX_EXTRA_SANS: usize = 16;
/// Certificates are valid from this instant (2025-01-01) so that a router booting with
/// an unset clock (1970) still produces a certificate that is valid once time is synced.
const NOT_BEFORE_UNIX: u64 = 1_735_689_600;
const VALIDITY: Duration = Duration::from_hours(10 * 365 * 24);

/// A DER-encoded certificate.
pub type CertDer = CertificateDer<'static>;

/// TLS setup failure.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("persisting {path}: {source}")]
    Persist {
        path: PathBuf,
        source: owr_common::AtomicWriteError,
    },
    #[error("certificate or key: {0}")]
    Crypto(String),
    #[error("rustls configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

fn crypto<E: std::fmt::Display>(e: E) -> TlsError {
    TlsError::Crypto(e.to_string())
}

/// Install the graviola crypto provider as the process default (idempotent).
pub fn install_crypto_provider() {
    // Err means a provider is already installed, which is fine.
    let _ = rustls_graviola::default_provider().install_default();
}

/// Return the server certificate and key from `dir`, generating them if either file is
/// missing. The key is written with mode 0600, the certificate with 0644.
///
/// A generated certificate lists `ferritewrt.lan`, `ferritewrt` and every entry of
/// `extra_sans` (IP addresses become IP SANs, anything else a DNS name), at most
/// [`MAX_EXTRA_SANS`] of them. An existing certificate is reused unchanged, so a changed
/// LAN address only shows up in the certificate after it is regenerated (factory reset).
pub fn ensure_cert(
    dir: &Path,
    extra_sans: &[String],
) -> Result<(CertDer, PrivateKeyDer<'static>), TlsError> {
    let key_path = dir.join(KEY_FILE);
    let cert_path = dir.join(CERT_FILE);
    if !(key_path.is_file() && cert_path.is_file()) {
        tracing::info!(dir = %dir.display(), "generating self-signed TLS certificate");
        fs::create_dir_all(dir).map_err(|source| TlsError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let (cert_pem, key_pem) = generate_pem(extra_sans)?;
        persist(&key_path, key_pem.as_bytes(), 0o600)?;
        persist(&cert_path, cert_pem.as_bytes(), 0o644)?;
    }
    load(&cert_path, &key_path)
}

fn persist(path: &Path, content: &[u8], mode: u32) -> Result<(), TlsError> {
    owr_common::atomic_write(path, content, mode)
        .map(|_| ())
        .map_err(|source| TlsError::Persist {
            path: path.to_path_buf(),
            source,
        })
}

fn read(path: &Path) -> Result<zeroize::Zeroizing<String>, TlsError> {
    fs::read_to_string(path)
        .map(zeroize::Zeroizing::new)
        .map_err(|source| TlsError::Io {
            path: path.to_path_buf(),
            source,
        })
}

/// A private key readable by group or others is as good as leaked: tighten it to 0600
/// (warning, since something else changed it) before the key is used.
#[cfg(unix)]
fn enforce_key_mode(path: &Path) -> Result<(), TlsError> {
    use std::os::unix::fs::PermissionsExt;
    let io = |source: std::io::Error| TlsError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mode = fs::metadata(path).map_err(io)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format_args!("{mode:03o}"),
            "TLS private key is accessible to group/others; restricting to 0600"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn enforce_key_mode(_path: &Path) -> Result<(), TlsError> {
    Ok(())
}

fn load(cert_path: &Path, key_path: &Path) -> Result<(CertDer, PrivateKeyDer<'static>), TlsError> {
    let cert = Certificate::from_pem(read(cert_path)?.as_bytes()).map_err(crypto)?;
    let cert_der = CertificateDer::from(cert.to_der().map_err(crypto)?);
    enforce_key_mode(key_path)?;
    let key = SigningKey::from_pkcs8_pem(&read(key_path)?).map_err(crypto)?;
    let key_der = key.to_pkcs8_der().map_err(crypto)?;
    let key_der = PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec());
    Ok((cert_der, PrivateKeyDer::Pkcs8(key_der)))
}

/// Generate `(certificate PEM, private key PEM)`.
fn generate_pem(extra_sans: &[String]) -> Result<(String, zeroize::Zeroizing<String>), TlsError> {
    let key = random_signing_key()?;
    let cert = build_certificate(&key, extra_sans)?;
    let cert_pem = cert.to_pem(LineEnding::LF).map_err(crypto)?;
    let key_pem = key.to_pkcs8_pem(LineEnding::LF).map_err(crypto)?;
    Ok((cert_pem, key_pem))
}

fn random_signing_key() -> Result<SigningKey, TlsError> {
    let mut rng = rand::rng();
    // A random 32-byte string is outside the curve order with probability ~2^-32.
    for _ in 0..8 {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        rng.fill(&mut bytes[..]);
        if let Ok(key) = SigningKey::from_slice(&bytes[..]) {
            return Ok(key);
        }
    }
    Err(TlsError::Crypto("could not generate a P-256 key".into()))
}

/// Self-signed profile (issuer = subject) that adds no extensions of its own; the
/// extensions we want are added explicitly through the builder.
struct SelfSigned {
    subject: Name,
}

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

/// The `SubjectAltName` extension: the fixed DNS names plus `extra_sans`, de-duplicated.
fn subject_alt_name(extra_sans: &[String]) -> Result<SubjectAltName, TlsError> {
    if extra_sans.len() > MAX_EXTRA_SANS {
        return Err(TlsError::Crypto(format!(
            "at most {MAX_EXTRA_SANS} extra certificate names are supported"
        )));
    }
    let mut seen = Vec::<String>::new();
    let mut names = Vec::new();
    for name in SAN_DNS
        .iter()
        .copied()
        .chain(extra_sans.iter().map(String::as_str))
    {
        if seen.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            continue;
        }
        seen.push(name.to_owned());
        names.push(match name.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                GeneralName::IpAddress(OctetString::new(ip.octets()).map_err(crypto)?)
            }
            Ok(IpAddr::V6(ip)) => {
                GeneralName::IpAddress(OctetString::new(ip.octets()).map_err(crypto)?)
            }
            Err(_) if !name.is_empty() && name.len() <= 253 => {
                GeneralName::DnsName(Ia5String::new(name).map_err(crypto)?)
            }
            Err(_) => return Err(TlsError::Crypto("invalid certificate name".into())),
        });
    }
    Ok(SubjectAltName(names))
}

fn build_certificate(key: &SigningKey, extra_sans: &[String]) -> Result<Certificate, TlsError> {
    let mut serial_bytes = [0u8; 16];
    rand::rng().fill(&mut serial_bytes);
    // Positive and non-zero leading byte, as required for an ASN.1 INTEGER serial.
    if let Some(first) = serial_bytes.first_mut() {
        *first = (*first & 0x3f) | 0x40;
    }
    let serial = SerialNumber::new(&serial_bytes).map_err(crypto)?;

    let not_before = UNIX_EPOCH
        .checked_add(Duration::from_secs(NOT_BEFORE_UNIX))
        .ok_or_else(|| TlsError::Crypto("validity start out of range".into()))?;
    let not_after = SystemTime::now()
        .max(not_before)
        .checked_add(VALIDITY)
        .ok_or_else(|| TlsError::Crypto("validity end out of range".into()))?;
    let validity = Validity::new(
        Time::try_from(not_before).map_err(crypto)?,
        Time::try_from(not_after).map_err(crypto)?,
    );

    let subject = Name::from_str("CN=ferritewrt").map_err(crypto)?;
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).map_err(crypto)?;

    // Self-signed (issuer = subject), only the extensions we list explicitly.
    let mut builder =
        CertificateBuilder::new(SelfSigned { subject }, serial, validity, spki).map_err(crypto)?;
    builder
        .add_extension(&BasicConstraints {
            ca: false,
            path_len_constraint: None,
        })
        .map_err(crypto)?;
    builder
        .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
        .map_err(crypto)?;
    builder
        .add_extension(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]))
        .map_err(crypto)?;
    builder
        .add_extension(&subject_alt_name(extra_sans)?)
        .map_err(crypto)?;
    builder.build::<_, DerSignature>(key).map_err(crypto)
}

/// Build the rustls server configuration: TLS 1.2 and 1.3, graviola's default cipher
/// suites, HTTP/1.1 ALPN, no client authentication.
pub fn server_config(cert: CertDer, key: PrivateKeyDer<'static>) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(rustls_graviola::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Build the server configuration from existing PEM files.
pub fn load_server_config_from(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerConfig, TlsError> {
    let (cert, key) = load(cert_path, key_path)?;
    server_config(cert, key)
}

/// Load (or create) the certificate in `dir` and build the server configuration.
pub fn load_server_config(dir: &Path, extra_sans: &[String]) -> Result<ServerConfig, TlsError> {
    let (cert, key) = ensure_cert(dir, extra_sans)?;
    server_config(cert, key)
}

/// SHA-256 fingerprint of the certificate as uppercase colon-separated hex.
pub fn fingerprint_sha256(cert: &CertDer) -> String {
    let digest = Sha256::digest(cert.as_ref());
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    hex.join(":")
}

/// Parse a DER certificate (used by tests and tooling).
pub fn parse_certificate(cert: &CertDer) -> Result<Certificate, TlsError> {
    Certificate::from_der(cert.as_ref()).map_err(crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::ext::pkix::name::GeneralName as Gn;

    #[test]
    fn generates_and_reuses_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let tls_dir = dir.path().join("tls");
        let (cert, key) = ensure_cert(&tls_dir, &[]).unwrap();
        assert!(tls_dir.join(KEY_FILE).is_file());
        assert!(tls_dir.join(CERT_FILE).is_file());
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));

        // second call loads the very same certificate
        let (cert2, _) = ensure_cert(&tls_dir, &[]).unwrap();
        assert_eq!(cert, cert2);

        // only one file present -> both are regenerated
        fs::remove_file(tls_dir.join(KEY_FILE)).unwrap();
        let (cert3, _) = ensure_cert(&tls_dir, &[]).unwrap();
        assert_ne!(cert, cert3);
        assert!(tls_dir.join(KEY_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        ensure_cert(dir.path(), &[]).unwrap();
        let mode = |f: &str| {
            fs::metadata(dir.path().join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(KEY_FILE), 0o600);
        assert_eq!(mode(CERT_FILE), 0o644);
    }

    #[test]
    fn certificate_contents() {
        let dir = tempfile::tempdir().unwrap();
        let (der, _) = ensure_cert(dir.path(), &[]).unwrap();
        let cert = parse_certificate(&der).unwrap();
        let tbs = cert.tbs_certificate();
        assert_eq!(tbs.subject().to_string(), "CN=ferritewrt");
        assert_eq!(tbs.issuer(), tbs.subject());
        assert_eq!(tbs.version(), x509_cert::Version::V3);
        let exts = tbs.extensions().unwrap();
        assert_eq!(exts.len(), 4);
        assert!(exts.iter().any(|e| e.extn_id == const_oid_san()));
        let san = san_of(&der);
        for name in SAN_DNS {
            assert!(
                san.iter()
                    .any(|n| matches!(n, Gn::DnsName(d) if d.as_str() == name)),
                "{name} missing"
            );
        }
        assert_eq!(san.len(), SAN_DNS.len());
        let years = tbs
            .validity()
            .not_after
            .to_unix_duration()
            .saturating_sub(tbs.validity().not_before.to_unix_duration())
            .as_secs()
            / (365 * 24 * 3600);
        assert!(years >= 10, "validity is {years} years");
    }

    fn san_of(der: &CertDer) -> Vec<Gn> {
        let cert = parse_certificate(der).unwrap();
        let exts = cert.tbs_certificate().extensions().unwrap();
        let ext = exts.iter().find(|e| e.extn_id == const_oid_san()).unwrap();
        SubjectAltName::from_der(ext.extn_value.as_bytes())
            .unwrap()
            .0
    }

    #[test]
    fn san_has_fixed_names_and_caller_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let extra = [
            "192.168.8.1".to_owned(),
            "127.0.0.1".to_owned(),
            "fd12:3456::1".to_owned(),
            "router.example".to_owned(),
            "FERRITEWRT.lan".to_owned(), // duplicate of a fixed name
        ];
        let (der, _) = ensure_cert(dir.path(), &extra).unwrap();
        let san = san_of(&der);
        let dns = |name: &str| {
            san.iter()
                .any(|n| matches!(n, Gn::DnsName(d) if d.as_str() == name))
        };
        let ip = |bytes: &[u8]| {
            san.iter()
                .any(|n| matches!(n, Gn::IpAddress(i) if i.as_bytes() == bytes))
        };
        assert!(dns("ferritewrt.lan") && dns("ferritewrt") && dns("router.example"));
        assert!(ip(&[192, 168, 8, 1]) && ip(&[127, 0, 0, 1]));
        assert!(ip(&"fd12:3456::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()));
        assert_eq!(san.len(), 6, "duplicates must be dropped: {san:?}");
    }

    #[test]
    fn bad_extra_sans_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            ensure_cert(dir.path(), &[String::new()]),
            Err(TlsError::Crypto(_))
        ));
        let many: Vec<String> = (0..=MAX_EXTRA_SANS).map(|i| format!("h{i}.lan")).collect();
        assert!(matches!(
            ensure_cert(dir.path(), &many),
            Err(TlsError::Crypto(_))
        ));
        assert!(!dir.path().join(KEY_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn loose_key_permissions_are_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        ensure_cert(dir.path(), &[]).unwrap();
        let key = dir.path().join(KEY_FILE);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        ensure_cert(dir.path(), &[]).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // also on the path the server uses to load existing files
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        load_server_config_from(&dir.path().join(CERT_FILE), &key).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn const_oid_san() -> x509_cert::der::oid::ObjectIdentifier {
        x509_cert::der::oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME
    }

    #[test]
    fn builds_server_config_and_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = ensure_cert(dir.path(), &[]).unwrap();
        let fp = fingerprint_sha256(&cert);
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(
            fp.split(':')
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        );
        let cfg = server_config(cert, key).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(load_server_config(dir.path(), &[]).is_ok());
    }

    #[test]
    fn corrupt_files_are_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KEY_FILE), "garbage").unwrap();
        fs::write(dir.path().join(CERT_FILE), "garbage").unwrap();
        assert!(matches!(
            ensure_cert(dir.path(), &[]),
            Err(TlsError::Crypto(_))
        ));
    }
}
