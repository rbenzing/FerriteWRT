#![cfg(test)]
//! Real-socket tests: plain HTTP and TLS (TLS 1.3 and 1.2, certificate pinning).

use std::sync::Arc;
use std::time::Duration;

use owr_api::dto::{Role, UserInfo};
use owr_api::mock::MockBackend;
use owr_api::password::hash_password;
use owr_api::tls::{CERT_FILE, KEY_FILE, ensure_cert, fingerprint_sha256};
use owr_api::{ServerConfig, SystemBackend, TlsConfig, serve_on};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// Accepts exactly one certificate (pinning) and verifies handshake signatures with
/// the graviola algorithms, which also proves the generated certificate parses.
#[derive(Debug)]
struct Pinned {
    cert: CertificateDer<'static>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate does not match the pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn client_config(
    pin: CertificateDer<'static>,
    versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    let provider = Arc::new(rustls_graviola::default_provider());
    let verifier = Arc::new(Pinned {
        cert: pin,
        algs: provider.signature_verification_algorithms,
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn start(tls: Option<TlsConfig>, dir: &std::path::Path) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(MockBackend::new());
    let hash = hash_password("correct horse battery").unwrap();
    backend
        .set_user(
            UserInfo {
                name: "admin".into(),
                role: Role::Admin,
                enabled: true,
            },
            Some(hash),
        )
        .await
        .unwrap();
    let cfg = ServerConfig {
        bind: addr,
        tls,
        session_ttl: Duration::from_secs(60),
        backend,
        ui_enabled: true,
        ui_dir: None,
        audit_log_path: dir.join("audit.log"),
    };
    tokio::spawn(serve_on(listener, cfg));
    addr
}

async fn exchange<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut stream: S, request: &str) -> String {
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    // TLS peers may close without close_notify; what was read so far is still valid.
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

const HEALTH: &str =
    "GET /api/v1/health HTTP/1.1\r\nHost: ferritewrt.lan\r\nConnection: close\r\n\r\n";

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_serves_api_and_records_peer_ip() {
    let dir = tempfile::tempdir().unwrap();
    let addr = start(None, dir.path()).await;

    let reply = exchange(TcpStream::connect(addr).await.unwrap(), HEALTH).await;
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.contains("{\"data\":null,\"ok\":true}") || reply.contains("\"ok\":true"));
    assert!(!reply.to_lowercase().contains("strict-transport-security"));

    let body = r#"{"username":"admin","password":"nope nope nope"}"#;
    let login = format!(
        "POST /api/v1/auth/login HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let reply = exchange(TcpStream::connect(addr).await.unwrap(), &login).await;
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
    let audit = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(audit.contains("\"ip\":\"127.0.0.1\""), "{audit}");
    assert!(audit.contains("\"outcome\":\"denied\""), "{audit}");
}

async fn tls_roundtrip(versions: &[&'static SupportedProtocolVersion], expect_version: &str) {
    let dir = tempfile::tempdir().unwrap();
    let tls_dir = dir.path().join("tls");
    let (cert, _key) = ensure_cert(&tls_dir, &[]).unwrap();
    println!("fingerprint {}", fingerprint_sha256(&cert));
    let addr = start(
        Some(TlsConfig {
            cert_path: tls_dir.join(CERT_FILE),
            key_path: tls_dir.join(KEY_FILE),
        }),
        dir.path(),
    )
    .await;

    let connector = TlsConnector::from(Arc::new(client_config(cert, versions)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("ferritewrt.lan").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let negotiated = format!("{:?}", tls.get_ref().1.protocol_version().unwrap());
    assert_eq!(negotiated, expect_version);
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let reply = exchange(tls, HEALTH).await;
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(
        reply
            .to_lowercase()
            .contains("strict-transport-security: max-age=86400"),
        "{reply}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls13_with_generated_certificate() {
    tls_roundtrip(&[&rustls::version::TLS13], "TLSv1_3").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tls12_with_generated_certificate() {
    tls_roundtrip(&[&rustls::version::TLS12], "TLSv1_2").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pin_is_rejected_by_client() {
    let dir = tempfile::tempdir().unwrap();
    let tls_dir = dir.path().join("tls");
    ensure_cert(&tls_dir, &[]).unwrap();
    let other = ensure_cert(&dir.path().join("other"), &[]).unwrap().0;
    let addr = start(
        Some(TlsConfig {
            cert_path: tls_dir.join(CERT_FILE),
            key_path: tls_dir.join(KEY_FILE),
        }),
        dir.path(),
    )
    .await;
    let connector = TlsConnector::from(Arc::new(client_config(other, &[&rustls::version::TLS13])));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let result = connector
        .connect(ServerName::try_from("ferritewrt.lan").unwrap(), tcp)
        .await;
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_on_tls_port_gets_no_http_response() {
    let dir = tempfile::tempdir().unwrap();
    let tls_dir = dir.path().join("tls");
    ensure_cert(&tls_dir, &[]).unwrap();
    let addr = start(
        Some(TlsConfig {
            cert_path: tls_dir.join(CERT_FILE),
            key_path: tls_dir.join(KEY_FILE),
        }),
        dir.path(),
    )
    .await;
    let reply = exchange(TcpStream::connect(addr).await.unwrap(), HEALTH).await;
    assert!(!reply.contains("200 OK"), "{reply}");
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_per_client_address_are_capped() {
    const CAP: usize = 16;
    let dir = tempfile::tempdir().unwrap();
    let addr = start(None, dir.path()).await;

    // Idle connections (no request yet) hold their slots.
    let mut idle = Vec::new();
    for _ in 0..CAP {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    // Let the accept loop register all of them.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reply = exchange(TcpStream::connect(addr).await.unwrap(), HEALTH).await;
    assert!(
        reply.is_empty(),
        "connection over the cap was served: {reply}"
    );

    // Slots are released when connections close.
    drop(idle);
    let mut served = false;
    for _ in 0..40 {
        let reply = exchange(TcpStream::connect(addr).await.unwrap(), HEALTH).await;
        if reply.starts_with("HTTP/1.1 200 OK") {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "slots were not released");
}
