#![cfg(test)]
//! End-to-end tests of the router (no sockets) against the mock backend.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use owr_api::SystemBackend;
use owr_api::dto::{Role, UserInfo};
use owr_api::mock::{MockBackend, MockUpgrade};
use owr_api::password::hash_password;
use owr_api::{ServerConfig, TlsConfig, router};
use serde_json::{Value, json};
use tower::ServiceExt;

const PW: &str = "correct horse battery";
const INDEX_HTML: &str = "<!doctype html><title>test ui</title>";

/// Hashing is slow in debug builds: hash the shared test password once.
fn pw_hash() -> String {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password(PW).unwrap()).clone()
}

struct Harness {
    app: Router,
    dir: tempfile::TempDir,
    backend: Arc<MockBackend>,
}

impl Harness {
    fn audit_path(&self) -> PathBuf {
        self.dir.path().join("audit.log")
    }

    fn audit_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.audit_path())
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

async fn add_user(b: &MockBackend, name: &str, role: Role) {
    let info = UserInfo {
        name: name.into(),
        role,
        enabled: true,
    };
    b.set_user(info, Some(pw_hash())).await.unwrap();
}

fn harness_opts(users: &[(&str, Role)], tls: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let ui = dir.path().join("ui");
    std::fs::create_dir(&ui).unwrap();
    std::fs::write(ui.join("index.html"), INDEX_HTML).unwrap();
    std::fs::write(ui.join("app.js"), "console.log(1);").unwrap();
    let backend = Arc::new(MockBackend::new());
    let rt = tokio::runtime::Handle::current();
    for (name, role) in users {
        tokio::task::block_in_place(|| rt.block_on(add_user(&backend, name, *role)));
    }
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: tls.then(|| TlsConfig {
            cert_path: "c".into(),
            key_path: "k".into(),
        }),
        session_ttl: Duration::from_mins(30),
        backend: backend.clone(),
        ui_enabled: true,
        ui_dir: Some(ui),
        audit_log_path: dir.path().join("audit.log"),
        upload_dir: dir.path().join("upload"),
    };
    Harness {
        app: router(&cfg),
        dir,
        backend,
    }
}

/// Admin "admin" and viewer "viewer", plain HTTP.
fn harness() -> Harness {
    harness_opts(&[("admin", Role::Admin), ("viewer", Role::Viewer)], false)
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn error_code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Resp {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

#[derive(Clone)]
struct Session {
    cookie: String,
    csrf: String,
}

fn req(method: Method, uri: &str, body: Option<Value>, s: Option<&Session>) -> Request<Body> {
    let is_get = method == Method::GET;
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(s) = s {
        b = b.header(header::COOKIE, format!("owr_session={}", s.cookie));
        if !is_get {
            b = b.header("x-csrf-token", &s.csrf);
        }
    }
    match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

async fn get(app: &Router, uri: &str, s: Option<&Session>) -> Resp {
    send(app, req(Method::GET, uri, None, s)).await
}

async fn call(app: &Router, method: Method, uri: &str, body: Option<Value>, s: &Session) -> Resp {
    send(app, req(method, uri, body, Some(s))).await
}

fn cookie_value(r: &Resp) -> String {
    let sc = r.header("set-cookie");
    sc.split(';')
        .next()
        .unwrap()
        .trim_start_matches("owr_session=")
        .to_owned()
}

async fn login_as(app: &Router, user: &str, password: &str) -> Resp {
    send(
        app,
        req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"username": user, "password": password})),
            None,
        ),
    )
    .await
}

async fn login(app: &Router, user: &str) -> Session {
    let r = login_as(app, user, PW).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    Session {
        cookie: cookie_value(&r),
        csrf: r.json()["data"]["csrf"].as_str().unwrap().to_owned(),
    }
}

// ---------------------------------------------------------------- setup & login

#[tokio::test(flavor = "multi_thread")]
async fn setup_flow_then_login() {
    let h = harness_opts(&[], false);
    let r = get(&h.app, "/api/v1/setup/status", None).await;
    assert_eq!(r.json()["data"]["needs_setup"], true);

    let r = send(
        &h.app,
        req(
            Method::POST,
            "/api/v1/setup",
            Some(json!({"username": "root", "password": PW})),
            None,
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"]["created"], true);

    assert_eq!(
        get(&h.app, "/api/v1/setup/status", None).await.json()["data"]["needs_setup"],
        false
    );

    // setup can only run once
    let r = send(
        &h.app,
        req(
            Method::POST,
            "/api/v1/setup",
            Some(json!({"username": "evil", "password": PW})),
            None,
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);

    let r = login_as(&h.app, "root", PW).await;
    assert_eq!(r.status, StatusCode::OK);
    let body = r.json();
    assert_eq!(body["ok"], true);
    assert_eq!(body["data"]["user"]["name"], "root");
    assert_eq!(body["data"]["user"]["role"], "admin");
    assert!(body["data"]["csrf"].as_str().unwrap().len() >= 40);
    assert!(!r.text().contains("password"));

    let users = h.backend.users().await.unwrap();
    assert_eq!(users.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_enforces_password_policy_and_username() {
    let h = harness_opts(&[], false);
    for pw in ["short", "root", "123456789012", "aaaaaaaaaaaaaaaa"] {
        let r = send(
            &h.app,
            req(
                Method::POST,
                "/api/v1/setup",
                Some(json!({"username": "root", "password": pw})),
                None,
            ),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "password {pw:?}"
        );
        assert_eq!(
            r.json()["error"]["details"]["errors"][0]["path"],
            "password"
        );
    }
    let r = send(
        &h.app,
        req(
            Method::POST,
            "/api/v1/setup",
            Some(json!({"username": "../x", "password": PW})),
            None,
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        r.json()["error"]["details"]["errors"][0]["path"],
        "username"
    );
    // nothing was created
    assert_eq!(h.backend.users().await.unwrap(), vec![]);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_rate_limit_blocks_sixth_attempt() {
    let h = harness();
    for _ in 0..5 {
        let r = login_as(&h.app, "admin", "wrong password!!").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = login_as(&h.app, "admin", "wrong password!!").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = r.header("retry-after").parse().unwrap();
    assert!((1..=300).contains(&retry));
    assert_eq!(r.error_code(), "too_many_requests");
    // even the right password is refused while blocked
    assert_eq!(
        login_as(&h.app, "admin", PW).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_is_per_ip_and_per_user() {
    let h = harness();
    let from = |addr: &str, user: &str, pw: &str| {
        let mut r = req(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({"username": user, "password": pw})),
            None,
        );
        r.extensions_mut()
            .insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        r
    };
    // 5 failures from one IP against different usernames exhaust that IP...
    for i in 0..5 {
        let r = send(
            &h.app,
            from("10.0.0.1:1000", &format!("ghost{i}"), "nope nope nope"),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        send(&h.app, from("10.0.0.1:1000", "admin", PW))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // ...but not another IP
    assert_eq!(
        send(&h.app, from("10.0.0.2:1000", "admin", PW))
            .await
            .status,
        StatusCode::OK
    );
    // 5 failures against one username from different IPs lock that username
    for i in 0..5 {
        let r = send(
            &h.app,
            from(&format!("10.0.1.{i}:1"), "viewer", "nope nope nope"),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        send(&h.app, from("10.0.2.1:1", "viewer", PW)).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_failures_cannot_beat_the_limit() {
    let h = harness();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let app = h.app.clone();
        set.spawn(async move { login_as(&app, "admin", "wrong password!!").await.status });
    }
    let mut unauthorized = 0;
    let mut limited = 0;
    while let Some(s) = set.join_next().await {
        match s.unwrap() {
            StatusCode::UNAUTHORIZED => unauthorized += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => unreachable!("unexpected {other}"),
        }
    }
    assert_eq!(unauthorized, 5);
    assert_eq!(limited, 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_user_is_indistinguishable_from_wrong_password() {
    let h = harness();
    let unknown = login_as(&h.app, "nobody", "whatever whatever").await;
    let wrong = login_as(&h.app, "admin", "whatever whatever").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.json()["error"], wrong.json()["error"]);
    assert!(unknown.headers.get("set-cookie").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_user_cannot_login() {
    let h = harness();
    let admin = login(&h.app, "admin").await;
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/viewer",
        Some(json!({"role": "viewer", "enabled": false})),
        &admin,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let r = login_as(&h.app, "viewer", PW).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.json()["error"]["message"], "invalid username or password");
}

// ---------------------------------------------------------------- sessions, CSRF, RBAC

#[tokio::test(flavor = "multi_thread")]
async fn session_cookie_flags_plain_http() {
    let h = harness();
    let r = login_as(&h.app, "admin", PW).await;
    let c = r.header("set-cookie");
    assert!(c.starts_with("owr_session="), "{c}");
    for flag in ["HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(c.contains(flag), "{c} lacks {flag}");
    }
    assert!(!c.contains("Secure"));
    // a browser-session cookie: the server-side idle/absolute TTLs govern the lifetime
    assert!(!c.contains("Max-Age") && !c.contains("Expires"), "{c}");
    assert_eq!(cookie_value(&r).len(), 43);
}

#[tokio::test(flavor = "multi_thread")]
async fn session_cookie_is_secure_and_hsts_with_tls() {
    let h = harness_opts(&[("admin", Role::Admin)], true);
    let r = login_as(&h.app, "admin", PW).await;
    assert!(r.header("set-cookie").contains("; Secure"));
    assert_eq!(r.header("strict-transport-security"), "max-age=86400");
    assert_eq!(
        get(&h.app, "/", None)
            .await
            .header("strict-transport-security"),
        "max-age=86400"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_endpoint_and_logout() {
    let h = harness();
    assert_eq!(
        get(&h.app, "/api/v1/auth/session", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let s = login(&h.app, "viewer").await;
    let r = get(&h.app, "/api/v1/auth/session", Some(&s)).await;
    let d = &r.json()["data"];
    assert_eq!(d["user"]["name"], "viewer");
    assert_eq!(d["role"], "viewer");
    assert_eq!(d["csrf"], s.csrf);

    // viewers can log out (POST) despite being read-only
    let r = call(&h.app, Method::POST, "/api/v1/auth/logout", None, &s).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.header("set-cookie").contains("Max-Age=0"));
    assert_eq!(
        get(&h.app, "/api/v1/auth/session", Some(&s)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_requests_are_rejected() {
    let h = harness();
    for uri in [
        "/api/v1/config",
        "/api/v1/board",
        "/api/v1/system/status",
        "/api/v1/users",
        "/api/v1/system/backup",
        "/api/v1/logs",
    ] {
        let r = get(&h.app, uri, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(r.error_code(), "unauthorized");
    }
    let bogus = Session {
        cookie: "A".repeat(43),
        csrf: "x".into(),
    };
    assert_eq!(
        get(&h.app, "/api/v1/config", Some(&bogus)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn csrf_token_is_required_for_mutations() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let cfg = get(&h.app, "/api/v1/config", Some(&s)).await.json()["data"].clone();

    // missing header
    let mut r = req(Method::PUT, "/api/v1/config", Some(cfg.clone()), None);
    r.headers_mut().insert(
        header::COOKIE,
        format!("owr_session={}", s.cookie).parse().unwrap(),
    );
    let r = send(&h.app, r).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "csrf_invalid");

    // wrong header
    let bad = Session {
        cookie: s.cookie.clone(),
        csrf: "wrong".into(),
    };
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/config",
        Some(cfg.clone()),
        &bad,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // correct header
    let r = call(&h.app, Method::PUT, "/api/v1/config", Some(cfg), &s).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_site_mutations_are_rejected() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let with = |k: &'static str, v: &'static str| {
        let mut r = req(Method::POST, "/api/v1/system/reboot", None, Some(&s));
        r.headers_mut().insert(k, v.parse().unwrap());
        r.headers_mut()
            .insert(header::HOST, "192.168.8.1".parse().unwrap());
        r
    };
    for (k, v) in [
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-site", "same-site"),
        ("origin", "https://evil.example"),
        ("origin", "null"),
    ] {
        let r = send(&h.app, with(k, v)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{k}: {v}");
        assert_eq!(r.error_code(), "cross_site");
    }
    for (k, v) in [
        ("sec-fetch-site", "same-origin"),
        ("origin", "https://192.168.8.1"),
    ] {
        assert_eq!(
            send(&h.app, with(k, v)).await.status,
            StatusCode::OK,
            "{k}: {v}"
        );
    }
    // reads are never blocked by this check
    let mut r = req(Method::GET, "/api/v1/board", None, Some(&s));
    r.headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert_eq!(send(&h.app, r).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn viewer_is_read_only() {
    let h = harness();
    let v = login(&h.app, "viewer").await;
    for uri in [
        "/api/v1/config",
        "/api/v1/system/status",
        "/api/v1/users",
        "/api/v1/services",
    ] {
        assert_eq!(
            get(&h.app, uri, Some(&v)).await.status,
            StatusCode::OK,
            "{uri}"
        );
    }
    let cfg = get(&h.app, "/api/v1/config", Some(&v)).await.json()["data"].clone();
    let r = call(&h.app, Method::PUT, "/api/v1/config", Some(cfg), &v).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "forbidden");
    for (m, uri) in [
        (Method::POST, "/api/v1/system/reboot"),
        (Method::POST, "/api/v1/services/dnsmasq/restart"),
        (Method::DELETE, "/api/v1/users/admin"),
    ] {
        assert_eq!(
            call(&h.app, m, uri, None, &v).await.status,
            StatusCode::FORBIDDEN,
            "{uri}"
        );
    }
}

// ---------------------------------------------------------------- config

#[tokio::test(flavor = "multi_thread")]
async fn config_is_redacted() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let r = get(&h.app, "/api/v1/config", Some(&s)).await;
    assert_eq!(r.status, StatusCode::OK);
    let text = r.text();
    assert!(!text.contains("correct-horse-battery"), "passphrase leaked");
    assert!(!text.contains("$argon2"), "hash leaked");
    let d = &r.json()["data"];
    assert_eq!(d["wireless"]["aps"][0]["security"]["passphrase"], "***");
    assert_eq!(d["users"][0]["password_hash"], "***");
    assert_eq!(d["system"]["hostname"], "ferritewrt");
    assert_eq!(d["network"]["lan"]["ports"].as_array().unwrap().len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_config_applies_and_keeps_secrets() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let mut cfg = get(&h.app, "/api/v1/config", Some(&s)).await.json()["data"].clone();
    cfg["system"]["hostname"] = json!("flint2");
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/config/validate",
        Some(cfg.clone()),
        &s,
    )
    .await;
    assert_eq!(r.json()["data"]["valid"], true);
    let r = call(&h.app, Method::PUT, "/api/v1/config", Some(cfg), &s).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"]["changed"], true);
    assert_eq!(r.json()["data"]["warnings"].as_array().unwrap().len(), 0);

    let status = get(&h.app, "/api/v1/system/status", Some(&s)).await;
    assert_eq!(status.json()["data"]["hostname"], "flint2");
    // the redacted placeholder did not overwrite the real passphrase
    let backup = get(&h.app, "/api/v1/system/backup", Some(&s)).await;
    assert!(backup.text().contains("correct-horse-battery"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_invalid_config_returns_422_with_paths() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let mut cfg = get(&h.app, "/api/v1/config", Some(&s)).await.json()["data"].clone();
    cfg["system"]["hostname"] = json!("not a hostname");
    cfg["wireless"]["aps"][0]["ssid"] = json!("");
    let r = call(&h.app, Method::PUT, "/api/v1/config", Some(cfg.clone()), &s).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(r.error_code(), "validation_failed");
    let paths: Vec<String> = r.json()["error"]["details"]["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_owned())
        .collect();
    assert!(paths.contains(&"system.hostname".to_owned()), "{paths:?}");
    assert!(
        paths.contains(&"wireless.aps[0].ssid".to_owned()),
        "{paths:?}"
    );
    // validate endpoint agrees and nothing was applied
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/config/validate",
        Some(cfg),
        &s,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let status = get(&h.app, "/api/v1/system/status", Some(&s)).await;
    assert_eq!(status.json()["data"]["hostname"], "ferritewrt");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_bodies_get_json_errors() {
    let h = harness();
    let s = login(&h.app, "admin").await;
    let mut r = req(Method::PUT, "/api/v1/config", None, Some(&s));
    *r.body_mut() = Body::from("{not json");
    r.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    let r = send(&h.app, r).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "bad_request");

    let mut r = req(Method::PUT, "/api/v1/config", None, Some(&s));
    *r.body_mut() = Body::from("{}");
    r.headers_mut()
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    let r = send(&h.app, r).await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(r.error_code(), "unsupported_media_type");

    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bob",
        Some(json!({"role": "emperor"})),
        &s,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------- read endpoints

#[tokio::test(flavor = "multi_thread")]
async fn status_endpoints_return_data() {
    let h = harness();
    let s = login(&h.app, "viewer").await;
    let d = get(&h.app, "/api/v1/system/status", Some(&s)).await.json()["data"].clone();
    assert_eq!(d["board"]["vendor"], "GL.iNet");
    assert_eq!(d["load"].as_array().unwrap().len(), 3);
    let d = get(&h.app, "/api/v1/network/status", Some(&s)).await.json()["data"].clone();
    let names: Vec<&str> = d["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    for n in ["lan1", "lan2", "lan3", "lan4", "lan5", "eth1"] {
        assert!(names.contains(&n), "{n}");
    }
    assert_eq!(d["wan"]["proto"], "dhcp");
    let d = get(&h.app, "/api/v1/wireless/status", Some(&s))
        .await
        .json()["data"]
        .clone();
    assert_eq!(d["radios"].as_array().unwrap().len(), 2);
    let d = get(&h.app, "/api/v1/dhcp/leases", Some(&s)).await.json()["data"].clone();
    assert!(d.as_array().unwrap().len() >= 3);
    assert_eq!(
        get(&h.app, "/api/v1/board", Some(&s)).await.json()["data"]["board"]["id"],
        "glinet_gl-mt6000"
    );

    let r = get(&h.app, "/api/v1/firewall/preview", Some(&s)).await;
    assert!(r.header("content-type").starts_with("text/plain"));
    assert!(r.text().contains("table inet owr"));
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_limit_is_clamped() {
    let h = harness();
    let s = login(&h.app, "viewer").await;
    let n = |r: &Resp| r.json()["data"].as_array().unwrap().len();
    assert_eq!(n(&get(&h.app, "/api/v1/logs", Some(&s)).await), 100);
    assert_eq!(
        n(&get(&h.app, "/api/v1/logs?limit=100000", Some(&s)).await),
        500
    );
    assert_eq!(n(&get(&h.app, "/api/v1/logs?limit=0", Some(&s)).await), 1);
    assert_eq!(n(&get(&h.app, "/api/v1/logs?limit=7", Some(&s)).await), 7);
    let first = get(&h.app, "/api/v1/logs?limit=3", Some(&s)).await.json();
    let last_seq = first["data"][2]["seq"].as_u64().unwrap();
    let next = get(
        &h.app,
        &format!("/api/v1/logs?since={last_seq}&limit=1"),
        Some(&s),
    )
    .await
    .json();
    assert_eq!(next["data"][0]["seq"].as_u64().unwrap(), last_seq + 1);
    assert_eq!(
        get(&h.app, "/api/v1/logs?limit=abc", Some(&s)).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn service_actions() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/services/dnsmasq/restart",
        None,
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"]["action"], "restart");
    assert_eq!(
        call(
            &h.app,
            Method::POST,
            "/api/v1/services/odhcpd/reload",
            None,
            &a
        )
        .await
        .status,
        StatusCode::OK
    );
    let list = get(&h.app, "/api/v1/services", Some(&a)).await.json();
    let dns = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "dnsmasq")
        .unwrap()
        .clone();
    assert_eq!(dns["restarts"], 1);
    assert_eq!(
        call(
            &h.app,
            Method::POST,
            "/api/v1/services/nonexistent/restart",
            None,
            &a
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &h.app,
            Method::POST,
            "/api/v1/services/dnsmasq/explode",
            None,
            &a
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &h.app,
            Method::POST,
            "/api/v1/services/..%2Fetc/restart",
            None,
            &a
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&h.app, Method::POST, "/api/v1/system/reboot", None, &a)
            .await
            .status,
        StatusCode::OK
    );
}

// ---------------------------------------------------------------- users

#[tokio::test(flavor = "multi_thread")]
async fn cannot_delete_or_demote_self_or_last_admin() {
    let h = harness_opts(&[("admin", Role::Admin)], false);
    let a = login(&h.app, "admin").await;
    let r = call(&h.app, Method::DELETE, "/api/v1/users/admin", None, &a).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/admin",
        Some(json!({"role": "viewer", "enabled": true})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/admin",
        Some(json!({"role": "admin", "enabled": false})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(
        call(&h.app, Method::DELETE, "/api/v1/users/ghost", None, &a)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.backend.users().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn user_lifecycle() {
    let h = harness_opts(&[("admin", Role::Admin)], false);
    let a = login(&h.app, "admin").await;

    // create requires a password that satisfies the policy
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bob",
        Some(json!({"role": "viewer"})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bob",
        Some(json!({"role": "viewer", "password": "weak"})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        r.json()["error"]["details"]["errors"][0]["path"],
        "password"
    );
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bad%20name",
        Some(json!({"role": "viewer", "password": PW})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bob",
        Some(json!({"role": "viewer", "password": PW})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    assert_eq!(
        r.json()["data"],
        json!({"name": "bob", "role": "viewer", "enabled": true})
    );

    let users = get(&h.app, "/api/v1/users", Some(&a)).await.json();
    assert_eq!(users["data"].as_array().unwrap().len(), 2);
    assert!(!users.to_string().contains("argon2"));

    // bob logs in, then gets promoted: his old session is revoked
    let bob = login(&h.app, "bob").await;
    let r = call(
        &h.app,
        Method::PUT,
        "/api/v1/users/bob",
        Some(json!({"role": "admin", "enabled": true})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        get(&h.app, "/api/v1/users", Some(&bob)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // with two admins, one may delete the other
    let r = call(&h.app, Method::DELETE, "/api/v1/users/bob", None, &a).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(
        login_as(&h.app, "bob", PW).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_flow() {
    let h = harness_opts(&[("admin", Role::Admin)], false);
    let a = login(&h.app, "admin").await;
    let other = login(&h.app, "admin").await;
    let new_pw = "an entirely new passphrase";

    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/auth/password",
        Some(json!({"current": "wrong wrong wrong", "new": new_pw})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/auth/password",
        Some(json!({"current": PW, "new": "weak"})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/auth/password",
        Some(json!({"current": PW, "new": PW})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/auth/password",
        Some(json!({"current": PW, "new": new_pw})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    // this session stays, the other one is revoked
    assert_eq!(
        get(&h.app, "/api/v1/board", Some(&a)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(&h.app, "/api/v1/board", Some(&other)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login_as(&h.app, "admin", PW).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login_as(&h.app, "admin", new_pw).await.status,
        StatusCode::OK
    );
}

// ---------------------------------------------------------------- backup / restore

#[tokio::test(flavor = "multi_thread")]
async fn backup_requires_admin() {
    let h = harness();
    let v = login(&h.app, "viewer").await;
    let r = get(&h.app, "/api/v1/system/backup", Some(&v)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "forbidden");

    let a = login(&h.app, "admin").await;
    let r = get(&h.app, "/api/v1/system/backup", Some(&a)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-type"), "application/octet-stream");
    assert!(r.header("content-disposition").starts_with("attachment"));
    assert!(r.text().contains("password_hash"));

    // downloading a backup is audited even though it is a GET
    let lines = h.audit_lines();
    let backups: Vec<_> = lines
        .iter()
        .filter(|l| l["path"] == "/api/v1/system/backup")
        .collect();
    assert_eq!(backups.len(), 2);
    assert_eq!(backups[0]["outcome"], "denied");
    assert_eq!(backups[1]["outcome"], "ok");
    assert_eq!(backups[1]["actor"], "admin");
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_roundtrip_and_limits() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let v = login(&h.app, "viewer").await;
    let backup = get(&h.app, "/api/v1/system/backup", Some(&a)).await.body;

    let post = |body: Vec<u8>, s: &Session| {
        let mut r = req(Method::POST, "/api/v1/system/restore", None, Some(s));
        *r.body_mut() = Body::from(body);
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
        r
    };
    assert_eq!(
        send(&h.app, post(backup.clone(), &v)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&h.app, post(Vec::new(), &a)).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = send(&h.app, post(b"{\"nope\": 1}".to_vec(), &a)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // larger than 1 MiB
    let r = send(&h.app, post(vec![b' '; 1024 * 1024 + 1], &a)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.error_code(), "payload_too_large");
    // 300 KiB passes the restore body limit (too large for any other route); the real
    // config model then rejects the unknown padding key, which proves the size gate did
    // not fire and that unknown fields never reach the stored config.
    let mut big: Value = serde_json::from_slice(&backup).unwrap();
    big["padding"] = json!("x".repeat(300 * 1024));
    let r = send(&h.app, post(serde_json::to_vec(&big).unwrap(), &a)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.text());
    assert_eq!(r.error_code(), "validation_failed");
    // and an untouched backup restores cleanly
    let r = send(&h.app, post(backup.clone(), &a)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());

    // restore invalidates all sessions
    assert_eq!(
        get(&h.app, "/api/v1/board", Some(&a)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(login_as(&h.app, "admin", PW).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_body_is_413() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let mut cfg = get(&h.app, "/api/v1/config", Some(&a)).await.json()["data"].clone();
    cfg["system"]["note"] = json!("x".repeat(300 * 1024));
    let r = call(&h.app, Method::PUT, "/api/v1/config", Some(cfg), &a).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.json()["ok"], false);
    assert_eq!(r.error_code(), "payload_too_large");
    // also for unauthenticated login attempts
    let big = json!({"username": "admin", "password": "p".repeat(300 * 1024)});
    let r = send(
        &h.app,
        req(Method::POST, "/api/v1/auth/login", Some(big), None),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ---------------------------------------------------------------- firmware upgrade

const IMAGE: &str = "ferritewrt-glinet_gl-mt6000-v9.0.0-sysupgrade.bin";
const OLD_IMAGE: &str = "ferritewrt-glinet_gl-mt6000-v0.0.1-sysupgrade.bin";

fn upload_req(name: &str, body: Vec<u8>, s: Option<&Session>) -> Request<Body> {
    let mut r = req(
        Method::PUT,
        &format!("/api/v1/system/upgrade/files/{name}"),
        None,
        s,
    );
    *r.body_mut() = Body::from(body);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    r
}

async fn upload(h: &Harness, name: &str, body: &[u8], s: &Session) -> Resp {
    send(&h.app, upload_req(name, body.to_vec(), Some(s))).await
}

async fn upload_bundle(h: &Harness, image: &str, s: &Session) {
    for (name, body) in [
        ("SHA256SUMS", &b"sums\n"[..]),
        ("SHA256SUMS.sig", b"sig\n"),
        (image, b"image bytes"),
    ] {
        let r = upload(h, name, body, s).await;
        assert_eq!(r.status, StatusCode::OK, "{name}: {}", r.text());
    }
}

impl Harness {
    fn uploads(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.path().join("upload"))
            .map(|d| {
                d.map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_routes_are_admin_only_and_need_csrf() {
    let h = harness();
    let v = login(&h.app, "viewer").await;
    let a = login(&h.app, "admin").await;
    let r = upload(&h, "SHA256SUMS", b"x", &v).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    for (method, uri) in [
        (Method::DELETE, "/api/v1/system/upgrade/files"),
        (Method::POST, "/api/v1/system/upgrade/check"),
        (Method::POST, "/api/v1/system/upgrade"),
    ] {
        let r = call(&h.app, method.clone(), uri, Some(json!({})), &v).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{method} {uri}");
        let r = send(&h.app, req(method.clone(), uri, Some(json!({})), None)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    let r = send(&h.app, upload_req("SHA256SUMS", b"x".to_vec(), None)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // an admin session without the CSRF token cannot upload or start an upgrade
    let no_csrf = Session {
        cookie: a.cookie.clone(),
        csrf: "wrong".into(),
    };
    let r = upload(&h, "SHA256SUMS", b"x", &no_csrf).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "csrf_invalid");
    upload_bundle(&h, IMAGE, &a).await;
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/system/upgrade",
        Some(json!({})),
        &no_csrf,
    )
    .await;
    assert_eq!(r.error_code(), "csrf_invalid");
    assert_eq!(h.backend.upgrades(), Vec::<MockUpgrade>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_accepts_only_release_file_names() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    for bad in [
        "config.toml",
        "sha256sums",
        ".upload-0",
        "ferritewrt-x-v1.0.0-factory.bin",
        "ferritewrt-a%2Fb-sysupgrade.bin",
        "..%2Fferritewrt-x-sysupgrade.bin",
    ] {
        let r = upload(&h, bad, b"x", &a).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {}", r.text());
    }
    assert_eq!(h.uploads(), Vec::<String>::new());
    let r = upload(&h, IMAGE, b"0123456789", &a).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"], json!({"name": IMAGE, "size": 10}));
    let r = upload(&h, "SHA256SUMS", b"", &a).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "empty files are refused");
    assert_eq!(h.uploads(), [IMAGE]);
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_upload_is_413_and_leaves_nothing_behind() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let r = upload(&h, "SHA256SUMS.sig", b"good", &a).await;
    assert_eq!(r.status, StatusCode::OK);
    // streamed past the 4 KiB limit of the signature file (no Content-Length)
    let r = upload(&h, "SHA256SUMS.sig", &[b'x'; 4097], &a).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", r.text());
    assert_eq!(r.error_code(), "payload_too_large");
    // announced as too large: refused before anything is read
    let mut big = upload_req("SHA256SUMS", vec![b'x'; 10], Some(&a));
    big.headers_mut()
        .insert(header::CONTENT_LENGTH, "65537".parse().unwrap());
    let r = send(&h.app, big).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // 300 KiB is fine for an image (larger than any other route allows)
    let r = upload(&h, IMAGE, &vec![0u8; 300 * 1024], &a).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    // the earlier signature is untouched, no partial file is left
    assert_eq!(h.uploads(), ["SHA256SUMS.sig", IMAGE]);
    assert_eq!(
        std::fs::read(h.dir.path().join("upload").join("SHA256SUMS.sig")).unwrap(),
        b"good"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_check_and_upgrade_on_the_mock() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    upload_bundle(&h, IMAGE, &a).await;
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/system/upgrade/check",
        Some(json!({})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let info = &r.json()["data"];
    assert_eq!(info["image"], IMAGE);
    assert_eq!(info["version"], "9.0.0");
    assert_eq!(info["board"], "glinet_gl-mt6000");
    assert_eq!(info["running"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["downgrade"], false);

    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/system/upgrade",
        Some(json!({"wipe_settings": true})),
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"], json!({"upgrading": true}));
    let done = h.backend.upgrades();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].dir, h.dir.path().join("upload"));
    assert!(done[0].wipe_settings && !done[0].allow_downgrade);
    let audited = h
        .audit_lines()
        .into_iter()
        .find(|l| l["path"] == "/api/v1/system/upgrade")
        .unwrap();
    assert_eq!(audited["actor"], "admin");
    assert_eq!(audited["outcome"], "ok");

    let r = call(
        &h.app,
        Method::DELETE,
        "/api/v1/system/upgrade/files",
        None,
        &a,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(h.uploads(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_checks_are_4xx_with_the_reason() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let check = |allow: bool| {
        call(
            &h.app,
            Method::POST,
            "/api/v1/system/upgrade/check",
            Some(json!({"allow_downgrade": allow})),
            &a,
        )
    };
    let upgrade = |allow: bool| {
        call(
            &h.app,
            Method::POST,
            "/api/v1/system/upgrade",
            Some(json!({"allow_downgrade": allow})),
            &a,
        )
    };
    let r = check(false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "bad_request");
    assert!(
        r.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SHA256SUMS"),
        "{}",
        r.text()
    );
    assert_eq!(upgrade(false).await.status, StatusCode::BAD_REQUEST);

    upload_bundle(&h, OLD_IMAGE, &a).await;
    let r = check(false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.text().contains("older"), "{}", r.text());
    let r = upgrade(false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.backend.upgrades(), Vec::<MockUpgrade>::new());

    let r = check(true).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    assert_eq!(r.json()["data"]["downgrade"], true);
    assert_eq!(upgrade(true).await.status, StatusCode::OK);
    assert!(h.backend.upgrades()[0].allow_downgrade);

    // a new image replaces the old one: one bundle at a time
    upload_bundle(&h, IMAGE, &a).await;
    assert_eq!(h.uploads(), ["SHA256SUMS", "SHA256SUMS.sig", IMAGE]);
}

// ---------------------------------------------------------------- audit

#[tokio::test(flavor = "multi_thread")]
async fn audit_log_records_mutations_without_secrets() {
    let h = harness();
    let failed = login_as(&h.app, "admin", "wrong password!!").await;
    assert_eq!(failed.status, StatusCode::UNAUTHORIZED);
    let a = login(&h.app, "admin").await;
    get(&h.app, "/api/v1/config", Some(&a)).await; // reads are not audited
    let cfg = get(&h.app, "/api/v1/config", Some(&a)).await.json()["data"].clone();
    call(&h.app, Method::PUT, "/api/v1/config", Some(cfg), &a).await;
    call(&h.app, Method::POST, "/api/v1/system/reboot", None, &a).await;

    let lines = h.audit_lines();
    let find = |method: &str, path: &str| {
        lines
            .iter()
            .find(|l| l["method"] == method && l["path"] == path)
            .unwrap_or_else(|| unreachable!("no audit line for {method} {path}: {lines:?}"))
    };
    let put = find("PUT", "/api/v1/config");
    assert_eq!(put["actor"], "admin");
    assert_eq!(put["outcome"], "ok");
    assert_eq!(put["ip"], "127.0.0.1");
    assert!(put["ts"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(find("POST", "/api/v1/system/reboot")["outcome"], "ok");
    let logins: Vec<_> = lines
        .iter()
        .filter(|l| l["path"] == "/api/v1/auth/login")
        .collect();
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0]["outcome"], "denied");
    assert_eq!(logins[1]["outcome"], "ok");
    assert!(
        lines
            .iter()
            .all(|l| l["method"] != "GET" || l["path"] == "/api/v1/system/backup")
    );

    let raw = std::fs::read_to_string(h.audit_path()).unwrap();
    assert!(
        !raw.contains(PW)
            && !raw.contains("wrong password")
            && !raw.contains(&a.cookie)
            && !raw.contains(&a.csrf)
    );
    assert!(!raw.contains("correct-horse-battery"));
}

// ---------------------------------------------------------------- headers, static UI, 404s

fn assert_security_headers(r: &Resp, hsts: bool) {
    assert_eq!(
        r.header("content-security-policy"),
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    );
    assert_eq!(r.header("x-content-type-options"), "nosniff");
    assert_eq!(r.header("referrer-policy"), "no-referrer");
    assert_eq!(r.header("x-frame-options"), "DENY");
    assert_eq!(r.header("cross-origin-opener-policy"), "same-origin");
    assert_eq!(
        r.header("permissions-policy"),
        "camera=(), microphone=(), geolocation=()"
    );
    assert_eq!(r.headers.contains_key("strict-transport-security"), hsts);
    assert!(!r.headers.contains_key("access-control-allow-origin"));
}

#[tokio::test(flavor = "multi_thread")]
async fn security_headers_on_every_kind_of_response() {
    let h = harness();
    assert_security_headers(&get(&h.app, "/", None).await, false);
    let health = get(&h.app, "/api/v1/health", None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json(), json!({"ok": true, "data": null}));
    assert_security_headers(&health, false);
    assert_security_headers(&get(&h.app, "/api/v1/config", None).await, false); // 401
    assert_security_headers(&get(&h.app, "/api/v1/nope", None).await, false); // 404
    assert_eq!(health.header("cache-control"), "no-store");
    let t = harness_opts(&[], true);
    assert_security_headers(&get(&t.app, "/", None).await, true);
    assert_security_headers(&get(&t.app, "/api/v1/health", None).await, true);
}

#[tokio::test(flavor = "multi_thread")]
async fn static_ui_is_served_with_cache_headers() {
    let h = harness();
    let r = get(&h.app, "/", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), INDEX_HTML);
    assert_eq!(r.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(r.header("cache-control"), "no-cache");
    assert!(r.header("etag").starts_with('"'));

    let r = get(&h.app, "/app.js", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.header("content-type").contains("javascript"));
    assert_eq!(r.header("cache-control"), "no-cache");
    let etag = r.header("etag").to_owned();
    let mut cond = req(Method::GET, "/app.js", None, None);
    cond.headers_mut()
        .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
    let r = send(&h.app, cond).await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);
    assert_eq!(r.body, Vec::<u8>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_paths_fall_back_to_index_but_api_404s_are_json() {
    let h = harness();
    let r = get(&h.app, "/network/lan/settings", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.text(), INDEX_HTML);
    // traversal attempts never leave the UI directory
    let r = get(&h.app, "/..%2f..%2fCargo.toml", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(!r.text().contains("[package]"));
    // a missing asset is a 404, not index.html with status 200
    let r = get(&h.app, "/js/missing.js", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_ne!(r.text(), INDEX_HTML);
    assert_eq!(get(&h.app, "/.hidden", None).await.text(), INDEX_HTML);

    for uri in ["/api/v1/nope", "/api/nope", "/api"] {
        let r = get(&h.app, uri, None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{uri}");
        assert!(
            r.header("content-type").starts_with("application/json"),
            "{uri}"
        );
        assert_eq!(r.json()["ok"], false);
        assert_eq!(r.error_code(), "not_found");
    }
    // wrong method on a real route is a JSON 405
    let r = send(&h.app, req(Method::DELETE, "/api/v1/health", None, None)).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(r.error_code(), "method_not_allowed");
    // POST to a UI path
    let r = send(&h.app, req(Method::POST, "/", None, None)).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        session_ttl: Duration::from_secs(60),
        backend: Arc::new(MockBackend::new()),
        ui_enabled: false,
        ui_dir: None,
        audit_log_path: dir.path().join("a.log"),
        upload_dir: dir.path().join("upload"),
    };
    let app = router(&cfg);
    assert_eq!(get(&app, "/", None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        get(&app, "/api/v1/health", None).await.status,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_ui_serves_something_at_root() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        session_ttl: Duration::from_secs(60),
        backend: Arc::new(MockBackend::new()),
        ui_enabled: true,
        ui_dir: None,
        audit_log_path: dir.path().join("a.log"),
        upload_dir: dir.path().join("upload"),
    };
    let app = router(&cfg);
    let r = get(&app, "/", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.header("content-type").starts_with("text/html"));
    assert!(
        r.text().to_lowercase().contains("<html") || r.text().to_lowercase().contains("<!doctype")
    );
    assert_eq!(get(&app, "/some/spa/route", None).await.text(), r.text());
}

// ---------------------------------------------------------------- review fixes

#[tokio::test(flavor = "multi_thread")]
async fn audit_noise_is_rate_limited_and_actions_are_kept() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let mut bad_csrf = a.clone();
    bad_csrf.csrf = "wrong".into();

    for _ in 0..20 {
        send(&h.app, req(Method::POST, "/api/v1/nope", None, None)).await;
        get(&h.app, "/api/v1/nope", None).await;
        get(&h.app, "/js/missing.js", None).await;
    }
    for _ in 0..5 {
        call(
            &h.app,
            Method::POST,
            "/api/v1/system/reboot",
            None,
            &bad_csrf,
        )
        .await;
        let mut cross = req(Method::POST, "/api/v1/system/reboot", None, Some(&a));
        cross
            .headers_mut()
            .insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert_eq!(send(&h.app, cross).await.status, StatusCode::FORBIDDEN);
    }
    for _ in 0..3 {
        let r = call(&h.app, Method::POST, "/api/v1/system/reboot", None, &a).await;
        assert_eq!(r.status, StatusCode::OK);
    }

    let lines = h.audit_lines();
    let rejected: Vec<_> = lines
        .iter()
        .filter(|l| l["outcome"] == "rejected")
        .collect();
    // 1 line/s/IP; allow one more in case the loop straddles a second boundary
    assert!(
        rejected.len() <= 2,
        "{} noise lines: {lines:?}",
        rejected.len()
    );
    assert!(rejected.iter().all(|l| l["actor"] == "-"));
    // CSRF and cross-site rejections are never attributed to the session's user
    assert!(
        lines
            .iter()
            .all(|l| l["actor"] != "admin" || l["outcome"] == "ok"),
        "{lines:?}"
    );
    let reboots = lines
        .iter()
        .filter(|l| l["actor"] == "admin" && l["path"] == "/api/v1/system/reboot")
        .count();
    assert_eq!(
        reboots, 3,
        "every authenticated action is audited: {lines:?}"
    );
    assert!(lines.iter().all(|l| l["method"] != "GET"));
    assert!(lines.len() <= 1 + 2 + 3, "{lines:?}"); // login + noise + actions
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_login_failures_are_rate_limited_but_success_is_always_logged() {
    let h = harness();
    let started = std::time::Instant::now();
    for _ in 0..4 {
        assert_eq!(
            login_as(&h.app, "admin", "wrong password!!").await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let elapsed = started.elapsed();
    login(&h.app, "admin").await;
    let lines = h.audit_lines();
    let outcomes = |o: &str| lines.iter().filter(|l| l["outcome"] == o).count();
    // Denied logins are audited at most once per second per client (the exact window is
    // unit-tested in audit.rs). Four argon2 verifications can take more than a second on
    // a slow CI runner, so bound the expectation by the time they actually took: one
    // line per started second, plus one for straddling a second boundary.
    let max_denied = usize::try_from(elapsed.as_secs())
        .unwrap_or(usize::MAX)
        .saturating_add(2);
    let denied = outcomes("denied");
    assert!(
        (1..=max_denied.min(4)).contains(&denied),
        "{denied} denied lines after {elapsed:?}: {lines:?}"
    );
    assert_eq!(outcomes("ok"), 1, "{lines:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_does_not_revert_a_concurrent_role_change() {
    let h = harness_opts(&[("admin", Role::Admin), ("bob", Role::Admin)], false);
    let bob = login(&h.app, "bob").await; // session snapshot says: admin
    // an admin demotes bob after bob's request passed the session guard
    h.backend
        .set_user(
            UserInfo {
                name: "bob".into(),
                role: Role::Viewer,
                enabled: true,
            },
            None,
        )
        .await
        .unwrap();
    let new_pw = "an entirely new passphrase";
    let r = call(
        &h.app,
        Method::POST,
        "/api/v1/auth/password",
        Some(json!({"current": PW, "new": new_pw})),
        &bob,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text());
    let users = h.backend.users().await.unwrap();
    let bob_now = users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob_now.role, Role::Viewer, "demotion was reverted");
    let again = login_as(&h.app, "bob", new_pw).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["data"]["role"], "viewer");
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_rejects_backups_without_an_enabled_admin() {
    let h = harness();
    let a = login(&h.app, "admin").await;
    let backup: Value =
        serde_json::from_slice(&get(&h.app, "/api/v1/system/backup", Some(&a)).await.body).unwrap();
    let post = |doc: &Value| {
        let mut r = req(Method::POST, "/api/v1/system/restore", None, Some(&a));
        *r.body_mut() = Body::from(serde_json::to_vec(doc).unwrap());
        r
    };

    let mut none = backup.clone();
    none["users"] = json!([]);
    let r = send(&h.app, post(&none)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.text());
    assert_eq!(r.error_code(), "validation_failed");

    let mut viewer_only = backup.clone();
    let viewer = backup["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "viewer")
        .unwrap()
        .clone();
    viewer_only["users"] = json!([viewer]);
    let r = send(&h.app, post(&viewer_only)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.text());

    // nothing was applied and the session survived the rejected restores
    assert_eq!(h.backend.users().await.unwrap().len(), 2);
    assert_eq!(
        get(&h.app, "/api/v1/board", Some(&a)).await.status,
        StatusCode::OK
    );
}

/// Delegates to a [`MockBackend`] but parks `reboot` until released, to observe what
/// happens to a backend call whose HTTP request goes away.
struct GatedBackend {
    inner: Arc<MockBackend>,
    entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    done: std::sync::atomic::AtomicBool,
}

type Bf<'a, T> = owr_api::BoxFuture<'a, owr_api::BackendResult<T>>;

impl SystemBackend for GatedBackend {
    fn board(&self) -> Bf<'_, Value> {
        self.inner.board()
    }
    fn status(&self) -> Bf<'_, owr_api::dto::SystemStatus> {
        self.inner.status()
    }
    fn config(&self) -> Bf<'_, Value> {
        self.inner.config()
    }
    fn validate_config(
        &self,
        cfg: Value,
    ) -> owr_api::BoxFuture<'_, Result<(), owr_api::dto::ValidationErrors>> {
        self.inner.validate_config(cfg)
    }
    fn save_config<'a>(&'a self, cfg: Value, actor: &'a str) -> Bf<'a, owr_api::dto::ApplyReport> {
        self.inner.save_config(cfg, actor)
    }
    fn network_status(&self) -> Bf<'_, owr_api::dto::NetworkStatus> {
        self.inner.network_status()
    }
    fn wireless_status(&self) -> Bf<'_, owr_api::dto::WirelessStatus> {
        self.inner.wireless_status()
    }
    fn dhcp_leases(&self) -> Bf<'_, Vec<owr_api::dto::Lease>> {
        self.inner.dhcp_leases()
    }
    fn firewall_preview(&self) -> Bf<'_, String> {
        self.inner.firewall_preview()
    }
    fn logs(&self, since_seq: u64, limit: u16) -> Bf<'_, Vec<owr_api::dto::LogEntry>> {
        self.inner.logs(since_seq, limit)
    }
    fn services(&self) -> Bf<'_, Vec<owr_api::dto::ServiceStatus>> {
        self.inner.services()
    }
    fn service_action<'a>(
        &'a self,
        name: &'a str,
        action: owr_api::dto::ServiceAction,
    ) -> Bf<'a, ()> {
        self.inner.service_action(name, action)
    }
    fn reboot(&self) -> Bf<'_, ()> {
        Box::pin(async move {
            if let Some(tx) = self.entered.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let release = self.release.lock().await.take();
            if let Some(rx) = release {
                let _ = rx.await;
            }
            let result = self.inner.reboot().await;
            self.done.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        })
    }
    fn users(&self) -> Bf<'_, Vec<UserInfo>> {
        self.inner.users()
    }
    fn set_user(&self, user: UserInfo, password_hash: Option<String>) -> Bf<'_, ()> {
        self.inner.set_user(user, password_hash)
    }
    fn set_password<'a>(&'a self, name: &'a str, password_hash: String) -> Bf<'a, ()> {
        self.inner.set_password(name, password_hash)
    }
    fn delete_user<'a>(&'a self, name: &'a str) -> Bf<'a, ()> {
        self.inner.delete_user(name)
    }
    fn verify_password<'a>(&'a self, name: &'a str, password: &'a str) -> Bf<'a, Option<UserInfo>> {
        self.inner.verify_password(name, password)
    }
    fn backup(&self) -> Bf<'_, Vec<u8>> {
        self.inner.backup()
    }
    fn restore<'a>(&'a self, bytes: Vec<u8>, actor: &'a str) -> Bf<'a, owr_api::dto::ApplyReport> {
        self.inner.restore(bytes, actor)
    }
    fn upgrade_check<'a>(
        &'a self,
        dir: &'a std::path::Path,
        allow_downgrade: bool,
    ) -> Bf<'a, owr_api::dto::UpgradeInfo> {
        self.inner.upgrade_check(dir, allow_downgrade)
    }
    fn upgrade<'a>(
        &'a self,
        dir: &'a std::path::Path,
        allow_downgrade: bool,
        wipe_settings: bool,
    ) -> Bf<'a, ()> {
        self.inner.upgrade(dir, allow_downgrade, wipe_settings)
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    unreachable!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_call_survives_a_cancelled_request_and_is_audited_as_aborted() {
    let dir = tempfile::tempdir().unwrap();
    let mock = Arc::new(MockBackend::new());
    add_user(&mock, "admin", Role::Admin).await;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let gated = Arc::new(GatedBackend {
        inner: mock,
        entered: std::sync::Mutex::new(Some(entered_tx)),
        release: tokio::sync::Mutex::new(Some(release_rx)),
        done: std::sync::atomic::AtomicBool::new(false),
    });
    let audit_path = dir.path().join("audit.log");
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        session_ttl: Duration::from_mins(30),
        backend: gated.clone(),
        ui_enabled: false,
        ui_dir: None,
        audit_log_path: audit_path.clone(),
        upload_dir: dir.path().join("upload"),
    };
    let app = router(&cfg);
    let a = login(&app, "admin").await;

    let request = tokio::spawn({
        let app = app.clone();
        let r = req(Method::POST, "/api/v1/system/reboot", None, Some(&a));
        async move { app.oneshot(r).await }
    });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .expect("backend call never started")
        .unwrap();

    // The client goes away mid-call: the request future is dropped.
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(!gated.done.load(std::sync::atomic::Ordering::SeqCst));

    // The call is still running and finishes once the backend lets it.
    release_tx.send(()).unwrap();
    wait_for("the detached backend call", || {
        gated.done.load(std::sync::atomic::Ordering::SeqCst)
    })
    .await;

    // The half-applied change is on record, attributed to the admin.
    wait_for("the aborted audit line", || {
        std::fs::read_to_string(&audit_path)
            .unwrap_or_default()
            .contains("\"outcome\":\"aborted\"")
    })
    .await;
    let log = std::fs::read_to_string(&audit_path).unwrap();
    let line: Value = log
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|l| l["outcome"] == "aborted")
        .unwrap();
    assert_eq!(line["actor"], "admin");
    assert_eq!(line["path"], "/api/v1/system/reboot");
}
