#![cfg(test)]
//! `RealBackend` against a temp directory: a board and config on disk, a fake init control
//! socket, a recording no-op applier. Nothing here touches netlink, nft or hostapd, except
//! that `network_status` / `wireless_status` open a read-only netlink dump and look for
//! (absent) hostapd sockets.

#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use owr_api::dto::{BackendError, Role, ServiceAction, UserInfo};
use owr_api::password::hash_password;
use owr_api::real::{Applier, RealBackend, RealConfig};
use owr_api::{BoxFuture, SystemBackend};
use owr_apply::run::{ApplyError, ApplyOutcome};
use owr_board::Board;
use owr_config::{Config, Store};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery";
const OTHER_PASSWORD: &str = "another long passphrase";
const KNOWN_SERVICES: [&str; 3] = ["dnsmasq", "owr-netd", "hostapd-phy0"];

/// Argon2 is slow in debug builds: hash each password once per test binary.
fn hash(password: &'static str) -> String {
    static HASHES: OnceLock<Mutex<Vec<(&'static str, String)>>> = OnceLock::new();
    let mut cache = HASHES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    if let Some((_, h)) = cache.iter().find(|(p, _)| *p == password) {
        return h.clone();
    }
    let h = hash_password(password).unwrap();
    cache.push((password, h.clone()));
    h
}

// ---------------------------------------------------------------- fake init

struct FakeInit {
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

fn journal_entry(seq: u64, ts_ms: u64, source: &str, msg: &str) -> String {
    json!({"seq": seq, "ts_ms": ts_ms, "prio": 6, "source": source, "msg": msg}).to_string()
}

fn status_reply() -> String {
    json!({
        "ok": true, "uptime_ms": 5000, "mode": "normal", "failsafe_reason": null,
        "services": [
            {"name": "dnsmasq", "state": "running", "pid": 42, "failures": 0, "oneshot": false,
             "healthy": null, "since_unix": 100, "restarts": 2},
            {"name": "owr-apply", "state": "stopped", "pid": null, "failures": 0, "oneshot": true,
             "healthy": null, "since_unix": 90, "restarts": 0}
        ]
    })
    .to_string()
        + "\n"
}

fn reply_to(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["status"] => status_reply(),
        ["journal", since, limit] => {
            let since: u64 = since.parse().unwrap();
            let limit: usize = limit.parse().unwrap();
            [
                (5, 1000, "init", "booted"),
                (6, 2000, "service:dnsmasq", "started"),
            ]
            .into_iter()
            .filter(|(seq, ..)| *seq > since)
            .take(limit)
            .map(|(seq, ts, src, msg)| journal_entry(seq, ts, src, msg) + "\n")
            .collect()
        }
        ["restart" | "reload", name] if KNOWN_SERVICES.contains(name) => "{\"ok\":true}\n".into(),
        ["restart" | "reload", _] => "{\"ok\":false,\"error\":\"unknown service\"}\n".into(),
        ["upgrade", dir, ..] if dir.ends_with("/refused") => {
            "{\"ok\":false,\"error\":\"failsafe mode: upgrades are disabled\"}\n".into()
        }
        ["reboot"] | ["upgrade", ..] => "{\"ok\":true}\n".into(),
        _ => "{\"ok\":false,\"error\":\"unsupported\"}\n".into(),
    }
}

fn serve_one(mut conn: &UnixStream, requests: &Mutex<Vec<String>>) {
    conn.set_nonblocking(false).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut line = String::new();
    BufReader::new(conn).read_line(&mut line).unwrap();
    let line = line.trim().to_owned();
    let reply = reply_to(&line);
    requests.lock().unwrap().push(line);
    conn.write_all(reply.as_bytes()).unwrap();
}

impl FakeInit {
    fn start(path: &Path) -> Self {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (reqs, flag) = (Arc::clone(&requests), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => serve_one(&conn, &reqs),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeInit {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ------------------------------------------------------------ recording applier

#[derive(Debug, Clone)]
enum Mode {
    Ok(ApplyOutcome),
    Partial(ApplyOutcome),
    Fail,
}

#[derive(Debug)]
struct RecordingApplier {
    mode: Mode,
    calls: Mutex<Vec<Config>>,
}

impl RecordingApplier {
    fn calls(&self) -> Vec<Config> {
        self.calls.lock().unwrap().clone()
    }
}

impl Applier for RecordingApplier {
    fn apply<'a>(
        &'a self,
        _board: &'a Board,
        cfg: &'a Config,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ApplyError>> {
        self.calls.lock().unwrap().push(cfg.clone());
        let result = match &self.mode {
            Mode::Ok(o) => Ok(o.clone()),
            Mode::Partial(o) => Err(ApplyError::Partial {
                outcome: Box::new(o.clone()),
                source: Box::new(ApplyError::NoDhcpClient),
            }),
            Mode::Fail => Err(ApplyError::NoDhcpClient),
        };
        Box::pin(std::future::ready(result))
    }
}

// ---------------------------------------------------------------- fixture

struct Fixture {
    dir: tempfile::TempDir,
    cfg: RealConfig,
    board: Board,
    backend: RealBackend,
    init: Option<FakeInit>,
    applier: Arc<RecordingApplier>,
}

fn user(name: &str, role: owr_config::Role, enabled: bool, hash: String) -> owr_config::User {
    owr_config::User {
        name: name.to_owned(),
        role,
        password_hash: owr_config::Secret::from(hash),
        enabled,
    }
}

fn ap(ssid: &str) -> owr_config::ApConfig {
    owr_config::ApConfig {
        radio: "radio0".to_owned(),
        ssid: ssid.to_owned(),
        hidden: false,
        security: owr_config::Security::Wpa3Sae {
            passphrase: owr_config::Secret::from("correct-horse-battery"),
        },
        network: "lan".to_owned(),
        isolate_clients: false,
        max_clients: None,
    }
}

fn changed_outcome() -> ApplyOutcome {
    ApplyOutcome {
        net_actions: 2,
        fw_changed: true,
        hostapd_changed: vec![("phy0".into(), true), ("phy1".into(), false)],
        dnsmasq_changed: true,
        netd_changed: false,
        pppoe_changed: false,
        warnings: vec!["sysctl x not available, skipped".into()],
    }
}

fn fixture_with(mode: Mode, init: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let run_dir = dir.path().join("run");
    std::fs::create_dir_all(&run_dir).unwrap();
    let mut cfg = RealConfig::with_run_dir(&run_dir);
    cfg.board_path = dir.path().join("board.toml");
    cfg.config_path = dir.path().join("etc").join("config.toml");
    cfg.release_key = dir.path().join("release.pub");
    std::fs::write(&cfg.board_path, owr_board::GL_MT6000_TOML).unwrap();
    let board = Board::load(&cfg.board_path).unwrap();

    let mut stored = Config::defaults_for(&board);
    stored.users = vec![
        user("admin", owr_config::Role::Admin, true, hash(PASSWORD)),
        user("viewer", owr_config::Role::Viewer, true, hash(PASSWORD)),
    ];
    stored.wireless.aps = vec![ap("home")];
    Store::new(&cfg.config_path)
        .save_for(&stored, &board)
        .unwrap();

    let init = init.then(|| FakeInit::start(&cfg.init_sock));
    let applier = Arc::new(RecordingApplier {
        mode,
        calls: Mutex::new(Vec::new()),
    });
    let backend = RealBackend::with_applier(cfg.clone(), board.clone(), applier.clone());
    Fixture {
        dir,
        cfg,
        board,
        backend,
        init,
        applier,
    }
}

fn fixture() -> Fixture {
    fixture_with(Mode::Ok(changed_outcome()), true)
}

impl Fixture {
    fn stored(&self) -> Config {
        Store::new(&self.cfg.config_path)
            .load_for(&self.board)
            .unwrap()
    }

    fn requests(&self) -> Vec<String> {
        self.init
            .as_ref()
            .map(FakeInit::requests)
            .unwrap_or_default()
    }

    fn file(&self) -> Vec<u8> {
        std::fs::read(&self.cfg.config_path).unwrap()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn info(name: &str, role: Role, enabled: bool) -> UserInfo {
    UserInfo {
        name: name.to_owned(),
        role,
        enabled,
    }
}

fn invalid_paths(err: BackendError) -> Vec<String> {
    match err {
        BackendError::Invalid(v) => v.errors.into_iter().map(|e| e.path).collect(),
        other => unreachable!("expected Invalid, got {other:?}"),
    }
}

// ------------------------------------------------------------------- reads

#[tokio::test]
async fn board_status_and_startup() {
    let f = fixture();
    let board = f.backend.board().await.unwrap();
    assert_eq!(board["board"]["id"], "glinet_gl-mt6000");

    let st = f.backend.status().await.unwrap();
    assert_ne!(st.hostname, "");
    assert!(st.mem.total_kib > 0 && st.mem.available_kib <= st.mem.total_kib);
    assert!(st.load.iter().all(|l| l.is_finite() && *l >= 0.0));
    assert_eq!(st.board.id, "glinet_gl-mt6000");
    assert_eq!(st.firmware.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(st.firmware.build, "dev");
    assert!(st.time_unix > 1_600_000_000);

    let start = f.backend.startup().unwrap();
    assert_eq!(start.lan_ipv4.to_string(), "192.168.8.1");
    assert_eq!(start.api_port, 443);
    assert_ne!(start.hostname, "");
}

#[tokio::test]
async fn config_is_redacted() {
    let f = fixture();
    let shown = f.backend.config().await.unwrap();
    assert_eq!(shown["users"][0]["name"], "admin");
    assert_eq!(shown["users"][0]["password_hash"], "***");
    assert_eq!(shown["wireless"]["aps"][0]["security"]["passphrase"], "***");
    let text = shown.to_string();
    assert!(!text.contains(&hash(PASSWORD)) && !text.contains("correct-horse-battery"));
}

#[tokio::test]
async fn validate_config_paths_and_placeholders() {
    let f = fixture();
    let shown = f.backend.config().await.unwrap();
    f.backend.validate_config(shown.clone()).await.unwrap();

    let mut bad_port = shown.clone();
    bad_port["network"]["lan"]["ports"] = json!(["no-such-port"]);
    let errs = f.backend.validate_config(bad_port).await.unwrap_err();
    assert!(
        errs.errors
            .iter()
            .any(|e| e.path.starts_with("network.lan"))
    );

    let garbage = f
        .backend
        .validate_config(json!({"x": 1}))
        .await
        .unwrap_err();
    assert_eq!(garbage.errors.len(), 1);

    // a new AP cannot inherit a secret it never had
    let mut fresh = shown.clone();
    let mut second = fresh["wireless"]["aps"][0].clone();
    second["ssid"] = json!("other");
    fresh["wireless"]["aps"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let errs = f.backend.validate_config(fresh).await.unwrap_err();
    assert!(errs.errors.iter().any(|e| e.path.ends_with("passphrase")));
}

#[tokio::test]
async fn leases_come_from_the_dnsmasq_file() {
    let f = fixture();
    assert_eq!(f.backend.dhcp_leases().await.unwrap(), []);
    std::fs::write(
        &f.cfg.leases_file,
        "duid 00:01:00:01\n1700000000 AA:bb:cc:00:11:22 192.168.8.101 laptop 01:aa\n\
         1700000500 3c:22:fb:aa:bb:cc 192.168.8.102 * *\n",
    )
    .unwrap();
    let leases = f.backend.dhcp_leases().await.unwrap();
    assert_eq!(leases.len(), 2);
    assert_eq!(leases[0].mac, "aa:bb:cc:00:11:22");
    assert_eq!(leases[0].hostname, "laptop");
    assert_eq!(leases[1].hostname, "");
}

#[tokio::test]
async fn firewall_preview_renders_the_ruleset() {
    let f = fixture();
    let text = f.backend.firewall_preview().await.unwrap();
    assert!(text.contains("table inet"), "{text}");
}

#[tokio::test]
async fn network_and_wireless_status_work_without_daemons() {
    let f = fixture();
    let net = f.backend.network_status().await.unwrap();
    assert!(net.interfaces.iter().all(|i| i.role.is_some()));
    let wifi = f.backend.wireless_status().await.unwrap();
    assert_eq!(wifi.radios.len(), 2);
    assert_eq!(wifi.radios[0].phy, "phy0");
    // hostapd is not running: the configured AP is listed without BSSID or clients
    assert_eq!(wifi.aps.len(), 1);
    assert_eq!(wifi.aps[0].ifname, "wlan0");
    assert_eq!(wifi.aps[0].ssid, "home");
    assert_eq!(wifi.aps[0].bssid, "");
    assert_eq!(wifi.aps[0].clients.len(), 0);
}

// -------------------------------------------------------------------- init

#[tokio::test]
async fn logs_are_mapped_to_wall_clock_time() {
    let f = fixture();
    let all = f.backend.logs(0, 10).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!((all[0].seq, all[0].source.as_str()), (5, "init"));
    assert_eq!(all[1].source, "service:dnsmasq");
    assert!(all[0].ts_ms > 1_600_000_000_000, "{}", all[0].ts_ms);
    assert_eq!(all[1].ts_ms - all[0].ts_ms, 1000);
    assert_eq!(f.backend.logs(5, 10).await.unwrap().len(), 1);
    assert_eq!(f.backend.logs(0, 1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn services_and_actions() {
    let f = fixture();
    let services = f.backend.services().await.unwrap();
    assert_eq!(services.len(), 2);
    assert_eq!(services[0].name, "dnsmasq");
    assert_eq!(services[0].pid, Some(42));
    assert_eq!(services[0].restarts, 2);

    f.backend
        .service_action("dnsmasq", ServiceAction::Restart)
        .await
        .unwrap();
    f.backend
        .service_action("owr-netd", ServiceAction::Reload)
        .await
        .unwrap();
    assert!(matches!(
        f.backend
            .service_action("nope", ServiceAction::Reload)
            .await,
        Err(BackendError::NotFound)
    ));
    // names that could smuggle a second command never reach the socket
    assert!(matches!(
        f.backend
            .service_action("dnsmasq\nreboot", ServiceAction::Restart)
            .await,
        Err(BackendError::NotFound)
    ));
    f.backend.reboot().await.unwrap();
    assert_eq!(
        f.requests().iter().filter(|r| *r == "reboot").count(),
        1,
        "the smuggled reboot never reached init: {:?}",
        f.requests()
    );
}

#[tokio::test]
async fn init_down_is_unavailable() {
    let f = fixture_with(Mode::Ok(ApplyOutcome::default()), false);
    assert!(matches!(
        f.backend.services().await,
        Err(BackendError::Unavailable(_))
    ));
    assert!(matches!(
        f.backend.logs(0, 5).await,
        Err(BackendError::Unavailable(_))
    ));
    assert!(matches!(
        f.backend.reboot().await,
        Err(BackendError::Unavailable(_))
    ));
}

// ------------------------------------------------------------------- users

#[tokio::test]
async fn users_list_and_verify() {
    let f = fixture();
    let users = f.backend.users().await.unwrap();
    assert_eq!(users.len(), 2);
    assert_eq!(users[0], info("admin", Role::Admin, true));

    let ok = f.backend.verify_password("admin", PASSWORD).await.unwrap();
    assert_eq!(ok, Some(info("admin", Role::Admin, true)));
    assert_eq!(
        f.backend.verify_password("admin", "wrong").await.unwrap(),
        None
    );
    assert_eq!(
        f.backend.verify_password("nobody", PASSWORD).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn set_user_creates_updates_and_keeps_the_hash() {
    let f = fixture();
    let missing_hash = f
        .backend
        .set_user(info("bob", Role::Viewer, true), None)
        .await
        .unwrap_err();
    assert_eq!(invalid_paths(missing_hash), ["password"]);

    f.backend
        .set_user(info("bob", Role::Viewer, true), Some(hash(OTHER_PASSWORD)))
        .await
        .unwrap();
    assert!(
        f.backend
            .verify_password("bob", OTHER_PASSWORD)
            .await
            .unwrap()
            .is_some()
    );

    // update without a hash keeps the stored one; disabled users still verify (routes decide)
    f.backend
        .set_user(info("bob", Role::Admin, false), None)
        .await
        .unwrap();
    let bob = f
        .backend
        .verify_password("bob", OTHER_PASSWORD)
        .await
        .unwrap();
    assert_eq!(bob, Some(info("bob", Role::Admin, false)));

    let bad_name = f
        .backend
        .set_user(info("bad name!", Role::Viewer, true), Some(hash(PASSWORD)))
        .await
        .unwrap_err();
    assert!(invalid_paths(bad_name).iter().any(|p| p.ends_with("name")));

    let bad_hash = f
        .backend
        .set_user(info("eve", Role::Viewer, true), Some("plaintext".into()))
        .await
        .unwrap_err();
    assert!(
        invalid_paths(bad_hash)
            .iter()
            .any(|p| p.ends_with("password_hash"))
    );
    assert_eq!(
        f.stored().users.len(),
        3,
        "rejected edits are not persisted"
    );
}

#[tokio::test]
async fn set_password_changes_only_the_hash() {
    let f = fixture();
    assert!(matches!(
        f.backend.set_password("nobody", hash(PASSWORD)).await,
        Err(BackendError::NotFound)
    ));
    f.backend
        .set_user(info("viewer", Role::Viewer, false), None)
        .await
        .unwrap();
    f.backend
        .set_password("viewer", hash(OTHER_PASSWORD))
        .await
        .unwrap();
    assert_eq!(
        f.backend.verify_password("viewer", PASSWORD).await.unwrap(),
        None
    );
    let v = f
        .backend
        .verify_password("viewer", OTHER_PASSWORD)
        .await
        .unwrap();
    assert_eq!(
        v,
        Some(info("viewer", Role::Viewer, false)),
        "role and enabled untouched"
    );
}

#[tokio::test]
async fn the_last_enabled_admin_cannot_go() {
    let f = fixture();
    for attempt in 0..3 {
        let err = match attempt {
            0 => f.backend.delete_user("admin").await,
            1 => {
                f.backend
                    .set_user(info("admin", Role::Viewer, true), None)
                    .await
            }
            _ => {
                f.backend
                    .set_user(info("admin", Role::Admin, false), None)
                    .await
            }
        }
        .unwrap_err();
        assert_eq!(invalid_paths(err), ["users"], "attempt {attempt}");
    }
    assert_eq!(
        f.backend.users().await.unwrap()[0],
        info("admin", Role::Admin, true)
    );

    // with a second admin the first may go; the viewer was never protected
    f.backend
        .set_user(info("root2", Role::Admin, true), Some(hash(PASSWORD)))
        .await
        .unwrap();
    f.backend.delete_user("admin").await.unwrap();
    f.backend.delete_user("viewer").await.unwrap();
    assert!(matches!(
        f.backend.delete_user("viewer").await,
        Err(BackendError::NotFound)
    ));
    let err = f.backend.delete_user("root2").await.unwrap_err();
    assert_eq!(invalid_paths(err), ["users"]);
}

// ------------------------------------------------------------ save and apply

async fn edited_hostname(f: &Fixture, name: &str) -> Value {
    let mut doc = f.backend.config().await.unwrap();
    doc["system"]["hostname"] = json!(name);
    doc
}

#[tokio::test]
async fn save_config_persists_applies_and_restarts_changed_daemons() {
    let f = fixture();
    let doc = edited_hostname(&f, "flint2").await;
    let report = f.backend.save_config(doc, "tester").await.unwrap();

    assert!(report.changed);
    assert_eq!(
        report.summary,
        [
            "configuration saved",
            "network: 2 change(s) applied",
            "firewall ruleset reloaded",
            "wireless phy0: configuration updated",
            "dnsmasq configuration updated",
        ]
    );
    assert_eq!(report.warnings, ["sysctl x not available, skipped"]);
    assert_eq!(f.requests(), ["restart hostapd-phy0", "restart dnsmasq"]);

    let calls = f.applier.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].system.hostname, "flint2");
    // the redacted placeholders were replaced by the stored secrets
    let stored = f.stored();
    assert_eq!(stored.system.hostname, "flint2");
    assert_eq!(stored.users.len(), 2);
    assert!(
        f.backend
            .verify_password("admin", PASSWORD)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        stored.wireless.aps[0]
            .security
            .passphrase()
            .unwrap()
            .expose(),
        "correct-horse-battery"
    );
}

#[tokio::test]
async fn saving_the_same_config_reports_what_apply_changed_only() {
    let f = fixture_with(Mode::Ok(ApplyOutcome::default()), true);
    let doc = f.backend.config().await.unwrap();
    let report = f.backend.save_config(doc, "tester").await.unwrap();
    assert!(!report.changed);
    assert_eq!(report.summary.len(), 0);
    assert_eq!(
        f.applier.calls().len(),
        1,
        "apply is idempotent and always runs"
    );
    assert_eq!(f.requests().len(), 0, "nothing changed, nothing restarted");
}

#[tokio::test]
async fn the_users_section_is_not_writable_through_the_config() {
    let f = fixture();
    let mut doc = f.backend.config().await.unwrap();
    doc["users"] = json!([]);
    let report = f.backend.save_config(doc, "tester").await.unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("users section")));
    assert_eq!(f.stored().users.len(), 2);
}

#[tokio::test]
async fn invalid_config_is_neither_saved_nor_applied() {
    let f = fixture();
    let before = f.file();
    let mut doc = edited_hostname(&f, "ok-name").await;
    doc["network"]["lan"]["ports"] = json!(["no-such-port"]);
    let err = f.backend.save_config(doc, "tester").await.unwrap_err();
    assert!(
        invalid_paths(err)
            .iter()
            .any(|p| p.starts_with("network.lan"))
    );
    assert_eq!(f.file(), before);
    assert_eq!(f.applier.calls().len(), 0);
    assert_eq!(f.requests().len(), 0);
}

#[tokio::test]
async fn unsupported_configs_are_rejected_before_saving() {
    let f = fixture();
    let before = f.file();
    let mut doc = f.backend.config().await.unwrap();
    // A static lease named like a dnsmasq keyword passes the config checks but cannot be
    // rendered into dnsmasq.conf.
    doc["dhcp"]["static_leases"] = json!([
        {"mac": "02:00:00:00:00:01", "ip": "192.168.8.20", "hostname": "infinite"}
    ]);
    let err = f.backend.save_config(doc, "tester").await.unwrap_err();
    assert!(matches!(err, BackendError::Invalid(_)), "{err:?}");
    assert_eq!(f.file(), before);
    assert_eq!(f.applier.calls().len(), 0);
}

#[tokio::test]
async fn a_failed_apply_is_an_internal_error_but_partial_changes_still_restart() {
    let f = fixture_with(Mode::Partial(changed_outcome()), true);
    let doc = edited_hostname(&f, "half-done").await;
    let err = f.backend.save_config(doc, "tester").await.unwrap_err();
    let BackendError::Internal(msg) = err else {
        unreachable!("expected Internal");
    };
    assert!(msg.contains("applying"), "{msg}");
    assert!(msg.contains("dnsmasq configuration updated"), "{msg}");
    assert_eq!(f.requests(), ["restart hostapd-phy0", "restart dnsmasq"]);
    assert_eq!(
        f.stored().system.hostname,
        "half-done",
        "config stays saved"
    );

    let f = fixture_with(Mode::Fail, true);
    let doc = edited_hostname(&f, "nothing-done").await;
    let err = f.backend.save_config(doc, "tester").await.unwrap_err();
    assert!(matches!(err, BackendError::Internal(_)));
    assert_eq!(f.requests().len(), 0);
}

#[tokio::test]
async fn restart_problems_become_warnings() {
    // init knows hostapd-phy0 and dnsmasq only; the outcome also asks for owr-netd + phy1
    let outcome = ApplyOutcome {
        hostapd_changed: vec![("phy1".into(), true)],
        netd_changed: true,
        ..ApplyOutcome::default()
    };
    let f = fixture_with(Mode::Ok(outcome), true);
    let doc = edited_hostname(&f, "warn").await;
    let report = f.backend.save_config(doc, "tester").await.unwrap();
    assert_eq!(f.requests(), ["restart hostapd-phy1", "restart owr-netd"]);
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(report.warnings[0].contains("hostapd-phy1 is not supervised"));

    let f = fixture_with(Mode::Ok(changed_outcome()), false);
    let doc = edited_hostname(&f, "no-init").await;
    let report = f.backend.save_config(doc, "tester").await.unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("init control socket unavailable")),
        "{:?}",
        report.warnings
    );
}

// ------------------------------------------------------------ backup, restore

#[tokio::test]
async fn backup_is_the_raw_file_and_restore_applies_it() {
    let f = fixture();
    let backup = f.backend.backup().await.unwrap();
    assert_eq!(backup, f.file());

    // edit the backup text: a new hostname, everything else (secrets included) as stored
    let text = String::from_utf8(backup).unwrap();
    let edited = text.replace("hostname = \"ferritewrt\"", "hostname = \"restored\"");
    assert_ne!(edited, text);
    let report = f
        .backend
        .restore(edited.into_bytes(), "tester")
        .await
        .unwrap();
    assert!(report.changed);
    assert_eq!(report.summary[0], "configuration restored from backup");
    assert_eq!(f.stored().system.hostname, "restored");
    assert_eq!(f.applier.calls().len(), 1);
    assert_eq!(f.requests(), ["restart hostapd-phy0", "restart dnsmasq"]);
}

#[tokio::test]
async fn restore_refuses_backups_that_lock_the_admin_out() {
    let f = fixture();
    let before = f.file();
    let mut cfg = f.stored();
    cfg.users.retain(|u| u.role == owr_config::Role::Viewer);
    let text = cfg.to_toml_string().unwrap();
    let err = f
        .backend
        .restore(text.into_bytes(), "tester")
        .await
        .unwrap_err();
    assert_eq!(invalid_paths(err), ["users"]);

    let mut cfg = f.stored();
    cfg.users.clear();
    let err = f
        .backend
        .restore(cfg.to_toml_string().unwrap().into_bytes(), "tester")
        .await
        .unwrap_err();
    assert_eq!(invalid_paths(err), ["users"]);

    assert_eq!(f.file(), before);
    assert_eq!(f.applier.calls().len(), 0);
}

#[tokio::test]
async fn restore_rejects_garbage_and_oversized_input() {
    let f = fixture();
    let before = f.file();
    for bytes in [
        b"not = [valid".to_vec(),
        vec![0xff, 0xfe, 0x00],
        b"schema = 1\n".to_vec(),
        vec![b'#'; 1024 * 1024 + 1],
    ] {
        let err = f.backend.restore(bytes, "tester").await.unwrap_err();
        assert!(matches!(err, BackendError::Invalid(_)), "{err:?}");
    }
    // a hash that is not a real PHC string is not an administrator with a valid hash
    let mut cfg = f.stored();
    cfg.users[0].password_hash = owr_config::Secret::from("***");
    let text = cfg.to_toml_string().unwrap();
    assert!(matches!(
        f.backend.restore(text.into_bytes(), "tester").await,
        Err(BackendError::Invalid(_))
    ));
    assert_eq!(f.file(), before);
    assert_eq!(f.applier.calls().len(), 0);
}

#[tokio::test]
async fn startup_writes_defaults_on_first_boot() {
    let f = fixture();
    let fresh = f.path("fresh-config.toml");
    let mut cfg = f.cfg.clone();
    cfg.config_path = fresh.clone();
    let backend = RealBackend::with_applier(cfg, f.board.clone(), f.applier.clone());
    assert!(!fresh.exists());
    let info = backend.startup().unwrap();
    assert!(fresh.exists());
    assert_eq!(info.lan_ipv4.to_string(), "192.168.8.1");
    // no users yet: the first one must be an enabled admin
    let err = backend
        .set_user(
            UserInfo {
                name: "v".into(),
                role: Role::Viewer,
                enabled: true,
            },
            Some(hash(PASSWORD)),
        )
        .await
        .unwrap_err();
    assert_eq!(invalid_paths(err), ["users"]);
    backend
        .set_user(
            UserInfo {
                name: "admin".into(),
                role: Role::Admin,
                enabled: true,
            },
            Some(hash(PASSWORD)),
        )
        .await
        .unwrap();
}

// ------------------------------------------------------------------- upgrade

const BOARD_ID: &str = "glinet_gl-mt6000";

fn image_name(version: &str) -> String {
    format!("ferritewrt-{BOARD_ID}-v{version}-sysupgrade.bin")
}

/// One GNU tar header block.
fn tar_header(name: &str, size: usize, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[156] = typeflag;
    h[257..265].copy_from_slice(b"ustar  \0");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

/// A sysupgrade image as `OpenWrt` builds it: `sysupgrade-<board>/` with CONTROL, kernel, root.
fn sysupgrade_image(board: &str) -> Vec<u8> {
    let dir = format!("sysupgrade-{board}/");
    let control = format!("BOARD={board}\n");
    let mut out = tar_header(&dir, 0, b'5').to_vec();
    for (name, data) in [
        ("CONTROL", control.as_bytes()),
        ("kernel", b"kernel-fit".as_slice()),
        ("root", b"squashfs-root".as_slice()),
    ] {
        out.extend_from_slice(&tar_header(&format!("{dir}{name}"), data.len(), b'0'));
        out.extend_from_slice(data);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// A release in `dir` (created) for our board at `version`, signed by `key`.
fn signed_release(dir: &Path, version: &str, key: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer as _;
    use owr_upgrade::release::{SIG_FILE, SUMS_FILE, hash_file, signature_text};

    std::fs::create_dir_all(dir).unwrap();
    let name = image_name(version);
    let path = dir.join(&name);
    std::fs::write(&path, sysupgrade_image(BOARD_ID)).unwrap();
    let sums = format!("{}  {name}\n", hash_file(&path).unwrap().0);
    std::fs::write(dir.join(SUMS_FILE), &sums).unwrap();
    let sig = signature_text(
        &key.verifying_key().to_bytes(),
        &key.sign(sums.as_bytes()).to_bytes(),
    );
    std::fs::write(dir.join(SIG_FILE), sig).unwrap();
}

fn release_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

/// Install `key`'s public half as the router's release key.
fn trust(f: &Fixture, key: &ed25519_dalek::SigningKey) {
    let mut hex = String::new();
    for b in key.verifying_key().to_bytes() {
        write!(hex, "{b:02x}").unwrap();
    }
    std::fs::write(&f.cfg.release_key, format!("{hex}\n")).unwrap();
}

fn refusal(err: BackendError) -> String {
    match err {
        BackendError::Refused(msg) => msg,
        other => unreachable!("expected Refused, got {other:?}"),
    }
}

#[tokio::test]
async fn upgrade_check_verifies_a_signed_bundle() {
    let f = fixture_with(Mode::Ok(ApplyOutcome::default()), false);
    let key = release_key();
    trust(&f, &key);
    let dir = f.path("upload");
    signed_release(&dir, "9.0.0", &key);
    let info = f.backend.upgrade_check(&dir, false).await.unwrap();
    assert_eq!(info.image, image_name("9.0.0"));
    assert_eq!(info.version, "9.0.0");
    assert_eq!(info.board, BOARD_ID);
    assert_eq!(info.running, env!("CARGO_PKG_VERSION"));
    assert!(!info.downgrade);

    // an older release needs the explicit downgrade, then reports it
    let old = f.path("old");
    signed_release(&old, "0.0.1", &key);
    let msg = refusal(f.backend.upgrade_check(&old, false).await.unwrap_err());
    assert!(msg.contains("older"), "{msg}");
    assert!(f.backend.upgrade_check(&old, true).await.unwrap().downgrade);

    // signed by someone else
    let other = f.path("other");
    signed_release(
        &other,
        "9.0.0",
        &ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]),
    );
    let msg = refusal(f.backend.upgrade_check(&other, false).await.unwrap_err());
    assert!(msg.starts_with("SHA256SUMS.sig"), "{msg}");

    // nothing uploaded
    let msg = refusal(
        f.backend
            .upgrade_check(&f.path("empty"), false)
            .await
            .unwrap_err(),
    );
    assert!(msg.starts_with("SHA256SUMS"), "{msg}");
}

#[tokio::test]
async fn upgrade_check_without_a_release_key_is_an_internal_error() {
    let f = fixture_with(Mode::Ok(ApplyOutcome::default()), false);
    let dir = f.path("upload");
    signed_release(&dir, "9.0.0", &release_key());
    assert!(matches!(
        f.backend.upgrade_check(&dir, false).await,
        Err(BackendError::Internal(_))
    ));
    std::fs::write(&f.cfg.release_key, "not a key").unwrap();
    assert!(matches!(
        f.backend.upgrade_check(&dir, false).await,
        Err(BackendError::Internal(_))
    ));
}

#[tokio::test]
async fn upgrade_is_handed_to_init_and_its_refusal_reaches_the_user() {
    let f = fixture();
    let dir = f.path("upload");
    f.backend.upgrade(&dir, true, false).await.unwrap();
    f.backend.upgrade(&dir, false, true).await.unwrap();
    let refused = f.path("refused");
    let msg = refusal(f.backend.upgrade(&refused, false, false).await.unwrap_err());
    assert_eq!(msg, "failsafe mode: upgrades are disabled");
    assert_eq!(
        f.requests(),
        [
            format!("upgrade {} downgrade", dir.display()),
            format!("upgrade {} wipe", dir.display()),
            format!("upgrade {}", refused.display()),
        ]
    );
    // without init the request cannot be delivered
    let down = fixture_with(Mode::Ok(ApplyOutcome::default()), false);
    assert!(matches!(
        down.backend.upgrade(&dir, false, false).await,
        Err(BackendError::Unavailable(_))
    ));
}
