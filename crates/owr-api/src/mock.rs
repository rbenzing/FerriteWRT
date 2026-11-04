//! In-memory [`SystemBackend`] with realistic GL.iNet Flint 2 data.
//!
//! Used by `owr-api --dev` and by the test-suite. Users are held with real Argon2id
//! hashes; the configuration is a mutable JSON document whose secrets are redacted
//! (`"***"`) when read and restored from the stored value when written back.

use std::collections::VecDeque;
use std::future::ready;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use owr_upgrade::Version;
use owr_upgrade::bundle::BundleError;
use owr_upgrade::release::{SIG_FILE, SUMS_FILE};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::backend::{BackendResult, BoxFuture, SystemBackend};
use crate::document;
use crate::dto::{
    ApStatus, ApplyReport, BackendError, BoardId, Client, Firmware, Iface, Lease, LogEntry,
    MemInfo, NetworkStatus, RadioStatus, Role, ServiceAction, ServiceStatus, SystemStatus,
    UpgradeInfo, UserInfo, ValidationErrors, WanStatus, WirelessStatus,
};
use crate::password;
use crate::secrets::{find_placeholders, redact, unredact};
use crate::upgrade::running_version;

const MAX_LOGS: usize = 2000;
const SEED_LOGS: u64 = 1200;
const SEED_UPTIME_SECS: u64 = 3 * 86_400 + 4 * 3600 + 17 * 60;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone)]
struct StoredUser {
    info: UserInfo,
    hash: String,
}

#[derive(Debug)]
struct State {
    /// Config document without the `users` section (users live in `users`).
    config: Value,
    users: Vec<StoredUser>,
    logs: VecDeque<LogEntry>,
    next_seq: u64,
    services: Vec<ServiceStatus>,
    upgrades: Vec<MockUpgrade>,
}

impl State {
    fn log(&mut self, prio: u8, source: &str, msg: String) {
        let ts_ms = unix_now().saturating_mul(1000);
        let seq = self.next_seq;
        self.next_seq = seq.saturating_add(1);
        self.logs.push_back(LogEntry {
            seq,
            ts_ms,
            prio,
            source: source.into(),
            msg,
        });
        while self.logs.len() > MAX_LOGS {
            self.logs.pop_front();
        }
    }

    /// Config document including users with their real hashes.
    fn full_config(&self) -> Value {
        let mut doc = self.config.clone();
        let users: Vec<Value> = self
            .users
            .iter()
            .map(|u| {
                json!({
                    "name": u.info.name,
                    "role": u.info.role,
                    "enabled": u.info.enabled,
                    "password_hash": u.hash,
                })
            })
            .collect();
        if let Some(obj) = doc.as_object_mut() {
            obj.insert("users".into(), Value::Array(users));
        }
        doc
    }
}

/// A firmware upgrade the mock accepted (recorded, never performed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockUpgrade {
    pub dir: PathBuf,
    pub allow_downgrade: bool,
    pub wipe_settings: bool,
}

/// In-memory backend; see the module docs.
#[derive(Debug)]
pub struct MockBackend {
    state: Mutex<State>,
    started: Instant,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// A backend with no users (the setup flow is required).
    pub fn new() -> Self {
        let now_ms = unix_now().saturating_mul(1000);
        let templates: [(u8, &str, &str); 8] = [
            (6, "owr-init", "service dnsmasq started"),
            (
                6,
                "kernel",
                "mt7530-mdio: port lan1 link up 2500Mbps full duplex",
            ),
            (5, "hostapd", "wlan1: STA-CONNECTED"),
            (6, "dnsmasq", "DHCPACK(br-lan) 192.168.8.101"),
            (4, "owr-net", "wan: DHCP lease renewed"),
            (6, "owr-api", "session established"),
            (3, "hostapd", "wlan0: AP-STA-POLL-OK"),
            (7, "kernel", "nf_conntrack: table checked"),
        ];
        let logs: VecDeque<LogEntry> = (1..=SEED_LOGS)
            .zip(templates.iter().cycle())
            .map(|(seq, (prio, source, msg))| LogEntry {
                seq,
                ts_ms: now_ms.saturating_sub(SEED_LOGS.saturating_sub(seq).saturating_mul(5000)),
                prio: *prio,
                source: (*source).into(),
                msg: format!("{msg} (#{seq})"),
            })
            .collect();
        let since = unix_now().saturating_sub(SEED_UPTIME_SECS);
        let services = [
            "dnsmasq",
            "hostapd-radio0",
            "hostapd-radio1",
            "odhcpd",
            "owr-api",
        ]
        .iter()
        .zip(1u32..)
        .map(|(name, pid)| ServiceStatus {
            name: (*name).into(),
            state: "running".into(),
            pid: Some(pid.saturating_mul(137)),
            since_unix: since,
            restarts: 0,
        })
        .collect();
        Self {
            state: Mutex::new(State {
                config: sample_config(),
                users: Vec::new(),
                logs,
                next_seq: SEED_LOGS.saturating_add(1),
                services,
                upgrades: Vec::new(),
            }),
            started: Instant::now(),
        }
    }

    /// A backend pre-populated with one user (hashes the password synchronously).
    pub fn with_user(name: &str, role: Role, password: &str) -> Self {
        let backend = Self::new();
        let hash = password::hash_password(password).unwrap_or_default();
        backend.lock().users.push(StoredUser {
            info: UserInfo {
                name: name.into(),
                role,
                enabled: true,
            },
            hash,
        });
        backend
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn uptime(&self) -> u64 {
        SEED_UPTIME_SECS.saturating_add(self.started.elapsed().as_secs())
    }

    /// The firmware upgrades accepted so far, oldest first.
    pub fn upgrades(&self) -> Vec<MockUpgrade> {
        self.lock().upgrades.clone()
    }
}

/// The mock's stand-in for bundle verification: `SHA256SUMS`, its signature and an image
/// named for the mock board must be in `dir`; the version comes from the image name. Nothing
/// is hashed or signature-checked. Refusals carry the same texts as the real verifier.
fn check_bundle(dir: &Path, allow_downgrade: bool) -> BackendResult<UpgradeInfo> {
    for file in [SUMS_FILE, SIG_FILE] {
        if !dir.join(file).is_file() {
            return Err(BackendError::Refused(format!("{file}: not uploaded")));
        }
    }
    let board = mock_board()
        .map_err(|e| BackendError::Internal(format!("builtin board: {e}")))?
        .board
        .id;
    let image = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .find_map(|name| {
            let version = name
                .strip_prefix("ferritewrt-")?
                .strip_prefix(board.as_str())?
                .strip_prefix("-v")?
                .strip_suffix("-sysupgrade.bin")
                .and_then(Version::parse)?;
            Some((name, version))
        });
    let Some((image, version)) = image else {
        return Err(BackendError::Refused(
            BundleError::NoImage(board).to_string(),
        ));
    };
    let running = running_version()
        .ok_or_else(|| BackendError::Internal("the running version does not parse".into()))?;
    let downgrade = version < running;
    if downgrade && !allow_downgrade {
        return Err(BackendError::Refused(
            BundleError::Downgrade {
                from: running.to_string(),
                to: version.to_string(),
            }
            .to_string(),
        ));
    }
    Ok(UpgradeInfo {
        image,
        version: version.to_string(),
        board,
        running: running.to_string(),
        downgrade,
    })
}

/// The board the mock pretends to run on.
fn mock_board() -> Result<owr_board::Board, owr_board::BoardError> {
    owr_board::Board::from_toml_str(owr_board::GL_MT6000_TOML)
}

/// Validation of an (unredacted) config document through the real owr-config model,
/// so the mock accepts exactly what production will accept.
fn validate_doc(doc: &Value) -> ValidationErrors {
    match mock_board() {
        Ok(board) => document::validate_doc(doc, &board),
        Err(e) => {
            ValidationErrors::single("", format!("builtin board descriptor unavailable: {e}"))
        }
    }
}

#[derive(Debug, Deserialize)]
struct BackupUser {
    name: String,
    role: Role,
    enabled: bool,
    password_hash: String,
}

impl MockBackend {
    /// Unredact against the stored document and validate; returns the usable document.
    fn prepare(&self, mut cfg: Value) -> Result<Value, ValidationErrors> {
        unredact(&mut cfg, &self.lock().full_config());
        let mut errs = validate_doc(&cfg);
        find_placeholders(&cfg, "", &mut errs);
        errs.into_result().map(|()| cfg)
    }

    fn apply(&self, cfg: Value, actor: &str) -> ApplyReport {
        let mut cfg = cfg;
        let mut state = self.lock();
        let mut warnings = Vec::new();
        let incoming_users = cfg.as_object_mut().and_then(|o| o.remove("users"));
        if let Some(users) = incoming_users
            && Some(&users) != state.full_config().get("users")
        {
            warnings.push("the users section is managed via /users and was ignored".to_owned());
        }
        let mut summary = Vec::new();
        if let (Some(new), Some(old)) = (cfg.as_object(), state.config.as_object()) {
            for (key, value) in new {
                if old.get(key) != Some(value) {
                    summary.push(format!("section '{key}' updated"));
                }
            }
        }
        let changed = !summary.is_empty();
        if changed {
            state.config = cfg;
            state.log(5, "owr-api", format!("configuration applied by {actor}"));
        }
        ApplyReport {
            changed,
            summary,
            warnings,
        }
    }
}

/// Board defaults plus one WPA2/WPA3 network per radio, exactly as the real
/// backend would produce after the first-boot wizard.
fn sample_config() -> Value {
    let Ok(board) = mock_board() else {
        return json!({});
    };
    let cfg = owr_config::Config::defaults_for(&board);
    let mut doc = serde_json::to_value(&cfg).unwrap_or_else(|_| json!({}));
    let aps = json!([
        {
            "radio": "radio0",
            "ssid": "ferritewrt",
            "hidden": false,
            "security": { "type": "wpa2_wpa3_mixed", "passphrase": "correct-horse-battery" },
            "network": "lan",
            "isolate_clients": false
        },
        {
            "radio": "radio1",
            "ssid": "ferritewrt-5G",
            "hidden": false,
            "security": { "type": "wpa2_wpa3_mixed", "passphrase": "staple-correct-horse" },
            "network": "lan",
            "isolate_clients": false
        }
    ]);
    if let Some(wireless) = doc.get_mut("wireless").and_then(Value::as_object_mut) {
        wireless.insert("aps".into(), aps);
    }
    doc
}

const FIREWALL_PREVIEW: &str = "\
table inet owr {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\tct state invalid drop
\t\tiifname \"lo\" accept
\t\tiifname \"br-lan\" accept
\t\tiifname \"eth1\" udp dport 68 accept
\t\tiifname \"eth1\" icmp type echo-request limit rate 5/second accept
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy drop;
\t\tct state established,related accept
\t\tct state invalid drop
\t\tiifname \"br-lan\" oifname \"eth1\" accept
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t}
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"eth1\" masquerade
\t}
}
";

fn iface(
    name: &str,
    role: Option<&str>,
    up: bool,
    speed: Option<u32>,
    mac: &str,
    v4: &[&str],
) -> Iface {
    Iface {
        name: name.into(),
        role: role.map(Into::into),
        up,
        carrier: up,
        speed_mbps: if up { speed } else { None },
        mac: mac.into(),
        ipv4: v4.iter().map(|s| (*s).into()).collect(),
        ipv6: Vec::new(),
        rx_bytes: 0,
        tx_bytes: 0,
    }
}

impl SystemBackend for MockBackend {
    fn board(&self) -> BoxFuture<'_, BackendResult<Value>> {
        // Serve the real descriptor so the UI sees exactly the production shape.
        let result = owr_board::Board::from_toml_str(owr_board::GL_MT6000_TOML)
            .map_err(|e| BackendError::Internal(format!("builtin board: {e}")))
            .and_then(|b| {
                serde_json::to_value(b)
                    .map_err(|e| BackendError::Internal(format!("board json: {e}")))
            });
        Box::pin(ready(result))
    }

    fn status(&self) -> BoxFuture<'_, BackendResult<SystemStatus>> {
        let hostname = self
            .lock()
            .config
            .pointer("/system/hostname")
            .and_then(Value::as_str)
            .unwrap_or("ferritewrt")
            .to_owned();
        Box::pin(ready(Ok(SystemStatus {
            hostname,
            uptime_secs: self.uptime(),
            load: [0.12, 0.18, 0.15],
            mem: MemInfo {
                total_kib: 1_007_616,
                free_kib: 742_300,
                available_kib: 801_120,
            },
            cpu_temp_mc: Some(52_300),
            board: BoardId {
                id: "glinet_gl-mt6000".into(),
                vendor: "GL.iNet".into(),
                model: "Flint 2 (GL-MT6000)".into(),
            },
            firmware: Firmware {
                version: env!("CARGO_PKG_VERSION").into(),
                build: "dev-mock".into(),
            },
            time_unix: unix_now(),
        })))
    }

    fn config(&self) -> BoxFuture<'_, BackendResult<Value>> {
        let mut doc = self.lock().full_config();
        redact(&mut doc);
        Box::pin(ready(Ok(doc)))
    }

    fn validate_config(&self, cfg: Value) -> BoxFuture<'_, Result<(), ValidationErrors>> {
        Box::pin(ready(self.prepare(cfg).map(|_| ())))
    }

    fn save_config<'a>(
        &'a self,
        cfg: Value,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>> {
        let result = self
            .prepare(cfg)
            .map(|doc| self.apply(doc, actor))
            .map_err(BackendError::Invalid);
        Box::pin(ready(result))
    }

    fn network_status(&self) -> BoxFuture<'_, BackendResult<NetworkStatus>> {
        let up = self.uptime();
        let counter = |rate: u64| up.saturating_mul(rate);
        let mut interfaces = vec![
            iface(
                "lan1",
                Some("lan"),
                true,
                Some(2500),
                "94:83:c4:a1:00:01",
                &[],
            ),
            iface(
                "lan2",
                Some("lan"),
                true,
                Some(1000),
                "94:83:c4:a1:00:02",
                &[],
            ),
            iface("lan3", Some("lan"), false, None, "94:83:c4:a1:00:03", &[]),
            iface("lan4", Some("lan"), false, None, "94:83:c4:a1:00:04", &[]),
            iface(
                "lan5",
                Some("lan"),
                true,
                Some(100),
                "94:83:c4:a1:00:05",
                &[],
            ),
            iface(
                "eth1",
                Some("wan"),
                true,
                Some(2500),
                "94:83:c4:a1:00:06",
                &["203.0.113.42/24"],
            ),
            iface(
                "br-lan",
                Some("bridge"),
                true,
                None,
                "94:83:c4:a1:00:01",
                &["192.168.8.1/24"],
            ),
        ];
        for (i, ifc) in interfaces.iter_mut().enumerate() {
            let factor = u64::try_from(i).unwrap_or(0).saturating_add(1);
            if ifc.up {
                ifc.rx_bytes = counter(factor.saturating_mul(18_000));
                ifc.tx_bytes = counter(factor.saturating_mul(6_500));
            }
        }
        if let Some(br) = interfaces.last_mut() {
            br.ipv6 = vec!["fd12:3456:789a::1/64".into()];
        }
        Box::pin(ready(Ok(NetworkStatus {
            interfaces,
            wan: Some(WanStatus {
                proto: "dhcp".into(),
                addr: "203.0.113.42/24".into(),
                gateway: "203.0.113.1".into(),
                dns: vec!["1.1.1.1".into(), "9.9.9.9".into()],
                uptime_secs: up.saturating_sub(35),
            }),
        })))
    }

    fn wireless_status(&self) -> BoxFuture<'_, BackendResult<WirelessStatus>> {
        let client =
            |mac: &str, host: Option<&str>, sig: i32, rx: u32, tx: u32, secs: u64| Client {
                mac: mac.into(),
                hostname: host.map(Into::into),
                signal_dbm: sig,
                rx_rate_kbps: rx,
                tx_rate_kbps: tx,
                connected_secs: secs,
            };
        Box::pin(ready(Ok(WirelessStatus {
            radios: vec![
                RadioStatus {
                    id: "radio0".into(),
                    phy: "phy0".into(),
                    band: "2g".into(),
                    channel: 6,
                    width_mhz: 40,
                    txpower_dbm: 20,
                    enabled: true,
                },
                RadioStatus {
                    id: "radio1".into(),
                    phy: "phy1".into(),
                    band: "5g".into(),
                    channel: 36,
                    width_mhz: 80,
                    txpower_dbm: 23,
                    enabled: true,
                },
            ],
            aps: vec![
                ApStatus {
                    ifname: "wlan0".into(),
                    radio: "radio0".into(),
                    ssid: "ferritewrt".into(),
                    bssid: "94:83:c4:a1:10:00".into(),
                    clients: vec![client(
                        "b8:27:eb:12:34:56",
                        Some("thermostat"),
                        -61,
                        72_200,
                        72_200,
                        86_400,
                    )],
                },
                ApStatus {
                    ifname: "wlan1".into(),
                    radio: "radio1".into(),
                    ssid: "ferritewrt-5G".into(),
                    bssid: "94:83:c4:a1:11:00".into(),
                    clients: vec![
                        client(
                            "3c:22:fb:aa:bb:cc",
                            Some("laptop"),
                            -48,
                            866_700,
                            780_000,
                            5_400,
                        ),
                        client("f0:18:98:de:ad:01", None, -67, 433_300, 390_000, 640),
                    ],
                },
            ],
        })))
    }

    fn dhcp_leases(&self) -> BoxFuture<'_, BackendResult<Vec<Lease>>> {
        let now = unix_now();
        let lease = |mac: &str, ip: &str, host: &str, left: u64| Lease {
            mac: mac.into(),
            ip: ip.into(),
            hostname: host.into(),
            expires_unix: now.saturating_add(left),
        };
        Box::pin(ready(Ok(vec![
            lease("aa:bb:cc:00:11:22", "192.168.8.10", "nas", 39_000),
            lease("3c:22:fb:aa:bb:cc", "192.168.8.101", "laptop", 41_200),
            lease("b8:27:eb:12:34:56", "192.168.8.102", "thermostat", 30_100),
            lease("f0:18:98:de:ad:01", "192.168.8.103", "*", 12_600),
        ])))
    }

    fn firewall_preview(&self) -> BoxFuture<'_, BackendResult<String>> {
        Box::pin(ready(Ok(FIREWALL_PREVIEW.to_owned())))
    }

    fn logs(&self, since_seq: u64, limit: u16) -> BoxFuture<'_, BackendResult<Vec<LogEntry>>> {
        let entries = self
            .lock()
            .logs
            .iter()
            .filter(|e| e.seq > since_seq)
            .take(usize::from(limit))
            .cloned()
            .collect();
        Box::pin(ready(Ok(entries)))
    }

    fn services(&self) -> BoxFuture<'_, BackendResult<Vec<ServiceStatus>>> {
        Box::pin(ready(Ok(self.lock().services.clone())))
    }

    fn service_action<'a>(
        &'a self,
        name: &'a str,
        action: ServiceAction,
    ) -> BoxFuture<'a, BackendResult<()>> {
        let mut state = self.lock();
        let now = unix_now();
        let found = state.services.iter_mut().find(|s| s.name == name).map(|s| {
            if action == ServiceAction::Restart {
                s.restarts = s.restarts.saturating_add(1);
                s.since_unix = now;
            }
        });
        let result = if found.is_some() {
            state.log(
                5,
                "owr-init",
                format!("service {name}: {action:?} requested"),
            );
            Ok(())
        } else {
            Err(BackendError::NotFound)
        };
        Box::pin(ready(result))
    }

    fn reboot(&self) -> BoxFuture<'_, BackendResult<()>> {
        self.lock()
            .log(4, "owr-init", "reboot requested (mock: ignored)".into());
        Box::pin(ready(Ok(())))
    }

    fn users(&self) -> BoxFuture<'_, BackendResult<Vec<UserInfo>>> {
        let users = self.lock().users.iter().map(|u| u.info.clone()).collect();
        Box::pin(ready(Ok(users)))
    }

    fn set_user(
        &self,
        user: UserInfo,
        password_hash: Option<String>,
    ) -> BoxFuture<'_, BackendResult<()>> {
        let mut state = self.lock();
        let result = match state.users.iter_mut().find(|u| u.info.name == user.name) {
            Some(existing) => {
                existing.info = user;
                if let Some(hash) = password_hash {
                    existing.hash = hash;
                }
                Ok(())
            }
            None => match password_hash {
                Some(hash) => {
                    state.users.push(StoredUser { info: user, hash });
                    Ok(())
                }
                None => Err(BackendError::Invalid(ValidationErrors::single(
                    "password",
                    "required for a new user",
                ))),
            },
        };
        Box::pin(ready(result))
    }

    fn set_password<'a>(
        &'a self,
        name: &'a str,
        password_hash: String,
    ) -> BoxFuture<'a, BackendResult<()>> {
        let mut state = self.lock();
        let result = match state.users.iter_mut().find(|u| u.info.name == name) {
            Some(user) => {
                user.hash = password_hash;
                Ok(())
            }
            None => Err(BackendError::NotFound),
        };
        Box::pin(ready(result))
    }

    fn delete_user<'a>(&'a self, name: &'a str) -> BoxFuture<'a, BackendResult<()>> {
        let mut state = self.lock();
        let before = state.users.len();
        state.users.retain(|u| u.info.name != name);
        let result = if state.users.len() < before {
            Ok(())
        } else {
            Err(BackendError::NotFound)
        };
        Box::pin(ready(result))
    }

    fn verify_password<'a>(
        &'a self,
        name: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, BackendResult<Option<UserInfo>>> {
        let found = self
            .lock()
            .users
            .iter()
            .find(|u| u.info.name == name)
            .cloned();
        let password = password.to_owned();
        Box::pin(async move {
            // Unknown users are verified against a dummy hash: same work either way.
            let hash = found
                .as_ref()
                .map_or_else(|| password::dummy_hash().to_owned(), |u| u.hash.clone());
            let ok =
                tokio::task::spawn_blocking(move || password::verify_password(&password, &hash))
                    .await
                    .map_err(|e| BackendError::Internal(e.to_string()))?;
            Ok(found.filter(|_| ok).map(|u| u.info))
        })
    }

    fn backup(&self) -> BoxFuture<'_, BackendResult<Vec<u8>>> {
        // The real backend returns config.toml; the mock has no TOML, so it returns JSON.
        let doc = self.lock().full_config();
        let result =
            serde_json::to_vec_pretty(&doc).map_err(|e| BackendError::Internal(e.to_string()));
        Box::pin(ready(result))
    }

    fn restore<'a>(
        &'a self,
        bytes: Vec<u8>,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>> {
        let result = (|| {
            let doc: Value = serde_json::from_slice(&bytes)
                .map_err(|e| ValidationErrors::single("", format!("not valid JSON: {e}")))?;
            let mut errs = validate_doc(&doc);
            find_placeholders(&doc, "", &mut errs);
            let users: Vec<BackupUser> = match doc.get("users") {
                Some(u) => serde_json::from_value(u.clone())
                    .map_err(|e| ValidationErrors::single("users", e.to_string()))?,
                None => Vec::new(),
            };
            // Every user's hash was already checked by owr-config (argon2id PHC with bounded
            // parameters) inside `validate_doc`; the backup must also keep the router manageable.
            if !users.iter().any(|u| u.enabled && u.role == Role::Admin) {
                errs.push(
                    "users",
                    "backup must contain at least one enabled administrator",
                );
            }
            errs.into_result()?;
            Ok::<_, ValidationErrors>((doc, users))
        })();
        let result = result
            .map_err(BackendError::Invalid)
            .map(|(mut doc, users)| {
                if let Some(obj) = doc.as_object_mut() {
                    obj.remove("users");
                }
                let mut state = self.lock();
                state.config = doc;
                state.users = users
                    .into_iter()
                    .map(|u| StoredUser {
                        info: UserInfo {
                            name: u.name,
                            role: u.role,
                            enabled: u.enabled,
                        },
                        hash: u.password_hash,
                    })
                    .collect();
                state.log(4, "owr-api", format!("configuration restored by {actor}"));
                ApplyReport {
                    changed: true,
                    summary: vec!["configuration restored from backup".into()],
                    warnings: Vec::new(),
                }
            });
        Box::pin(ready(result))
    }

    fn upgrade_check<'a>(
        &'a self,
        dir: &'a Path,
        allow_downgrade: bool,
    ) -> BoxFuture<'a, BackendResult<UpgradeInfo>> {
        Box::pin(ready(check_bundle(dir, allow_downgrade)))
    }

    fn upgrade<'a>(
        &'a self,
        dir: &'a Path,
        allow_downgrade: bool,
        wipe_settings: bool,
    ) -> BoxFuture<'a, BackendResult<()>> {
        // Like init, refuse a bundle that does not pass the check.
        let result = check_bundle(dir, allow_downgrade).map(|info| {
            let mut state = self.lock();
            state.log(
                4,
                "owr-init",
                format!(
                    "upgrade to {} requested (mock: ignored, wipe settings: {wipe_settings})",
                    info.version
                ),
            );
            state.upgrades.push(MockUpgrade {
                dir: dir.to_path_buf(),
                allow_downgrade,
                wipe_settings,
            });
        });
        Box::pin(ready(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::REDACTED;

    #[tokio::test]
    async fn config_roundtrip_keeps_secrets() {
        let b = MockBackend::with_user("admin", Role::Admin, "correct horse battery");
        let shown = b.config().await.unwrap();
        assert_eq!(
            shown["wireless"]["aps"][0]["security"]["passphrase"],
            REDACTED
        );
        assert_eq!(shown["users"][0]["password_hash"], REDACTED);

        let mut edited = shown.clone();
        edited["system"]["hostname"] = json!("flint2");
        let report = b.save_config(edited, "admin").await.unwrap();
        assert!(report.changed);
        assert_eq!(report.warnings, Vec::<String>::new());
        // secrets survived the round trip
        let state = b.lock();
        assert_eq!(
            state.config.pointer("/wireless/aps/0/security/passphrase"),
            Some(&json!("correct-horse-battery"))
        );
        assert_eq!(
            state.config.pointer("/system/hostname"),
            Some(&json!("flint2"))
        );
    }

    #[tokio::test]
    async fn validation_reports_paths() {
        let b = MockBackend::new();
        let mut cfg = b.config().await.unwrap();
        cfg["system"]["hostname"] = json!("bad host!");
        cfg["wireless"]["aps"][1]["ssid"] = json!("");
        cfg["wireless"]["aps"][0]["security"]["passphrase"] = json!("short");
        cfg["services"]["api"]["port"] = json!(0);
        let errs = b.validate_config(cfg).await.unwrap_err();
        let paths: Vec<&str> = errs.errors.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"system.hostname"), "{paths:?}");
        assert!(paths.contains(&"wireless.aps[1].ssid"), "{paths:?}");
        assert!(
            paths.contains(&"wireless.aps[0].security.passphrase"),
            "{paths:?}"
        );
        assert!(paths.contains(&"services.api.port"), "{paths:?}");
    }

    #[tokio::test]
    async fn placeholder_without_stored_value_is_rejected() {
        let b = MockBackend::new();
        let mut cfg = b.config().await.unwrap();
        cfg["wireless"]["aps"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "radio": "radio1", "ssid": "x", "passphrase": REDACTED }));
        let errs = b.validate_config(cfg).await.unwrap_err();
        assert!(
            errs.errors
                .iter()
                .any(|e| e.path.ends_with("aps[2].passphrase"))
        );
    }

    #[tokio::test]
    async fn logs_filter_and_limit() {
        let b = MockBackend::new();
        let all = b.logs(0, 5).await.unwrap();
        assert_eq!(all.len(), 5);
        let next = b.logs(all[4].seq, 3).await.unwrap();
        assert_eq!(next[0].seq, all[4].seq + 1);
        assert_eq!(b.logs(u64::MAX, 10).await.unwrap(), vec![]);
    }

    #[tokio::test]
    async fn backup_restore_roundtrip() {
        let b = MockBackend::with_user("admin", Role::Admin, "correct horse battery");
        let bytes = b.backup().await.unwrap();
        b.delete_user("admin").await.unwrap();
        assert_eq!(b.users().await.unwrap(), vec![]);
        let report = b.restore(bytes, "admin").await.unwrap();
        assert!(report.changed);
        let who = b
            .verify_password("admin", "correct horse battery")
            .await
            .unwrap();
        assert_eq!(who.map(|u| u.role), Some(Role::Admin));
        assert!(b.restore(b"{}".to_vec(), "admin").await.is_err());
    }

    async fn restore_with_users(b: &MockBackend, users: Value) -> BackendResult<ApplyReport> {
        let mut doc: Value = serde_json::from_slice(&b.backup().await.unwrap()).unwrap();
        doc["users"] = users;
        b.restore(serde_json::to_vec(&doc).unwrap(), "admin").await
    }

    #[tokio::test]
    async fn restore_must_leave_an_enabled_admin_with_a_valid_hash() {
        let b = MockBackend::with_user("admin", Role::Admin, "correct horse battery");
        let doc: Value = serde_json::from_slice(&b.backup().await.unwrap()).unwrap();
        let admin = doc["users"][0].clone();
        let with = |patch: &dyn Fn(&mut Value)| {
            let mut u = admin.clone();
            patch(&mut u);
            json!([u])
        };
        let rejected = [
            json!([]),
            with(&|u| {
                u["role"] = json!("viewer");
            }),
            with(&|u| {
                u["enabled"] = json!(false);
            }),
            with(&|u| {
                u["password_hash"] = json!("plaintext-not-a-hash");
            }),
            // valid shape, cost parameters outside owr-config's bounds
            with(&|u| {
                u["password_hash"] =
                    json!("$argon2id$v=19$m=1,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA");
            }),
        ];
        for users in rejected {
            let result = restore_with_users(&b, users.clone()).await;
            assert!(
                matches!(result, Err(BackendError::Invalid(_))),
                "{users} was accepted"
            );
            // nothing was applied
            assert_eq!(b.users().await.unwrap().len(), 1);
            assert!(
                b.verify_password("admin", "correct horse battery")
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let accepted = restore_with_users(&b, json!([admin])).await;
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn set_password_changes_only_the_hash() {
        let b = MockBackend::with_user("bob", Role::Viewer, "correct horse battery");
        let new_hash = password::hash_password("another horse staple").unwrap();
        b.set_password("bob", new_hash).await.unwrap();
        let user = b
            .verify_password("bob", "another horse staple")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((user.role, user.enabled), (Role::Viewer, true));
        assert!(matches!(
            b.set_password("nobody", "x".into()).await,
            Err(BackendError::NotFound)
        ));
    }

    #[tokio::test]
    async fn placeholders_are_matched_by_identity_not_position() {
        let b = MockBackend::new();
        let mut cfg = b.config().await.unwrap();
        // reorder: positional matching would hand radio0's passphrase to the 5 GHz AP
        cfg["wireless"]["aps"].as_array_mut().unwrap().reverse();
        b.save_config(cfg, "admin").await.unwrap();
        let stored = b.lock().config.clone();
        let aps = stored["wireless"]["aps"].as_array().unwrap();
        let pass = |radio: &str| {
            aps.iter()
                .find(|a| a["radio"] == radio)
                .map(|a| a["security"]["passphrase"].clone())
        };
        assert_eq!(pass("radio0"), Some(json!("correct-horse-battery")));
        assert_eq!(pass("radio1"), Some(json!("staple-correct-horse")));

        // a renamed AP has no stored identity to inherit a secret from
        let mut cfg = b.config().await.unwrap();
        cfg["wireless"]["aps"][0]["ssid"] = json!("renamed");
        let errs = b.validate_config(cfg).await.unwrap_err();
        assert!(errs.errors.iter().any(|e| e.path.ends_with("passphrase")));
    }

    #[tokio::test]
    async fn verify_password_paths() {
        let b = MockBackend::with_user("admin", Role::Admin, "correct horse battery");
        assert!(
            b.verify_password("admin", "correct horse battery")
                .await
                .unwrap()
                .is_some()
        );
        assert!(b.verify_password("admin", "wrong").await.unwrap().is_none());
        assert!(
            b.verify_password("nobody", "whatever")
                .await
                .unwrap()
                .is_none()
        );
    }
}
