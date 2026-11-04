//! The production [`SystemBackend`] (Linux only): the glue between the HTTP layer and the
//! rest of the system.
//!
//! | API call | source of truth |
//! |---|---|
//! | `board`, `status` | board descriptor loaded at start, `/proc`, `/sys/class/thermal` |
//! | `config`, `users`, `backup` | `config.toml` via `owr_config::Store` (secrets redacted on the way out) |
//! | `save_config`, `restore` | validate, `Store::save_for`, [`Applier`] (`owr_apply::run::apply_all`), then init restarts the daemons whose files changed |
//! | `network_status` | rtnetlink dump (`owr_net::linux::observe`) + the persisted DHCP lease |
//! | `wireless_status` | the hostapd control sockets |
//! | `dhcp_leases` | the dnsmasq lease file |
//! | `logs`, `services`, `service_action`, `reboot`, `upgrade` | init's control socket (`owr_init::client`) |
//! | `upgrade_check` | `owr_upgrade::bundle::verify` against the release key, the board and this version |
//!
//! Everything that blocks (files, sockets, argon2) runs in `spawn_blocking`. Operations that
//! read-modify-write the configuration hold one async mutex, so concurrent saves, restores
//! and user edits cannot lose each other's changes.

use std::collections::HashMap;
use std::io::{self, Read as _};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use owr_apply::run::{ApplyError, ApplyOutcome, Paths};
use owr_board::{Board, BoardError};
use owr_common::{Outcome, paths};
use owr_config::{Config, ConfigError, Role as CfgRole, Secret, Store, User};
use owr_init::client::{ClientError, InitClient};
use owr_init::control::UpgradeRequest;
use owr_net::Observed;
use owr_upgrade::bundle::{self, Expect};
use owr_upgrade::release::parse_pubkey;
use owr_wifi::sys::ctrl::HostapdCtl;
use serde_json::Value;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::backend::{BackendResult, BoxFuture, SystemBackend};
use crate::document::{check, issues_to_errors, parse_doc};
use crate::dto::{
    ApplyReport, BackendError, BoardId, Firmware, Lease, LogEntry, NetworkStatus, Role,
    ServiceAction, ServiceStatus, SystemStatus, UpgradeInfo, UserInfo, ValidationErrors,
    WirelessStatus,
};
use crate::password;
use crate::procfs::{
    ThermalZone, choose_cpu_temp, parse_leases, parse_loadavg, parse_meminfo, parse_temp_mc,
    parse_uptime,
};
use crate::secrets::{find_placeholders, unredact};
use crate::upgrade::running_version;
use crate::view::{self, ApProbe};

/// Largest file read into memory (config backup, lease file, `/proc` files).
const MAX_FILE_BYTES: usize = 1024 * 1024;
const THERMAL_ROOT: &str = "/sys/class/thermal";
const MAX_THERMAL_ZONES: usize = 64;

/// Where the backend reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealConfig {
    /// Installed board descriptor, loaded once at start.
    pub board_path: PathBuf,
    /// `config.toml`.
    pub config_path: PathBuf,
    /// Rendered daemon configs, the persisted DHCP lease and the hostapd client sockets.
    pub run_dir: PathBuf,
    /// init's control socket.
    pub init_sock: PathBuf,
    /// The `nft` binary used to load the firewall.
    pub nft_bin: PathBuf,
    /// dnsmasq's lease file.
    pub leases_file: PathBuf,
    /// Directory with one hostapd control socket per BSS.
    pub hostapd_ctrl_dir: PathBuf,
    /// The release public key firmware upgrades are verified against.
    pub release_key: PathBuf,
}

impl Default for RealConfig {
    fn default() -> Self {
        let run_dir = PathBuf::from(paths::RUN_DIR);
        Self {
            board_path: PathBuf::from(paths::BOARD_FILE),
            config_path: PathBuf::from(paths::CONFIG_FILE),
            init_sock: run_dir.join("init.sock"),
            nft_bin: Paths::default().nft_bin,
            leases_file: run_dir.join("dhcp.leases"),
            hostapd_ctrl_dir: owr_wifi::ctrl_dir(),
            release_key: PathBuf::from(paths::RELEASE_KEY_FILE),
            run_dir,
        }
    }
}

impl RealConfig {
    /// The defaults with every run-time path below `run_dir` (hostapd's control directory
    /// is `<run_dir>/hostapd`, as rendered by owr-wifi).
    pub fn with_run_dir(run_dir: impl Into<PathBuf>) -> Self {
        let run_dir = run_dir.into();
        Self {
            init_sock: run_dir.join("init.sock"),
            leases_file: run_dir.join("dhcp.leases"),
            hostapd_ctrl_dir: run_dir.join("hostapd"),
            run_dir,
            ..Self::default()
        }
    }
}

/// Applies a validated, persisted configuration to the running system.
/// [`SystemApplier`] is the production one; tests plug in a recording no-op.
pub trait Applier: std::fmt::Debug + Send + Sync + 'static {
    fn apply<'a>(
        &'a self,
        board: &'a Board,
        cfg: &'a Config,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ApplyError>>;
}

/// Drives netlink, nft and the daemon configs through `owr_apply::run::apply_all`.
#[derive(Debug, Clone)]
pub struct SystemApplier {
    paths: Paths,
}

impl SystemApplier {
    pub fn new(cfg: &RealConfig) -> Self {
        Self {
            paths: Paths {
                run_dir: cfg.run_dir.clone(),
                nft_bin: cfg.nft_bin.clone(),
                ..Paths::default()
            },
        }
    }
}

impl Applier for SystemApplier {
    fn apply<'a>(
        &'a self,
        board: &'a Board,
        cfg: &'a Config,
    ) -> BoxFuture<'a, Result<ApplyOutcome, ApplyError>> {
        Box::pin(owr_apply::run::apply_all(board, cfg, &self.paths))
    }
}

/// What the binary needs to know before it can listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupInfo {
    /// The router's own LAN address (`network.lan.ipv4`).
    pub lan_ipv4: Ipv4Addr,
    pub hostname: String,
    pub api_port: u16,
    pub session_ttl: Duration,
}

/// The production backend; see the module docs.
#[derive(Debug)]
pub struct RealBackend {
    cfg: RealConfig,
    board: Arc<Board>,
    store: Store,
    applier: Arc<dyn Applier>,
    /// Serializes every read-modify-write of the configuration and every apply.
    write_lock: tokio::sync::Mutex<()>,
}

// ------------------------------------------------------------------ helpers

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

async fn blocking<T, F>(f: F) -> BackendResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> BackendResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| BackendError::Internal(format!("background task failed: {e}")))?
}

/// Read `path` fully, refusing files larger than `cap` bytes.
fn read_capped(path: &Path, cap: usize) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {cap} bytes", path.display()),
        ));
    }
    Ok(buf)
}

fn read_text(path: &Path) -> io::Result<String> {
    String::from_utf8(read_capped(path, MAX_FILE_BYTES)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// A `/proc` file, parsed; unreadable or unparsable is an internal error.
fn proc_value<T>(path: &str, parse: impl FnOnce(&str) -> Option<T>) -> BackendResult<T> {
    let text = read_text(Path::new(path))
        .map_err(|e| BackendError::Internal(format!("reading {path}: {e}")))?;
    parse(&text).ok_or_else(|| BackendError::Internal(format!("cannot parse {path}")))
}

fn cpu_temp_mc(root: &Path) -> Option<i32> {
    let mut zones: Vec<(u32, ThermalZone)> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            let index: u32 = name.strip_prefix("thermal_zone")?.parse().ok()?;
            let dir = entry.path();
            let kind = read_text(&dir.join("type")).unwrap_or_default();
            let temp_mc = read_text(&dir.join("temp"))
                .ok()
                .and_then(|t| parse_temp_mc(&t));
            Some((
                index,
                ThermalZone {
                    kind: kind.trim().to_owned(),
                    temp_mc,
                },
            ))
        })
        .take(MAX_THERMAL_ZONES)
        .collect();
    zones.sort_by_key(|(index, _)| *index);
    let zones: Vec<ThermalZone> = zones.into_iter().map(|(_, z)| z).collect();
    choose_cpu_temp(&zones)
}

fn system_status(board: &Board) -> BackendResult<SystemStatus> {
    Ok(SystemStatus {
        hostname: proc_value("/proc/sys/kernel/hostname", |t| Some(t.trim().to_owned()))?,
        uptime_secs: proc_value("/proc/uptime", parse_uptime)?.as_secs(),
        load: proc_value("/proc/loadavg", parse_loadavg)?,
        mem: proc_value("/proc/meminfo", parse_meminfo)?,
        cpu_temp_mc: cpu_temp_mc(Path::new(THERMAL_ROOT)),
        board: BoardId {
            id: board.board.id.clone(),
            vendor: board.board.vendor.clone(),
            model: board.board.model.clone(),
        },
        firmware: Firmware {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build: option_env!("OWR_BUILD").unwrap_or("dev").to_owned(),
        },
        time_unix: unix_ms() / 1000,
    })
}

/// The lease file; a missing file (dnsmasq has not handed out a lease yet) is no leases.
fn read_leases(path: &Path) -> io::Result<Vec<Lease>> {
    match read_capped(path, MAX_FILE_BYTES) {
        Ok(bytes) => Ok(parse_leases(&String::from_utf8_lossy(&bytes))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn load_error(e: &ConfigError) -> BackendError {
    error!(error = %e, "the stored configuration cannot be used");
    BackendError::Unavailable(format!("stored configuration unusable: {e}"))
}

fn save_error(e: ConfigError) -> BackendError {
    match e {
        ConfigError::Invalid(issues) => BackendError::Invalid(issues_to_errors(issues)),
        other => {
            error!(error = %other, "saving the configuration failed");
            BackendError::Internal(format!("saving the configuration failed: {other}"))
        }
    }
}

fn init_error(e: &ClientError) -> BackendError {
    match e {
        ClientError::BadName | ClientError::UnknownService => BackendError::NotFound,
        ClientError::Io(_) | ClientError::Refused(_) => BackendError::Unavailable(e.to_string()),
        // The API chooses the upgrade directory itself; a bad one is a bug here.
        ClientError::TooLarge | ClientError::Malformed(_) | ClientError::BadUpgradeDir => {
            BackendError::Internal(e.to_string())
        }
    }
}

/// init refusing an upgrade (bad bundle, failsafe, already upgrading) is the user's to see.
fn upgrade_error(e: ClientError) -> BackendError {
    match e {
        ClientError::Refused(reason) => BackendError::Refused(reason),
        other => init_error(&other),
    }
}

/// Verify the bundle in `dir` against the release key at `key_path`, `board` and this
/// version (blocking: hashes the whole image).
fn check_bundle(
    dir: &Path,
    key_path: &Path,
    board: &Board,
    allow_downgrade: bool,
) -> BackendResult<UpgradeInfo> {
    let key = read_text(key_path)
        .map_err(|e| e.to_string())
        .and_then(|text| parse_pubkey(&text).ok_or_else(|| "not a public key".to_owned()))
        .map_err(|e| {
            error!(path = %key_path.display(), error = %e, "release key unusable");
            BackendError::Internal(format!("release key {}: {e}", key_path.display()))
        })?;
    let running = running_version()
        .ok_or_else(|| BackendError::Internal("the running version does not parse".into()))?;
    let expect = Expect {
        board_id: &board.board.id,
        profile: &board.openwrt.profile,
        current: &running,
    };
    let verified = bundle::verify(dir, &key, &expect, allow_downgrade)
        .map_err(|e| BackendError::Refused(e.to_string()))?;
    Ok(UpgradeInfo {
        image: verified.image_name,
        downgrade: verified.version < running,
        version: verified.version.to_string(),
        board: board.board.id.clone(),
        running: running.to_string(),
    })
}

const fn role_out(role: CfgRole) -> Role {
    match role {
        CfgRole::Admin => Role::Admin,
        CfgRole::Viewer => Role::Viewer,
    }
}

const fn role_in(role: Role) -> CfgRole {
    match role {
        Role::Admin => CfgRole::Admin,
        Role::Viewer => CfgRole::Viewer,
    }
}

fn user_info(user: &User) -> UserInfo {
    UserInfo {
        name: user.name.clone(),
        role: role_out(user.role),
        enabled: user.enabled,
    }
}

/// The backend refuses any change that would leave the router without an enabled admin.
fn require_admin(cfg: &Config) -> BackendResult<()> {
    if cfg
        .users
        .iter()
        .any(|u| u.enabled && u.role == CfgRole::Admin)
    {
        Ok(())
    } else {
        Err(BackendError::Invalid(ValidationErrors::single(
            "users",
            "at least one enabled administrator is required",
        )))
    }
}

/// One line per thing [`apply_all`](owr_apply::run::apply_all) changed.
fn summarize(config_label: Option<&str>, outcome: &ApplyOutcome) -> Vec<String> {
    let mut summary: Vec<String> = config_label.map(str::to_owned).into_iter().collect();
    if outcome.net_actions > 0 {
        summary.push(format!(
            "network: {} change(s) applied",
            outcome.net_actions
        ));
    }
    if outcome.fw_changed {
        summary.push("firewall ruleset reloaded".to_owned());
    }
    for (phy, changed) in &outcome.hostapd_changed {
        if *changed {
            summary.push(format!("wireless {phy}: configuration updated"));
        }
    }
    if outcome.dnsmasq_changed {
        summary.push("dnsmasq configuration updated".to_owned());
    }
    if outcome.odhcpd_changed {
        summary.push("odhcpd configuration updated".to_owned());
    }
    summary
}

/// init's service names for the daemons whose files changed (`hostapd-<phy>` per radio, as
/// in `owr_init::services`).
fn daemons_to_restart(outcome: &ApplyOutcome) -> Vec<String> {
    let mut names: Vec<String> = outcome
        .hostapd_changed
        .iter()
        .filter(|(_, changed)| *changed)
        .map(|(phy, _)| format!("hostapd-{phy}"))
        .collect();
    if outcome.dnsmasq_changed {
        names.push("dnsmasq".to_owned());
    }
    if outcome.odhcpd_changed {
        names.push("odhcpd".to_owned());
    }
    names
}

/// Ask init to restart `names`; problems become warnings, never failures (the files are
/// written, a reboot picks them up).
fn restart_all(init_sock: &Path, names: &[String]) -> Vec<String> {
    let client = match InitClient::connect(init_sock) {
        Ok(client) => client,
        Err(e) => {
            warn!(error = %e, "init control socket unavailable");
            return vec![format!(
                "could not restart {}: init control socket unavailable ({e}); reboot to apply",
                names.join(", ")
            )];
        }
    };
    names
        .iter()
        .filter_map(|name| match client.restart(name) {
            Ok(()) => {
                info!(service = %name, "restarted after configuration change");
                None
            }
            Err(ClientError::UnknownService) => Some(format!(
                "{name} is not supervised by init; reboot to start it"
            )),
            Err(e) => {
                warn!(service = %name, error = %e, "restart failed");
                Some(format!("restarting {name} failed: {e}"))
            }
        })
        .collect()
}

fn probe_aps(ctrl_dir: &Path, ifnames: Vec<String>) -> HashMap<String, ApProbe> {
    ifnames
        .into_iter()
        .filter_map(|ifname| {
            let ctl = HostapdCtl::connect(ctrl_dir, &ifname)
                .inspect_err(|e| debug!(%ifname, error = %e, "hostapd not reachable"))
                .ok()?;
            let status = ctl
                .status()
                .inspect_err(|e| debug!(%ifname, error = %e, "hostapd STATUS failed"))
                .ok();
            let stations = if status.is_some() {
                ctl.stations().unwrap_or_else(|e| {
                    warn!(%ifname, error = %e, "listing stations failed");
                    Vec::new()
                })
            } else {
                Vec::new()
            };
            Some((ifname, ApProbe { status, stations }))
        })
        .collect()
}

/// A fresh rtnetlink connection for one dump (same pattern as `owr-apply`).
async fn observe_network() -> BackendResult<Observed> {
    let (conn, handle, _) = rtnetlink::new_connection()
        .map_err(|e| BackendError::Unavailable(format!("opening netlink: {e}")))?;
    let task = tokio::spawn(conn);
    let result = owr_net::linux::observe(&handle).await;
    drop(handle);
    task.abort();
    result.map_err(|e| BackendError::Unavailable(format!("observing the network: {e}")))
}

// ---------------------------------------------------------------- the backend

impl RealBackend {
    /// Load the board descriptor and use the production applier.
    pub fn new(cfg: RealConfig) -> Result<Self, BoardError> {
        let board = Board::load(&cfg.board_path)?;
        let applier = Arc::new(SystemApplier::new(&cfg));
        Ok(Self::with_applier(cfg, board, applier))
    }

    /// Like [`new`](Self::new) with an explicit board and applier (tests).
    pub fn with_applier(cfg: RealConfig, board: Board, applier: Arc<dyn Applier>) -> Self {
        Self {
            store: Store::new(&cfg.config_path),
            board: Arc::new(board),
            applier,
            cfg,
            write_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Load the configuration for the listener settings, writing the board defaults first
    /// when there is none (first boot, as `owr-apply boot` does; the API does not wait for it).
    pub fn startup(&self) -> Result<StartupInfo, ConfigError> {
        let (cfg, created) = self.store.load_or_default(&self.board)?;
        if created {
            info!(path = %self.store.path().display(), "first boot: wrote the default configuration");
        }
        Ok(StartupInfo {
            lan_ipv4: cfg.network.lan.ipv4.addr(),
            hostname: cfg.system.hostname,
            api_port: cfg.services.api.port,
            session_ttl: cfg.services.api.session_ttl,
        })
    }

    async fn load(&self) -> BackendResult<Config> {
        let (store, board) = (self.store.clone(), Arc::clone(&self.board));
        blocking(move || store.load_for(&board).map_err(|e| load_error(&e))).await
    }

    /// Unredact `doc` against `stored`, parse it and run every check that `save_config` would
    /// fail on later: schema, board, mapping to plans, leftover placeholders.
    fn prepare(&self, mut doc: Value, stored: Option<&Config>) -> Result<Config, ValidationErrors> {
        if let Some(old) = stored.and_then(|c| serde_json::to_value(c).ok()) {
            unredact(&mut doc, &old);
        }
        let mut errs = ValidationErrors::default();
        let parsed = parse_doc(&doc);
        if let Ok(cfg) = &parsed {
            match check(cfg, &self.board) {
                Err(e) => errs.errors.extend(e.errors),
                Ok(()) => {
                    if let Err(e) = owr_apply::build_plans(&self.board, cfg) {
                        errs.push("", format!("cannot be applied: {e}"));
                    }
                }
            }
        }
        find_placeholders(&doc, "", &mut errs);
        match parsed {
            Ok(cfg) if errs.is_empty() => Ok(cfg),
            Ok(_) => Err(errs),
            Err(e) => {
                errs.errors.splice(0..0, e.errors);
                Err(errs)
            }
        }
    }

    /// A backup must be a complete, applicable configuration that keeps the router manageable.
    fn parse_backup(&self, bytes: &[u8]) -> Result<Config, ValidationErrors> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(ValidationErrors::single("", "backup is larger than 1 MiB"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ValidationErrors::single("", "backup is not valid UTF-8 text"))?;
        let cfg = Config::from_toml_str(text).map_err(|e| match e {
            ConfigError::Invalid(issues) => issues_to_errors(issues),
            other => ValidationErrors::single("", other.to_string()),
        })?;
        check(&cfg, &self.board)?;
        let mut errs = ValidationErrors::default();
        if require_admin(&cfg).is_err() {
            errs.push(
                "users",
                "backup must contain at least one enabled administrator",
            );
        }
        if let Ok(doc) = serde_json::to_value(&cfg) {
            find_placeholders(&doc, "", &mut errs);
        }
        if let Err(e) = owr_apply::build_plans(&self.board, &cfg) {
            errs.push("", format!("cannot be applied: {e}"));
        }
        errs.into_result().map(|()| cfg)
    }

    /// Persist `cfg`, apply it and restart the daemons whose files changed. The write lock
    /// must be held. A failed apply is an internal error; the configuration stays saved and
    /// the next boot applies it.
    async fn persist_and_apply(
        &self,
        cfg: Config,
        mut warnings: Vec<String>,
        label: &str,
    ) -> BackendResult<ApplyReport> {
        let (store, board) = (self.store.clone(), Arc::clone(&self.board));
        let saved = {
            let cfg = cfg.clone();
            blocking(move || store.save_for(&cfg, &board).map_err(save_error)).await?
        };
        let applied = self.applier.apply(&self.board, &cfg).await;
        let (outcome, failure) = match applied {
            Ok(outcome) => (Some(outcome), None),
            Err(e) => (e.partial_outcome().cloned(), Some(e)),
        };
        let label = (saved == Outcome::Written).then_some(label);
        let summary = summarize(label, &outcome.clone().unwrap_or_default());
        if let Some(outcome) = &outcome {
            warnings.extend(outcome.warnings.iter().cloned());
            let names = daemons_to_restart(outcome);
            if !names.is_empty() {
                let sock = self.cfg.init_sock.clone();
                let restart = blocking(move || Ok(restart_all(&sock, &names))).await?;
                warnings.extend(restart);
            }
        }
        if let Some(e) = failure {
            error!(error = %e, "applying the configuration failed");
            return Err(BackendError::Internal(format!(
                "applying the saved configuration failed (changed before the failure: {})",
                if summary.is_empty() {
                    "nothing".to_owned()
                } else {
                    summary.join("; ")
                }
            )));
        }
        Ok(ApplyReport {
            changed: !summary.is_empty(),
            summary,
            warnings,
        })
    }

    /// Read-modify-write the users under the write lock; refuses to leave no admin.
    async fn edit_config<F>(&self, edit: F) -> BackendResult<()>
    where
        F: FnOnce(&mut Config) -> BackendResult<()> + Send + 'static,
    {
        let _guard = self.write_lock.lock().await;
        let (store, board) = (self.store.clone(), Arc::clone(&self.board));
        blocking(move || {
            let mut cfg = store.load_for(&board).map_err(|e| load_error(&e))?;
            edit(&mut cfg)?;
            require_admin(&cfg)?;
            store.save_for(&cfg, &board).map(|_| ()).map_err(save_error)
        })
        .await
    }

    async fn init<T, F>(&self, f: F) -> BackendResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&InitClient) -> Result<T, ClientError> + Send + 'static,
    {
        let sock = self.cfg.init_sock.clone();
        blocking(move || {
            let client = InitClient::connect(&sock).map_err(|e| {
                BackendError::Unavailable(format!("init control socket {}: {e}", sock.display()))
            })?;
            f(&client).map_err(|e| init_error(&e))
        })
        .await
    }
}

impl SystemBackend for RealBackend {
    fn board(&self) -> BoxFuture<'_, BackendResult<Value>> {
        Box::pin(async move {
            serde_json::to_value(&*self.board)
                .map_err(|e| BackendError::Internal(format!("board json: {e}")))
        })
    }

    fn status(&self) -> BoxFuture<'_, BackendResult<SystemStatus>> {
        Box::pin(async move {
            let board = Arc::clone(&self.board);
            blocking(move || system_status(&board)).await
        })
    }

    fn config(&self) -> BoxFuture<'_, BackendResult<Value>> {
        Box::pin(async move {
            let cfg = self.load().await?;
            serde_json::to_value(owr_config::redact(&cfg))
                .map_err(|e| BackendError::Internal(format!("config json: {e}")))
        })
    }

    fn validate_config(&self, cfg: Value) -> BoxFuture<'_, Result<(), ValidationErrors>> {
        Box::pin(async move {
            let stored = self.load().await.ok();
            self.prepare(cfg, stored.as_ref()).map(|_| ())
        })
    }

    fn save_config<'a>(
        &'a self,
        cfg: Value,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock().await;
            let stored = self.load().await?;
            let had_users = cfg.get("users").is_some();
            let mut new = self.prepare(cfg, Some(&stored))?;
            let mut warnings = Vec::new();
            if had_users && new.users != stored.users {
                warnings.push("the users section is managed via /users and was ignored".to_owned());
            }
            new.users.clone_from(&stored.users);
            info!(actor, "saving configuration");
            self.persist_and_apply(new, warnings, "configuration saved")
                .await
        })
    }

    fn network_status(&self) -> BoxFuture<'_, BackendResult<NetworkStatus>> {
        Box::pin(async move {
            let cfg = self.load().await?;
            let observed = observe_network().await?;
            let wan_dev = self
                .board
                .port(&cfg.network.wan.port)
                .map(|p| p.netdev.clone());
            let run_dir = self.cfg.run_dir.clone();
            let lease = match wan_dev.clone() {
                Some(dev) => {
                    blocking(move || {
                        Ok(owr_apply::lease::load_valid_lease(
                            &run_dir,
                            &dev,
                            SystemTime::now(),
                        ))
                    })
                    .await?
                }
                None => None,
            };
            let wan = wan_dev.and_then(|dev| {
                view::wan_status(&cfg, &dev, &observed, lease.as_ref(), SystemTime::now())
            });
            Ok(view::network_status(&self.board, &cfg, &observed, wan))
        })
    }

    fn wireless_status(&self) -> BoxFuture<'_, BackendResult<WirelessStatus>> {
        Box::pin(async move {
            let cfg = self.load().await?;
            let plans = owr_apply::build_plans(&self.board, &cfg)
                .map_err(|e| BackendError::Internal(format!("mapping the configuration: {e}")))?
                .radios;
            let ifnames: Vec<String> = plans
                .iter()
                .flat_map(|r| r.aps.iter().map(|ap| ap.ifname.clone()))
                .collect();
            let (ctrl_dir, leases_file) = (
                self.cfg.hostapd_ctrl_dir.clone(),
                self.cfg.leases_file.clone(),
            );
            let (probes, leases) = blocking(move || {
                let leases = read_leases(&leases_file).unwrap_or_else(|e| {
                    debug!(error = %e, "lease file unreadable; clients without hostnames");
                    Vec::new()
                });
                Ok((probe_aps(&ctrl_dir, ifnames), leases))
            })
            .await?;
            Ok(view::wireless_status(
                &self.board,
                &cfg,
                &plans,
                &probes,
                &leases,
            ))
        })
    }

    fn dhcp_leases(&self) -> BoxFuture<'_, BackendResult<Vec<Lease>>> {
        Box::pin(async move {
            let path = self.cfg.leases_file.clone();
            blocking(move || {
                read_leases(&path).map_err(|e| {
                    BackendError::Unavailable(format!("reading {}: {e}", path.display()))
                })
            })
            .await
        })
    }

    fn firewall_preview(&self) -> BoxFuture<'_, BackendResult<String>> {
        Box::pin(async move {
            let cfg = self.load().await?;
            let board = Arc::clone(&self.board);
            blocking(move || {
                let plans = owr_apply::build_plans(&board, &cfg).map_err(|e| {
                    BackendError::Internal(format!("mapping the configuration: {e}"))
                })?;
                owr_fw::render(&plans.fw)
                    .map_err(|e| BackendError::Internal(format!("rendering the firewall: {e}")))
            })
            .await
        })
    }

    fn logs(&self, since_seq: u64, limit: u16) -> BoxFuture<'_, BackendResult<Vec<LogEntry>>> {
        Box::pin(async move {
            self.init(move |client| {
                let entries = client.journal(since_seq, usize::from(limit))?;
                // init stamps entries relative to boot; the API speaks wall-clock time.
                let uptime_ms = read_text(Path::new("/proc/uptime"))
                    .ok()
                    .and_then(|t| parse_uptime(&t))
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                let boot_unix_ms = unix_ms().saturating_sub(uptime_ms);
                Ok(view::map_journal(entries, boot_unix_ms))
            })
            .await
        })
    }

    fn services(&self) -> BoxFuture<'_, BackendResult<Vec<ServiceStatus>>> {
        Box::pin(async move {
            self.init(|client| client.status().map(view::map_services))
                .await
        })
    }

    fn service_action<'a>(
        &'a self,
        name: &'a str,
        action: ServiceAction,
    ) -> BoxFuture<'a, BackendResult<()>> {
        Box::pin(async move {
            let name = name.to_owned();
            self.init(move |client| match action {
                ServiceAction::Restart => client.restart(&name),
                ServiceAction::Reload => client.reload(&name),
            })
            .await
        })
    }

    fn reboot(&self) -> BoxFuture<'_, BackendResult<()>> {
        Box::pin(async move { self.init(InitClient::reboot).await })
    }

    fn users(&self) -> BoxFuture<'_, BackendResult<Vec<UserInfo>>> {
        Box::pin(async move { Ok(self.load().await?.users.iter().map(user_info).collect()) })
    }

    fn set_user(
        &self,
        user: UserInfo,
        password_hash: Option<String>,
    ) -> BoxFuture<'_, BackendResult<()>> {
        Box::pin(async move {
            self.edit_config(move |cfg| {
                let hash = password_hash.map(Secret::from);
                if let Some(existing) = cfg.users.iter_mut().find(|u| u.name == user.name) {
                    existing.role = role_in(user.role);
                    existing.enabled = user.enabled;
                    if let Some(hash) = hash {
                        existing.password_hash = hash;
                    }
                } else {
                    let password_hash = hash.ok_or_else(|| {
                        BackendError::Invalid(ValidationErrors::single(
                            "password",
                            "required for a new user",
                        ))
                    })?;
                    cfg.users.push(User {
                        name: user.name,
                        role: role_in(user.role),
                        password_hash,
                        enabled: user.enabled,
                    });
                }
                Ok(())
            })
            .await
        })
    }

    fn set_password<'a>(
        &'a self,
        name: &'a str,
        password_hash: String,
    ) -> BoxFuture<'a, BackendResult<()>> {
        Box::pin(async move {
            let name = name.to_owned();
            self.edit_config(move |cfg| {
                let user = cfg
                    .users
                    .iter_mut()
                    .find(|u| u.name == name)
                    .ok_or(BackendError::NotFound)?;
                user.password_hash = Secret::from(password_hash);
                Ok(())
            })
            .await
        })
    }

    fn delete_user<'a>(&'a self, name: &'a str) -> BoxFuture<'a, BackendResult<()>> {
        Box::pin(async move {
            let name = name.to_owned();
            self.edit_config(move |cfg| {
                let before = cfg.users.len();
                cfg.users.retain(|u| u.name != name);
                if cfg.users.len() < before {
                    Ok(())
                } else {
                    Err(BackendError::NotFound)
                }
            })
            .await
        })
    }

    fn verify_password<'a>(
        &'a self,
        name: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, BackendResult<Option<UserInfo>>> {
        Box::pin(async move {
            let cfg = self.load().await?;
            let found = cfg.users.iter().find(|u| u.name == name);
            let info = found.map(user_info);
            // Unknown users are verified against a dummy hash: same work either way.
            let hash = Zeroizing::new(found.map_or_else(
                || password::dummy_hash().to_owned(),
                |u| u.password_hash.expose().to_owned(),
            ));
            drop(cfg);
            let password = Zeroizing::new(password.to_owned());
            let ok =
                tokio::task::spawn_blocking(move || password::verify_password(&password, &hash))
                    .await
                    .map_err(|e| BackendError::Internal(format!("background task failed: {e}")))?;
            Ok(info.filter(|_| ok))
        })
    }

    fn backup(&self) -> BoxFuture<'_, BackendResult<Vec<u8>>> {
        Box::pin(async move {
            let path = self.store.path().to_path_buf();
            blocking(move || {
                read_capped(&path, MAX_FILE_BYTES).map_err(|e| {
                    BackendError::Unavailable(format!("reading {}: {e}", path.display()))
                })
            })
            .await
        })
    }

    fn restore<'a>(
        &'a self,
        bytes: Vec<u8>,
        actor: &'a str,
    ) -> BoxFuture<'a, BackendResult<ApplyReport>> {
        Box::pin(async move {
            let _guard = self.write_lock.lock().await;
            let cfg = self.parse_backup(&bytes)?;
            info!(actor, "restoring configuration from backup");
            self.persist_and_apply(cfg, Vec::new(), "configuration restored from backup")
                .await
        })
    }

    fn upgrade_check<'a>(
        &'a self,
        dir: &'a Path,
        allow_downgrade: bool,
    ) -> BoxFuture<'a, BackendResult<UpgradeInfo>> {
        Box::pin(async move {
            let (dir, key, board) = (
                dir.to_path_buf(),
                self.cfg.release_key.clone(),
                Arc::clone(&self.board),
            );
            blocking(move || check_bundle(&dir, &key, &board, allow_downgrade)).await
        })
    }

    fn upgrade<'a>(
        &'a self,
        dir: &'a Path,
        allow_downgrade: bool,
        wipe_settings: bool,
    ) -> BoxFuture<'a, BackendResult<()>> {
        Box::pin(async move {
            let dir = dir.to_str().map(str::to_owned).ok_or_else(|| {
                BackendError::Internal(format!("upload directory {} is not UTF-8", dir.display()))
            })?;
            info!(%dir, allow_downgrade, wipe_settings, "handing the firmware upgrade to init");
            let req = UpgradeRequest {
                dir,
                allow_downgrade,
                wipe_settings,
            };
            // Init's verdict is kept as a value: a refusal must reach the user as such.
            self.init(move |client| Ok(client.upgrade(&req)))
                .await?
                .map_err(upgrade_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome() -> ApplyOutcome {
        ApplyOutcome {
            net_actions: 3,
            fw_changed: true,
            hostapd_changed: vec![("phy0".into(), true), ("phy1".into(), false)],
            dnsmasq_changed: true,
            odhcpd_changed: false,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn summary_has_one_line_per_change() {
        let s = summarize(Some("configuration saved"), &outcome());
        assert_eq!(
            s,
            [
                "configuration saved",
                "network: 3 change(s) applied",
                "firewall ruleset reloaded",
                "wireless phy0: configuration updated",
                "dnsmasq configuration updated",
            ]
        );
        assert_eq!(
            summarize(None, &ApplyOutcome::default()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn only_changed_daemons_are_restarted_by_their_init_names() {
        assert_eq!(daemons_to_restart(&outcome()), ["hostapd-phy0", "dnsmasq"]);
        let all = ApplyOutcome {
            odhcpd_changed: true,
            ..outcome()
        };
        assert_eq!(
            daemons_to_restart(&all),
            ["hostapd-phy0", "dnsmasq", "odhcpd"]
        );
        assert_eq!(
            daemons_to_restart(&ApplyOutcome::default()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn init_names_match_the_supervisor() {
        // `hostapd-<phy>` is how owr-init names the per-radio daemon (services.rs).
        let ctx = owr_init::services::ServiceContext {
            failsafe: false,
            apply_present: true,
            ssh_enabled: false,
            radio_phys: vec![0],
        };
        let names: Vec<String> = owr_init::services::build_services(&ctx)
            .into_iter()
            .map(|s| s.name)
            .collect();
        for wanted in daemons_to_restart(&outcome()) {
            assert!(names.contains(&wanted), "{wanted} not in {names:?}");
        }
    }

    #[test]
    fn init_errors_map_to_backend_errors() {
        assert!(matches!(
            init_error(&ClientError::UnknownService),
            BackendError::NotFound
        ));
        assert!(matches!(
            init_error(&ClientError::Refused("x".into())),
            BackendError::Unavailable(_)
        ));
        assert!(matches!(
            init_error(&ClientError::Malformed("x".into())),
            BackendError::Internal(_)
        ));
    }

    #[test]
    fn upgrade_refusals_reach_the_user() {
        assert!(matches!(
            upgrade_error(ClientError::Refused("failsafe mode".into())),
            BackendError::Refused(m) if m == "failsafe mode"
        ));
        assert!(matches!(
            upgrade_error(ClientError::BadUpgradeDir),
            BackendError::Internal(_)
        ));
    }
}
