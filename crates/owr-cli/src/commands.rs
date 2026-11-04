//! Command handlers. Each writes its normal output to `out` so tests can call it directly.

use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use owr_apply::Plans;
use owr_board::{Board, BoardError};
use owr_common::paths::BOARD_FILE;
use owr_config::{Config, ConfigError, Issue, Role, Secret, Store, User};
use zeroize::Zeroizing;

use crate::{CliError, What};

/// Board used by `config defaults` when neither `--board` nor `--board-id` is given and no
/// descriptor is installed (offline bootstrap on a workstation).
const DEFAULT_BOARD_ID: &str = "glinet_gl-mt6000";
/// Same bounds as the owr-api password policy.
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_CHARS: usize = 256;

/// Result of commands that can report problems with the *input* (as opposed to failing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    Ok,
    Issues,
}

impl Exit {
    pub(crate) fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Issues => 1,
        }
    }
}

/// The global `--board`, `--board-id` and `--config` options.
#[derive(Debug, Clone)]
pub(crate) struct Env {
    pub board: Option<PathBuf>,
    pub board_id: Option<String>,
    pub config: PathBuf,
}

impl Env {
    /// `--board` file, else the builtin `--board-id`, else the installed descriptor.
    /// `fallback_id` is used only when nothing was asked for and nothing is installed.
    fn board_or(&self, fallback_id: Option<&str>) -> Result<Board, CliError> {
        if let Some(path) = &self.board {
            return Ok(Board::load(path)?);
        }
        if let Some(id) = &self.board_id {
            return Ok(owr_board::builtin(id)?);
        }
        match (Board::load(Path::new(BOARD_FILE)), fallback_id) {
            (Err(BoardError::Io { source, .. }), Some(id))
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(owr_board::builtin(id)?)
            }
            (other, _) => Ok(other?),
        }
    }

    pub(crate) fn board(&self) -> Result<Board, CliError> {
        self.board_or(None)
    }

    fn store(&self) -> Store {
        Store::new(&self.config)
    }
}

pub(crate) fn io_error(path: &Path, source: &std::io::Error) -> CliError {
    CliError::Io(std::io::Error::new(
        source.kind(),
        format!("{}: {source}", path.display()),
    ))
}

/// Parse `path` and validate it against `board`, without touching the file.
/// `Ok(Err(issues))` means the file is readable but invalid.
fn check_file(path: &Path, board: &Board) -> Result<Result<Config, Vec<Issue>>, CliError> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| io_error(path, &e))?);
    match Config::from_toml_str(&text) {
        Ok(cfg) => Ok(cfg.validate_against(board).map(|()| cfg)),
        Err(ConfigError::Invalid(issues)) => Ok(Err(issues)),
        Err(other) => Err(other.into()),
    }
}

fn print_issues(out: &mut dyn Write, issues: &[Issue]) -> Result<(), CliError> {
    for issue in issues {
        writeln!(out, "{issue}")?;
    }
    Ok(())
}

pub(crate) fn config_validate(
    out: &mut dyn Write,
    env: &Env,
    file: Option<&Path>,
) -> Result<Exit, CliError> {
    let board = env.board()?;
    let path = file.unwrap_or(&env.config);
    match check_file(path, &board)? {
        Ok(_) => {
            writeln!(out, "{}: valid for {}", path.display(), board.board.id)?;
            Ok(Exit::Ok)
        }
        Err(issues) => {
            print_issues(out, &issues)?;
            Ok(Exit::Issues)
        }
    }
}

pub(crate) fn config_defaults(out: &mut dyn Write, env: &Env) -> Result<(), CliError> {
    let board = env.board_or(Some(DEFAULT_BOARD_ID))?;
    write!(out, "{}", Config::defaults_for(&board).to_toml_string()?)?;
    Ok(())
}

pub(crate) fn config_show(out: &mut dyn Write, env: &Env, json: bool) -> Result<(), CliError> {
    let board = env.board()?;
    let cfg = owr_config::redact(&env.store().load_for(&board)?);
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&cfg)?)?;
    } else {
        write!(out, "{}", cfg.to_toml_string()?)?;
    }
    Ok(())
}

pub(crate) fn config_init(out: &mut dyn Write, env: &Env) -> Result<(), CliError> {
    let board = env.board()?;
    let (_, created) = env.store().load_or_default(&board)?;
    writeln!(out, "{}", if created { "created" } else { "exists" })?;
    Ok(())
}

/// Argon2id with m = 19456 KiB, t = 2, p = 1, as owr-api hashes.
fn hash_password(password: &str) -> Result<String, CliError> {
    let params = Params::new(19_456, 2, 1, None)
        .map_err(|e| CliError::Usage(format!("argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CliError::Usage(format!("hashing password: {e}")))
}

pub(crate) fn config_set_password(
    out: &mut dyn Write,
    env: &Env,
    input: &mut dyn BufRead,
    user: &str,
) -> Result<(), CliError> {
    let board = env.board()?;
    let mut line = Zeroizing::new(String::new());
    input.read_line(&mut line)?;
    let password = line.trim_end_matches(['\n', '\r']);
    let len = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&len) {
        return Err(CliError::Usage(format!(
            "password must be {MIN_PASSWORD_CHARS}..={MAX_PASSWORD_CHARS} characters"
        )));
    }
    let hash = Secret::from(hash_password(password)?);

    let store = env.store();
    let (mut cfg, _) = store.load_or_default(&board)?;
    let result = if let Some(existing) = cfg.users.iter_mut().find(|u| u.name == user) {
        existing.password_hash = hash;
        "updated"
    } else {
        cfg.users.push(User {
            name: user.to_owned(),
            role: Role::Admin,
            password_hash: hash,
            enabled: true,
        });
        "created"
    };
    store.save_for(&cfg, &board)?;
    writeln!(out, "user {user}: {result}")?;
    Ok(())
}

/// Board, config and plans. A missing config file falls back to the board defaults, like
/// `owr-apply render`; an invalid one is an error.
fn load_plans(env: &Env) -> Result<Plans, CliError> {
    let board = env.board()?;
    let cfg = match env.store().load_for(&board) {
        Err(ConfigError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Config::defaults_for(&board)
        }
        other => other?,
    };
    Ok(owr_apply::build_plans(&board, &cfg)?)
}

/// Replace the values of `wpa_passphrase=` and `sae_password=` lines with `***`.
fn mask_secrets(conf: &str) -> String {
    conf.lines().fold(String::new(), |mut acc, line| {
        match line.split_once('=') {
            Some((key @ ("wpa_passphrase" | "sae_password"), _)) => {
                let _ = writeln!(acc, "{key}={}", Secret::REDACTED);
            }
            _ => {
                let _ = writeln!(acc, "{line}");
            }
        }
        acc
    })
}

pub(crate) fn render(
    out: &mut dyn Write,
    env: &Env,
    what: What,
    json: bool,
    reveal_secrets: bool,
) -> Result<(), CliError> {
    let plans = load_plans(env)?;
    let text_only = |name: &str| {
        Err(CliError::Usage(format!(
            "--json is not supported for {name}"
        )))
    };
    match what {
        What::Net => writeln!(out, "{}", serde_json::to_string_pretty(&plans.net)?)?,
        What::Sysctl => writeln!(out, "{}", serde_json::to_string_pretty(&plans.sysctl)?)?,
        What::Fw if json => return text_only("fw"),
        What::Fw => write!(out, "{}", owr_fw::render(&plans.fw)?)?,
        What::Dnsmasq if json => return text_only("dnsmasq"),
        What::Dnsmasq => write!(out, "{}", plans.dnsmasq_conf)?,
        What::Netd => writeln!(out, "{}", serde_json::to_string_pretty(&plans.netd)?)?,
        What::Wifi if json => {
            let radios = if reveal_secrets {
                plans.radios
            } else {
                owr_apply::redact_radios(&plans.radios)
            };
            writeln!(out, "{}", serde_json::to_string_pretty(&radios)?)?;
        }
        What::Wifi => {
            for radio in &plans.radios {
                let conf = Zeroizing::new(owr_wifi::render_hostapd(radio)?);
                writeln!(out, "# --- {} ---", radio.phy)?;
                if reveal_secrets {
                    write!(out, "{}", conf.as_str())?;
                } else {
                    write!(out, "{}", mask_secrets(&conf))?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn check(out: &mut dyn Write, env: &Env) -> Result<Exit, CliError> {
    let board = env.board()?;
    let cfg = match check_file(&env.config, &board)? {
        Ok(cfg) => cfg,
        Err(issues) => {
            print_issues(out, &issues)?;
            writeln!(out, "FAIL: {} configuration issue(s)", issues.len())?;
            return Ok(Exit::Issues);
        }
    };
    let plans = match owr_apply::build_plans(&board, &cfg) {
        Ok(plans) => plans,
        Err(err) => {
            writeln!(out, "plans: {err}")?;
            writeln!(out, "FAIL: configuration cannot be mapped to plans")?;
            return Ok(Exit::Issues);
        }
    };
    let zones = plans
        .fw
        .zones
        .iter()
        .map(|z| String::from(z.name.clone()))
        .collect::<Vec<_>>()
        .join(", ");
    let enabled = cfg.wireless.radios.iter().filter(|r| r.enabled).count();
    let rows = [
        (
            "board",
            format!(
                "{} ({} {})",
                board.board.id, board.board.vendor, board.board.model
            ),
        ),
        (
            "ports",
            format!(
                "{} ({} wan, {} lan)",
                board.ethernet.ports.len(),
                board.wan_ports().count(),
                board.lan_ports().count()
            ),
        ),
        (
            "radios",
            format!("{enabled} enabled of {}", board.wifi.radios.len()),
        ),
        ("zones", format!("{} ({zones})", plans.fw.zones.len())),
        (
            "aps",
            plans
                .radios
                .iter()
                .map(|r| r.aps.len())
                .sum::<usize>()
                .to_string(),
        ),
    ];
    for (key, value) in rows {
        writeln!(out, "{key:<8}{value}")?;
    }
    writeln!(out, "ok")?;
    Ok(Exit::Ok)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const PASS: &str = "correct horse battery";
    const AP: &str = "\n[[wireless.aps]]\nradio = \"radio0\"\nssid = \"home\"\n\
        security = { type = \"wpa2_psk\", passphrase = \"wifi-secret-1\" }\n";

    fn env(dir: &Path) -> Env {
        Env {
            board: None,
            board_id: Some(DEFAULT_BOARD_ID.to_owned()),
            config: dir.join("config.toml"),
        }
    }

    fn run_ok(f: impl FnOnce(&mut dyn Write) -> Result<(), CliError>) -> String {
        let mut out = Vec::new();
        f(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn exit_of(f: impl FnOnce(&mut dyn Write) -> Result<Exit, CliError>) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = f(&mut out).unwrap();
        (exit, String::from_utf8(out).unwrap())
    }

    fn set_password(env: &Env, input: &str, user: &str) -> Result<String, CliError> {
        let mut out = Vec::new();
        config_set_password(&mut out, env, &mut Cursor::new(input.to_owned()), user)?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// A tempdir whose `config.toml` holds the defaults plus `extra` TOML.
    fn with_config(extra: &str) -> (tempfile::TempDir, Env) {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        let text = run_ok(|out| config_defaults(out, &env)) + extra;
        fs::write(&env.config, text).unwrap();
        (dir, env)
    }

    fn builtin_board() -> Board {
        owr_board::builtin(DEFAULT_BOARD_ID).unwrap()
    }

    #[test]
    fn defaults_parse_back_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let text = run_ok(|out| config_defaults(out, &env(dir.path())));
        let cfg = Config::from_toml_str(&text).unwrap();
        cfg.validate_against(&builtin_board()).unwrap();
    }

    #[test]
    fn unknown_board_id_is_an_error() {
        let mut env = env(Path::new("."));
        env.board_id = Some("nope".to_owned());
        let err = config_defaults(&mut Vec::new(), &env).unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
    }

    #[test]
    fn validate_accepts_defaults() {
        let (_dir, env) = with_config("");
        let (exit, out) = exit_of(|o| config_validate(o, &env, None));
        assert_eq!(exit, Exit::Ok);
        assert!(out.contains("valid"), "{out}");
    }

    #[test]
    fn validate_reports_unknown_port_with_path() {
        let (dir, env) = with_config("");
        let text = fs::read_to_string(&env.config).unwrap();
        let other = dir.path().join("other.toml");
        fs::write(&other, text.replace("port = \"wan\"", "port = \"eth9\"")).unwrap();
        let (exit, out) = exit_of(|o| config_validate(o, &env, Some(&other)));
        assert_eq!(exit, Exit::Issues);
        assert!(
            out.lines()
                .any(|l| l.starts_with("network.wan.port: ") && l.contains("eth9")),
            "{out}"
        );
    }

    #[test]
    fn validate_missing_file_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = config_validate(&mut Vec::new(), &env(dir.path()), None).unwrap_err();
        assert!(err.to_string().contains("config.toml"), "{err}");
    }

    #[test]
    fn show_redacts_secrets_in_toml_and_json() {
        let (_dir, env) = with_config(AP);
        for json in [false, true] {
            let out = run_ok(|o| config_show(o, &env, json));
            assert!(out.contains("***"), "{out}");
            assert!(!out.contains("wifi-secret-1"), "{out}");
        }
    }

    #[test]
    fn init_creates_then_reports_exists() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        assert_eq!(run_ok(|o| config_init(o, &env)), "created\n");
        assert!(env.config.exists());
        assert_eq!(run_ok(|o| config_init(o, &env)), "exists\n");
    }

    #[test]
    fn set_password_creates_admin_with_argon2id_hash() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        assert_eq!(
            set_password(&env, &format!("{PASS}\n"), "root").unwrap(),
            "user root: created\n"
        );
        let cfg = env.store().load_for(&builtin_board()).unwrap();
        let user = cfg.users.iter().find(|u| u.name == "root").unwrap();
        assert_eq!(user.role, Role::Admin);
        let hash = user.password_hash.expose();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert!(!hash.contains(PASS));
        let (exit, _) = exit_of(|o| config_validate(o, &env, None));
        assert_eq!(exit, Exit::Ok);
    }

    #[test]
    fn set_password_updates_existing_user() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        for expected in ["created", "updated"] {
            let out = set_password(&env, &format!("{PASS}\r\n"), "root").unwrap();
            assert_eq!(out, format!("user root: {expected}\n"));
        }
        let cfg = env.store().load_for(&builtin_board()).unwrap();
        assert_eq!(cfg.users.len(), 1);
    }

    #[test]
    fn set_password_rejects_short_and_empty_input_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        for input in ["short\n", ""] {
            let err = set_password(&env, input, "root").unwrap_err();
            assert!(matches!(err, CliError::Usage(_)), "{err}");
        }
        assert!(!env.config.exists());
    }

    #[test]
    fn render_fw_is_an_nft_script() {
        let (_dir, env) = with_config("");
        let out = run_ok(|o| render(o, &env, What::Fw, false, false));
        assert!(out.starts_with("#!/usr/sbin/nft -f"), "{out}");
        assert!(out.contains("table inet owr"), "{out}");
    }

    #[test]
    fn render_without_config_file_uses_board_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_ok(|o| render(o, &env(dir.path()), What::Dnsmasq, false, false));
        assert!(out.contains("domain=lan"), "{out}");
    }

    #[test]
    fn render_wifi_masks_passphrases_unless_revealed() {
        let (_dir, env) = with_config(AP);
        let masked = run_ok(|o| render(o, &env, What::Wifi, false, false));
        assert!(masked.starts_with("# --- phy"), "{masked}");
        assert!(masked.contains("wpa_passphrase=***\n"), "{masked}");
        assert!(!masked.contains("wifi-secret-1"), "{masked}");
        let json = run_ok(|o| render(o, &env, What::Wifi, true, false));
        assert!(
            json.contains("***") && !json.contains("wifi-secret-1"),
            "{json}"
        );
        let revealed = run_ok(|o| render(o, &env, What::Wifi, false, true));
        assert!(
            revealed.contains("wpa_passphrase=wifi-secret-1\n"),
            "{revealed}"
        );
    }

    #[test]
    fn render_net_and_sysctl_are_json() {
        let (_dir, env) = with_config("");
        for what in [What::Net, What::Sysctl] {
            let out = run_ok(|o| render(o, &env, what, true, false));
            serde_json::from_str::<serde_json::Value>(&out).unwrap();
        }
    }

    #[test]
    fn render_json_for_text_plans_is_a_usage_error() {
        let (_dir, env) = with_config("");
        let err = render(&mut Vec::new(), &env, What::Fw, true, false).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err}");
    }

    #[test]
    fn check_summarises_a_valid_config() {
        let (_dir, env) = with_config(AP);
        let (exit, out) = exit_of(|o| check(o, &env));
        assert_eq!(exit, Exit::Ok);
        assert!(out.contains("ports") && out.contains("radios"), "{out}");
        assert!(out.contains("zones") && out.contains("wan"), "{out}");
        assert!(
            out.lines()
                .any(|l| l.starts_with("aps") && l.ends_with('1')),
            "{out}"
        );
        assert!(out.ends_with("ok\n"), "{out}");
    }

    #[test]
    fn check_exits_1_on_invalid_config() {
        let (_dir, env) = with_config("");
        let text = fs::read_to_string(&env.config).unwrap();
        fs::write(
            &env.config,
            text.replace("port = \"wan\"", "port = \"eth9\""),
        )
        .unwrap();
        let (exit, out) = exit_of(|o| check(o, &env));
        assert_eq!(exit, Exit::Issues);
        assert_eq!(exit.code(), 1);
        assert!(
            out.contains("network.wan.port") && out.contains("FAIL"),
            "{out}"
        );
    }

    #[test]
    fn mask_secrets_only_touches_secret_keys() {
        let conf = "ssid=wpa_passphrase=x\nwpa_passphrase=a=b\nsae_password=c\nwpa=2\n";
        assert_eq!(
            mask_secrets(conf),
            "ssid=wpa_passphrase=x\nwpa_passphrase=***\nsae_password=***\nwpa=2\n"
        );
    }
}
