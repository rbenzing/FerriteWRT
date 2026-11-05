//! Writing the rendered daemon configs below the run directory (works on any host).
//!
//! | file | consumer | mode |
//! |---|---|---|
//! | `hostapd-<phy>.conf` | hostapd | 0600 (passphrases; written by `owr-wifi`) |
//! | `dnsmasq.conf` | dnsmasq | 0644 |
//! | `netd.json` | `owr-apply netd` (read-only view; a change restarts the daemon) | 0644 |
//! | `pppoe-wan.conf` | pppd, only on a `PPPoE` WAN (removed otherwise) | 0600 (password) |
//! | `resolv.conf.ppp` | written by pppd (created empty here); dnsmasq `resolv-file` on `PPPoE` | 0644 |
//! | `resolv.conf.auto` | dnsmasq `resolv-file` | 0644 |

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use owr_common::paths::{PPP_RESOLV, PPPOE_CONF};
use owr_common::{AtomicWriteError, Outcome, atomic_write};
use owr_config::{Config, WanProto};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::dnsmasq::resolv_conf;
use crate::pppoe::render_pppoe;
use crate::{NetdPlan, Plans, PppoePlan};

/// File name of the dnsmasq configuration inside the run directory.
pub const DNSMASQ_CONF: &str = "dnsmasq.conf";
/// File name of the network daemon plan inside the run directory.
pub const NETD_PLAN: &str = "netd.json";
/// File name of the upstream resolver list inside the run directory.
pub const RESOLV_AUTO: &str = "resolv.conf.auto";

/// Mode of daemon configs that contain no secrets.
const DAEMON_MODE: u32 = 0o644;
/// Mode of daemon configs that contain a secret.
const SECRET_MODE: u32 = 0o600;

/// Failure writing a daemon config.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error(transparent)]
    Wifi(#[from] owr_wifi::ConfigWriteError),
    #[error(transparent)]
    Write(#[from] AtomicWriteError),
    #[error("{context}: {source}")]
    Io { context: String, source: io::Error },
}

/// Which files changed; the supervisor restarts only the matching daemons.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DaemonFiles {
    /// `(phy, changed)` for every radio that has a hostapd config.
    pub hostapd_changed: Vec<(String, bool)>,
    pub dnsmasq_changed: bool,
    pub netd_changed: bool,
    /// pppd's options were written with new content or removed (the WAN is no longer
    /// `PPPoE`); either way pppd must be restarted, which stops it when the file is gone.
    pub pppoe_changed: bool,
}

/// Write one daemon config file; `true` when its content changed.
fn write_text(run_dir: &Path, file: &str, text: &str) -> Result<bool, FilesError> {
    let path: PathBuf = run_dir.join(file);
    Ok(atomic_write(&path, text.as_bytes(), DAEMON_MODE)? == Outcome::Written)
}

/// The text of `netd.json`: pretty JSON with a trailing newline.
pub fn netd_json(plan: &NetdPlan) -> Result<String, FilesError> {
    let mut text = serde_json::to_string_pretty(plan).map_err(|e| FilesError::Io {
        context: format!("rendering {NETD_PLAN}"),
        source: io::Error::other(e),
    })?;
    text.push('\n');
    Ok(text)
}

/// pppd's options for a `PPPoE` WAN (0600: the password), or no file at all for any other
/// WAN, which is what keeps owr-init from starting pppd. Also makes sure pppd's DNS file
/// exists before dnsmasq starts, so its sandbox can grant reading it; pppd overwrites it
/// in place when the link comes up. `true` when the options file changed or was removed.
fn write_pppoe(plan: Option<&PppoePlan>, run_dir: &Path) -> Result<bool, FilesError> {
    let conf = run_dir.join(PPPOE_CONF);
    let Some(plan) = plan else {
        return match std::fs::remove_file(&conf) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(FilesError::Io {
                context: format!("removing {}", conf.display()),
                source,
            }),
        };
    };
    let resolv = run_dir.join(PPP_RESOLV);
    if !resolv.exists() {
        atomic_write(&resolv, b"", DAEMON_MODE)?;
    }
    let text = Zeroizing::new(render_pppoe(plan, true));
    Ok(atomic_write(&conf, text.as_bytes(), SECRET_MODE)? == Outcome::Written)
}

/// Write `<run_dir>/resolv.conf.auto` for `dns`; `true` when its content changed.
pub fn write_resolv(run_dir: &Path, dns: &[IpAddr]) -> Result<bool, FilesError> {
    write_text(run_dir, RESOLV_AUTO, &resolv_conf(dns))
}

/// Write hostapd configs, `dnsmasq.conf`, the network daemon plan and the initial
/// `resolv.conf.auto` below `run_dir` (created if missing).
///
/// A static WAN writes its DNS servers into `resolv.conf.auto`; a DHCP WAN only makes sure
/// the file exists, so that a lease written earlier is not clobbered.
///
/// On failure nothing is reported; use [`write_daemon_files_partial`] to learn which files
/// changed before the failure.
pub fn write_daemon_files(
    plans: &Plans,
    cfg: &Config,
    run_dir: &Path,
) -> Result<DaemonFiles, FilesError> {
    let mut out = DaemonFiles::default();
    write_daemon_files_partial(plans, cfg, run_dir, &mut out)?;
    Ok(out)
}

/// Like [`write_daemon_files`], but records progress in `out` as it goes, so that after an
/// error `out` still tells which daemons' files changed (and must be restarted).
pub fn write_daemon_files_partial(
    plans: &Plans,
    cfg: &Config,
    run_dir: &Path,
    out: &mut DaemonFiles,
) -> Result<(), FilesError> {
    std::fs::create_dir_all(run_dir).map_err(|source| FilesError::Io {
        context: format!("creating {}", run_dir.display()),
        source,
    })?;
    for radio in &plans.radios {
        let (_, outcome) = owr_wifi::write_config(radio, run_dir)?;
        out.hostapd_changed
            .push((radio.phy.clone(), outcome == Outcome::Written));
    }
    out.dnsmasq_changed = write_text(run_dir, DNSMASQ_CONF, &plans.dnsmasq_conf)?;
    out.netd_changed = write_text(run_dir, NETD_PLAN, &netd_json(&plans.netd)?)?;
    out.pppoe_changed = write_pppoe(plans.pppoe.as_ref(), run_dir)?;
    match &cfg.network.wan.proto {
        WanProto::Static { dns, .. } => {
            write_resolv(run_dir, dns)?;
        }
        WanProto::Dhcp { .. } | WanProto::Pppoe { .. } => {
            if !run_dir.join(RESOLV_AUTO).exists() {
                write_resolv(run_dir, &[])?;
            }
        }
    }
    Ok(())
}
