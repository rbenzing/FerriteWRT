//! Confinement profiles for the C daemons that parse untrusted network input (dnsmasq,
//! odhcpd, hostapd). Pure data; the Linux launcher (`owr-init --sandbox <profile> -- argv`)
//! enforces it and then `exec`s the daemon, which inherits every restriction:
//!
//! * capability bounding set reduced to [`Profile::keep_caps`] (the daemon still starts as
//!   uid 0, but root without `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_*`, ... cannot load
//!   modules, remount, read raw flash or bypass file permissions);
//! * `no_new_privs`;
//! * Landlock: the file system is read-only and limited to the system directories plus the
//!   files the profile names; `/etc/ferritewrt` (passwords, keys, the full config), the data
//!   partition and block devices are out of reach;
//! * seccomp: syscalls no network daemon needs (module loading, mounts, kexec, reboot,
//!   ptrace, bpf, `io_uring`, keyrings, ...) fail with `EPERM`.
//!
//! Paths a profile writes are created by the supervisor before the start, so the daemon never
//! needs the right to create files where it must not ([`Profile::prepare`]).
//!
//! The profiles are written from the daemons' documented behaviour and our rendered configs,
//! not from a trace on the router. `/etc/ferritewrt/sandbox.off` turns them off (reboot or
//! restart the service), which is the way out if one turns out too tight.

use owr_common::paths::{CONFIG_DIR, RUN_DIR};

/// The launcher: `owr-init` itself.
pub const LAUNCHER: &str = "/sbin/owr-init";
/// Launcher flag: `owr-init --sandbox <profile> -- <argv>`.
pub const SANDBOX_FLAG: &str = "--sandbox";
/// File name in [`CONFIG_DIR`] that disables every profile.
pub const DISABLE_MARKER: &str = "sandbox.off";

/// `/etc/ferritewrt/sandbox.off`.
pub fn disable_marker() -> String {
    format!("{CONFIG_DIR}/{DISABLE_MARKER}")
}

/// Capabilities a profile may keep (everything else leaves the bounding set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    NetAdmin,
    NetRaw,
    NetBindService,
    /// dnsmasq drops to its own user after binding its sockets.
    SetUid,
    SetGid,
}

/// Directories every profile may read and execute from (programs, libraries, the loader).
pub const EXEC_TREES: &[&str] = &["/bin", "/sbin", "/usr", "/lib"];
/// Trees every profile may read.
pub const READ_TREES: &[&str] = &["/proc", "/sys"];
/// Read: every entry of `/etc` except these (decided when the sandbox is applied).
pub const ETC: &str = "/etc";
pub const ETC_HIDDEN: &[&str] = &["ferritewrt"];
/// Device nodes every profile may read; only `/dev/null` is writable.
pub const DEV_READ: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];
pub const DEV_WRITE: &[&str] = &["/dev/null"];

/// What one confined service may do beyond the common rules above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub keep_caps: Vec<Cap>,
    /// Files it reads (its rendered config).
    pub read_files: Vec<String>,
    /// Existing files it rewrites (leases, pid file); created empty before the start.
    pub write_files: Vec<String>,
    /// Trees in which it may write existing files but create nothing (`/proc/sys/net`).
    pub write_trees: Vec<String>,
    /// Directories it owns: create, remove and use files and sockets (hostapd's control
    /// sockets); created before the start.
    pub own_dirs: Vec<String>,
    /// Device nodes it reads and writes besides `/dev/null`.
    pub devices: Vec<String>,
}

impl Profile {
    /// Files and directories the supervisor creates before starting the service.
    pub fn prepare(&self) -> (Vec<&str>, Vec<&str>) {
        (
            self.write_files.iter().map(String::as_str).collect(),
            self.own_dirs.iter().map(String::as_str).collect(),
        )
    }
}

fn run(name: &str) -> String {
    format!("{RUN_DIR}/{name}")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The profile for a service name, `None` if the service runs unconfined.
pub fn profile_for(service: &str) -> Option<Profile> {
    let p = match service {
        "dnsmasq" => Profile {
            name: service.to_owned(),
            keep_caps: vec![
                Cap::NetBindService,
                Cap::NetAdmin,
                Cap::NetRaw,
                Cap::SetUid,
                Cap::SetGid,
            ],
            read_files: vec![run("dnsmasq.conf"), run("resolv.conf.auto")],
            write_files: vec![run("dhcp.leases"), run("dnsmasq.pid")],
            write_trees: Vec::new(),
            own_dirs: Vec::new(),
            devices: Vec::new(),
        },
        "odhcpd" => Profile {
            name: service.to_owned(),
            keep_caps: vec![Cap::NetBindService, Cap::NetAdmin, Cap::NetRaw],
            // `/etc/config/dhcp` links to the rendered file.
            read_files: vec![run("dhcp")],
            write_files: vec![run("odhcpd.leases")],
            write_trees: strings(&["/proc/sys/net"]),
            own_dirs: Vec::new(),
            devices: Vec::new(),
        },
        _ => {
            let phy = service.strip_prefix("hostapd-phy")?;
            if phy.is_empty() || !phy.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Profile {
                name: service.to_owned(),
                keep_caps: vec![Cap::NetAdmin, Cap::NetRaw],
                read_files: vec![run(&format!("hostapd-phy{phy}.conf"))],
                write_files: Vec::new(),
                write_trees: strings(&["/proc/sys/net"]),
                own_dirs: vec![run("hostapd")],
                devices: strings(&["/dev/rfkill"]),
            }
        }
    };
    Some(p)
}

/// The argv that starts `exec` under `profile` through the launcher.
pub fn launcher_argv(profile: &str, exec: &[String]) -> Vec<String> {
    let mut argv = vec![
        LAUNCHER.to_owned(),
        SANDBOX_FLAG.to_owned(),
        profile.to_owned(),
        "--".to_owned(),
    ];
    argv.extend(exec.iter().cloned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confined_services_and_their_files() {
        let d = profile_for("dnsmasq").unwrap();
        assert!(
            d.keep_caps.contains(&Cap::SetUid),
            "dnsmasq drops to its own user"
        );
        assert_eq!(
            d.prepare().0,
            ["/run/ferritewrt/dhcp.leases", "/run/ferritewrt/dnsmasq.pid"]
        );
        let h = profile_for("hostapd-phy1").unwrap();
        assert_eq!(h.read_files, ["/run/ferritewrt/hostapd-phy1.conf"]);
        assert_eq!(h.own_dirs, ["/run/ferritewrt/hostapd"]);
        assert!(!h.keep_caps.contains(&Cap::NetBindService));
        assert!(profile_for("odhcpd").is_some());
        for unconfined in [
            "owr-api",
            "owr-apply",
            "kmodloader",
            "hostapd-phy",
            "hostapd-phyx",
        ] {
            assert_eq!(profile_for(unconfined), None, "{unconfined}");
        }
    }

    #[test]
    fn no_profile_reaches_the_settings_directory() {
        for name in ["dnsmasq", "odhcpd", "hostapd-phy0"] {
            let p = profile_for(name).unwrap();
            let paths = p
                .read_files
                .iter()
                .chain(&p.write_files)
                .chain(&p.write_trees)
                .chain(&p.own_dirs)
                .chain(&p.devices);
            for path in paths {
                assert!(!path.starts_with(CONFIG_DIR), "{name}: {path}");
                assert!(!path.starts_with("/overlay"), "{name}: {path}");
            }
        }
        assert_eq!(ETC_HIDDEN, ["ferritewrt"]);
    }

    #[test]
    fn launcher_argv_wraps_the_command() {
        let exec = vec!["/usr/sbin/odhcpd".to_owned()];
        assert_eq!(
            launcher_argv("odhcpd", &exec),
            [
                "/sbin/owr-init",
                "--sandbox",
                "odhcpd",
                "--",
                "/usr/sbin/odhcpd"
            ]
        );
    }
}
