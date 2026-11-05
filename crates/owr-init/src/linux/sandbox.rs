//! `owr-init --sandbox <profile> -- <argv>`: confine this process with a
//! [`crate::sandbox`] profile, then `exec` the daemon, which inherits every restriction.
//!
//! Fails closed: if any step cannot be applied the daemon is not started (exit 126) and the
//! reason goes to the service's journal. The one exception is a kernel without Landlock,
//! which is reported and tolerated (the reference kernel has it; development hosts may not).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus,
};
use rustix::io::Errno;
use rustix::thread::{
    CapabilitySet, clear_ambient_capability_set, remove_capability_from_bounding_set,
    set_no_new_privs,
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter};

use super::console_log;
use crate::sandbox::{
    Cap, DEV_READ, DEV_WRITE, ETC, ETC_HIDDEN, EXEC_TREES, Profile, READ_TREES, profile_for,
};

/// Landlock ABI whose rights are handled (Linux 6.10+; older kernels get best effort).
const LANDLOCK_ABI: ABI = ABI::V5;

/// `libc` lacks this number for aarch64 musl; 294 is its asm-generic number, which aarch64 uses.
#[cfg(target_arch = "aarch64")]
const SYS_KEXEC_FILE_LOAD: libc::c_long = 294;
#[cfg(not(target_arch = "aarch64"))]
const SYS_KEXEC_FILE_LOAD: libc::c_long = libc::SYS_kexec_file_load;

/// Syscalls no confined daemon may make; they fail with `EPERM`. A deny list rather than an
/// allow list: an allow list for three C daemons nobody has traced on the router would break
/// them in ways that only show on hardware.
const DENIED_SYSCALLS: &[(&str, libc::c_long)] = &[
    // kernel modules, kexec, reboot, swap, accounting
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("kexec_load", libc::SYS_kexec_load),
    ("kexec_file_load", SYS_KEXEC_FILE_LOAD),
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
    ("acct", libc::SYS_acct),
    // mounts and namespaces
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("chroot", libc::SYS_chroot),
    ("fsopen", libc::SYS_fsopen),
    ("fsconfig", libc::SYS_fsconfig),
    ("fsmount", libc::SYS_fsmount),
    ("fspick", libc::SYS_fspick),
    ("move_mount", libc::SYS_move_mount),
    ("open_tree", libc::SYS_open_tree),
    ("mount_setattr", libc::SYS_mount_setattr),
    ("unshare", libc::SYS_unshare),
    ("setns", libc::SYS_setns),
    // other processes, kernel attack surface
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("kcmp", libc::SYS_kcmp),
    ("bpf", libc::SYS_bpf),
    ("perf_event_open", libc::SYS_perf_event_open),
    ("userfaultfd", libc::SYS_userfaultfd),
    ("io_uring_setup", libc::SYS_io_uring_setup),
    ("io_uring_enter", libc::SYS_io_uring_enter),
    ("io_uring_register", libc::SYS_io_uring_register),
    ("keyctl", libc::SYS_keyctl),
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("open_by_handle_at", libc::SYS_open_by_handle_at),
    ("name_to_handle_at", libc::SYS_name_to_handle_at),
    ("quotactl", libc::SYS_quotactl),
    ("syslog", libc::SYS_syslog),
    ("vhangup", libc::SYS_vhangup),
    // clock and identity
    ("settimeofday", libc::SYS_settimeofday),
    ("clock_settime", libc::SYS_clock_settime),
    ("clock_adjtime", libc::SYS_clock_adjtime),
    ("adjtimex", libc::SYS_adjtimex),
    ("sethostname", libc::SYS_sethostname),
    ("setdomainname", libc::SYS_setdomainname),
];

/// Entry point of the launcher. Only returns on failure.
pub(super) fn run(profile: &str, argv: &[String]) -> ExitCode {
    let Some(p) = profile_for(profile) else {
        console_log(format_args!("sandbox: unknown profile {profile:?}"));
        return ExitCode::from(2);
    };
    if let Err(e) = confine(&p) {
        console_log(format_args!(
            "sandbox {profile}: {e}; not starting (create /etc/ferritewrt/sandbox.off to run \
             unconfined)"
        ));
        return ExitCode::from(126);
    }
    let Some((program, rest)) = argv.split_first() else {
        return ExitCode::from(2);
    };
    let err = Command::new(program).args(rest).exec();
    console_log(format_args!("sandbox {profile}: exec {program}: {err}"));
    ExitCode::from(127)
}

/// Apply every restriction of `p` to this process, strongest last (seccomp also blocks
/// syscalls the earlier steps no longer need).
pub(super) fn confine(p: &Profile) -> Result<(), String> {
    drop_capabilities(&p.keep_caps)?;
    set_no_new_privs(true).map_err(|e| format!("no_new_privs: {e}"))?;
    landlock(p)?;
    seccomp()
}

fn capability(c: Cap) -> CapabilitySet {
    match c {
        Cap::NetAdmin => CapabilitySet::NET_ADMIN,
        Cap::NetRaw => CapabilitySet::NET_RAW,
        Cap::NetBindService => CapabilitySet::NET_BIND_SERVICE,
        Cap::SetUid => CapabilitySet::SETUID,
        Cap::SetGid => CapabilitySet::SETGID,
    }
}

/// Remove everything but `keep` from the bounding set: after `exec` even uid 0 holds no
/// other capability. Clears the ambient set too.
fn drop_capabilities(keep: &[Cap]) -> Result<(), String> {
    let keep = keep
        .iter()
        .fold(CapabilitySet::empty(), |acc, c| acc | capability(*c));
    for cap in CapabilitySet::all().iter() {
        if keep.contains(cap) {
            continue;
        }
        match remove_capability_from_bounding_set(cap) {
            // EINVAL: a capability this kernel does not know.
            Ok(()) | Err(Errno::INVAL) => {}
            Err(e) => return Err(format!("dropping {cap:?} from the bounding set: {e}")),
        }
    }
    match clear_ambient_capability_set() {
        Ok(()) | Err(Errno::INVAL) => Ok(()),
        Err(e) => Err(format!("clearing ambient capabilities: {e}")),
    }
}

/// Paths and the access each gets. Missing paths are left out (and reported when the
/// profile names them).
fn landlock_rules(p: &Profile) -> Vec<(PathBuf, BitFlags<AccessFs>)> {
    let abi = LANDLOCK_ABI;
    let read_exec = AccessFs::from_read(abi);
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let file_rw = AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate;
    // A device a profile names is used through ioctls too (pppd and /dev/ppp); every
    // other device stays without them (`IoctlDev` is a handled right from ABI 5).
    let device = file_rw | AccessFs::IoctlDev;
    let tree_write = read | AccessFs::WriteFile | AccessFs::Truncate;
    let own = read
        | AccessFs::WriteFile
        | AccessFs::Truncate
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::RemoveFile;

    let read_only = BitFlags::from(AccessFs::ReadFile);
    let owned = |paths: &[String]| -> Vec<String> { paths.to_vec() };
    let fixed = |paths: &[&str]| -> Vec<String> { paths.iter().map(|s| (*s).to_owned()).collect() };
    let groups = [
        (fixed(EXEC_TREES), read_exec),
        (fixed(READ_TREES), read),
        (fixed(DEV_READ), read_only),
        (fixed(DEV_WRITE), file_rw),
        (owned(&p.read_files), read_only),
        (owned(&p.write_files), file_rw),
        (owned(&p.write_trees), tree_write),
        (owned(&p.own_dirs), own),
        (owned(&p.devices), device),
    ];
    let mut rules: Vec<(PathBuf, BitFlags<AccessFs>)> = groups
        .into_iter()
        .flat_map(|(paths, access)| paths.into_iter().map(move |p| (PathBuf::from(p), access)))
        .collect();
    // /etc entry by entry, so the settings directory stays out of reach.
    if let Ok(entries) = fs::read_dir(ETC) {
        for entry in entries.filter_map(Result::ok) {
            if ETC_HIDDEN.iter().any(|h| entry.file_name() == **h) {
                continue;
            }
            rules.push((entry.path(), read));
        }
    }
    rules
}

fn landlock(p: &Profile) -> Result<(), String> {
    let err = |what: &str, e: &dyn std::fmt::Display| format!("landlock {what}: {e}");
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(LANDLOCK_ABI))
        .map_err(|e| err("ruleset", &e))?
        .create()
        .map_err(|e| err("create", &e))?;
    let named = |path: &Path| {
        let s = path.to_string_lossy();
        p.read_files
            .iter()
            .chain(&p.write_files)
            .chain(&p.write_trees)
            .chain(&p.own_dirs)
            .chain(&p.devices)
            .any(|n| *n == s)
    };
    for (path, access) in landlock_rules(p) {
        let Ok(md) = fs::metadata(&path) else {
            if named(&path) {
                console_log(format_args!(
                    "sandbox {}: {} missing, no access to it",
                    p.name,
                    path.display()
                ));
            }
            continue;
        };
        // Directory-only rights are invalid on a file.
        let access = if md.is_dir() {
            access
        } else {
            access & AccessFs::from_file(LANDLOCK_ABI)
        };
        let fd = PathFd::new(&path).map_err(|e| err(&path.display().to_string(), &e))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| err(&path.display().to_string(), &e))?;
    }
    let status = ruleset.restrict_self().map_err(|e| err("restrict", &e))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        console_log(format_args!(
            "sandbox {}: this kernel has no Landlock; file system access is not restricted",
            p.name
        ));
    }
    Ok(())
}

fn seccomp() -> Result<(), String> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| format!("seccomp: unsupported architecture: {e}"))?;
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = DENIED_SYSCALLS
        .iter()
        .map(|&(_, nr)| (nr, Vec::new()))
        .collect();
    let eperm = u32::try_from(libc::EPERM).unwrap_or(1);
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(eperm),
        arch,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| format!("seccomp compile: {e}"))?;
    apply_filter(&program).map_err(|e| format!("seccomp install: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_has_no_duplicates() {
        let mut nrs: Vec<_> = DENIED_SYSCALLS.iter().map(|&(_, nr)| nr).collect();
        nrs.sort_unstable();
        nrs.dedup();
        assert_eq!(nrs.len(), DENIED_SYSCALLS.len());
    }

    #[test]
    fn settings_directory_gets_no_rule() {
        let p = profile_for("dnsmasq").unwrap();
        let rules = landlock_rules(&p);
        assert!(
            rules
                .iter()
                .all(|(path, _)| !path.starts_with("/etc/ferritewrt")),
            "{rules:?}"
        );
        assert!(rules.iter().any(|(path, _)| path == Path::new("/usr")));
    }

    /// Set in the child run of [`confined_process_is_restricted`].
    const PROBE_ENV: &str = "OWR_SANDBOX_PROBE";

    fn status_field(status: &str, key: &str) -> String {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    /// The child half: confine this thread with the dnsmasq profile, then report what is
    /// still possible. Does nothing unless started by the parent test.
    #[test]
    #[allow(
        clippy::print_stdout,
        reason = "the child reports to the parent on stdout"
    )]
    fn sandbox_probe_child() {
        if std::env::var_os(PROBE_ENV).is_none() {
            return;
        }
        confine(&profile_for("dnsmasq").unwrap()).unwrap();
        let status = fs::read_to_string("/proc/thread-self/status").unwrap();
        println!("PROBE capbnd={}", status_field(&status, "CapBnd:"));
        println!("PROBE nnp={}", status_field(&status, "NoNewPrivs:"));
        println!("PROBE seccomp={}", status_field(&status, "Seccomp:"));
        let write = fs::write("/tmp/owr-sandbox-probe", b"x");
        println!("PROBE tmp_write={}", write.is_ok());
        let _ = fs::remove_file("/tmp/owr-sandbox-probe");
        println!("PROBE usr_read={}", fs::read_dir("/usr").is_ok());
        let mount = rustix::mount::mount(
            "none",
            "/mnt",
            "tmpfs",
            rustix::mount::MountFlags::empty(),
            None,
        );
        println!("PROBE mount={mount:?}");
    }

    /// Run [`sandbox_probe_child`] in a child process (restrictions cannot be undone, so
    /// never in this one) and check the report. Needs root (dropping capabilities); skipped
    /// otherwise.
    #[test]
    fn confined_process_is_restricted() {
        if !rustix::process::geteuid().is_root() {
            // Dropping capabilities needs root (CI runs these tests unprivileged).
            return;
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "linux::sandbox::tests::sandbox_probe_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PROBE_ENV, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{text}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let probe = |key: &str| {
            text.lines()
                // libtest may print the first probe after its own "test ... " prefix.
                .find_map(|l| l.split_once(&format!("PROBE {key}=")).map(|(_, v)| v))
                .unwrap_or_default()
                .to_owned()
        };
        assert!(!probe("capbnd").is_empty(), "no probe report in {text}");
        // dnsmasq keeps SETGID(6), SETUID(7), NET_BIND_SERVICE(10), NET_ADMIN(12) and
        // NET_RAW(13), nothing else.
        let kept = u64::from_str_radix(&probe("capbnd"), 16).unwrap();
        let expected = (1u64 << 6) | (1 << 7) | (1 << 10) | (1 << 12) | (1 << 13);
        assert_eq!(kept, expected, "bounding set {kept:#x}");
        assert_eq!(probe("nnp"), "1");
        assert_eq!(probe("seccomp"), "2", "filter mode");
        assert!(
            probe("mount").contains("code: 1,"),
            "EPERM: {}",
            probe("mount")
        );
        assert_eq!(probe("usr_read"), "true");
        // A kernel without Landlock leaves the file system unrestricted and `confine` says so
        // on stderr; everywhere else the write outside the profile must fail.
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("has no Landlock") {
            assert_eq!(probe("tmp_write"), "false", "/tmp is not in the profile");
        }
    }
}
