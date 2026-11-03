//! hostapd control-interface client over Unix datagram sockets.
//!
//! Protocol: send an ASCII command to `<ctrl_dir>/<ifname>`, receive one datagram reply.
//! The client socket is bound at `<client_dir>/cli-<pid>-<n>` (hostapd needs a bound peer
//! to answer) and removed on drop. `client_dir` is `<run_dir>/hostapd-cli`, a private (0700)
//! sibling of hostapd's control directory, so clients never write into that directory.
//!
//! One request, one reply. If a reply times out it may still arrive later and would be taken
//! for the answer to the *next* request, so a timeout poisons the client: further requests
//! fail with [`ReplyError::Desynced`] until the caller reconnects.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::reply::ReplyError;
pub use crate::reply::{ApStatus, Station};
use crate::reply::{parse_station, parse_status};
use crate::sys::SysError;
use crate::validate::is_valid_ifname;

/// Receive timeout per request.
pub const TIMEOUT: Duration = Duration::from_secs(2);
/// Largest reply accepted.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;
/// Most stations returned by [`HostapdCtl::stations`].
pub const MAX_STATIONS: usize = 512;
/// Overall time budget of one [`HostapdCtl::stations`] walk.
pub const STATIONS_DEADLINE: Duration = Duration::from_secs(10);
/// Stale datagrams discarded before each request; more than this means the peer is
/// flooding us and the client is treated as desynchronised.
const MAX_DRAIN: usize = 16;
/// Directory (next to the hostapd control dir) holding client sockets.
const CLIENT_DIR_NAME: &str = "hostapd-cli";
/// Client sockets older than this whose owner is gone are removed on connect.
const STALE_AFTER: Duration = Duration::from_mins(10);

static NEXT_CLIENT: AtomicU32 = AtomicU32::new(0);

/// Connected control-interface client for one hostapd BSS.
#[derive(Debug)]
pub struct HostapdCtl {
    sock: UnixDatagram,
    local: PathBuf,
    ifname: String,
    /// Set after a receive timeout; see the module docs.
    poisoned: AtomicBool,
}

impl HostapdCtl {
    /// Connect to `<ctrl_dir>/<ifname>`, binding the client socket in the private
    /// `hostapd-cli` directory next to `ctrl_dir` (`<run_dir>/hostapd-cli`).
    pub fn connect(ctrl_dir: &Path, ifname: &str) -> Result<Self, SysError> {
        Self::connect_in(ctrl_dir, &ctrl_dir.with_file_name(CLIENT_DIR_NAME), ifname)
    }

    /// Like [`connect`](Self::connect) with an explicit client-socket directory
    /// (created with mode 0700).
    pub fn connect_in(ctrl_dir: &Path, client_dir: &Path, ifname: &str) -> Result<Self, SysError> {
        if !is_valid_ifname(ifname) {
            return Err(SysError::BadIfname(ifname.to_owned()));
        }
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| SysError::Io { path, source }
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(client_dir)
            .and_then(|()| fs::set_permissions(client_dir, fs::Permissions::from_mode(0o700)))
            .map_err(io(client_dir))?;
        sweep_stale_sockets(client_dir, STALE_AFTER);

        let n = NEXT_CLIENT.fetch_add(1, Ordering::Relaxed);
        let local = client_dir.join(format!("cli-{}-{n}", std::process::id()));
        let remote = ctrl_dir.join(ifname);
        // A stale file from a crashed process with a recycled pid would make bind fail.
        let _ = fs::remove_file(&local);
        let sock = UnixDatagram::bind(&local).map_err(io(&local))?;
        // From here on Drop of `ctl` removes the socket file on any error.
        let ctl = Self {
            sock,
            local,
            ifname: ifname.to_owned(),
            poisoned: AtomicBool::new(false),
        };
        ctl.sock.connect(&remote).map_err(io(&remote))?;
        ctl.sock
            .set_read_timeout(Some(TIMEOUT))
            .map_err(io(&remote))?;
        ctl.sock
            .set_write_timeout(Some(TIMEOUT))
            .map_err(io(&remote))?;
        Ok(ctl)
    }

    fn io_err(&self) -> impl FnOnce(std::io::Error) -> SysError + use<> {
        let path = self.local.clone();
        move |source| SysError::Io { path, source }
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    /// Discard datagrams already queued on our socket (late replies, stray events), at
    /// most `limit` of them; more than that poisons the client.
    fn drain_pending(&self, limit: usize) -> Result<(), SysError> {
        self.sock.set_nonblocking(true).map_err(self.io_err())?;
        let drained = self.discard_queued(limit);
        // Restore blocking mode (the receive timeout is kept) even if draining failed.
        self.sock.set_nonblocking(false).map_err(self.io_err())?;
        drained
    }

    fn discard_queued(&self, limit: usize) -> Result<(), SysError> {
        let mut scratch = [0u8; 1]; // the payload is truncated and thrown away
        for discarded in 0..=limit {
            match self.sock.recv(&mut scratch) {
                Ok(_) if discarded == limit => {
                    self.poison();
                    return Err(ReplyError::Desynced.into());
                }
                Ok(_) => {
                    tracing::debug!(ifname = %self.ifname, "discarded stale hostapd datagram");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(self.io_err()(e)),
            }
        }
        Ok(())
    }

    /// Send `cmd` and return hostapd's reply text.
    fn request(&self, cmd: &str) -> Result<String, SysError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(ReplyError::Desynced.into());
        }
        self.drain_pending(MAX_DRAIN)?;
        self.sock.send(cmd.as_bytes()).map_err(self.io_err())?;
        // One extra byte distinguishes "exactly at the cap" from "truncated by the kernel".
        let mut buf = vec![0u8; MAX_REPLY_BYTES.saturating_add(1)];
        let n = match self.sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // The reply may still arrive and be mistaken for the next answer.
                self.poison();
                return Err(SysError::Timeout(TIMEOUT));
            }
            Err(e) => return Err(self.io_err()(e)),
        };
        if n > MAX_REPLY_BYTES {
            return Err(SysError::ReplyTooLarge(MAX_REPLY_BYTES));
        }
        Ok(String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).into_owned())
    }

    /// `PING`; succeeds when hostapd answers `PONG`.
    pub fn ping(&self) -> Result<(), SysError> {
        let reply = self.request("PING")?;
        if reply.trim() == "PONG" {
            Ok(())
        } else {
            Err(SysError::Rejected(reply.trim().to_owned()))
        }
    }

    /// `STATUS` for this interface.
    pub fn status(&self) -> Result<ApStatus, SysError> {
        let reply = self.request("STATUS")?;
        Ok(parse_status(&reply, &self.ifname)?)
    }

    /// All associated stations (`STA-FIRST`, then `STA-NEXT <mac>` until an empty reply),
    /// truncated to [`MAX_STATIONS`] and bounded by [`STATIONS_DEADLINE`] overall.
    pub fn stations(&self) -> Result<Vec<Station>, SysError> {
        self.stations_within(STATIONS_DEADLINE)
    }

    fn stations_within(&self, budget: Duration) -> Result<Vec<Station>, SysError> {
        let start = Instant::now();
        let request = |cmd: &str| {
            if start.elapsed() >= budget {
                return Err(SysError::Timeout(budget));
            }
            self.request(cmd)
        };
        let mut out: Vec<Station> = Vec::new();
        let mut reply = request("STA-FIRST")?;
        loop {
            if reply.trim().is_empty() {
                break;
            }
            let sta = parse_station(&reply)?;
            if out.last().is_some_and(|prev| prev.mac == sta.mac) {
                break; // defensive: hostapd repeating itself must not loop us forever
            }
            let mac = sta.mac;
            out.push(sta);
            if out.len() >= MAX_STATIONS {
                tracing::warn!(ifname = %self.ifname, cap = MAX_STATIONS, "station list truncated");
                break;
            }
            reply = request(&format!("STA-NEXT {mac}"))?;
        }
        Ok(out)
    }
}

impl Drop for HostapdCtl {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.local);
    }
}

/// Best-effort removal of leftover `cli-<pid>-<n>` sockets from crashed clients: older than
/// `max_age`, not ours, and whose pid no longer exists (a long-lived client of another live
/// process must keep its socket).
fn sweep_stale_sockets(dir: &Path, max_age: Duration) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let own_prefix = format!("cli-{}-", std::process::id());
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(owner) = name.strip_prefix("cli-") else {
            continue;
        };
        if name.starts_with(&own_prefix) {
            continue;
        }
        let owner_alive = owner
            .split('-')
            .next()
            .and_then(|pid| pid.parse::<u32>().ok())
            .is_some_and(|pid| Path::new("/proc").join(pid.to_string()).exists());
        let old_file = entry.metadata().is_ok_and(|m| {
            !m.is_dir()
                && m.modified()
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > max_age)
        });
        if old_file && !owner_alive {
            let path = entry.path();
            match fs::remove_file(&path) {
                Ok(()) => tracing::debug!(path = %path.display(), "removed stale client socket"),
                Err(error) => {
                    tracing::debug!(path = %path.display(), %error, "stale client socket kept");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use std::thread;

    use super::*;

    /// Client directory used by tests: inside the temp dir, never the system one.
    fn client_dir(dir: &Path) -> PathBuf {
        dir.join("cli")
    }

    fn connect(dir: &Path, ifname: &str) -> Result<HostapdCtl, SysError> {
        HostapdCtl::connect_in(dir, &client_dir(dir), ifname)
    }

    /// Fake hostapd: answers each request from `script` (command prefix -> reply).
    fn fake_hostapd(
        dir: &Path,
        ifname: &str,
        script: Vec<(&'static str, String)>,
    ) -> thread::JoinHandle<()> {
        let server = UnixDatagram::bind(dir.join(ifname)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 256];
            for (want, reply) in script {
                let (n, from) = server.recv_from(&mut buf).unwrap();
                let got = std::str::from_utf8(&buf[..n]).unwrap();
                assert!(got.starts_with(want), "got {got:?}, want {want:?}");
                server.send_to_addr(reply.as_bytes(), &from).unwrap();
            }
        })
    }

    #[test]
    fn ping_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let status = "state=ENABLED\nfreq=2437\nchannel=6\nbss[0]=wlan0\nbssid[0]=02:00:00:00:00:01\nssid[0]=x\nnum_sta[0]=2\n";
        let h = fake_hostapd(
            dir.path(),
            "wlan0",
            vec![("PING", "PONG\n".into()), ("STATUS", status.into())],
        );
        let ctl = connect(dir.path(), "wlan0").unwrap();
        ctl.ping().unwrap();
        let st = ctl.status().unwrap();
        assert_eq!((st.channel, st.freq, st.num_sta), (6, 2437, 2));
        h.join().unwrap();
    }

    #[test]
    fn status_for_unknown_interface_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let status = "state=ENABLED\nbss[0]=wlan1\nssid[0]=other\n";
        let h = fake_hostapd(dir.path(), "wlan0", vec![("STATUS", status.into())]);
        let ctl = connect(dir.path(), "wlan0").unwrap();
        assert!(matches!(
            ctl.status(),
            Err(SysError::Reply(ReplyError::NoSuchBss(_)))
        ));
        h.join().unwrap();
    }

    #[test]
    fn stations_walks_until_empty_reply() {
        let dir = tempfile::tempdir().unwrap();
        let a = "aa:bb:cc:dd:ee:01\nsignal=-50\n";
        let b = "aa:bb:cc:dd:ee:02\nsignal=-60\n";
        let h = fake_hostapd(
            dir.path(),
            "wlan0",
            vec![
                ("STA-FIRST", a.into()),
                ("STA-NEXT aa:bb:cc:dd:ee:01", b.into()),
                ("STA-NEXT aa:bb:cc:dd:ee:02", String::new()),
            ],
        );
        let ctl = connect(dir.path(), "wlan0").unwrap();
        let stas = ctl.stations().unwrap();
        assert_eq!(stas.len(), 2);
        assert_eq!(stas[1].signal_dbm, Some(-60));
        h.join().unwrap();
    }

    #[test]
    fn stations_walk_has_an_overall_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        // An endless, slow station list: every request yields a new station.
        let h = thread::spawn(move || {
            let mut buf = [0u8; 256];
            let mut i = 0u32;
            while let Ok((_, from)) = server.recv_from(&mut buf) {
                thread::sleep(Duration::from_millis(20));
                let reply = format!("aa:bb:cc:00:{:02x}:{:02x}\nsignal=-50\n", i / 256, i % 256);
                server.send_to_addr(reply.as_bytes(), &from).unwrap();
                i += 1;
            }
        });
        let ctl = connect(dir.path(), "wlan0").unwrap();
        let err = ctl.stations_within(Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, SysError::Timeout(d) if d == Duration::from_millis(100)));
        drop(ctl);
        h.join().unwrap();
    }

    #[test]
    fn ping_rejects_unexpected_reply() {
        let dir = tempfile::tempdir().unwrap();
        let h = fake_hostapd(dir.path(), "wlan0", vec![("PING", "FAIL\n".into())]);
        let ctl = connect(dir.path(), "wlan0").unwrap();
        assert!(matches!(ctl.ping(), Err(SysError::Rejected(_))));
        h.join().unwrap();
    }

    #[test]
    fn oversized_reply_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let h = fake_hostapd(
            dir.path(),
            "wlan0",
            vec![("STATUS", "x".repeat(MAX_REPLY_BYTES + 1))],
        );
        let ctl = connect(dir.path(), "wlan0").unwrap();
        assert!(matches!(ctl.status(), Err(SysError::ReplyTooLarge(_))));
        h.join().unwrap();
    }

    #[test]
    fn client_socket_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let _server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let ctl = connect(dir.path(), "wlan0").unwrap();
        let local = ctl.local.clone();
        assert!(local.exists());
        drop(ctl);
        assert!(!local.exists());
    }

    #[test]
    fn connect_failure_leaves_no_socket_behind() {
        let dir = tempfile::tempdir().unwrap();
        assert!(connect(dir.path(), "wlan0").is_err());
        let leftovers: Vec<_> = fs::read_dir(client_dir(dir.path())).unwrap().collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn rejects_path_traversal_ifname() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            connect(dir.path(), "../etc"),
            Err(SysError::BadIfname(_))
        ));
    }

    #[test]
    fn times_out_when_hostapd_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        let _server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let ctl = connect(dir.path(), "wlan0").unwrap();
        ctl.sock
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(matches!(ctl.ping(), Err(SysError::Timeout(_))));
    }

    #[test]
    fn timeout_poisons_the_client_until_reconnect() {
        let dir = tempfile::tempdir().unwrap();
        let server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let ctl = connect(dir.path(), "wlan0").unwrap();
        ctl.sock
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(matches!(ctl.ping(), Err(SysError::Timeout(_))));

        // The late reply to the first PING arrives now ...
        let mut buf = [0u8; 16];
        let (_, from) = server.recv_from(&mut buf).unwrap();
        server.send_to_addr(b"PONG\n", &from).unwrap();
        // ... and must never be taken for the answer to a later request.
        assert!(matches!(
            ctl.status(),
            Err(SysError::Reply(ReplyError::Desynced))
        ));
        assert!(matches!(
            ctl.ping(),
            Err(SysError::Reply(ReplyError::Desynced))
        ));
        drop(ctl);

        let h = fake_hostapd_on(server, vec![("PING", "PONG\n".into())]);
        connect(dir.path(), "wlan0").unwrap().ping().unwrap();
        h.join().unwrap();
    }

    /// Like [`fake_hostapd`] but on an already bound socket.
    fn fake_hostapd_on(
        server: UnixDatagram,
        script: Vec<(&'static str, String)>,
    ) -> thread::JoinHandle<()> {
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 256];
            for (want, reply) in script {
                let (n, from) = server.recv_from(&mut buf).unwrap();
                let got = std::str::from_utf8(&buf[..n]).unwrap();
                assert!(got.starts_with(want), "got {got:?}, want {want:?}");
                server.send_to_addr(reply.as_bytes(), &from).unwrap();
            }
        })
    }

    #[test]
    fn stale_datagrams_are_drained_before_a_request() {
        let dir = tempfile::tempdir().unwrap();
        let server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let ctl = connect(dir.path(), "wlan0").unwrap();
        for _ in 0..3 {
            server.send_to(b"STALE\n", &ctl.local).unwrap();
        }
        let h = fake_hostapd_on(server, vec![("PING", "PONG\n".into())]);
        ctl.ping().unwrap();
        h.join().unwrap();
    }

    #[test]
    fn draining_more_than_the_limit_poisons_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let ctl = connect(dir.path(), "wlan0").unwrap();
        for _ in 0..3 {
            server.send_to(b"STALE\n", &ctl.local).unwrap();
        }
        assert!(matches!(
            ctl.drain_pending(2),
            Err(SysError::Reply(ReplyError::Desynced))
        ));
        assert!(matches!(
            ctl.ping(),
            Err(SysError::Reply(ReplyError::Desynced))
        ));
        // Exactly at the limit is fine.
        let ctl = connect(dir.path(), "wlan0").unwrap();
        for _ in 0..2 {
            server.send_to(b"STALE\n", &ctl.local).unwrap();
        }
        ctl.drain_pending(2).unwrap();
    }

    #[test]
    fn client_socket_lives_in_private_hostapd_cli_dir_next_to_ctrl_dir() {
        use std::os::unix::fs::PermissionsExt;
        let run = tempfile::tempdir().unwrap();
        let hostapd_dir = run.path().join("hostapd");
        fs::create_dir(&hostapd_dir).unwrap();
        let _server = UnixDatagram::bind(hostapd_dir.join("wlan0")).unwrap();
        let ctl = HostapdCtl::connect(&hostapd_dir, "wlan0").unwrap();
        let cli_dir = run.path().join("hostapd-cli");
        assert_eq!(ctl.local.parent(), Some(cli_dir.as_path()));
        let mode = fs::metadata(&cli_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // hostapd's own directory stays free of client sockets.
        let in_ctrl: Vec<_> = fs::read_dir(&hostapd_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(in_ctrl, ["wlan0"]);
    }

    #[test]
    fn existing_client_dir_is_tightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let cli = client_dir(dir.path());
        fs::create_dir(&cli).unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755)).unwrap();
        let _ctl = connect(dir.path(), "wlan0").unwrap();
        assert_eq!(
            fs::metadata(&cli).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    fn touch_aged(path: &Path, age: Duration) {
        let file = fs::File::create(path).unwrap();
        file.set_modified(std::time::SystemTime::now().checked_sub(age).unwrap())
            .unwrap();
    }

    #[test]
    fn stale_client_sockets_are_swept_on_connect() {
        let dir = tempfile::tempdir().unwrap();
        let _server = UnixDatagram::bind(dir.path().join("wlan0")).unwrap();
        let cli = client_dir(dir.path());
        fs::create_dir(&cli).unwrap();
        let old = Duration::from_mins(11);
        // Pid that cannot exist (above any pid_max).
        let dead_old = cli.join("cli-4294967295-0");
        let dead_fresh = cli.join("cli-4294967295-1");
        // Pid 1 is alive: its socket must be kept however old it looks.
        let alive_old = cli.join("cli-1-0");
        let own_old = cli.join(format!("cli-{}-9999", std::process::id()));
        let unrelated = cli.join("notes.txt");
        touch_aged(&dead_old, old);
        touch_aged(&dead_fresh, Duration::from_secs(60));
        touch_aged(&alive_old, old);
        touch_aged(&own_old, old);
        touch_aged(&unrelated, old);

        let _ctl = connect(dir.path(), "wlan0").unwrap();

        assert!(!dead_old.exists(), "stale socket of a dead pid is removed");
        assert!(dead_fresh.exists(), "recent socket is kept");
        assert!(alive_old.exists(), "socket of a live pid is kept");
        assert!(own_old.exists(), "own sockets are never swept");
        assert!(unrelated.exists(), "only cli-* files are touched");
    }
}
