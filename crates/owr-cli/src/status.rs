//! `owr status`: ask init for its service table over the control socket.
//!
//! The socket protocol lives in `owr_init::client`; this module only formats. The client
//! needs a unix host; elsewhere the command reports that it needs the router. Formatting is
//! pure and tested on every host.

use std::io::Write;

use owr_init::client::InitStatus;

use crate::CliError;

pub(crate) fn run(out: &mut dyn Write, json: bool) -> Result<(), CliError> {
    let path = std::path::Path::new(owr_common::paths::RUN_DIR).join("init.sock");
    let status = fetch(&path)?;
    if json {
        writeln!(out, "{}", serde_json::to_string(&status)?)?;
        return Ok(());
    }
    print_status(out, &status)
}

/// Table of services from init's `status` reply.
fn print_status(out: &mut dyn Write, status: &InitStatus) -> Result<(), CliError> {
    writeln!(out, "mode {}, up {}s", status.mode, status.uptime_ms / 1000)?;
    if let Some(why) = &status.failsafe_reason {
        writeln!(out, "failsafe: {why}")?;
    }
    writeln!(
        out,
        "{:<16} {:<10} {:>7} {:>6} {:>8}",
        "SERVICE", "STATE", "PID", "FAILS", "RESTARTS"
    )?;
    for s in &status.services {
        let pid = s.pid.map_or_else(|| "-".to_owned(), |p| p.to_string());
        let health = if s.healthy == Some(false) {
            " unhealthy"
        } else {
            ""
        };
        writeln!(
            out,
            "{:<16} {:<10} {:>7} {:>6} {:>8}{health}",
            s.name, s.state, pid, s.failures, s.restarts
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn fetch(path: &std::path::Path) -> Result<InitStatus, CliError> {
    let client = owr_init::client::InitClient::connect(path)
        .map_err(|e| CliError::Usage(format!("connecting to {}: {e}", path.display())))?;
    client
        .status_report()
        .map_err(|e| CliError::Usage(format!("querying init at {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn fetch(_path: &std::path::Path) -> Result<InitStatus, CliError> {
    Err(CliError::NotRouter)
}

#[cfg(test)]
mod tests {
    use owr_init::client::ServiceInfo;

    use super::*;

    fn service(name: &str, state: &str, pid: Option<u32>) -> ServiceInfo {
        ServiceInfo {
            name: name.to_owned(),
            state: state.to_owned(),
            pid,
            since_unix: 0,
            restarts: 0,
            failures: 0,
            oneshot: false,
            healthy: None,
        }
    }

    #[test]
    fn prints_services_table() {
        let mut api = service("owr-api", "running", Some(42));
        api.restarts = 1;
        api.healthy = Some(false);
        let mut hostapd = service("hostapd", "stopped", None);
        hostapd.failures = 3;
        let status = InitStatus {
            uptime_ms: 12_345,
            mode: "normal".to_owned(),
            failsafe_reason: None,
            services: vec![api, hostapd],
        };
        let mut out = Vec::new();
        print_status(&mut out, &status).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("mode normal, up 12s\n"), "{text}");
        assert!(
            text.contains("owr-api") && text.contains("unhealthy"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("hostapd") && l.contains(" - ")),
            "{text}"
        );
    }

    #[test]
    fn failsafe_reason_is_shown() {
        let status = InitStatus {
            uptime_ms: 0,
            mode: "failsafe".to_owned(),
            failsafe_reason: Some("button".to_owned()),
            services: Vec::new(),
        };
        let mut out = Vec::new();
        print_status(&mut out, &status).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("failsafe: button\n"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn fetch_speaks_the_line_protocol() {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&conn).read_line(&mut line).unwrap();
            assert_eq!(line, "status\n");
            conn.write_all(
                b"{\"ok\":true,\"uptime_ms\":1000,\"mode\":\"normal\",\"failsafe_reason\":null,\"services\":[]}\n",
            )
            .unwrap();
        });
        let status = fetch(&path).unwrap();
        assert_eq!((status.mode.as_str(), status.uptime_ms), ("normal", 1000));
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refused_status_is_an_error() {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("init.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            BufReader::new(&conn).read_line(&mut String::new()).unwrap();
            conn.write_all(b"{\"ok\":false,\"error\":\"busy\"}\n")
                .unwrap();
        });
        let err = fetch(&path).unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fetch_reports_a_missing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let err = fetch(&dir.path().join("nope.sock")).unwrap_err();
        assert!(err.to_string().contains("connecting to"), "{err}");
    }
}
