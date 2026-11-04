//! The network daemon stops on SIGTERM even while its tasks are still waiting for links.
//!
//! Its own test binary: the daemon installs process-wide signal handlers.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

use owr_apply::run::Paths;
use owr_config::{Config, LanIpv6};

#[tokio::test]
async fn stops_on_sigterm_while_waiting_for_its_links() {
    let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
    let mut cfg = Config::defaults_for(&board);
    // A DHCP WAN on eth1 and router advertisements on br-lan: neither link exists here, so
    // both tasks are in their retry loops when the signal arrives.
    cfg.network.lan.ipv6 = LanIpv6::Ula;
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths {
        run_dir: dir.path().join("run"),
        ula_file: dir.path().join("ula-prefix"),
        ..Paths::default()
    };
    let reload_board = board.clone();
    let reload_cfg = cfg.clone();
    let reload = move || Ok::<_, String>((reload_board.clone(), reload_cfg.clone()));

    let daemon =
        tokio::spawn(async move { owr_apply::daemon::run(board, cfg, reload, &paths).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!daemon.is_finished(), "the daemon runs until stopped");
    assert!(
        dir.path().join("ula-prefix").exists(),
        "the ULA prefix was created"
    );

    let pid = std::process::id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let stopped = tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .expect("stopped within the grace period")
        .unwrap();
    assert!(stopped.is_ok(), "{stopped:?}");
}
