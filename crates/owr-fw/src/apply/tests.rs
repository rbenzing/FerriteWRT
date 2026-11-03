use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;
use crate::fixtures::{basic, rule};

/// Fake `nft`: records one line per invocation to `<dir>/calls`, then runs `body`.
fn fake_nft(dir: &Path, body: &str) -> PathBuf {
    let calls = dir.join("calls");
    let script = format!("#!/bin/sh\necho \"$@\" >> {}\n{body}\n", calls.display());
    let path = dir.join("fake-nft");
    fs::write(&path, script).expect("write fake nft");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

fn nft_parts(err: &ApplyError) -> (&ExitStatus, &str) {
    match err {
        ApplyError::Nft { status, stderr } => Some((status, stderr.as_str())),
        _ => None,
    }
    .expect("expected ApplyError::Nft")
}

fn call_count(dir: &Path) -> usize {
    fs::read_to_string(dir.join("calls")).map_or(0, |s| s.lines().count())
}

fn run_dir(dir: &Path) -> PathBuf {
    let run = dir.join("run");
    fs::create_dir_all(&run).expect("mkdir run");
    run
}

#[tokio::test]
async fn first_apply_runs_nft_and_second_is_a_noop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let rs = basic();

    let first = apply(&rs, &nft, &run).await.expect("first apply");
    assert!(first.changed);
    assert_eq!(first.bytes, render(&rs).expect("render").len());
    assert_eq!(call_count(tmp.path()), 1);

    let second = apply(&rs, &nft, &run).await.expect("second apply");
    assert!(!second.changed);
    assert_eq!(second.bytes, first.bytes);
    assert_eq!(
        call_count(tmp.path()),
        2,
        "only the table liveness probe may run, not a reload"
    );
}

#[tokio::test]
async fn nft_is_invoked_with_f_and_the_script_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    apply(&basic(), &nft, &run).await.expect("apply");
    let calls = fs::read_to_string(tmp.path().join("calls")).expect("calls");
    assert_eq!(
        calls.trim(),
        format!("-f {}", run.join("firewall.nft").display())
    );
}

#[tokio::test]
async fn script_file_has_rendered_content_and_private_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let rs = basic();
    apply(&rs, &nft, &run).await.expect("apply");
    let script = run.join("firewall.nft");
    assert_eq!(
        fs::read_to_string(&script).expect("read"),
        render(&rs).expect("render")
    );
    let mode = fs::metadata(&script).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn changed_ruleset_is_applied_again() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let mut rs = basic();
    apply(&rs, &nft, &run).await.expect("first");
    rs.rules.push(rule("new rule"));
    let again = apply(&rs, &nft, &run).await.expect("second");
    assert!(again.changed);
    assert_eq!(call_count(tmp.path()), 2);
}

#[tokio::test]
async fn missing_marker_forces_reapply_even_if_script_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let rs = basic();
    apply(&rs, &nft, &run).await.expect("first");
    fs::remove_file(run.join("firewall.applied")).expect("remove marker");
    assert!(apply(&rs, &nft, &run).await.expect("second").changed);
    assert_eq!(call_count(tmp.path()), 2);
}

#[tokio::test]
async fn nft_failure_reports_status_and_stderr_and_is_retried() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "echo 'syntax error near foo' >&2; exit 3");
    let run = run_dir(tmp.path());
    let rs = basic();

    let err = apply(&rs, &nft, &run).await.expect_err("must fail");
    let (status, stderr) = nft_parts(&err);
    assert_eq!(status.code(), Some(3));
    assert_eq!(stderr, "syntax error near foo");
    assert!(
        !run.join("firewall.applied").exists(),
        "no marker after failure"
    );

    assert!(apply(&rs, &nft, &run).await.is_err());
    assert_eq!(call_count(tmp.path()), 2, "failed apply must be retried");
}

#[tokio::test]
async fn stderr_is_truncated_to_4_kib() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(
        tmp.path(),
        "head -c 20000 /dev/zero | tr '\\0' x >&2; exit 1",
    );
    let run = run_dir(tmp.path());
    let err = apply(&basic(), &nft, &run).await.expect_err("must fail");
    let (_, stderr) = nft_parts(&err);
    assert!(stderr.starts_with("xxxx"));
    assert!(stderr.ends_with("[truncated]"));
    assert!(stderr.len() <= 4096 + " [truncated]".len());
}

#[tokio::test]
async fn hung_nft_times_out() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exec sleep 30");
    let run = run_dir(tmp.path());
    let err = apply_with_timeout(&basic(), &nft, &run, Duration::from_millis(200))
        .await
        .expect_err("must time out");
    assert!(matches!(err, ApplyError::Timeout(_)), "{err}");
    assert!(!run.join("firewall.applied").exists());
}

#[tokio::test]
async fn missing_binary_is_a_spawn_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run = run_dir(tmp.path());
    let err = apply(&basic(), &tmp.path().join("no-such-nft"), &run)
        .await
        .expect_err("must fail");
    assert!(matches!(err, ApplyError::Spawn { .. }), "{err}");
}

#[tokio::test]
async fn invalid_ruleset_never_reaches_nft() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let mut rs = basic();
    rs.options.table_name = "bad name".to_owned();
    let err = apply(&rs, &nft, &run).await.expect_err("must fail");
    assert!(matches!(err, ApplyError::Render(_)), "{err}");
    assert_eq!(call_count(tmp.path()), 0);
    assert!(!run.join("firewall.nft").exists());
}

#[tokio::test]
async fn check_feeds_script_on_stdin_with_dash_c() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let stdin_copy = tmp.path().join("stdin");
    let nft = fake_nft(tmp.path(), &format!("cat > {}", stdin_copy.display()));
    let rs = basic();
    check(&rs, &nft).await.expect("check");
    let calls = fs::read_to_string(tmp.path().join("calls")).expect("calls");
    assert_eq!(calls.trim(), "-c -f -");
    assert_eq!(
        fs::read_to_string(stdin_copy).expect("stdin"),
        render(&rs).expect("render")
    );
}

#[tokio::test]
async fn check_reports_nft_errors() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "cat > /dev/null; echo bad >&2; exit 1");
    let err = check(&basic(), &nft).await.expect_err("must fail");
    assert!(
        matches!(err, ApplyError::Nft { ref stderr, .. } if stderr == "bad"),
        "{err}"
    );
}

#[tokio::test]
async fn check_tolerates_nft_exiting_without_reading_stdin() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "echo early >&2; exit 2");
    let err = check(&basic(), &nft).await.expect_err("must fail");
    assert!(
        matches!(err, ApplyError::Nft { ref stderr, .. } if stderr == "early"),
        "{err}"
    );
}

#[tokio::test]
async fn noop_apply_confirms_table_with_nft_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    let rs = basic();
    apply(&rs, &nft, &run).await.expect("first");
    apply(&rs, &nft, &run).await.expect("second");
    let calls = fs::read_to_string(tmp.path().join("calls")).expect("calls");
    assert_eq!(calls.lines().last(), Some("list table inet owr"));
}

#[tokio::test]
async fn externally_flushed_table_is_reloaded_despite_matching_marker() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // `nft list table` fails (table gone); everything else succeeds.
    let nft = fake_nft(
        tmp.path(),
        "if [ \"$1\" = list ]; then echo 'No such file or directory' >&2; exit 1; fi; exit 0",
    );
    let run = run_dir(tmp.path());
    let rs = basic();
    assert!(apply(&rs, &nft, &run).await.expect("first").changed);
    let second = apply(&rs, &nft, &run).await.expect("second");
    assert!(second.changed, "must reload when the table is missing");
    let calls = fs::read_to_string(tmp.path().join("calls")).expect("calls");
    let calls: Vec<&str> = calls.lines().collect();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(calls.get(1), Some(&"list table inet owr"));
    assert!(calls.get(2).is_some_and(|c| c.starts_with("-f ")));
}

#[tokio::test]
async fn marker_is_the_lowercase_hex_sha256_of_the_script() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nft = fake_nft(tmp.path(), "exit 0");
    let run = run_dir(tmp.path());
    apply(&basic(), &nft, &run).await.expect("apply");
    let marker = fs::read_to_string(run.join("firewall.applied")).expect("marker");
    assert_eq!(marker.len(), 64);
    assert!(
        marker
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(hex(&[0x00, 0x0f, 0xab]), "000fab");
}
