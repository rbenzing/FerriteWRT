//! Persisting the rendered hostapd configuration.

use std::path::{Path, PathBuf};
use std::{fs, io};

use owr_common::{AtomicWriteError, Outcome, atomic_write};
use zeroize::Zeroizing;

use crate::model::RadioPlan;
use crate::render::{RenderError, render_hostapd};

/// Failure writing `hostapd-<phy>.conf`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigWriteError {
    #[error(transparent)]
    Render(#[from] RenderError),
    #[error("creating run directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Write(#[from] AtomicWriteError),
}

/// The hostapd config holds passphrases: owner read/write only.
const FILE_MODE: u32 = 0o600;

/// Render `plan` and atomically write it to `<run_dir>/hostapd-<phy>.conf` (mode 0600, it
/// contains passphrases). Returns the path and whether the file changed; the supervisor
/// restarts hostapd only on [`Outcome::Written`].
///
/// The rendered text is held in a [`Zeroizing`] buffer and wiped before returning. The mode is
/// also enforced when the content is unchanged, so a file created by an older version (or
/// loosened by hand) is tightened on the next apply.
pub fn write_config(
    plan: &RadioPlan,
    run_dir: &Path,
) -> Result<(PathBuf, Outcome), ConfigWriteError> {
    let conf = Zeroizing::new(render_hostapd(plan)?);
    fs::create_dir_all(run_dir).map_err(|source| ConfigWriteError::CreateDir {
        path: run_dir.to_path_buf(),
        source,
    })?;
    // plan.phy was validated as path-safe by render_hostapd.
    let path = run_dir.join(format!("hostapd-{}.conf", plan.phy));
    let outcome = atomic_write(&path, conf.as_bytes(), FILE_MODE)?;
    if outcome == Outcome::Unchanged {
        enforce_private_mode(&path);
    }
    Ok((path, outcome))
}

/// Best effort: a failure is logged, not fatal (the content is already in place).
#[cfg(unix)]
fn enforce_private_mode(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE)) {
        tracing::warn!(path = %path.display(), %error, "could not enforce mode 0600 on hostapd config");
    }
}

#[cfg(not(unix))]
fn enforce_private_mode(_path: &Path) {}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::validate::tests::plan_2g;

    #[test]
    fn writes_then_reports_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_2g();
        let (path, outcome) = write_config(&plan, dir.path()).unwrap();
        assert_eq!(path, dir.path().join("hostapd-phy0.conf"));
        assert_eq!(outcome, Outcome::Written);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            render_hostapd(&plan).unwrap()
        );
        let (_, again) = write_config(&plan, dir.path()).unwrap();
        assert_eq!(again, Outcome::Unchanged);
    }

    #[test]
    fn change_is_reported_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = plan_2g();
        write_config(&plan, dir.path()).unwrap();
        plan.aps[0].ssid = "other".into();
        assert_eq!(write_config(&plan, dir.path()).unwrap().1, Outcome::Written);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = write_config(&plan_2g(), dir.path()).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn unchanged_file_with_loose_mode_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_2g();
        let (path, _) = write_config(&plan, dir.path()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let (_, outcome) = write_config(&plan, dir.path()).unwrap();
        assert_eq!(outcome, Outcome::Unchanged);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn invalid_plan_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = plan_2g();
        plan.aps.clear();
        assert!(matches!(
            write_config(&plan, dir.path()),
            Err(ConfigWriteError::Render(_))
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
