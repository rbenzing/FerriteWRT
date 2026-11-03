//! Linux-only system interfaces: sysfs phy discovery and the hostapd control client.

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::model::MacAddr;

pub mod ctrl;

pub use crate::config_file::write_config;

const SYSFS_IEEE80211: &str = "/sys/class/ieee80211";

/// Errors from sysfs discovery and the control client.
#[derive(Debug, thiserror::Error)]
pub enum SysError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path}: unparsable phy index {value:?}")]
    BadIndex { path: PathBuf, value: String },
    #[error("no phy with index {0}")]
    NoPhy(u8),
    #[error("invalid hostapd interface name {0:?}")]
    BadIfname(String),
    #[error("hostapd did not answer within {0:?}")]
    Timeout(std::time::Duration),
    #[error("hostapd reply larger than {0} bytes")]
    ReplyTooLarge(usize),
    #[error("hostapd rejected the command: {0}")]
    Rejected(String),
    #[error(transparent)]
    Reply(#[from] crate::reply::ReplyError),
}

/// One wireless phy found under `/sys/class/ieee80211`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhyInfo {
    /// Kernel name, e.g. `phy0`.
    pub name: String,
    /// Wiphy index (the `N` of `phyN` unless renamed).
    pub index: u32,
    /// Bound driver (`device/driver` link basename), `"unknown"` when not bound (e.g. hwsim).
    pub driver: String,
    pub mac: Option<MacAddr>,
}

/// List all phys, sorted by index.
pub fn discover_phys() -> Result<Vec<PhyInfo>, SysError> {
    discover_phys_in(Path::new(SYSFS_IEEE80211))
}

/// Name of the phy whose wiphy index is `idx` (board descriptors address radios by index).
pub fn phy_for_index(idx: u8) -> Result<String, SysError> {
    discover_phys()?
        .into_iter()
        .find(|p| p.index == u32::from(idx))
        .map(|p| p.name)
        .ok_or(SysError::NoPhy(idx))
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> SysError + '_ {
    move |source| SysError::Io {
        path: path.to_path_buf(),
        source,
    }
}

pub(crate) fn discover_phys_in(root: &Path) -> Result<Vec<PhyInfo>, SysError> {
    let mut phys = Vec::new();
    for entry in fs::read_dir(root).map_err(io_err(root))? {
        let entry = entry.map_err(io_err(root))?;
        let dir = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let index_path = dir.join("index");
        let raw = fs::read_to_string(&index_path).map_err(io_err(&index_path))?;
        let index = raw.trim().parse().map_err(|_| SysError::BadIndex {
            path: index_path.clone(),
            value: raw.trim().to_owned(),
        })?;
        let driver = fs::read_link(dir.join("device/driver"))
            .ok()
            .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "unknown".to_owned());
        let mac = fs::read_to_string(dir.join("macaddress"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        phys.push(PhyInfo {
            name,
            index,
            driver,
            mac,
        });
    }
    phys.sort_by(|a, b| a.index.cmp(&b.index).then_with(|| a.name.cmp(&b.name)));
    Ok(phys)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use std::os::unix::fs::symlink;

    use super::*;

    fn fake_phy(root: &Path, name: &str, index: &str, driver: Option<&str>, mac: Option<&str>) {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("device")).unwrap();
        fs::write(dir.join("index"), format!("{index}\n")).unwrap();
        if let Some(mac) = mac {
            fs::write(dir.join("macaddress"), format!("{mac}\n")).unwrap();
        }
        if let Some(driver) = driver {
            // Outside `root`: every entry under the sysfs root is a phy.
            let target = root.with_file_name("drivers").join(driver);
            fs::create_dir_all(&target).unwrap();
            symlink(&target, dir.join("device/driver")).unwrap();
        }
    }

    #[test]
    fn discovers_and_sorts_phys() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ieee80211");
        fake_phy(
            &root,
            "phy1",
            "1",
            Some("mt7915e"),
            Some("02:00:00:00:00:02"),
        );
        fake_phy(
            &root,
            "phy0",
            "0",
            Some("mt7915e"),
            Some("02:00:00:00:00:01"),
        );
        let phys = discover_phys_in(&root).unwrap();
        assert_eq!(phys.len(), 2);
        assert_eq!(phys[0].name, "phy0");
        assert_eq!(phys[0].driver, "mt7915e");
        assert_eq!(phys[0].mac, Some(MacAddr([2, 0, 0, 0, 0, 1])));
        assert_eq!(phys[1].index, 1);
    }

    #[test]
    fn missing_driver_and_mac_are_tolerated() {
        let tmp = tempfile::tempdir().unwrap();
        fake_phy(tmp.path(), "phy0", "0", None, None);
        let phys = discover_phys_in(tmp.path()).unwrap();
        assert_eq!(phys[0].driver, "unknown");
        assert_eq!(phys[0].mac, None);
    }

    #[test]
    fn bad_index_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        fake_phy(tmp.path(), "phy0", "zero", None, None);
        assert!(matches!(
            discover_phys_in(tmp.path()),
            Err(SysError::BadIndex { .. })
        ));
    }

    #[test]
    fn missing_root_is_an_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            discover_phys_in(&tmp.path().join("nope")),
            Err(SysError::Io { .. })
        ));
    }
}
