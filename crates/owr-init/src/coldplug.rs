//! Bounded coldplug walk: find every `uevent` file under a sysfs tree so the runtime can
//! write `add` to it and make the kernel replay events for devices that exist already.
//!
//! The walk never follows symlinks and is bounded in depth and entry count, so a pathological
//! or looping tree cannot stall PID 1.

use std::fs;
use std::path::{Path, PathBuf};

/// Limits for [`walk_uevent_files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_entries: usize,
}

/// Generous for a router (a few thousand sysfs entries), tight enough to bound a bad tree.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_depth: 16,
    max_entries: 50_000,
};

/// How many times a lost-events overflow (`ENOBUFS` on the uevent socket) triggers another
/// coldplug. Bounded: the replay itself produces a burst, so an unbounded retry could feed
/// itself forever.
pub const MAX_OVERFLOW_REPLAYS: u32 = 1;

/// Bounded counter of overflow-triggered replays.
#[derive(Debug, Clone, Copy)]
pub struct ReplayBudget {
    left: u32,
}

impl ReplayBudget {
    pub fn new() -> Self {
        Self {
            left: MAX_OVERFLOW_REPLAYS,
        }
    }

    /// `true` once per available replay; `false` when the budget is spent.
    pub fn take(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left = self.left.saturating_sub(1);
        true
    }
}

impl Default for ReplayBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub entries: usize,
    pub uevent_files: usize,
    /// A limit was hit before the walk finished.
    pub truncated: bool,
}

/// Visit every regular file named `uevent` below `root` (depth-first, names sorted).
pub fn walk_uevent_files(root: &Path, limits: Limits, mut visit: impl FnMut(&Path)) -> WalkStats {
    let mut stats = WalkStats::default();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        // Reverse so the stack pops in sorted order.
        for entry in entries.into_iter().rev() {
            stats.entries = stats.entries.saturating_add(1);
            if stats.entries > limits.max_entries {
                stats.truncated = true;
                return stats;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                if depth < limits.max_depth {
                    stack.push((entry.path(), depth.saturating_add(1)));
                } else {
                    stats.truncated = true;
                }
            } else if ft.is_file() && entry.file_name() == "uevent" {
                stats.uevent_files = stats.uevent_files.saturating_add(1);
                visit(&entry.path());
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_replay_is_bounded_to_one() {
        let mut b = ReplayBudget::new();
        assert!(b.take(), "the first overflow re-runs coldplug");
        assert!(!b.take(), "a second one must not loop");
        assert!(!b.take());
    }

    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "").unwrap();
    }

    fn rels(root: &Path, limits: Limits) -> (Vec<String>, WalkStats) {
        let mut seen = Vec::new();
        let stats = walk_uevent_files(root, limits, |p| {
            seen.push(
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        });
        (seen, stats)
    }

    #[test]
    fn finds_uevent_files_only_in_sorted_order() {
        let d = tempfile::tempdir().unwrap();
        touch(d.path(), "b/uevent");
        touch(d.path(), "a/x/uevent");
        touch(d.path(), "a/other");
        touch(d.path(), "uevent");
        touch(d.path(), "a/uevent");
        let (seen, stats) = rels(d.path(), DEFAULT_LIMITS);
        assert_eq!(seen, ["uevent", "a/uevent", "a/x/uevent", "b/uevent"]);
        assert_eq!(stats.uevent_files, 4);
        assert!(!stats.truncated);
    }

    #[test]
    fn depth_limit_truncates() {
        let d = tempfile::tempdir().unwrap();
        touch(d.path(), "a/b/c/uevent");
        touch(d.path(), "a/uevent");
        let (seen, stats) = rels(
            d.path(),
            Limits {
                max_depth: 1,
                max_entries: 100,
            },
        );
        assert_eq!(seen, ["a/uevent"]);
        assert!(stats.truncated);
    }

    #[test]
    fn entry_limit_truncates() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..20 {
            touch(d.path(), &format!("d{i:02}/uevent"));
        }
        let (seen, stats) = rels(
            d.path(),
            Limits {
                max_depth: 8,
                max_entries: 10,
            },
        );
        assert!(stats.truncated);
        assert!(seen.len() < 20);
    }

    #[test]
    fn missing_root_is_empty_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let (seen, stats) = rels(&d.path().join("nope"), DEFAULT_LIMITS);
        assert_eq!(seen, Vec::<String>::new());
        assert_eq!(stats, WalkStats::default());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loops_are_not_followed() {
        let d = tempfile::tempdir().unwrap();
        touch(d.path(), "a/uevent");
        std::os::unix::fs::symlink(d.path(), d.path().join("a/loop")).unwrap();
        let (seen, stats) = rels(d.path(), DEFAULT_LIMITS);
        assert_eq!(seen, ["a/uevent"]);
        assert!(!stats.truncated);
    }
}
