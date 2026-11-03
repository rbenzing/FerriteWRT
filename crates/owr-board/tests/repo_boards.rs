//! Repository consistency: every `boards/<id>.toml` is registered, builds with its own
//! `build/openwrt/<id>.diffconfig`, and lists exactly the modules that diffconfig selects.
//! These are the mistakes a new board most often makes; catching them here costs seconds,
//! catching them in the image build costs an hour. See docs/PORTING.md.
#![allow(clippy::unwrap_used, clippy::panic)] // test helpers: fail loudly

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use owr_board::{Board, builtin_boards};

/// Repository root, or `None` when this test binary was cross-built and runs on another OS
/// (scripts/linux-tests.sh), where the host's paths are not visible. The host run covers it.
fn repo() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if root.join("boards").is_dir() {
        Some(root)
    } else {
        eprintln!("skipping: {} not visible from this OS", root.display());
        None
    }
}

/// `boards/*.toml` as `(id from the file name, file text)`.
fn board_files(root: &Path) -> BTreeMap<String, String> {
    fs::read_dir(root.join("boards"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .map(|p| {
            let id = p.file_stem().unwrap().to_string_lossy().into_owned();
            (id, fs::read_to_string(&p).unwrap())
        })
        .collect()
}

/// `symbol -> value` for every `CONFIG_X=v` and `# CONFIG_X is not set` line.
fn config_lines(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("CONFIG_") {
            if let Some((sym, val)) = rest.split_once('=') {
                out.insert(sym.to_owned(), val.to_owned());
            }
        } else if let Some(sym) = line
            .strip_prefix("# CONFIG_")
            .and_then(|r| r.strip_suffix(" is not set"))
        {
            out.insert(sym.to_owned(), "n".to_owned());
        }
    }
    out
}

fn diffconfig(root: &Path, name: &str) -> String {
    let path = root.join("build/openwrt").join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}); every board needs one, see docs/PORTING.md",
            path.display()
        )
    })
}

#[test]
fn every_board_file_is_registered_and_every_registration_has_a_file() {
    let Some(root) = repo() else { return };
    let files = board_files(&root);
    let registered: BTreeMap<&str, &str> = builtin_boards().iter().copied().collect();
    for (id, text) in &files {
        let embedded = registered.get(id.as_str()).unwrap_or_else(|| {
            panic!("boards/{id}.toml is not in owr_board::builtin_boards() (crates/owr-board/src/lib.rs)")
        });
        assert_eq!(
            embedded, text,
            "builtin_boards() entry {id:?} embeds a different file than boards/{id}.toml"
        );
        let board = Board::from_toml_str(text).unwrap();
        assert_eq!(
            &board.board.id, id,
            "boards/{id}.toml: board.id must equal the file name"
        );
    }
    for id in registered.keys() {
        assert!(
            files.contains_key(*id),
            "builtin_boards() has {id:?} but boards/{id}.toml does not exist"
        );
    }
}

#[test]
fn every_board_diffconfig_selects_its_openwrt_device() {
    let Some(root) = repo() else { return };
    for (id, text) in board_files(&root) {
        let b = Board::from_toml_str(&text).unwrap().openwrt;
        let cfg = config_lines(&diffconfig(&root, &format!("{id}.diffconfig")));
        for sym in [
            format!("TARGET_{}", b.target),
            format!("TARGET_{}_{}", b.target, b.subtarget),
            format!("TARGET_{}_{}_DEVICE_{}", b.target, b.subtarget, b.profile),
        ] {
            assert_eq!(
                cfg.get(&sym).map(String::as_str),
                Some("y"),
                "build/openwrt/{id}.diffconfig must contain CONFIG_{sym}=y"
            );
        }
    }
}

#[test]
fn board_module_lists_match_the_diffconfigs() {
    let Some(root) = repo() else { return };
    let common = config_lines(&diffconfig(&root, "common.diffconfig"));
    for (id, text) in board_files(&root) {
        let b = Board::from_toml_str(&text).unwrap().openwrt;
        let own = config_lines(&diffconfig(&root, &format!("{id}.diffconfig")));
        let listed: BTreeSet<&str> = b
            .kernel_modules
            .iter()
            .chain(&b.firmware_packages)
            .map(String::as_str)
            .collect();
        for pkg in &listed {
            let sym = format!("PACKAGE_{pkg}");
            let on = |c: &BTreeMap<String, String>| c.get(&sym).is_some_and(|v| v == "y");
            assert!(
                on(&own) || on(&common),
                "boards/{id}.toml lists {pkg:?}, but neither common.diffconfig nor \
                 {id}.diffconfig sets CONFIG_{sym}=y (built into the kernel? then drop it from the list)"
            );
        }
        for (sym, val) in &own {
            let Some(pkg) = sym.strip_prefix("PACKAGE_") else {
                continue;
            };
            let driver = pkg.starts_with("kmod-") || pkg.ends_with("-firmware");
            assert!(
                !(driver && val == "y" && !listed.contains(pkg)),
                "{id}.diffconfig selects {pkg:?}; add it to [openwrt] kernel_modules or \
                 firmware_packages in boards/{id}.toml"
            );
        }
    }
}

#[test]
fn board_diffconfigs_do_not_repeat_or_contradict_common() {
    let Some(root) = repo() else { return };
    let common = config_lines(&diffconfig(&root, "common.diffconfig"));
    for id in board_files(&root).keys() {
        let own = config_lines(&diffconfig(&root, &format!("{id}.diffconfig")));
        let shared: Vec<&String> = own.keys().filter(|s| common.contains_key(*s)).collect();
        assert!(
            shared.is_empty(),
            "{id}.diffconfig repeats symbols of common.diffconfig: {shared:?}. Drop them, or \
             move the line out of common.diffconfig if this board needs a different value"
        );
    }
}

#[test]
fn boards_satisfy_what_build_image_sh_parses() {
    let Some(root) = repo() else { return };
    for (id, text) in board_files(&root) {
        let board = Board::from_toml_str(&text).unwrap();
        assert_eq!(
            board.soc.arch, "aarch64",
            "boards/{id}.toml: the build supports aarch64 boards only today (docs/PORTING.md)"
        );
        // build-image.sh reads target, subtarget, profile and images with a line-based
        // parser: each must be a single line inside [openwrt].
        let table = text.split_once("\n[openwrt]").map_or_else(
            || panic!("boards/{id}.toml: no [openwrt] table"),
            |(_, t)| t,
        );
        for key in ["target", "subtarget", "profile", "images"] {
            let line = table
                .lines()
                .find(|l| l.split('=').next().is_some_and(|k| k.trim() == key))
                .unwrap_or_else(|| panic!("boards/{id}.toml: [openwrt] has no {key} line"));
            assert!(
                key != "images" || (line.contains('[') && line.contains(']')),
                "boards/{id}.toml: [openwrt] images must be written on one line"
            );
        }
        // build-image.sh collects "squashfs-<image>" files and matches *.bin exactly.
        for img in &board.openwrt.images {
            assert!(
                Path::new(img).extension().is_some_and(|e| e == "bin"),
                "boards/{id}.toml: image {img:?} must end in .bin"
            );
        }
    }
}
