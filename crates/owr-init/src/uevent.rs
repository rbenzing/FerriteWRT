//! Kernel uevent parsing and classification (pure).
//!
//! The kernel multicasts `"ACTION@DEVPATH\0KEY=VALUE\0..."` datagrams on
//! `NETLINK_KOBJECT_UEVENT` group 1. Init reacts to two things only:
//! * `SUBSYSTEM=net ACTION=add`: announce the interface so `owr-apply` can re-converge,
//! * `SUBSYSTEM=input` event nodes: candidates for the `gpio-keys` button reader.
//!
//! Everything else is ignored, including `SUBSYSTEM=firmware`: with
//! `CONFIG_FW_LOADER_USER_HELPER` off the kernel loads firmware from `/lib/firmware` itself.

use std::collections::BTreeMap;

/// Upper bound on variables kept per event (a hostile or buggy sender cannot grow memory).
const MAX_VARS: usize = 128;

/// A decoded uevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uevent {
    pub action: String,
    pub devpath: String,
    pub vars: BTreeMap<String, String>,
}

impl Uevent {
    pub fn var(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn subsystem(&self) -> Option<&str> {
        self.var("SUBSYSTEM")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UeventError {
    #[error("empty uevent datagram")]
    Empty,
    /// udev-formatted (`libudev\0`) rebroadcast, not a kernel event.
    #[error("libudev message")]
    Libudev,
    #[error("missing ACTION@DEVPATH header")]
    NoHeader,
}

/// Decode a uevent datagram.
pub fn parse_uevent(buf: &[u8]) -> Result<Uevent, UeventError> {
    if buf.is_empty() {
        return Err(UeventError::Empty);
    }
    if buf.starts_with(b"libudev\0") {
        return Err(UeventError::Libudev);
    }
    let mut parts = buf.split(|b| *b == 0).filter(|p| !p.is_empty());
    let header = String::from_utf8_lossy(parts.next().ok_or(UeventError::Empty)?);
    let (action, devpath) = header.split_once('@').ok_or(UeventError::NoHeader)?;
    if action.is_empty() || !devpath.starts_with('/') {
        return Err(UeventError::NoHeader);
    }
    let mut vars = BTreeMap::new();
    for part in parts.take(MAX_VARS) {
        let text = String::from_utf8_lossy(part);
        if let Some((k, v)) = text.split_once('=') {
            vars.insert(k.to_owned(), v.to_owned());
        }
    }
    Ok(Uevent {
        action: action.to_owned(),
        devpath: devpath.to_owned(),
        vars,
    })
}

/// What init does with an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UeventAction {
    /// A network interface appeared.
    NetAdd {
        ifname: String,
    },
    /// An input event node appeared; read `name_path` to see if it is `gpio-keys`.
    InputNode {
        devnode: String,
        name_path: String,
    },
    Ignore,
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && !s.contains(['/', ' ']) && s != "." && s != ".."
}

fn safe_devpath(p: &str) -> bool {
    p.starts_with('/') && !p.split('/').any(|c| c == "..")
}

pub fn classify(ev: &Uevent) -> UeventAction {
    if ev.action != "add" {
        return UeventAction::Ignore;
    }
    match ev.subsystem() {
        Some("net") => match ev.var("INTERFACE") {
            Some(i) if valid_ifname(i) => UeventAction::NetAdd {
                ifname: i.to_owned(),
            },
            _ => UeventAction::Ignore,
        },
        Some("input") => match ev.var("DEVNAME") {
            Some(n)
                if n.starts_with("input/event")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/')
                    && safe_devpath(&ev.devpath) =>
            {
                UeventAction::InputNode {
                    devnode: format!("/dev/{n}"),
                    name_path: format!("/sys{}/../name", ev.devpath),
                }
            }
            _ => UeventAction::Ignore,
        },
        _ => UeventAction::Ignore,
    }
}

/// Does the sysfs `name` of an input device identify a `gpio-keys` button device?
pub fn is_gpio_keys_name(name: &str) -> bool {
    let n = name.trim();
    n.contains("gpio-keys") || n.contains("gpio_keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(parts: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend(p.as_bytes());
            v.push(0);
        }
        v
    }

    fn classify_msg(parts: &[&str]) -> UeventAction {
        classify(&parse_uevent(&msg(parts)).unwrap())
    }

    #[test]
    fn parses_net_add() {
        let ev = parse_uevent(&msg(&[
            "add@/devices/platform/soc/1b100000.ethernet/net/eth0",
            "ACTION=add",
            "DEVPATH=/devices/platform/soc/1b100000.ethernet/net/eth0",
            "SUBSYSTEM=net",
            "INTERFACE=eth0",
            "IFINDEX=2",
            "SEQNUM=1234",
        ]))
        .unwrap();
        assert_eq!(ev.action, "add");
        assert_eq!(
            ev.devpath,
            "/devices/platform/soc/1b100000.ethernet/net/eth0"
        );
        assert_eq!(ev.subsystem(), Some("net"));
        assert_eq!(ev.var("IFINDEX"), Some("2"));
        assert_eq!(
            classify(&ev),
            UeventAction::NetAdd {
                ifname: "eth0".into()
            }
        );
    }

    #[test]
    fn only_add_triggers_actions() {
        for action in ["remove", "change", "bind"] {
            let head = format!("{action}@/devices/net/eth0");
            assert_eq!(
                classify_msg(&[&head, "SUBSYSTEM=net", "INTERFACE=eth0"]),
                UeventAction::Ignore
            );
        }
    }

    #[test]
    fn firmware_and_other_subsystems_are_ignored() {
        assert_eq!(
            classify_msg(&[
                "add@/devices/x",
                "SUBSYSTEM=firmware",
                "FIRMWARE=mt7986.bin"
            ]),
            UeventAction::Ignore
        );
        assert_eq!(
            classify_msg(&["add@/devices/x", "SUBSYSTEM=block", "DEVNAME=mmcblk0"]),
            UeventAction::Ignore
        );
        assert_eq!(classify_msg(&["add@/devices/x"]), UeventAction::Ignore);
    }

    #[test]
    fn input_event_node_becomes_candidate() {
        assert_eq!(
            classify_msg(&[
                "add@/devices/platform/gpio-keys/input/input0/event0",
                "SUBSYSTEM=input",
                "DEVNAME=input/event0",
                "MAJOR=13",
            ]),
            UeventAction::InputNode {
                devnode: "/dev/input/event0".into(),
                name_path: "/sys/devices/platform/gpio-keys/input/input0/event0/../name".into(),
            }
        );
    }

    #[test]
    fn input_parent_device_without_devname_is_ignored() {
        assert_eq!(
            classify_msg(&[
                "add@/devices/platform/gpio-keys/input/input0",
                "SUBSYSTEM=input",
                "NAME=\"gpio-keys\"",
            ]),
            UeventAction::Ignore
        );
    }

    #[test]
    fn hostile_paths_and_names_are_rejected() {
        let bad = [
            [
                "add@/devices/../../etc",
                "SUBSYSTEM=input",
                "DEVNAME=input/event0",
            ],
            [
                "add@/devices/x",
                "SUBSYSTEM=input",
                "DEVNAME=input/../../etc/passwd",
            ],
            ["add@/devices/x", "SUBSYSTEM=net", "INTERFACE=a/b"],
            [
                "add@/devices/x",
                "SUBSYSTEM=net",
                "INTERFACE=aaaaaaaaaaaaaaaaaaaa",
            ],
        ];
        for parts in bad {
            assert_eq!(classify_msg(&parts), UeventAction::Ignore, "{parts:?}");
        }
    }

    #[test]
    fn malformed_datagrams_error() {
        assert_eq!(parse_uevent(b""), Err(UeventError::Empty));
        assert_eq!(parse_uevent(b"\0\0"), Err(UeventError::Empty));
        assert_eq!(
            parse_uevent(b"libudev\0\xfe\xed\xca\xfe"),
            Err(UeventError::Libudev)
        );
        assert_eq!(parse_uevent(b"nohdr\0A=b\0"), Err(UeventError::NoHeader));
        assert_eq!(parse_uevent(b"@/dev\0"), Err(UeventError::NoHeader));
        assert_eq!(parse_uevent(b"add@relative\0"), Err(UeventError::NoHeader));
    }

    #[test]
    fn tolerates_missing_trailing_nul_non_utf8_and_junk_vars() {
        let ev = parse_uevent(b"add@/d\0K=v\0junk\0X=\xff\xfe\0LAST=1").unwrap();
        assert_eq!(ev.var("K"), Some("v"));
        assert_eq!(ev.var("LAST"), Some("1"));
        assert!(ev.var("X").is_some());
        assert!(ev.var("junk").is_none());
    }

    #[test]
    fn variable_count_is_bounded() {
        let mut buf = b"add@/d\0".to_vec();
        for i in 0..1000 {
            buf.extend(format!("K{i}=v\0").as_bytes());
        }
        assert_eq!(parse_uevent(&buf).unwrap().vars.len(), MAX_VARS);
    }

    #[test]
    fn gpio_keys_name_detection() {
        assert!(is_gpio_keys_name("gpio-keys\n"));
        assert!(is_gpio_keys_name("gpio-keys-polled"));
        assert!(!is_gpio_keys_name("Logitech USB Keyboard"));
        assert!(!is_gpio_keys_name(""));
    }
}
