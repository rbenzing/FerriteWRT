//! Reading `gpio-keys` evdev nodes and the boot-time failsafe button check.

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

use owr_board::Board;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use tokio::sync::mpsc;

use super::fdwatch::wait_readable;
use super::runtime::Msg;
use crate::boot::ButtonWindow;
use crate::button::{
    ButtonBinding, INPUT_EVENT_SIZE, KEY_RESTART, keycode_from_name, parse_input_event,
};
use crate::uevent::is_gpio_keys_name;

/// Open an evdev node non-blocking.
pub(super) fn open_input(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

/// Feed events from one evdev node to the board's buttons from a background thread, until the
/// device goes away or init stops listening.
pub(super) fn spawn_reader(
    fd: OwnedFd,
    bindings: Vec<ButtonBinding>,
    tx: mpsc::Sender<Msg>,
    devnode: PathBuf,
) -> io::Result<()> {
    thread::Builder::new()
        .name("buttons".into())
        .spawn(move || read_loop(&fd, bindings, &tx, &devnode))?;
    Ok(())
}

fn read_loop(fd: &OwnedFd, mut bindings: Vec<ButtonBinding>, tx: &mpsc::Sender<Msg>, dev: &Path) {
    let mut buf = vec![0u8; INPUT_EVENT_SIZE * 32];
    loop {
        match wait_readable(fd) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!("{}: {e}", dev.display());
                return;
            }
        }
        loop {
            let n = match rustix::io::read(fd, &mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(Errno::AGAIN) => break,
                Err(e) => {
                    // ENODEV: the device was unplugged.
                    tracing::info!("{}: input reader stopped: {e}", dev.display());
                    return;
                }
            };
            for rec in buf
                .get(..n)
                .unwrap_or_default()
                .as_chunks::<INPUT_EVENT_SIZE>()
                .0
            {
                let Some(ev) = parse_input_event(rec) else {
                    continue;
                };
                for b in &mut bindings {
                    if let Some((press, action)) = b.feed(ev) {
                        let msg = Msg::Button {
                            name: b.name.clone(),
                            press,
                            action,
                        };
                        if tx.blocking_send(msg).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// `/dev/input/eventN` nodes of every `gpio-keys` input device.
pub(super) fn gpio_key_nodes() -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir("/sys/class/input") else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    for dev in rd.filter_map(Result::ok) {
        let is_keys =
            fs::read_to_string(dev.path().join("name")).is_ok_and(|n| is_gpio_keys_name(&n));
        if !is_keys {
            continue;
        }
        let Ok(children) = fs::read_dir(dev.path()) else {
            continue;
        };
        for child in children.filter_map(Result::ok) {
            let name = child.file_name();
            if name.to_string_lossy().starts_with("event") {
                nodes.push(Path::new("/dev/input").join(name));
            }
        }
    }
    nodes.sort();
    nodes
}

/// Was a failsafe button (the board's reset key) pressed within the boot window?
///
/// The window ([`ButtonWindow`]) starts once the `gpio-keys` devices are open, and the function
/// returns immediately when there is none. Only a *press event* inside the window counts: the
/// kernel does not replay the state of a key that was already held when the device was opened
/// (reading it needs the `EVIOCGKEY` ioctl, which is unavailable without `unsafe`).
pub(super) fn button_pressed_in_window(board: &Board) -> bool {
    let codes: Vec<u16> = board
        .buttons
        .iter()
        .filter(|b| b.name == "reset" || keycode_from_name(&b.keycode) == Some(KEY_RESTART))
        .filter_map(|b| keycode_from_name(&b.keycode))
        .collect();
    let fds: Vec<OwnedFd> = gpio_key_nodes()
        .iter()
        .filter_map(|p| open_input(p).ok())
        .collect();
    if codes.is_empty() || fds.is_empty() {
        return false;
    }
    let window = ButtonWindow::open(Instant::now());
    let mut buf = vec![0u8; INPUT_EVENT_SIZE * 16];
    loop {
        if !window.is_open(Instant::now()) {
            return false;
        }
        for fd in &fds {
            // EAGAIN (nothing queued) and transient errors both mean "no press yet".
            let Ok(n) = rustix::io::read(fd, &mut buf) else {
                continue;
            };
            let pressed = buf
                .get(..n)
                .unwrap_or_default()
                .as_chunks::<INPUT_EVENT_SIZE>()
                .0
                .iter()
                .filter_map(|rec| parse_input_event(rec))
                .any(|ev| ev.value == 1 && codes.contains(&ev.code));
            if pressed {
                return true;
            }
        }
        sleep(Duration::from_millis(20));
    }
}
