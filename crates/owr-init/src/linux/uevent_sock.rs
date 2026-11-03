//! Netlink uevent listener and coldplug.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::thread;

use owr_board::Board;
use rustix::io::Errno;
use rustix::net::netlink::{KOBJECT_UEVENT, SocketAddrNetlink};
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, bind, recvfrom, socket_with};
use tokio::sync::{broadcast, mpsc};

use super::buttons::{open_input, spawn_reader};
use super::fdwatch::wait_readable;
use super::runtime::Msg;
use crate::button::ButtonBinding;
use crate::coldplug::{DEFAULT_LIMITS, ReplayBudget, walk_uevent_files};
use crate::uevent::{UeventAction, classify, is_gpio_keys_name, parse_uevent};

/// Kernel uevent multicast group.
const KERNEL_GROUP: u32 = 1;
const BUF: usize = 16 * 1024;
/// Socket receive queue size requested from the kernel.
const RECV_BUFFER: usize = 1 << 20;

/// Open the listener and dispatch events from a background thread. The socket is bound before
/// this returns, so a following [`coldplug`] cannot miss events.
pub(super) fn spawn(
    board: Option<&Board>,
    net_events: broadcast::Sender<String>,
    tx: mpsc::Sender<Msg>,
) -> io::Result<()> {
    let fd = socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(KOBJECT_UEVENT),
    )
    .map_err(io::Error::from)?;
    bind(&fd, &SocketAddrNetlink::new(0, KERNEL_GROUP)).map_err(io::Error::from)?;
    // A larger queue survives the coldplug burst. SO_RCVBUFFORCE ignores `rmem_max` (PID 1 has
    // CAP_NET_ADMIN); if it is refused fall back to SO_RCVBUF, which the kernel may clamp.
    if let Err(e) = rustix::net::sockopt::set_socket_recv_buffer_size_force(&fd, RECV_BUFFER) {
        tracing::debug!("SO_RCVBUFFORCE refused ({e}); using SO_RCVBUF");
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(&fd, RECV_BUFFER);
    }
    let bindings = button_bindings(board);
    thread::Builder::new()
        .name("uevent".into())
        .spawn(move || run(&fd, &bindings, &net_events, &tx))?;
    Ok(())
}

/// Write `add` to every `uevent` file under `/sys/devices` so the kernel replays events.
pub(super) fn coldplug() {
    let stats = walk_uevent_files(Path::new("/sys/devices"), DEFAULT_LIMITS, |p| {
        // Individual failures are normal (read-only attributes, devices vanishing).
        let _ = fs::write(p, "add");
    });
    tracing::info!(
        "coldplug: {} uevent files triggered{}",
        stats.uevent_files,
        if stats.truncated {
            " (walk truncated by limits)"
        } else {
            ""
        }
    );
}

fn button_bindings(board: Option<&Board>) -> Vec<ButtonBinding> {
    board
        .iter()
        .flat_map(|b| b.buttons.iter())
        .filter_map(|b| {
            let binding = ButtonBinding::from_board(b);
            if binding.is_none() {
                tracing::warn!("button {}: unknown keycode {:?}", b.name, b.keycode);
            }
            binding
        })
        .collect()
}

fn run(
    fd: &OwnedFd,
    bindings: &[ButtonBinding],
    net_events: &broadcast::Sender<String>,
    tx: &mpsc::Sender<Msg>,
) {
    let mut opened: HashSet<String> = HashSet::new();
    let mut replays = ReplayBudget::new();
    let mut buf = vec![0u8; BUF];
    loop {
        match wait_readable(fd) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::error!("uevent poll failed: {e}");
                return;
            }
        }
        loop {
            match recvfrom(fd, &mut *buf, RecvFlags::empty()) {
                Ok((n, _full, addr)) => {
                    // Only the kernel (netlink port 0) may announce devices.
                    let from_kernel = addr
                        .and_then(|a| SocketAddrNetlink::try_from(a).ok())
                        .is_some_and(|a| a.pid() == 0);
                    if from_kernel {
                        handle(
                            buf.get(..n).unwrap_or_default(),
                            bindings,
                            &mut opened,
                            net_events,
                            tx,
                        );
                    }
                }
                Err(Errno::AGAIN) => break,
                Err(Errno::NOBUFS) => {
                    if replays.take() {
                        // Lost events may include device additions: replay them once. This
                        // thread owns the socket, so the blocking walk only delays dispatch.
                        tracing::warn!(
                            "uevent queue overflowed; events were lost, re-running coldplug"
                        );
                        coldplug();
                    } else {
                        tracing::warn!("uevent queue overflowed again; events were lost");
                    }
                }
                Err(e) => {
                    tracing::error!("uevent receive failed: {e}");
                    return;
                }
            }
        }
    }
}

fn handle(
    datagram: &[u8],
    bindings: &[ButtonBinding],
    opened: &mut HashSet<String>,
    net_events: &broadcast::Sender<String>,
    tx: &mpsc::Sender<Msg>,
) {
    let Ok(ev) = parse_uevent(datagram) else {
        return;
    };
    match classify(&ev) {
        UeventAction::NetAdd { ifname } => {
            tracing::debug!("uevent: net add {ifname}");
            // No subscribers is fine; owr-apply will listen later.
            let _ = net_events.send(ifname);
        }
        UeventAction::InputNode { devnode, name_path } => {
            let is_keys = fs::read_to_string(&name_path).is_ok_and(|n| is_gpio_keys_name(&n));
            if !is_keys || bindings.is_empty() || !opened.insert(devnode.clone()) {
                return;
            }
            let started = open_input(Path::new(&devnode)).and_then(|fd| {
                spawn_reader(fd, bindings.to_vec(), tx.clone(), devnode.clone().into())
            });
            match started {
                Ok(()) => tracing::info!("watching buttons on {devnode}"),
                Err(e) => {
                    opened.remove(&devnode);
                    tracing::warn!("{devnode}: {e}");
                }
            }
        }
        UeventAction::Ignore => {}
    }
}
