//! `DHCPv4` client on a real UDP socket (`0.0.0.0:68`, bound to one interface).
//!
//! The state machine lives in [`crate::dhcp`]; this module only supplies the
//! socket. The client never configures addresses: it reports [`DhcpEvent`]s and
//! the caller (owr-apply / owr-init) merges the lease and runs `converge`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{Instrument, info_span, warn};

use crate::dhcp::{CLIENT_PORT, Transport, run_with};
pub use crate::dhcp::{DhcpEvent, Lease};
use crate::model::{DhcpClientSpec, MacAddr};

const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const OPEN_RETRY: Duration = Duration::from_secs(5);

/// Broadcast-capable UDP socket pinned to one interface with `SO_BINDTODEVICE`.
#[derive(Debug)]
struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    fn open(ifname: &str) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;
        socket.bind_device(Some(ifname.as_bytes()))?;
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            CLIENT_PORT,
        )))?;
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
        })
    }
}

impl Transport for UdpTransport {
    async fn send(&self, payload: &[u8], dest: SocketAddrV4) -> io::Result<()> {
        let send = self.socket.send_to(payload, SocketAddr::V4(dest));
        tokio::time::timeout(SEND_TIMEOUT, send)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dhcp send timed out"))??;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }
}

/// A `DHCPv4` client for one interface.
#[derive(Debug)]
pub struct DhcpClient;

impl DhcpClient {
    /// Run until `shutdown` turns true (or its sender is dropped) or `events` is
    /// closed. `ifindex` is used for tracing; the socket is bound by `spec.link`.
    ///
    /// If the socket cannot be opened (interface missing), retries every 5s.
    pub async fn run(
        spec: DhcpClientSpec,
        ifindex: u32,
        mac: MacAddr,
        events: mpsc::Sender<DhcpEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let span = info_span!("dhcp_client", link = %spec.link, ifindex, %mac);
        async move {
            loop {
                match UdpTransport::open(&spec.link) {
                    Ok(transport) => {
                        run_with(&transport, spec, mac, events, shutdown).await;
                        return;
                    }
                    Err(e) => warn!(error = %e, "cannot open dhcp socket; retrying"),
                }
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    () = tokio::time::sleep(OPEN_RETRY) => {}
                }
            }
        }
        .instrument(span)
        .await;
    }
}
