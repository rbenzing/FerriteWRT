//! `DHCPv6` client on a real UDP socket (`[::]:546`, bound to one interface).
//!
//! The state machine lives in [`crate::dhcp6`]; this module only supplies the socket, which
//! sends to the all-agents multicast group on its interface. The client never configures
//! addresses: it reports [`Dhcp6Event`]s and the caller converges the system.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{Instrument, info, info_span, warn};

use super::sysfs;
use crate::dhcp6::{ALL_AGENTS, CLIENT_PORT, SERVER_PORT, Transport, run_with};
pub use crate::dhcp6::{Dhcp6ClientSpec, Dhcp6Event, Lease6};
use crate::model::MacAddr;

const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const OPEN_RETRY: Duration = Duration::from_secs(5);

/// UDP socket pinned to one interface with `SO_BINDTODEVICE`.
#[derive(Debug)]
struct UdpTransport {
    socket: UdpSocket,
    dest: SocketAddr,
}

impl UdpTransport {
    fn open(ifname: &str, ifindex: u32) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        socket.bind_device(Some(ifname.as_bytes()))?;
        socket.set_multicast_if_v6(ifindex)?;
        socket.set_multicast_loop_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SockAddr::from(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            CLIENT_PORT,
            0,
            0,
        )))?;
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
            dest: SocketAddr::V6(SocketAddrV6::new(ALL_AGENTS, SERVER_PORT, 0, ifindex)),
        })
    }
}

impl Transport for UdpTransport {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        let send = self.socket.send_to(payload, self.dest);
        tokio::time::timeout(SEND_TIMEOUT, send)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dhcpv6 send timed out"))??;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }
}

/// The socket on `spec.link` and the hardware address that identifies the client.
fn open(spec: &Dhcp6ClientSpec) -> io::Result<(UdpTransport, MacAddr)> {
    let mac = sysfs::mac(&spec.identity_link)?;
    let ifindex = sysfs::ifindex(&spec.link)?;
    Ok((UdpTransport::open(&spec.link, ifindex)?, mac))
}

/// A `DHCPv6` prefix-delegation client for one interface.
#[derive(Debug)]
pub struct Dhcp6Client;

impl Dhcp6Client {
    /// Run until `shutdown` turns true (or its sender is dropped) or `events` is closed.
    ///
    /// If the interface or the socket is not available yet (a PPP interface appears only
    /// once the session is up), retries every 5s.
    pub async fn run(
        spec: Dhcp6ClientSpec,
        events: mpsc::Sender<Dhcp6Event>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let span = info_span!("dhcp6_client", link = %spec.link);
        async move {
            loop {
                match open(&spec) {
                    Ok((transport, mac)) => {
                        info!(%mac, "dhcpv6 client started");
                        run_with(&transport, spec, mac, events, shutdown).await;
                        return;
                    }
                    Err(e) => warn!(error = %e, "cannot open dhcpv6 socket; retrying"),
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

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use std::process::Command;

    use rtnetlink::{LinkUnspec, LinkVeth};

    use super::*;
    use crate::dhcp6::{Message, duid_ll, iaid, test_reply};

    const CLIENT_LINK: &str = "owr-d60";
    const SERVER_LINK: &str = "owr-d61";
    const MSG_SOLICIT: u8 = 1;
    const MSG_ADVERTISE: u8 = 2;
    const MSG_REQUEST: u8 = 3;
    const MSG_REPLY: u8 = 7;

    /// Deletes the veth pair (both ends) when the test ends, also on failure.
    struct Veth;
    impl Drop for Veth {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", CLIENT_LINK])
                .status();
        }
    }

    fn ip(args: &[&str]) -> bool {
        Command::new("ip")
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    }

    fn conf(link: &str, key: &str, value: &str) {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{link}/{key}"), value).unwrap();
    }

    fn has_link_local(link: &str) -> bool {
        std::fs::read_to_string("/proc/net/if_inet6")
            .unwrap_or_default()
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .any(|f| {
                f.len() == 6
                    && f[5] == link
                    && f[0].starts_with("fe80")
                    && u8::from_str_radix(f[4], 16).is_ok_and(|flags| flags & 0x40 == 0)
            })
    }

    /// The client on one end of a veth pair, a server socket on the other: the real
    /// multicast Solicit reaches the server, the unicast Advertise and Reply reach the
    /// client's link-local address, and the delegated prefix comes out as a Bound event.
    #[tokio::test]
    async fn solicits_over_multicast_and_binds_the_delegated_prefix() {
        if !rustix::process::geteuid().is_root() || !ip(&["link", "show", "lo"]) {
            return;
        }
        let _ = ip(&["link", "del", CLIENT_LINK]);
        let (conn, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(conn);
        handle
            .link()
            .add(LinkVeth::new(CLIENT_LINK, SERVER_LINK).build())
            .execute()
            .await
            .unwrap();
        let _veth = Veth;
        for link in [CLIENT_LINK, SERVER_LINK] {
            conf(link, "accept_dad", "0");
            conf(link, "router_solicitations", "0");
            let up = LinkUnspec::new_with_name(link).up().build();
            handle.link().set(up).execute().await.unwrap();
        }
        for _ in 0..100 {
            if has_link_local(CLIENT_LINK) && has_link_local(SERVER_LINK) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(has_link_local(CLIENT_LINK) && has_link_local(SERVER_LINK));

        let server_index = sysfs::ifindex(SERVER_LINK).unwrap();
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_only_v6(true).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.bind_device(Some(SERVER_LINK.as_bytes())).unwrap();
        socket.join_multicast_v6(&ALL_AGENTS, server_index).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
            .bind(&SockAddr::from(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                SERVER_PORT,
                0,
                0,
            )))
            .unwrap();
        let server = UdpSocket::from_std(socket.into()).unwrap();

        let spec = Dhcp6ClientSpec {
            link: CLIENT_LINK.to_owned(),
            identity_link: CLIENT_LINK.to_owned(),
            prefix_len_hint: Some(60),
        };
        let mac = sysfs::mac(CLIENT_LINK).unwrap();
        let (events_tx, mut events) = mpsc::channel(4);
        let (stop, shutdown) = watch::channel(false);
        let client = tokio::spawn(Dhcp6Client::run(spec, events_tx, shutdown));

        let prefix = "2001:db8:5::/60".parse().unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1500];
        let exchange = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let msg = Message::parse(&buf[..n]).unwrap();
                seen.push(msg.msg_type);
                assert_eq!(msg.option(1), Some(duid_ll(mac).as_slice()));
                let reply_kind = match msg.msg_type {
                    MSG_SOLICIT => MSG_ADVERTISE,
                    MSG_REQUEST => MSG_REPLY,
                    other => unreachable!("unexpected message {other}"),
                };
                let SocketAddr::V6(from) = from else {
                    unreachable!("an IPv6 socket")
                };
                assert!(from.ip().is_unicast_link_local(), "source {from}");
                let reply = test_reply(reply_kind, msg.xid, &duid_ll(mac), iaid(mac), prefix);
                server.send_to(&reply, SocketAddr::V6(from)).await.unwrap();
                if reply_kind == MSG_REPLY {
                    break;
                }
            }
        })
        .await;
        assert!(exchange.is_ok(), "exchange incomplete, saw {seen:?}");
        assert_eq!(seen, [MSG_SOLICIT, MSG_REQUEST]);

        let Some(Dhcp6Event::Bound(lease)) = events.recv().await else {
            unreachable!("expected Bound");
        };
        assert_eq!(lease.nets(), vec![prefix]);

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), client)
            .await
            .unwrap()
            .unwrap();
    }
}
