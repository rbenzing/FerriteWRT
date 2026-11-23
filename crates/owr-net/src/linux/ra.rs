//! Router Advertisement sender on a raw `ICMPv6` socket bound to one link.
//!
//! What is sent and when is decided in [`crate::ra`]; this module only owns the socket.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::StdRng;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{Instrument, debug, error, info, info_span, warn};

use super::sysfs;
use crate::ra::{Pacer, is_router_solicitation, router_advertisement_with};
pub use crate::ra::{RaDynamic, RaPrefix, RaSpec};
#[cfg(test)]
use ipnet::Ipv6Net;

/// Where advertisements go (all nodes on the link).
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// Where solicitations arrive (all routers on the link).
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// Neighbor Discovery packets carry hop limit 255 so that receivers can tell they were not
/// forwarded (RFC 4861 6.1.2).
const ND_HOP_LIMIT: u32 = 255;
const OPEN_RETRY: Duration = Duration::from_secs(5);
/// Pause after a failed receive, so that a link that went away does not spin the loop.
const RECV_ERROR_PAUSE: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct RaSocket {
    socket: UdpSocket,
    dest: SocketAddr,
}

impl RaSocket {
    fn open(link: &str) -> io::Result<Self> {
        let ifindex = sysfs::ifindex(link)?;
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.bind_device(Some(link.as_bytes()))?;
        socket.set_multicast_if_v6(ifindex)?;
        socket.set_multicast_hops_v6(ND_HOP_LIMIT)?;
        socket.set_unicast_hops_v6(ND_HOP_LIMIT)?;
        socket.set_multicast_loop_v6(false)?;
        socket.join_multicast_v6(&ALL_ROUTERS, ifindex)?;
        socket.set_nonblocking(true)?;
        // tokio has no raw-socket type. `UdpSocket` only issues sendto/recvfrom on the
        // descriptor, which work the same on a raw ICMPv6 socket (the payload starts at the
        // ICMPv6 header; the kernel computes and checks the checksum).
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
            dest: SocketAddr::V6(SocketAddrV6::new(ALL_NODES, 0, 0, ifindex)),
        })
    }
}

/// Advertise `spec` alone (no delegated prefixes) until `shutdown` turns true.
pub async fn run(spec: RaSpec, shutdown: watch::Receiver<bool>) {
    let (_keep_open, updates) = watch::channel(RaDynamic::none());
    run_dynamic(spec, updates, shutdown).await;
}

/// Advertise `spec` plus the delegated prefixes `updates` currently holds until `shutdown`
/// turns true (or its sender is dropped). Every change of `updates` is advertised soon and then
/// repeated at the short initial intervals; a prefix that is not a global /64 is skipped with a
/// warning. An invalid spec is logged and nothing is sent; a link that cannot be opened yet is
/// retried every 5 s.
pub async fn run_dynamic(
    spec: RaSpec,
    mut updates: watch::Receiver<RaDynamic>,
    mut shutdown: watch::Receiver<bool>,
) {
    let span = info_span!("ra", link = %spec.link, prefix = %spec.prefix);
    async move {
        if let Err(e) = spec.validate() {
            error!(error = %e, "not advertising");
            return;
        }
        loop {
            match RaSocket::open(&spec.link) {
                Ok(socket) => {
                    serve(&socket, &spec, &mut updates, &mut shutdown).await;
                    return;
                }
                Err(e) => warn!(error = %e, "cannot open the advertisement socket; retrying"),
            }
            if wait_or_stop(&mut shutdown, OPEN_RETRY).await {
                return;
            }
        }
    }
    .instrument(span)
    .await;
}

/// Sleep for `d`; `true` when `shutdown` asked to stop first.
async fn wait_or_stop(shutdown: &mut watch::Receiver<bool>, d: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        () = tokio::time::sleep(d) => false,
    }
}

/// The advertisement for `spec` and what `updates` holds now; unusable prefixes are dropped.
fn current_packet(spec: &RaSpec, updates: &watch::Receiver<RaDynamic>) -> Vec<u8> {
    let mut dynamic = updates.borrow().clone();
    dynamic.prefixes.retain(|p| match p.validate(&spec.link) {
        Ok(()) => true,
        Err(e) => {
            warn!(error = %e, "not advertising the delegated prefix");
            false
        }
    });
    router_advertisement_with(spec, &dynamic, Instant::now())
}

async fn serve(
    socket: &RaSocket,
    spec: &RaSpec,
    updates: &mut watch::Receiver<RaDynamic>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut updates_open = true;
    let mut rng = StdRng::from_rng(&mut rand::rng());
    let mut pacer = Pacer::new(Instant::now());
    let mut buf = [0u8; 1500];
    info!("advertising");
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(pacer.due()) => {
                let packet = current_packet(spec, updates);
                match socket.socket.send_to(&packet, socket.dest).await {
                    Ok(_) => debug!("router advertisement sent"),
                    // Typically: no usable link-local address yet (no carrier, DAD running).
                    Err(e) => warn!(error = %e, "router advertisement not sent"),
                }
                pacer.sent(Instant::now(), &mut rng);
            }
            received = socket.socket.recv_from(&mut buf) => match received {
                Ok((len, from)) => {
                    if buf.get(..len).is_some_and(is_router_solicitation) {
                        debug!(%from, "router solicitation");
                        pacer.solicited(Instant::now(), &mut rng);
                    }
                }
                Err(e) => {
                    warn!(error = %e, "receive failed");
                    if wait_or_stop(shutdown, RECV_ERROR_PAUSE).await {
                        return;
                    }
                }
            },
            changed = updates.changed(), if updates_open => {
                if changed.is_ok() {
                    info!("advertised prefixes changed");
                    pacer.updated(Instant::now());
                } else {
                    // The owner went away: keep advertising what was last set.
                    updates_open = false;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use std::process::Command;

    use rtnetlink::{LinkUnspec, LinkVeth};

    use super::*;
    use crate::ra::{
        MAX_INITIAL_RTR_ADVERT_INTERVAL, MIN_DELAY_BETWEEN_RAS, ROUTER_ADVERTISEMENT,
        ROUTER_LIFETIME, router_advertisement,
    };

    /// Deletes the veth pair (both ends) when the test ends, also on failure.
    struct Veth(&'static str);
    impl Drop for Veth {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", self.0]).status();
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

    /// Whether `link` has a usable (non-tentative) link-local address.
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

    async fn next_ra(socket: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 1500];
        tokio::time::timeout(within, async {
            loop {
                let (len, from) = socket.recv_from(&mut buf).await.ok()?;
                if buf.first() == Some(&ROUTER_ADVERTISEMENT) {
                    return Some((buf[..len].to_vec(), from));
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    /// A veth pair `server` / `host`, both up with a link-local address, and a raw `ICMPv6`
    /// socket on the host end. `None` when the test cannot run (not root, no `ip`).
    async fn pair(server: &'static str, host: &'static str) -> Option<(Veth, UdpSocket, u32)> {
        if !rustix::process::geteuid().is_root() || !ip(&["link", "show", "lo"]) {
            return None;
        }
        let _ = ip(&["link", "del", server]);
        // rtnetlink rather than `ip`: BusyBox `ip` ignores the peer name.
        let (conn, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(conn);
        handle
            .link()
            .add(LinkVeth::new(server, host).build())
            .execute()
            .await
            .unwrap();
        let veth = Veth(server);
        for link in [server, host] {
            conf(link, "accept_dad", "0");
            // No kernel solicitations: the only one the server sees is the test's.
            conf(link, "router_solicitations", "0");
            let up = LinkUnspec::new_with_name(link).up().build();
            handle.link().set(up).execute().await.unwrap();
        }
        for _ in 0..100 {
            if has_link_local(server) && has_link_local(host) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(has_link_local(server) && has_link_local(host));

        let host_index = sysfs::ifindex(host).unwrap();
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        socket.bind_device(Some(host.as_bytes())).unwrap();
        socket.set_multicast_if_v6(host_index).unwrap();
        socket.set_multicast_hops_v6(ND_HOP_LIMIT).unwrap();
        socket.set_nonblocking(true).unwrap();
        Some((
            veth,
            UdpSocket::from_std(socket.into()).unwrap(),
            host_index,
        ))
    }

    fn lan_spec(link: &str) -> RaSpec {
        RaSpec {
            link: link.to_owned(),
            prefix: "fd00:1:2:3::/64".parse().unwrap(),
            dns: vec!["fd00:1:2:3::1".parse().unwrap()],
        }
    }

    /// Router lifetime and the `(prefix length, valid, preferred, prefix)` of every Prefix
    /// Information option of an advertisement.
    fn parse_ra(p: &[u8]) -> (u16, Vec<(u8, u32, u32, Ipv6Addr)>) {
        let lifetime = u16::from_be_bytes([p[6], p[7]]);
        let mut prefixes = Vec::new();
        let mut at = 16;
        while at + 2 <= p.len() {
            let len = usize::from(p[at + 1]) * 8;
            if p[at] == 3 {
                let be = |o: usize| u32::from_be_bytes(p[at + o..at + o + 4].try_into().unwrap());
                let addr: [u8; 16] = p[at + 16..at + 32].try_into().unwrap();
                prefixes.push((p[at + 2], be(4), be(8), Ipv6Addr::from(addr)));
            }
            at += len;
        }
        (lifetime, prefixes)
    }

    /// The server on one end of a veth pair, a host socket on the other: the first
    /// advertisement arrives at once with the rendered content and a link-local source, and a
    /// solicitation is answered at the rate limit rather than at the next 16 s tick.
    #[tokio::test]
    async fn advertises_on_the_link_and_answers_solicitations() {
        const SERVER: &str = "owr-ra0";
        const HOST: &str = "owr-ra1";
        let Some((_veth, host, host_index)) = pair(SERVER, HOST).await else {
            return;
        };
        let spec = lan_spec(SERVER);
        let expected = router_advertisement(&spec);
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(run(spec, shutdown));

        let (first, from) = next_ra(&host, Duration::from_secs(3)).await.unwrap();
        let first_at = Instant::now();
        assert_eq!(first.len(), expected.len());
        assert_eq!(first[..2], expected[..2]);
        assert_eq!(first[4..], expected[4..], "everything but the checksum");
        let SocketAddr::V6(from) = from else {
            unreachable!("an IPv6 socket")
        };
        assert!(from.ip().is_unicast_link_local(), "source {from}");

        let rs = [133u8, 0, 0, 0, 0, 0, 0, 0];
        let all_routers = SocketAddrV6::new(ALL_ROUTERS, 0, 0, host_index);
        host.send_to(&rs, SocketAddr::V6(all_routers))
            .await
            .unwrap();
        let (_, _) = next_ra(&host, Duration::from_secs(6)).await.unwrap();
        let gap = first_at.elapsed();
        assert!(
            gap >= MIN_DELAY_BETWEEN_RAS.saturating_sub(Duration::from_millis(200))
                && gap < MAX_INITIAL_RTR_ADVERT_INTERVAL / 2,
            "answered after {gap:?}"
        );

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// A delegated prefix handed to a running sender shows up on the wire soon, with the
    /// router as default router; withdrawing it advertises the prefix with lifetimes of zero
    /// and drops the router lifetime.
    #[tokio::test]
    async fn a_delegated_prefix_is_advertised_when_it_arrives_and_deprecated_when_it_goes() {
        const SERVER: &str = "owr-ra2";
        const HOST: &str = "owr-ra3";
        let Some((_veth, host, _)) = pair(SERVER, HOST).await else {
            return;
        };
        let (updates, updates_rx) = watch::channel(RaDynamic::none());
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(run_dynamic(lan_spec(SERVER), updates_rx, shutdown));

        let (first, _) = next_ra(&host, Duration::from_secs(3)).await.unwrap();
        let (lifetime, prefixes) = parse_ra(&first);
        assert_eq!(lifetime, 0, "no uplink yet: not a default router");
        assert_eq!(prefixes.len(), 1);

        let delegated: Ipv6Net = "2001:db8:5:1::/64".parse().unwrap();
        updates
            .send(RaDynamic {
                prefixes: vec![RaPrefix {
                    prefix: delegated,
                    valid: Duration::from_secs(7200),
                    preferred: Duration::from_secs(3600),
                }],
                as_of: Instant::now(),
            })
            .unwrap();
        // The next advertisement carries it (held back to 3 s after the previous one).
        let got = loop {
            let (ra, _) = next_ra(&host, Duration::from_secs(8)).await.unwrap();
            let parsed = parse_ra(&ra);
            if parsed.1.len() == 2 {
                break parsed;
            }
        };
        assert_eq!(got.0, u16::try_from(ROUTER_LIFETIME.as_secs()).unwrap());
        let (len, valid, preferred, addr) = got.1[1];
        assert_eq!((len, addr), (64, delegated.network()));
        assert!(valid <= 7200 && valid > 7000, "valid {valid}");
        assert!(
            preferred <= 3600 && preferred > 3400,
            "preferred {preferred}"
        );

        updates
            .send(RaDynamic {
                prefixes: vec![RaPrefix {
                    prefix: delegated,
                    valid: Duration::ZERO,
                    preferred: Duration::ZERO,
                }],
                as_of: Instant::now(),
            })
            .unwrap();
        let gone = loop {
            let (ra, _) = next_ra(&host, Duration::from_secs(8)).await.unwrap();
            let parsed = parse_ra(&ra);
            if parsed.0 == 0 {
                break parsed;
            }
        };
        assert_eq!(
            gone.1.len(),
            2,
            "the prefix is still named, with no lifetime"
        );
        assert_eq!((gone.1[1].1, gone.1[1].2), (0, 0));

        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
