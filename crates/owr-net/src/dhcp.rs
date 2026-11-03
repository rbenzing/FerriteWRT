//! `DHCPv4` client engine (RFC 2131): lease model, timers and the state machine.
//!
//! The engine is transport-agnostic ([`Transport`]) so it is tested on any host
//! with an in-memory fake. `linux::dhcp` supplies the real UDP socket.
//!
//! ```text
//!            +------+  shutdown / events closed: return from any state
//!   +------->| INIT |<-----------------------------------+
//!   |        +--+---+                                    |
//!   |           | DISCOVER (broadcast, backoff 4..64s)   |
//!   |           v                                        |
//!   |      SELECTING --OFFER--> REQUESTING --NAK/timeout-+
//!   |                              | ACK
//!   |                              v
//!   |   expiry / NAK            BOUND  -- emits Bound(lease)
//!   |   (emit Lost)                | T1
//!   |        +---------------- RENEWING (unicast to server, until T2)
//!   |        |                     | T2, no answer          ACK -> BOUND
//!   |        |                     v                        (emit Renewed)
//!   +--------+---------------- REBINDING (broadcast, until expiry)
//! ```
//!
//! The client never configures the interface. It emits [`DhcpEvent`]s; the caller
//! merges the lease with [`merge_lease`] and re-runs the planner/applier.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::model::{AddrSpec, DhcpClientSpec, MacAddr, NetPlan, RouteProto, RouteSpec, TABLE_MAIN};
use crate::wire::{ClasslessRoute, Message, MessageType, Op};

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
/// Longest hostname / vendor class we will send.
const MAX_TEXT_OPTION: usize = 64;
const RECV_BUF: usize = 2048;
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(60);
const REQUEST_ATTEMPTS: u32 = 4;
/// `lease_secs` value meaning "infinite" (RFC 2131 section 3.3).
pub const INFINITE_LEASE: u32 = u32::MAX;

const BASE_PARAM_REQUEST: [u8; 9] = [1, 3, 6, 15, 28, 51, 58, 59, 121];

/// An address lease handed out by a DHCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub addr: Ipv4Net,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    /// Option 121 routes; when present they replace `routers` (RFC 3442).
    pub classless_routes: Vec<ClasslessRoute>,
    /// [`INFINITE_LEASE`] never expires.
    pub lease_secs: u32,
    /// Renewal time, seconds after `obtained_at` (server value or `lease/2`).
    pub t1: u32,
    /// Rebinding time, seconds after `obtained_at` (server value or `lease*7/8`).
    pub t2: u32,
    pub server: Ipv4Addr,
    /// Wall clock at acknowledgement; informational only (the clock may jump
    /// after NTP sync). Timers use the monotonic clock.
    pub obtained_at: SystemTime,
}

/// What the client reports to its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpEvent {
    /// A new lease (or the same server granted a different address).
    Bound(Lease),
    /// The existing lease was extended.
    Renewed(Lease),
    /// The lease is gone (NAK or expiry); remove its address and routes.
    Lost,
}

/// An ACK that cannot be turned into a usable [`Lease`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    #[error("not an ACK")]
    NotAck,
    #[error("no server identifier")]
    NoServerId,
    #[error("no lease time")]
    NoLeaseTime,
    #[error("zero lease time")]
    ZeroLease,
    #[error("unusable address {0}")]
    BadAddress(Ipv4Addr),
    #[error("non-contiguous subnet mask {0}")]
    BadMask(Ipv4Addr),
    #[error("unusable prefix length /{0} (accepted: /8 to /30)")]
    BadPrefix(u8),
}

/// Shortest and longest leased prefix we are willing to configure.
const MIN_PREFIX: u8 = 8;
const MAX_PREFIX: u8 = 30;

fn classful_mask(ip: Ipv4Addr) -> Ipv4Addr {
    match ip.octets().first().copied().unwrap_or(0) {
        0..=127 => Ipv4Addr::new(255, 0, 0, 0),
        128..=191 => Ipv4Addr::new(255, 255, 0, 0),
        _ => Ipv4Addr::new(255, 255, 255, 0),
    }
}

impl Lease {
    /// Build a lease from an ACK, applying defaults and sanity checks.
    pub fn from_ack(ack: &Message, now: SystemTime) -> Result<Self, LeaseError> {
        let o = &ack.options;
        if o.msg_type != Some(MessageType::Ack) {
            return Err(LeaseError::NotAck);
        }
        let ip = ack.yiaddr;
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ip.is_loopback()
            || ip.is_link_local()
        {
            return Err(LeaseError::BadAddress(ip));
        }
        let server = o.server_id.ok_or(LeaseError::NoServerId)?;
        let lease_secs = o.lease_time.ok_or(LeaseError::NoLeaseTime)?;
        if lease_secs == 0 {
            return Err(LeaseError::ZeroLease);
        }
        let mask = o.subnet_mask.unwrap_or_else(|| classful_mask(ip));
        let bits = u32::from(mask);
        let prefix = u8::try_from(bits.leading_ones()).map_err(|_| LeaseError::BadMask(mask))?;
        if bits.count_ones() != bits.leading_ones() {
            return Err(LeaseError::BadMask(mask));
        }
        if !(MIN_PREFIX..=MAX_PREFIX).contains(&prefix) {
            return Err(LeaseError::BadPrefix(prefix));
        }
        let addr = Ipv4Net::new(ip, prefix).map_err(|_| LeaseError::BadMask(mask))?;
        // A router that is 0.0.0.0 or off-subnet cannot be used as a gateway (the
        // kernel needs `onlink`, which is unsupported): drop it, keep the lease.
        let routers = o
            .routers
            .iter()
            .copied()
            .filter(|r| {
                let usable = !r.is_unspecified() && addr.contains(r);
                if !usable {
                    warn!(router = %r, %addr, "dhcp router is unusable; ignored");
                }
                usable
            })
            .collect();

        let default_t1 = lease_secs / 2;
        let default_t2 =
            u32::try_from(u64::from(lease_secs).saturating_mul(7) / 8).unwrap_or(INFINITE_LEASE);
        let (t1, t2) = match (o.t1, o.t2) {
            (Some(t1), Some(t2)) if 0 < t1 && t1 < t2 && t2 < lease_secs => (t1, t2),
            (Some(t1), None) if 0 < t1 && t1 < default_t2 => (t1, default_t2),
            _ => (default_t1, default_t2),
        };
        Ok(Self {
            addr,
            routers,
            dns: o.dns.clone(),
            domain: o.domain.clone(),
            classless_routes: o.classless_routes.clone(),
            lease_secs,
            t1,
            t2,
            server,
            obtained_at: now,
        })
    }

    /// The address as a plan entry.
    pub fn addr_spec(&self, link: &str) -> AddrSpec {
        AddrSpec {
            link: link.to_owned(),
            addr: self.addr.into(),
        }
    }

    /// Routes implied by the lease (protocol [`RouteProto::Dhcp`]): option 121 if
    /// present, otherwise a default route via the first router. A gateway outside
    /// the leased subnet is not supported (the kernel rejects it without `onlink`).
    pub fn route_specs(&self, link: &str, metric: u32) -> Vec<RouteSpec> {
        let mk = |dest: Ipv4Net, gw: Ipv4Addr| RouteSpec {
            dest: dest.trunc().into(),
            via: (!gw.is_unspecified()).then_some(gw.into()),
            dev: Some(link.to_owned()),
            metric,
            table: TABLE_MAIN,
            proto: RouteProto::Dhcp,
        };
        if !self.classless_routes.is_empty() {
            return self
                .classless_routes
                .iter()
                .map(|r| mk(r.dest, r.gateway))
                .collect();
        }
        self.routers
            .first()
            .map(|gw| mk(Ipv4Net::default(), *gw))
            .into_iter()
            .collect()
    }
}

/// `plan` with the lease's address and routes added (the single-writer hand-off).
pub fn merge_lease(plan: &NetPlan, spec: &DhcpClientSpec, lease: &Lease) -> NetPlan {
    let mut merged = plan.clone();
    merged.addresses.push(lease.addr_spec(&spec.link));
    merged
        .routes
        .extend(lease.route_specs(&spec.link, spec.default_route_metric));
    merged
}

/// Retransmission delay for attempt `attempt` (0-based): 4, 8, 16, 32, 64s then
/// capped at 64s, plus `jitter_ms` clamped to +-1000ms (RFC 2131 section 4.1).
pub fn retransmit_delay(attempt: u32, jitter_ms: i64) -> Duration {
    let base_secs = 4u64.saturating_mul(1u64 << attempt.min(4)).min(64);
    let base_ms = i64::try_from(base_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let ms = base_ms.saturating_add(jitter_ms.clamp(-1000, 1000));
    Duration::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// Datagram I/O used by the engine.
pub trait Transport {
    fn send(
        &self,
        payload: &[u8],
        dest: SocketAddrV4,
    ) -> impl Future<Output = io::Result<()>> + Send;
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

/// The engine was asked to stop (shutdown signalled or event receiver dropped).
#[derive(Debug)]
struct Stop;

#[derive(Debug, Clone, Copy)]
enum Pacing {
    /// Exponential backoff (INIT / REQUESTING).
    Backoff,
    /// Half the remaining time, at least 60s (RENEWING / REBINDING).
    HalfRemaining,
}

/// Time budget measured on the monotonic clock.
#[derive(Debug, Clone, Copy)]
struct Budget {
    start: Instant,
    limit: Duration,
}

impl Budget {
    fn remaining(self) -> Duration {
        self.limit.saturating_sub(self.start.elapsed())
    }
}

struct Ctx<'a, T> {
    t: &'a T,
    spec: DhcpClientSpec,
    mac: MacAddr,
    events: mpsc::Sender<DhcpEvent>,
    shutdown: watch::Receiver<bool>,
    xid: u32,
    buf: Vec<u8>,
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() || rx.changed().await.is_err() {
            return;
        }
    }
}

fn jitter() -> i64 {
    rand::random_range(-1000..=1000)
}

/// Run the `DHCPv4` state machine until `shutdown` turns true (or its sender is
/// dropped) or the event receiver is dropped.
pub async fn run_with<T: Transport>(
    transport: &T,
    mut spec: DhcpClientSpec,
    mac: MacAddr,
    events: mpsc::Sender<DhcpEvent>,
    shutdown: watch::Receiver<bool>,
) {
    for (what, v) in [
        ("hostname", &mut spec.hostname),
        ("vendor_class", &mut spec.vendor_class),
    ] {
        if v.as_ref().is_some_and(|s| s.len() > MAX_TEXT_OPTION) {
            warn!(what, "dhcp option too long; not sent");
            *v = None;
        }
    }
    let mut ctx = Ctx {
        t: transport,
        spec,
        mac,
        events,
        shutdown,
        xid: 0,
        buf: vec![0; RECV_BUF],
    };
    let Err(Stop) = ctx.run().await;
    info!(link = %ctx.spec.link, "dhcp client stopped");
}

impl<T: Transport> Ctx<'_, T> {
    async fn run(&mut self) -> Result<std::convert::Infallible, Stop> {
        // RFC 2131 4.4.1: small random delay before the first DISCOVER.
        let mut delay = Duration::from_millis(rand::random_range(0..=1000));
        loop {
            self.pause(delay).await?;
            delay = Duration::from_millis(rand::random_range(1000..=3000));
            if let Some(lease) = self.acquire().await? {
                self.emit(DhcpEvent::Bound(lease.clone())).await?;
                self.maintain(lease).await?;
            }
        }
    }

    async fn pause(&mut self, d: Duration) -> Result<(), Stop> {
        tokio::select! {
            () = stopped(&mut self.shutdown) => Err(Stop),
            () = tokio::time::sleep(d) => Ok(()),
        }
    }

    /// Deliver `ev`, waiting for the consumer as long as it takes: a dropped
    /// `Lost` would leave a dead lease configured. Shutdown or a closed channel
    /// ends the wait.
    async fn emit(&mut self, ev: DhcpEvent) -> Result<(), Stop> {
        tokio::select! {
            () = stopped(&mut self.shutdown) => Err(Stop),
            sent = self.events.send(ev) => sent.map_err(|_| Stop),
        }
    }

    fn message(&self, ty: MessageType) -> Message {
        let mut m = Message::new_client(self.xid, self.mac, ty);
        let o = &mut m.options;
        let mut client_id = vec![1];
        client_id.extend_from_slice(&self.mac.octets());
        o.client_id = Some(client_id);
        o.hostname.clone_from(&self.spec.hostname);
        o.vendor_class.clone_from(&self.spec.vendor_class);
        o.param_request = BASE_PARAM_REQUEST
            .iter()
            .copied()
            .filter(|c| self.spec.request_dns || !matches!(c, 6 | 15))
            .collect();
        m
    }

    /// Send `msg` and wait for a reply accepted by `accept`, retransmitting per
    /// `pacing` until `budget` or `max_attempts` runs out (`Ok(None)`).
    async fn transact(
        &mut self,
        dest: SocketAddrV4,
        msg: &Message,
        pacing: Pacing,
        budget: Option<Budget>,
        max_attempts: Option<u32>,
        accept: impl Fn(&Message) -> bool,
    ) -> Result<Option<Message>, Stop> {
        let payload = match msg.encode() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "cannot encode dhcp message");
                self.pause(Duration::from_secs(30)).await?;
                return Ok(None);
            }
        };
        let mut attempt = 0u32;
        loop {
            let remaining = budget.map(Budget::remaining);
            if remaining == Some(Duration::ZERO) || max_attempts == Some(attempt) {
                return Ok(None);
            }
            if let Err(e) = self.t.send(&payload, dest).await {
                debug!(error = %e, %dest, "dhcp send failed");
            }
            let mut wait = match pacing {
                Pacing::Backoff => retransmit_delay(attempt, jitter()),
                Pacing::HalfRemaining => remaining
                    .unwrap_or(MIN_RENEW_INTERVAL)
                    .div_f32(2.0)
                    .max(MIN_RENEW_INTERVAL),
            };
            if let Some(r) = remaining {
                wait = wait.min(r);
            }
            attempt = attempt.saturating_add(1);

            let started = Instant::now();
            loop {
                let left = wait.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                let got = tokio::select! {
                    () = stopped(&mut self.shutdown) => return Err(Stop),
                    r = tokio::time::timeout(left, self.t.recv(&mut self.buf)) => r,
                };
                match got {
                    Err(_) => break,
                    Ok(Err(e)) => {
                        debug!(error = %e, "dhcp recv failed");
                        self.pause(left.min(Duration::from_millis(200))).await?;
                    }
                    Ok(Ok(n)) => {
                        let Some(pkt) = self.buf.get(..n) else {
                            continue;
                        };
                        match Message::parse(pkt) {
                            Ok(m) if self.is_reply_to_us(&m) && accept(&m) => return Ok(Some(m)),
                            Ok(_) => {}
                            Err(e) => debug!(error = %e, "ignoring malformed dhcp packet"),
                        }
                    }
                }
            }
        }
    }

    fn is_reply_to_us(&self, m: &Message) -> bool {
        m.op == Op::Reply
            && m.xid == self.xid
            && m.chaddr == self.mac
            && m.options.msg_type.is_some()
    }

    /// INIT -> SELECTING -> REQUESTING. `None` means go back to INIT.
    async fn acquire(&mut self) -> Result<Option<Lease>, Stop> {
        self.xid = rand::random();
        let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);

        let mut discover = self.message(MessageType::Discover);
        discover.broadcast = true;
        let offer = self
            .transact(broadcast, &discover, Pacing::Backoff, None, None, |m| {
                m.options.msg_type == Some(MessageType::Offer)
                    && !m.yiaddr.is_unspecified()
                    && m.options.server_id.is_some()
            })
            .await?;
        let Some(offer) = offer else { return Ok(None) };
        let (Some(server), yiaddr) = (offer.options.server_id, offer.yiaddr) else {
            return Ok(None);
        };
        debug!(%yiaddr, %server, "dhcp offer");

        let mut request = self.message(MessageType::Request);
        request.broadcast = true;
        request.options.requested_ip = Some(yiaddr);
        request.options.server_id = Some(server);
        let reply = self
            .transact(
                broadcast,
                &request,
                Pacing::Backoff,
                None,
                Some(REQUEST_ATTEMPTS),
                |m| ack_or_nak(m, Some(server), yiaddr),
            )
            .await?;
        Ok(self.lease_from_reply(reply))
    }

    fn lease_from_reply(&self, reply: Option<Message>) -> Option<Lease> {
        let reply = reply?;
        if reply.options.msg_type == Some(MessageType::Nak) {
            info!(link = %self.spec.link, reason = ?reply.options.message, "dhcp NAK");
            return None;
        }
        Lease::from_ack(&reply, SystemTime::now()).ok()
    }

    /// BOUND -> RENEWING -> REBINDING until the lease is lost.
    async fn maintain(&mut self, mut lease: Lease) -> Result<(), Stop> {
        loop {
            let start = Instant::now();
            if lease.lease_secs == INFINITE_LEASE {
                stopped(&mut self.shutdown).await;
                return Err(Stop);
            }
            let secs = |s: u32| Duration::from_secs(u64::from(s));
            self.pause(secs(lease.t1)).await?;

            self.xid = rand::random();
            let mut renew = self.message(MessageType::Request);
            renew.ciaddr = lease.addr.addr();
            let unicast = SocketAddrV4::new(lease.server, SERVER_PORT);
            let t2 = Budget {
                start,
                limit: secs(lease.t2),
            };
            // RENEWING: only the server that holds the lease may answer
            let mut reply = self
                .transact(
                    unicast,
                    &renew,
                    Pacing::HalfRemaining,
                    Some(t2),
                    None,
                    |m| ack_or_nak(m, Some(lease.server), lease.addr.addr()),
                )
                .await?;
            if reply.is_none() {
                debug!(link = %self.spec.link, "dhcp rebinding");
                let expiry = Budget {
                    start,
                    limit: secs(lease.lease_secs),
                };
                reply = self
                    .transact(
                        SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT),
                        &renew,
                        Pacing::HalfRemaining,
                        Some(expiry),
                        None,
                        |m| ack_or_nak(m, None, lease.addr.addr()),
                    )
                    .await?;
            }
            match self.lease_from_reply(reply) {
                Some(new) if new.addr == lease.addr => {
                    self.emit(DhcpEvent::Renewed(new.clone())).await?;
                    lease = new;
                }
                Some(new) => {
                    self.emit(DhcpEvent::Bound(new.clone())).await?;
                    lease = new;
                }
                None => {
                    self.emit(DhcpEvent::Lost).await?;
                    return Ok(());
                }
            }
        }
    }
}

/// Whether `m` is an ACK / NAK answering our REQUEST for `requested`.
///
/// Both must carry a server identifier, and when `server` is given (REQUESTING,
/// RENEWING) it must be that server; in REBINDING (`None`) any server may answer.
/// An ACK must also confirm exactly the requested address.
fn ack_or_nak(m: &Message, server: Option<Ipv4Addr>, requested: Ipv4Addr) -> bool {
    let Some(from) = m.options.server_id else {
        return false;
    };
    if server.is_some_and(|s| s != from) {
        return false;
    }
    match m.options.msg_type {
        Some(MessageType::Nak) => true,
        Some(MessageType::Ack) => {
            m.yiaddr == requested && Lease::from_ack(m, SystemTime::now()).is_ok()
        }
        _ => false,
    }
}

/// Sysctls a DHCP-managed link needs so replies to the broadcast DISCOVER are not
/// dropped: the link has no address yet, so strict reverse-path filtering
/// (`rp_filter = 1`) may reject the server's reply; loose mode (2) accepts it.
///
/// The owner (owr-apply) adds these to `NetPlan::sysctls`; being per-interface keys
/// the planner writes them after the link exists.
pub fn dhcp_link_sysctls(link: &str) -> Vec<(String, String)> {
    vec![(format!("net/ipv4/conf/{link}/rp_filter"), "2".to_owned())]
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unused_async_trait_impl
)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::sync::Notify;

    use super::*;

    const MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const YIADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

    fn ack_msg(
        req: &Message,
        ty: MessageType,
        lease: u32,
        t1: Option<u32>,
        t2: Option<u32>,
    ) -> Message {
        let mut m = Message::new_client(req.xid, req.chaddr, ty);
        m.op = Op::Reply;
        m.yiaddr = YIADDR;
        m.options.server_id = Some(SERVER);
        if ty != MessageType::Nak {
            m.options.lease_time = Some(lease);
            m.options.t1 = t1;
            m.options.t2 = t2;
            m.options.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
            m.options.routers = vec![SERVER];
            m.options.dns = vec![Ipv4Addr::new(9, 9, 9, 9)];
        }
        m
    }

    type Handler = Box<dyn FnMut(&Message, SocketAddrV4) -> Vec<Message> + Send>;

    /// In-memory network: every datagram the client sends is shown to `handler`,
    /// whose replies are queued for `recv`.
    struct Fake {
        handler: Mutex<Handler>,
        queue: Mutex<VecDeque<Vec<u8>>>,
        notify: Notify,
        sent: Mutex<Vec<(Message, SocketAddrV4)>>,
    }

    impl Fake {
        fn new(
            handler: impl FnMut(&Message, SocketAddrV4) -> Vec<Message> + Send + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                handler: Mutex::new(Box::new(handler)),
                queue: Mutex::default(),
                notify: Notify::new(),
                sent: Mutex::default(),
            })
        }

        fn sent_types(&self) -> Vec<(MessageType, SocketAddrV4)> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(m, d)| (m.options.msg_type.unwrap(), *d))
                .collect()
        }
    }

    impl Transport for Arc<Fake> {
        async fn send(&self, payload: &[u8], dest: SocketAddrV4) -> io::Result<()> {
            let msg = Message::parse(payload).map_err(io::Error::other)?;
            let replies = (self.handler.lock().unwrap())(&msg, dest);
            self.sent.lock().unwrap().push((msg, dest));
            for r in replies {
                self.queue
                    .lock()
                    .unwrap()
                    .push_back(r.encode().map_err(io::Error::other)?);
            }
            self.notify.notify_one();
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let next = self.queue.lock().unwrap().pop_front();
                if let Some(p) = next {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    return Ok(n);
                }
                self.notify.notified().await;
            }
        }
    }

    fn spec() -> DhcpClientSpec {
        DhcpClientSpec {
            link: "eth1".into(),
            hostname: Some("flint2".into()),
            vendor_class: None,
            request_dns: true,
            default_route_metric: 10,
        }
    }

    struct Running {
        events: mpsc::Receiver<DhcpEvent>,
        shutdown: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    fn start(fake: &Arc<Fake>, spec: DhcpClientSpec) -> Running {
        start_cap(fake, spec, 16)
    }

    fn start_cap(fake: &Arc<Fake>, spec: DhcpClientSpec, capacity: usize) -> Running {
        let (tx, events) = mpsc::channel(capacity);
        let (shutdown, rx) = watch::channel(false);
        let f = Arc::clone(fake);
        let task = tokio::spawn(async move { run_with(&f, spec, MAC, tx, rx).await });
        Running {
            events,
            shutdown,
            task,
        }
    }

    impl Running {
        async fn stop(self) {
            self.shutdown.send(true).unwrap();
            self.task.await.unwrap();
        }
    }

    /// A well-behaved server: OFFER, then ACK every REQUEST with the given lease.
    fn good_server(lease: u32, t1: Option<u32>, t2: Option<u32>) -> Handler {
        Box::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => vec![ack_msg(m, MessageType::Offer, lease, t1, t2)],
            Some(MessageType::Request) => vec![ack_msg(m, MessageType::Ack, lease, t1, t2)],
            _ => vec![],
        })
    }

    #[tokio::test(start_paused = true)]
    async fn acquires_lease_and_emits_bound() {
        let fake = Fake::new(good_server(3600, None, None));
        let mut run = start(&fake, spec());
        let event = run.events.recv().await;
        let Some(DhcpEvent::Bound(lease)) = event else {
            unreachable!("expected Bound, got {event:?}");
        };
        assert_eq!(lease.addr, "192.168.1.50/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(lease.routers, vec![SERVER]);
        assert_eq!((lease.t1, lease.t2), (1800, 3150));
        {
            let sent = fake.sent.lock().unwrap();
            let (d, dest) = &sent[0];
            assert_eq!(d.options.msg_type, Some(MessageType::Discover));
            assert!(d.broadcast);
            assert_eq!(*dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 67));
            assert_eq!(d.options.client_id, Some(vec![1, 2, 0, 0, 0, 0, 1]));
            assert_eq!(d.options.hostname.as_deref(), Some("flint2"));
            let (r, _) = &sent[1];
            assert_eq!(r.options.msg_type, Some(MessageType::Request));
            assert_eq!(r.options.requested_ip, Some(YIADDR));
            assert_eq!(r.options.server_id, Some(SERVER));
            assert!(r.broadcast);
        }
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn request_dns_false_drops_dns_options_from_request_list() {
        let fake = Fake::new(good_server(3600, None, None));
        let mut s = spec();
        s.request_dns = false;
        let mut run = start(&fake, s);
        run.events.recv().await.unwrap();
        let list = fake.sent.lock().unwrap()[0].0.options.param_request.clone();
        assert_eq!(list, vec![1, 3, 28, 51, 58, 59, 121]);
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn renews_by_unicast_at_t1() {
        let fake = Fake::new(good_server(100, Some(50), Some(87)));
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        assert!(matches!(
            run.events.recv().await,
            Some(DhcpEvent::Renewed(_))
        ));
        let sent = fake.sent_types();
        let (ty, dest) = sent[2];
        assert_eq!(ty, MessageType::Request);
        assert_eq!(dest, SocketAddrV4::new(SERVER, 67));
        let renew = fake.sent.lock().unwrap()[2].0.clone();
        assert_eq!(renew.ciaddr, YIADDR);
        assert!(!renew.broadcast);
        assert_eq!(renew.options.requested_ip, None);
        assert_eq!(renew.options.server_id, None);
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn nak_on_renew_emits_lost_and_restarts() {
        let mut requests = 0;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => vec![ack_msg(m, MessageType::Offer, 100, None, None)],
            Some(MessageType::Request) => {
                requests += 1;
                let ty = if requests == 2 {
                    MessageType::Nak
                } else {
                    MessageType::Ack
                };
                vec![ack_msg(m, ty, 100, None, None)]
            }
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        assert_eq!(run.events.recv().await, Some(DhcpEvent::Lost));
        // back in INIT: a new DISCOVER and a fresh Bound follow
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        let discovers = fake
            .sent_types()
            .iter()
            .filter(|(t, _)| *t == MessageType::Discover)
            .count();
        assert_eq!(discovers, 2);
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn silent_server_leads_to_rebinding_then_lost_at_expiry() {
        let mut requests = 0;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => {
                vec![ack_msg(m, MessageType::Offer, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) if requests == 0 => {
                requests += 1;
                vec![ack_msg(m, MessageType::Ack, 100, Some(50), Some(87))]
            }
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        let before = Instant::now();
        assert_eq!(run.events.recv().await, Some(DhcpEvent::Lost));
        let e = before.elapsed();
        assert!(
            e >= Duration::from_secs(99) && e <= Duration::from_secs(101),
            "lost at expiry (100s): {e:?}"
        );
        let sent = fake.sent.lock().unwrap().clone();
        let unicast = sent
            .iter()
            .filter(|(m, d)| m.ciaddr == YIADDR && d.ip() == &SERVER)
            .count();
        let rebind = sent
            .iter()
            .filter(|(m, d)| m.ciaddr == YIADDR && d.ip() == &Ipv4Addr::BROADCAST)
            .count();
        assert!(unicast >= 1, "renewing is unicast");
        assert!(rebind >= 1, "rebinding is broadcast");
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn nak_in_requesting_does_not_bind_and_retries() {
        let mut requests = 0;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => vec![ack_msg(m, MessageType::Offer, 3600, None, None)],
            Some(MessageType::Request) => {
                requests += 1;
                let ty = if requests == 1 {
                    MessageType::Nak
                } else {
                    MessageType::Ack
                };
                vec![ack_msg(m, ty, 3600, None, None)]
            }
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        // first event must be the Bound that follows the second attempt; no Lost
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        assert_eq!(
            fake.sent_types()
                .iter()
                .filter(|(t, _)| *t == MessageType::Discover)
                .count(),
            2
        );
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_replies_with_wrong_xid_or_chaddr() {
        let mut first = true;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => {
                let mut wrong_xid = ack_msg(m, MessageType::Offer, 3600, None, None);
                wrong_xid.xid = wrong_xid.xid.wrapping_add(1);
                let mut wrong_mac = ack_msg(m, MessageType::Offer, 3600, None, None);
                wrong_mac.chaddr = MacAddr([9; 6]);
                let mut v = vec![wrong_xid, wrong_mac];
                if !std::mem::take(&mut first) {
                    v.push(ack_msg(m, MessageType::Offer, 3600, None, None));
                }
                v
            }
            Some(MessageType::Request) => vec![ack_msg(m, MessageType::Ack, 3600, None, None)],
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        // the first DISCOVER got only bogus replies, so it was retransmitted
        assert_eq!(
            fake.sent_types()
                .iter()
                .filter(|(t, _)| *t == MessageType::Discover)
                .count(),
            2
        );
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_the_client_from_any_state() {
        // never answers: stuck in SELECTING
        let fake = Fake::new(|_, _| vec![]);
        let run = start(&fake, spec());
        tokio::time::sleep(Duration::from_secs(20)).await;
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_event_receiver_stops_the_client() {
        let fake = Fake::new(good_server(3600, None, None));
        let run = start(&fake, spec());
        drop(run.events);
        run.task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn infinite_lease_never_renews() {
        let fake = Fake::new(good_server(INFINITE_LEASE, None, None));
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        tokio::time::sleep(Duration::from_hours(720)).await;
        assert_eq!(fake.sent_types().len(), 2, "only DISCOVER and REQUEST");
        run.stop().await;
    }

    #[test]
    fn retransmit_backoff_is_4_8_16_32_64_capped_with_bounded_jitter() {
        let secs = |a| retransmit_delay(a, 0).as_secs();
        assert_eq!(
            (0..8).map(secs).collect::<Vec<_>>(),
            [4, 8, 16, 32, 64, 64, 64, 64]
        );
        assert_eq!(retransmit_delay(0, -5000), Duration::from_millis(3000));
        assert_eq!(retransmit_delay(0, 5000), Duration::from_millis(5000));
        assert_eq!(retransmit_delay(u32::MAX, 1000), Duration::from_secs(65));
    }

    fn ack(f: impl FnOnce(&mut Message)) -> Message {
        let req = Message::new_client(1, MAC, MessageType::Request);
        let mut m = ack_msg(&req, MessageType::Ack, 3600, None, None);
        f(&mut m);
        m
    }

    #[test]
    fn lease_defaults_and_validation() {
        let now = SystemTime::UNIX_EPOCH;
        let l = Lease::from_ack(&ack(|_| {}), now).unwrap();
        assert_eq!((l.t1, l.t2, l.lease_secs), (1800, 3150, 3600));

        let l = Lease::from_ack(
            &ack(|m| {
                m.options.t1 = Some(10);
                m.options.t2 = Some(20);
            }),
            now,
        )
        .unwrap();
        assert_eq!((l.t1, l.t2), (10, 20));
        // inconsistent timers fall back to defaults
        let l = Lease::from_ack(
            &ack(|m| {
                m.options.t1 = Some(30);
                m.options.t2 = Some(20);
            }),
            now,
        )
        .unwrap();
        assert_eq!((l.t1, l.t2), (1800, 3150));
        let l = Lease::from_ack(
            &ack(|m| {
                m.options.t1 = Some(0);
                m.options.t2 = Some(5000);
            }),
            now,
        )
        .unwrap();
        assert_eq!((l.t1, l.t2), (1800, 3150));

        let err = |f: fn(&mut Message)| Lease::from_ack(&ack(f), now).unwrap_err();
        assert_eq!(err(|m| m.options.server_id = None), LeaseError::NoServerId);
        assert_eq!(
            err(|m| m.options.lease_time = None),
            LeaseError::NoLeaseTime
        );
        assert_eq!(
            err(|m| m.options.lease_time = Some(0)),
            LeaseError::ZeroLease
        );
        assert!(matches!(
            err(|m| m.yiaddr = Ipv4Addr::UNSPECIFIED),
            LeaseError::BadAddress(_)
        ));
        assert!(matches!(
            err(|m| m.yiaddr = Ipv4Addr::LOCALHOST),
            LeaseError::BadAddress(_)
        ));
        assert!(matches!(
            err(|m| m.options.subnet_mask = Some(Ipv4Addr::new(255, 0, 255, 0))),
            LeaseError::BadMask(_)
        ));
        assert_eq!(
            err(|m| m.options.msg_type = Some(MessageType::Offer)),
            LeaseError::NotAck
        );
    }

    #[test]
    fn lease_uses_classful_mask_when_missing() {
        let l = Lease::from_ack(
            &ack(|m| m.options.subnet_mask = None),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(l.addr.prefix_len(), 24);
        let l = Lease::from_ack(
            &ack(|m| {
                m.options.subnet_mask = None;
                m.yiaddr = Ipv4Addr::new(10, 1, 2, 3);
            }),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(l.addr.prefix_len(), 8);
    }

    #[test]
    fn lease_routes_prefer_option_121_over_routers() {
        let l = Lease::from_ack(&ack(|_| {}), SystemTime::UNIX_EPOCH).unwrap();
        let r = l.route_specs("eth1", 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].dest, "0.0.0.0/0".parse().unwrap());
        assert_eq!(r[0].via, Some(SERVER.into()));
        assert_eq!(r[0].proto, RouteProto::Dhcp);
        assert_eq!(r[0].metric, 10);

        let l = Lease::from_ack(
            &ack(|m| {
                m.options.classless_routes = vec![
                    ClasslessRoute {
                        dest: "10.0.0.0/8".parse().unwrap(),
                        gateway: Ipv4Addr::new(192, 168, 1, 2),
                    },
                    ClasslessRoute {
                        dest: "172.16.0.0/16".parse().unwrap(),
                        gateway: Ipv4Addr::UNSPECIFIED,
                    },
                ];
            }),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        let r = l.route_specs("eth1", 5);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].via, Some(Ipv4Addr::new(192, 168, 1, 2).into()));
        assert_eq!(r[1].via, None, "0.0.0.0 gateway means on-link");
    }

    #[test]
    fn merge_lease_adds_address_and_routes_and_still_plans() {
        let plan = NetPlan {
            links: vec![crate::model::LinkSpec::Physical {
                name: "eth1".into(),
                up: true,
                mtu: None,
                mac: None,
            }],
            dhcp_clients: vec![spec()],
            ..NetPlan::default()
        };
        let l = Lease::from_ack(&ack(|_| {}), SystemTime::UNIX_EPOCH).unwrap();
        let merged = merge_lease(&plan, &spec(), &l);
        assert_eq!(merged.addresses.len(), 1);
        assert_eq!(merged.routes.len(), 1);
        assert!(plan.validate().is_ok());
        assert!(
            merged.validate().is_err(),
            "strict check still flags the static conflict"
        );
        assert!(merged.validate_inner(false).is_ok());
    }

    // ---- review regressions -------------------------------------------------------

    const OTHER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const WRONG_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 99);

    fn from_server(mut m: Message, server: Option<Ipv4Addr>) -> Message {
        m.options.server_id = server;
        m
    }

    /// Replies a client must not accept for a REQUEST of `YIADDR` to `SERVER`.
    fn bogus_replies(m: &Message) -> Vec<Message> {
        let mut wrong_addr = ack_msg(m, MessageType::Ack, 100, Some(50), Some(87));
        wrong_addr.yiaddr = WRONG_ADDR;
        vec![
            from_server(ack_msg(m, MessageType::Nak, 100, None, None), Some(OTHER)),
            from_server(ack_msg(m, MessageType::Nak, 100, None, None), None),
            wrong_addr,
            from_server(
                ack_msg(m, MessageType::Ack, 100, Some(50), Some(87)),
                Some(OTHER),
            ),
        ]
    }

    #[tokio::test(start_paused = true)]
    async fn n7_requesting_ignores_naks_and_acks_from_the_wrong_server_or_address() {
        let fake = Fake::new(|m, _| match m.options.msg_type {
            Some(MessageType::Discover) => {
                vec![ack_msg(m, MessageType::Offer, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) => {
                let mut v = bogus_replies(m);
                v.push(ack_msg(m, MessageType::Ack, 100, Some(50), Some(87)));
                v
            }
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        let Some(DhcpEvent::Bound(lease)) = run.events.recv().await else {
            unreachable!("expected Bound");
        };
        assert_eq!((lease.addr.addr(), lease.server), (YIADDR, SERVER));
        let types: Vec<_> = fake.sent_types().into_iter().map(|(t, _)| t).collect();
        assert_eq!(
            types,
            [MessageType::Discover, MessageType::Request],
            "a bogus NAK must not restart the exchange"
        );
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn n7_offer_without_server_id_is_ignored() {
        let mut first = true;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) if std::mem::take(&mut first) => {
                vec![from_server(
                    ack_msg(m, MessageType::Offer, 100, None, None),
                    None,
                )]
            }
            Some(MessageType::Discover) => vec![ack_msg(m, MessageType::Offer, 100, None, None)],
            Some(MessageType::Request) => vec![ack_msg(m, MessageType::Ack, 100, None, None)],
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        assert_eq!(fake.sent_types()[0].0, MessageType::Discover);
        assert_eq!(fake.sent_types()[1].0, MessageType::Discover);
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn n7_renewing_only_accepts_the_lease_holder_and_the_leased_address() {
        let fake = Fake::new(|m, _| match m.options.msg_type {
            Some(MessageType::Discover) => {
                vec![ack_msg(m, MessageType::Offer, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) if m.ciaddr.is_unspecified() => {
                vec![ack_msg(m, MessageType::Ack, 100, Some(50), Some(87))]
            }
            // the renewal: bogus answers first, then the real one
            Some(MessageType::Request) => {
                let mut v = bogus_replies(m);
                v.push(ack_msg(m, MessageType::Ack, 100, Some(50), Some(87)));
                v
            }
            _ => vec![],
        });
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        let Some(DhcpEvent::Renewed(lease)) = run.events.recv().await else {
            unreachable!("a bogus NAK must not end the lease");
        };
        assert_eq!(lease.server, SERVER);
        assert_eq!(fake.sent_types().len(), 3, "one renewal REQUEST");
        run.stop().await;
    }

    /// Server that answers the DISCOVER / first REQUEST and then stays silent to the
    /// unicast renewal, so the client rebinds; `rebind` answers the broadcast.
    fn rebinding_server(rebind: fn(&Message) -> Vec<Message>) -> Handler {
        Box::new(move |m, dest| match m.options.msg_type {
            Some(MessageType::Discover) => {
                vec![ack_msg(m, MessageType::Offer, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) if m.ciaddr.is_unspecified() => {
                vec![ack_msg(m, MessageType::Ack, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) if dest.ip() == &Ipv4Addr::BROADCAST => rebind(m),
            _ => vec![],
        })
    }

    #[tokio::test(start_paused = true)]
    async fn n7_rebinding_accepts_any_server_but_still_needs_a_server_id() {
        let fake = Fake::new(rebinding_server(|m| {
            vec![
                from_server(ack_msg(m, MessageType::Nak, 100, None, None), None),
                from_server(
                    ack_msg(m, MessageType::Ack, 100, Some(50), Some(87)),
                    Some(OTHER),
                ),
            ]
        }));
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        let Some(DhcpEvent::Renewed(lease)) = run.events.recv().await else {
            unreachable!("expected the rebind ACK from another server");
        };
        assert_eq!((lease.addr.addr(), lease.server), (YIADDR, OTHER));
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn n7_rebinding_nak_from_any_server_ends_the_lease() {
        let fake = Fake::new(rebinding_server(|m| {
            vec![from_server(
                ack_msg(m, MessageType::Nak, 100, None, None),
                Some(OTHER),
            )]
        }));
        let mut run = start(&fake, spec());
        assert!(matches!(run.events.recv().await, Some(DhcpEvent::Bound(_))));
        assert_eq!(run.events.recv().await, Some(DhcpEvent::Lost));
        run.stop().await;
    }

    #[test]
    fn n8_unusable_addresses_and_prefixes_are_rejected() {
        let now = SystemTime::UNIX_EPOCH;
        for ip in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(127, 1, 2, 3),
            Ipv4Addr::new(169, 254, 7, 7),
            Ipv4Addr::new(224, 0, 0, 5),
            Ipv4Addr::new(239, 1, 1, 1),
        ] {
            let mut m = ack(|_| {});
            m.yiaddr = ip;
            assert_eq!(
                Lease::from_ack(&m, now).unwrap_err(),
                LeaseError::BadAddress(ip)
            );
        }
        let with_mask = |mask: [u8; 4]| {
            let mut m = ack(|_| {});
            m.options.subnet_mask = Some(Ipv4Addr::from(mask));
            Lease::from_ack(&m, now)
        };
        assert_eq!(
            with_mask([254, 0, 0, 0]).unwrap_err(),
            LeaseError::BadPrefix(7)
        );
        assert_eq!(
            with_mask([255, 255, 255, 254]).unwrap_err(),
            LeaseError::BadPrefix(31)
        );
        assert_eq!(
            with_mask([255, 255, 255, 255]).unwrap_err(),
            LeaseError::BadPrefix(32)
        );
        assert_eq!(with_mask([255, 0, 0, 0]).unwrap().addr.prefix_len(), 8);
        assert_eq!(
            with_mask([255, 255, 255, 252]).unwrap().addr.prefix_len(),
            30
        );
    }

    #[test]
    fn n8_unusable_routers_are_dropped_but_the_lease_is_kept() {
        let l = Lease::from_ack(
            &ack(|m| {
                m.options.routers = vec![
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::new(10, 9, 9, 9), // outside 192.168.1.0/24
                    SERVER,
                ];
            }),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(l.routers, vec![SERVER]);
        assert_eq!(l.route_specs("eth1", 10).len(), 1);

        let l = Lease::from_ack(
            &ack(|m| m.options.routers = vec![Ipv4Addr::new(10, 9, 9, 9)]),
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(l.routers, Vec::<Ipv4Addr>::new());
        assert!(l.route_specs("eth1", 10).is_empty(), "no default route");
        assert_eq!(l.addr, "192.168.1.50/24".parse::<Ipv4Net>().unwrap());
    }

    /// The next event, failing the test (rather than hanging) if none arrives.
    async fn next_event(rx: &mut mpsc::Receiver<DhcpEvent>) -> Option<DhcpEvent> {
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("event missing: it was dropped")
    }

    #[tokio::test(start_paused = true)]
    async fn n9_lost_is_delivered_even_when_the_consumer_is_slow() {
        let mut requests = 0;
        let fake = Fake::new(move |m, _| match m.options.msg_type {
            Some(MessageType::Discover) => {
                vec![ack_msg(m, MessageType::Offer, 100, Some(50), Some(87))]
            }
            Some(MessageType::Request) if requests == 0 => {
                requests += 1;
                vec![ack_msg(m, MessageType::Ack, 100, Some(50), Some(87))]
            }
            _ => vec![],
        });
        // room for one event and nobody reading: Lost has to wait
        let mut run = start_cap(&fake, spec(), 1);
        tokio::time::sleep(Duration::from_secs(600)).await;
        let bound = next_event(&mut run.events).await;
        assert!(matches!(bound, Some(DhcpEvent::Bound(_))));
        let lost = next_event(&mut run.events).await;
        assert_eq!(lost, Some(DhcpEvent::Lost), "Lost survives a stall");
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn n9_shutdown_ends_a_blocked_emit() {
        // capacity 1: Bound fills it, so the Renewed at t1 blocks in emit
        let fake = Fake::new(good_server(100, Some(50), Some(87)));
        let run = start_cap(&fake, spec(), 1);
        tokio::time::sleep(Duration::from_secs(120)).await;
        run.stop().await; // would hang if emit ignored shutdown
    }

    #[test]
    fn n10_dhcp_links_get_loose_reverse_path_filtering() {
        let s = dhcp_link_sysctls("eth1");
        assert_eq!(
            s,
            vec![("net/ipv4/conf/eth1/rp_filter".to_owned(), "2".to_owned())]
        );
        for (k, v) in &s {
            assert!(crate::model::sysctl_path(k).is_ok());
            assert!(crate::model::valid_sysctl_value(v));
        }
    }
}
