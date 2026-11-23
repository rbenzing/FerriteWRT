//! `DHCPv6` prefix-delegation client (RFC 8415): the codec, the validation of server
//! replies and the state machine. Pure: the socket lives in `linux::dhcp6`.
//!
//! The router asks its upstream for an `IA_PD` (a delegated prefix), nothing else but the DNS
//! servers: the WAN address and the default route come from the ISP's router advertisements
//! (the kernel handles those, see `owr-apply`), and the router's own LAN addresses come from
//! the delegated prefix. Like [`crate::dhcp`], the client never configures anything: it emits
//! [`Dhcp6Event`]s and the caller converges the system.
//!
//! Exchanges: Solicit / Advertise (the best preference within one retransmission window wins),
//! Request / Reply, then Renew at T1 and Rebind at T2 until the shortest valid lifetime runs
//! out ([`Dhcp6Event::Lost`]) and a fresh Solicit. No Release on shutdown: a reload of the
//! network daemon would otherwise hand the prefix back and risk a different one.

use std::convert::Infallible;
use std::io;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::model::MacAddr;

/// UDP port clients listen on.
pub const CLIENT_PORT: u16 = 546;
/// UDP port servers and relays listen on.
pub const SERVER_PORT: u16 = 547;
/// `All_DHCP_Relay_Agents_and_Servers`, `ff02::1:2`.
pub const ALL_AGENTS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// A lifetime of this many seconds never expires.
pub const INFINITE: u32 = u32::MAX;
/// At most this many DNS servers are kept.
pub const MAX_DNS: usize = 3;
/// The longest prefix that can still be split into /64 subnets.
pub const MAX_DELEGATED_LEN: u8 = 64;

const RECV_BUF: usize = 4096;
const MAX_OPTIONS: usize = 64;

const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_RENEW: u8 = 5;
const MSG_REBIND: u8 = 6;
const MSG_REPLY: u8 = 7;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_ORO: u16 = 6;
const OPT_PREFERENCE: u16 = 7;
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_IA_PD: u16 = 25;
const OPT_IAPREFIX: u16 = 26;

/// Status code: no prefix available (RFC 8415 21.13).
const STATUS_NO_PREFIX_AVAIL: u16 = 6;
/// Status code: the server has no binding for the client (RFC 8415 21.13).
const STATUS_NO_BINDING: u16 = 3;

/// A server preference of this value ends the wait for further advertisements.
const PREFERENCE_IMMEDIATE: u8 = 255;

/// Retransmission parameters of one exchange (RFC 8415 section 7.6).
#[derive(Debug, Clone, Copy)]
struct Timing {
    irt: Duration,
    mrt: Duration,
    /// Maximum retransmission count, 0 for unlimited.
    mrc: u32,
    /// Maximum retransmission duration, `None` for unlimited.
    mrd: Option<Duration>,
}

const SOL_IRT: Duration = Duration::from_secs(1);
/// RFC 8415 allows an hour; a router that has no prefix should keep asking more often.
const SOL_MAX_RT: Duration = Duration::from_secs(120);
const REQ_TIMING: Timing = Timing {
    irt: Duration::from_secs(1),
    mrt: Duration::from_secs(30),
    mrc: 10,
    mrd: None,
};
const REN_IRT: Duration = Duration::from_secs(10);
const REN_MAX_RT: Duration = Duration::from_secs(600);
/// Pause before a fresh Solicit after a failed Request.
const RESTART_DELAY: Duration = Duration::from_secs(5);
/// Smallest renewal time that is honoured (a server sending tiny values must not be flooded).
const MIN_T1: u32 = 30;

/// What to ask for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dhcp6ClientSpec {
    /// The upstream interface (the WAN port, or the PPP interface of a `PPPoE` WAN).
    pub link: String,
    /// The interface whose hardware address identifies this client: `link` itself on an
    /// Ethernet WAN, the physical port under a `PPPoE` interface (PPP has no address).
    pub identity_link: String,
    /// Prefix length to ask for (a hint: the server decides); `None` leaves it to the server.
    pub prefix_len_hint: Option<u8>,
}

/// A prefix the server delegated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedPrefix {
    pub prefix: Ipv6Net,
    pub preferred_secs: u32,
    pub valid_secs: u32,
}

/// The state the server granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease6 {
    /// At least one, each at most [`MAX_DELEGATED_LEN`] bits long.
    pub prefixes: Vec<DelegatedPrefix>,
    /// At most [`MAX_DNS`], global or unique-local unicast.
    pub dns: Vec<Ipv6Addr>,
    /// Seconds after `obtained_at` at which renewal starts; [`INFINITE`] for never.
    pub t1: u32,
    /// Seconds after `obtained_at` at which rebinding starts; [`INFINITE`] for never.
    pub t2: u32,
    pub server_id: Vec<u8>,
    /// Wall clock at the Reply; informational (timers use the monotonic clock).
    pub obtained_at: SystemTime,
}

impl Lease6 {
    /// The prefixes without their lifetimes, in server order.
    pub fn nets(&self) -> Vec<Ipv6Net> {
        self.prefixes.iter().map(|p| p.prefix).collect()
    }

    /// The shortest valid lifetime in seconds; the lease is over when it runs out.
    fn shortest_valid(&self) -> u32 {
        self.prefixes
            .iter()
            .map(|p| p.valid_secs)
            .min()
            .unwrap_or(0)
    }
}

/// What the client reports to its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcp6Event {
    /// A lease, or the same server delegated a different prefix.
    Bound(Lease6),
    /// The same prefixes were confirmed for longer.
    Renewed(Lease6),
    /// The lease ran out or the server withdrew it; remove what it configured.
    Lost,
}

/// A datagram that cannot be read as a `DHCPv6` message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("message shorter than its header")]
    Truncated,
    #[error("option {0} is cut off")]
    BadOption(u16),
    #[error("more than {MAX_OPTIONS} options")]
    TooManyOptions,
}

/// Why a server message is not an acceptable offer or reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    #[error("malformed")]
    Malformed,
    #[error("addressed to another client")]
    WrongClient,
    #[error("no server identifier")]
    NoServerId,
    #[error("status {0}")]
    Status(u16),
    #[error("no usable delegated prefix")]
    NoPrefix,
}

/// A parsed message; the options borrow the datagram.
#[derive(Debug)]
pub struct Message<'a> {
    pub msg_type: u8,
    pub xid: [u8; 3],
    options: Vec<(u16, &'a [u8])>,
}

fn be16(d: &[u8]) -> Option<(u16, &[u8])> {
    let (h, t) = d.split_first_chunk::<2>()?;
    Some((u16::from_be_bytes(*h), t))
}

fn be32(d: &[u8]) -> Option<(u32, &[u8])> {
    let (h, t) = d.split_first_chunk::<4>()?;
    Some((u32::from_be_bytes(*h), t))
}

fn options(mut rest: &[u8]) -> Result<Vec<(u16, &[u8])>, ParseError> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (code, tail) = be16(rest).ok_or(ParseError::BadOption(0))?;
        let (len, tail) = be16(tail).ok_or(ParseError::BadOption(code))?;
        let (value, tail) = tail
            .split_at_checked(usize::from(len))
            .ok_or(ParseError::BadOption(code))?;
        if out.len() >= MAX_OPTIONS {
            return Err(ParseError::TooManyOptions);
        }
        out.push((code, value));
        rest = tail;
    }
    Ok(out)
}

impl<'a> Message<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let (&msg_type, rest) = data.split_first().ok_or(ParseError::Truncated)?;
        let (xid, rest) = rest.split_first_chunk::<3>().ok_or(ParseError::Truncated)?;
        Ok(Self {
            msg_type,
            xid: *xid,
            options: options(rest)?,
        })
    }

    pub fn option(&self, code: u16) -> Option<&'a [u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| *v)
    }
}

fn put_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value);
}

/// DUID-LL (RFC 8415 11.4) of an Ethernet interface.
pub fn duid_ll(mac: MacAddr) -> Vec<u8> {
    let mut d = vec![0, 3, 0, 1];
    d.extend_from_slice(&mac.0);
    d
}

/// The IAID of the one `IA_PD`: the low 32 bits of the hardware address.
pub fn iaid(mac: MacAddr) -> u32 {
    let m = mac.0;
    u32::from_be_bytes([m[2], m[3], m[4], m[5]])
}

/// Everything a client message is built from.
struct Request<'a> {
    kind: u8,
    xid: [u8; 3],
    duid: &'a [u8],
    server_id: Option<&'a [u8]>,
    iaid: u32,
    /// Prefixes to name inside the `IA_PD` (Request, Renew, Rebind).
    prefixes: &'a [Ipv6Net],
    hint: Option<u8>,
    /// Centiseconds since the exchange began, saturated to 16 bits.
    elapsed: u16,
}

impl Request<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut p = vec![self.kind];
        p.extend_from_slice(&self.xid);
        put_option(&mut p, OPT_CLIENTID, self.duid);
        if let Some(id) = self.server_id {
            put_option(&mut p, OPT_SERVERID, id);
        }
        put_option(&mut p, OPT_ELAPSED_TIME, &self.elapsed.to_be_bytes());
        put_option(&mut p, OPT_ORO, &OPT_DNS_SERVERS.to_be_bytes());
        let mut ia = Vec::new();
        ia.extend_from_slice(&self.iaid.to_be_bytes());
        ia.extend_from_slice(&[0; 8]); // T1 and T2 are the server's to set
        for net in self.prefixes {
            put_option(
                &mut ia,
                OPT_IAPREFIX,
                &iaprefix(net.addr(), net.prefix_len()),
            );
        }
        if let (Some(len), true) = (self.hint, self.prefixes.is_empty()) {
            put_option(&mut ia, OPT_IAPREFIX, &iaprefix(Ipv6Addr::UNSPECIFIED, len));
        }
        put_option(&mut p, OPT_IA_PD, &ia);
        p
    }
}

fn iaprefix(addr: Ipv6Addr, len: u8) -> Vec<u8> {
    let mut v = vec![0; 8]; // lifetimes: 0 in client messages
    v.push(len);
    v.extend_from_slice(&addr.octets());
    v
}

/// A server message for tests of the socket: `kind`, the client's DUID and `IA_PD` with one
/// prefix (`valid` 200s, `preferred` 100s, T1 50s, T2 80s) from `server`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_reply(
    kind: u8,
    xid: [u8; 3],
    client: &[u8],
    iaid: u32,
    prefix: Ipv6Net,
) -> Vec<u8> {
    let mut p = vec![kind];
    p.extend_from_slice(&xid);
    put_option(&mut p, OPT_CLIENTID, client);
    put_option(
        &mut p,
        OPT_SERVERID,
        &[0, 3, 0, 1, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
    );
    let mut ia = Vec::new();
    ia.extend_from_slice(&iaid.to_be_bytes());
    ia.extend_from_slice(&50u32.to_be_bytes());
    ia.extend_from_slice(&80u32.to_be_bytes());
    let mut v = Vec::new();
    v.extend_from_slice(&100u32.to_be_bytes());
    v.extend_from_slice(&200u32.to_be_bytes());
    v.push(prefix.prefix_len());
    v.extend_from_slice(&prefix.addr().octets());
    put_option(&mut ia, OPT_IAPREFIX, &v);
    put_option(&mut p, OPT_IA_PD, &ia);
    p
}

/// A server's answer, checked against this client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub preference: u8,
    pub lease: Lease6,
}

fn usable_prefix(addr: Ipv6Addr) -> bool {
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unicast_link_local())
}

fn status_of(value: &[u8]) -> Option<u16> {
    be16(value).map(|(code, _)| code)
}

/// Read an IAPREFIX option; `None` when it is unusable (it is then skipped, not fatal).
fn read_prefix(value: &[u8]) -> Option<DelegatedPrefix> {
    let (preferred_secs, rest) = be32(value)?;
    let (valid_secs, rest) = be32(rest)?;
    let (&len, rest) = rest.split_first()?;
    let (addr, _) = rest.split_first_chunk::<16>()?;
    let net = Ipv6Net::new(Ipv6Addr::from(*addr), len).ok()?.trunc();
    let usable = (1..=MAX_DELEGATED_LEN).contains(&len)
        && usable_prefix(net.addr())
        && valid_secs > 0
        && preferred_secs <= valid_secs;
    usable.then_some(DelegatedPrefix {
        prefix: net,
        preferred_secs,
        valid_secs,
    })
}

/// A lifetime fraction in seconds: `secs * num / den`, infinite stays infinite.
fn fraction(secs: u32, num: u64, den: u64) -> u32 {
    if secs == INFINITE {
        return INFINITE;
    }
    let v = u64::from(secs).saturating_mul(num).checked_div(den);
    v.and_then(|v| u32::try_from(v).ok()).unwrap_or(secs)
}

/// Check a server message (Advertise or Reply) and turn it into an [`Offer`].
pub fn analyse(
    msg: &Message<'_>,
    duid: &[u8],
    iaid: u32,
    now: SystemTime,
) -> Result<Offer, ReplyError> {
    if msg.option(OPT_CLIENTID) != Some(duid) {
        return Err(ReplyError::WrongClient);
    }
    let server_id = msg.option(OPT_SERVERID).ok_or(ReplyError::NoServerId)?;
    if server_id.is_empty() {
        return Err(ReplyError::NoServerId);
    }
    if let Some(code) = msg
        .option(OPT_STATUS_CODE)
        .and_then(status_of)
        .filter(|c| *c != 0)
    {
        return Err(ReplyError::Status(code));
    }
    let ia = msg
        .options
        .iter()
        .filter(|(c, _)| *c == OPT_IA_PD)
        .find_map(|(_, v)| {
            let (id, rest) = be32(v)?;
            (id == iaid).then_some(rest)
        })
        .ok_or(ReplyError::NoPrefix)?;
    let (t1, rest) = be32(ia).ok_or(ReplyError::Malformed)?;
    let (t2, rest) = be32(rest).ok_or(ReplyError::Malformed)?;
    let mut prefixes = Vec::new();
    for (code, value) in options(rest).map_err(|_| ReplyError::Malformed)? {
        match code {
            OPT_STATUS_CODE => {
                if let Some(c) = status_of(value).filter(|c| *c != 0) {
                    return Err(ReplyError::Status(c));
                }
            }
            OPT_IAPREFIX => {
                if let Some(p) = read_prefix(value) {
                    prefixes.push(p);
                } else {
                    debug!("ignoring an unusable delegated prefix");
                }
            }
            _ => {}
        }
    }
    if prefixes.is_empty() {
        return Err(ReplyError::NoPrefix);
    }
    let shortest_preferred = prefixes.iter().map(|p| p.preferred_secs).min().unwrap_or(0);
    let mut t1_secs = if t1 == 0 {
        fraction(shortest_preferred, 1, 2)
    } else {
        t1
    };
    let mut t2_secs = if t2 == 0 {
        fraction(shortest_preferred, 4, 5)
    } else {
        t2
    };
    if t1_secs > t2_secs {
        // RFC 8415 21.4: inconsistent times are ignored, the client picks its own.
        t1_secs = fraction(shortest_preferred, 1, 2);
        t2_secs = fraction(shortest_preferred, 4, 5);
    }
    let dns = msg.option(OPT_DNS_SERVERS).map_or_else(Vec::new, |v| {
        v.as_chunks::<16>()
            .0
            .iter()
            .map(|c| Ipv6Addr::from(*c))
            .filter(|a| usable_prefix(*a))
            .take(MAX_DNS)
            .collect()
    });
    let preference = msg
        .option(OPT_PREFERENCE)
        .and_then(|v| v.first().copied())
        .unwrap_or(0);
    Ok(Offer {
        preference,
        lease: Lease6 {
            prefixes,
            dns,
            t1: t1_secs.max(MIN_T1.min(t2_secs)),
            t2: t2_secs,
            server_id: server_id.to_vec(),
            obtained_at: now,
        },
    })
}

/// The `n` first /64 subnets of the delegated prefixes, in order (an empty list when they
/// hold fewer). One prefix covers `2^(64 - len)` of them.
pub fn split_into_64s(prefixes: &[DelegatedPrefix], n: usize) -> Vec<Ipv6Net> {
    let mut out = Vec::new();
    for p in prefixes {
        let Ok(subnets) = p.prefix.subnets(64) else {
            continue;
        };
        for net in subnets {
            if out.len() >= n {
                return out;
            }
            out.push(net);
        }
    }
    out
}

/// Retransmission delay (RFC 8415 15): `prev` is the previous delay, `rand_permille` the
/// random factor in `-100..=100` (tenths of a percent of a hundredth: +-10%).
pub fn retransmit_delay(
    prev: Option<Duration>,
    irt: Duration,
    mrt: Duration,
    rand_permille: i64,
) -> Duration {
    let jitter = |d: Duration| -> Duration {
        let ms = i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        let r = rand_permille.clamp(-100, 100);
        let ms = ms.saturating_add(ms.saturating_mul(r).checked_div(1000).unwrap_or(0));
        Duration::from_millis(u64::try_from(ms).unwrap_or(0))
    };
    let Some(prev) = prev else {
        return jitter(irt);
    };
    let next = prev.saturating_mul(2);
    let next = jitter(next);
    if next > mrt { jitter(mrt) } else { next }
}

/// Datagram I/O used by the engine. The transport knows where to send (the
/// all-agents multicast group on its interface).
pub trait Transport {
    fn send(&self, payload: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

/// The engine was asked to stop (shutdown signalled or event receiver dropped).
#[derive(Debug)]
struct Stop;

enum Verdict<R> {
    /// Not for us or not usable: keep waiting.
    Wait,
    Done(R),
    /// The server says there is no binding: stop retrying.
    Abort,
}

enum Outcome<R> {
    Done(R),
    TimedOut,
    Aborted,
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() || rx.changed().await.is_err() {
            return;
        }
    }
}

fn jitter() -> i64 {
    rand::random_range(-100..=100)
}

fn new_xid() -> [u8; 3] {
    let [_, a, b, c] = rand::random::<u32>().to_be_bytes();
    [a, b, c]
}

/// `d` from now (saturating at now).
fn after(d: Duration) -> Instant {
    Instant::now().checked_add(d).unwrap_or_else(Instant::now)
}

fn secs(s: u32) -> Option<Duration> {
    (s != INFINITE).then(|| Duration::from_secs(u64::from(s)))
}

struct Ctx<'a, T> {
    t: &'a T,
    spec: Dhcp6ClientSpec,
    duid: Vec<u8>,
    iaid: u32,
    events: mpsc::Sender<Dhcp6Event>,
    shutdown: watch::Receiver<bool>,
    buf: Vec<u8>,
}

/// Run the client until `shutdown` turns true (or its sender is dropped) or the event
/// receiver is dropped.
pub async fn run_with<T: Transport>(
    transport: &T,
    spec: Dhcp6ClientSpec,
    mac: MacAddr,
    events: mpsc::Sender<Dhcp6Event>,
    shutdown: watch::Receiver<bool>,
) {
    let mut ctx = Ctx {
        t: transport,
        spec,
        duid: duid_ll(mac),
        iaid: iaid(mac),
        events,
        shutdown,
        buf: vec![0; RECV_BUF],
    };
    let Err(Stop) = ctx.run().await;
    info!(link = %ctx.spec.link, "dhcpv6 client stopped");
}

impl<T: Transport> Ctx<'_, T> {
    async fn run(&mut self) -> Result<Infallible, Stop> {
        // RFC 8415 18.2.1: a random delay of up to a second before the first Solicit.
        let mut delay = Duration::from_millis(rand::random_range(0..=1000));
        loop {
            self.pause(delay).await?;
            delay = Duration::ZERO;
            let offer = self.solicit().await?;
            let Some(lease) = self.request(&offer).await? else {
                delay = RESTART_DELAY;
                continue;
            };
            info!(
                prefixes = ?lease.nets(),
                t1 = lease.t1,
                t2 = lease.t2,
                "delegated prefix bound"
            );
            self.emit(Dhcp6Event::Bound(lease.clone())).await?;
            self.maintain(lease).await?;
            warn!("delegated prefix lost");
            self.emit(Dhcp6Event::Lost).await?;
        }
    }

    async fn emit(&self, event: Dhcp6Event) -> Result<(), Stop> {
        self.events.send(event).await.map_err(|_| Stop)
    }

    async fn pause(&mut self, d: Duration) -> Result<(), Stop> {
        tokio::select! {
            () = tokio::time::sleep(d) => Ok(()),
            () = stopped(&mut self.shutdown) => Err(Stop),
        }
    }

    fn message(
        &self,
        kind: u8,
        xid: [u8; 3],
        server_id: Option<&[u8]>,
        prefixes: &[Ipv6Net],
        began: Instant,
    ) -> Vec<u8> {
        let cs = u16::try_from(began.elapsed().as_millis().checked_div(10).unwrap_or(0))
            .unwrap_or(u16::MAX);
        Request {
            kind,
            xid,
            duid: &self.duid,
            server_id,
            iaid: self.iaid,
            prefixes,
            hint: self.spec.prefix_len_hint,
            elapsed: cs,
        }
        .encode()
    }

    async fn transmit(&self, payload: &[u8]) {
        if let Err(e) = self.t.send(payload).await {
            warn!(error = %e, "dhcpv6 send failed");
        }
    }

    /// Solicit until at least one acceptable Advertise arrived within a retransmission
    /// window; the best preference wins, 255 wins at once.
    async fn solicit(&mut self) -> Result<Offer, Stop> {
        let xid = new_xid();
        let began = Instant::now();
        let mut best: Option<Offer> = None;
        let mut rt: Option<Duration> = None;
        loop {
            let msg = self.message(MSG_SOLICIT, xid, None, &[], began);
            self.transmit(&msg).await;
            let wait = retransmit_delay(rt, SOL_IRT, SOL_MAX_RT, jitter());
            rt = Some(wait);
            let end = after(wait);
            loop {
                let n = tokio::select! {
                    r = self.t.recv(&mut self.buf) => r,
                    () = tokio::time::sleep_until(end) => break,
                    () = stopped(&mut self.shutdown) => return Err(Stop),
                };
                let Ok(n) = n else {
                    // A socket error would spin; wait out the window instead.
                    self.pause(end.saturating_duration_since(Instant::now()))
                        .await?;
                    break;
                };
                let Some(data) = self.buf.get(..n) else {
                    continue;
                };
                let Ok(m) = Message::parse(data) else {
                    continue;
                };
                if m.xid != xid || m.msg_type != MSG_ADVERTISE {
                    continue;
                }
                match analyse(&m, &self.duid, self.iaid, SystemTime::now()) {
                    Ok(offer) => {
                        if offer.preference == PREFERENCE_IMMEDIATE {
                            return Ok(offer);
                        }
                        if best
                            .as_ref()
                            .is_none_or(|b| offer.preference > b.preference)
                        {
                            best = Some(offer);
                        }
                    }
                    Err(e) => debug!(error = %e, "advertise not usable"),
                }
            }
            if let Some(offer) = best.take() {
                return Ok(offer);
            }
        }
    }

    /// Send `kind` and wait for an acceptable Reply, retransmitting per `timing`.
    async fn exchange<R>(
        &mut self,
        kind: u8,
        server_id: Option<&[u8]>,
        prefixes: &[Ipv6Net],
        timing: Timing,
        mut judge: impl FnMut(&Message<'_>) -> Verdict<R>,
    ) -> Result<Outcome<R>, Stop> {
        let xid = new_xid();
        let began = Instant::now();
        let mut rt: Option<Duration> = None;
        let mut attempt = 0u32;
        loop {
            if (timing.mrc != 0 && attempt >= timing.mrc)
                || timing.mrd.is_some_and(|d| began.elapsed() >= d)
            {
                return Ok(Outcome::TimedOut);
            }
            let msg = self.message(kind, xid, server_id, prefixes, began);
            self.transmit(&msg).await;
            let wait = retransmit_delay(rt, timing.irt, timing.mrt, jitter());
            rt = Some(wait);
            let mut end = after(wait);
            if let Some(limit) = timing.mrd.and_then(|d| began.checked_add(d)) {
                end = end.min(limit);
            }
            loop {
                let n = tokio::select! {
                    r = self.t.recv(&mut self.buf) => r,
                    () = tokio::time::sleep_until(end) => break,
                    () = stopped(&mut self.shutdown) => return Err(Stop),
                };
                let Ok(n) = n else {
                    self.pause(end.saturating_duration_since(Instant::now()))
                        .await?;
                    break;
                };
                let Some(data) = self.buf.get(..n) else {
                    continue;
                };
                let Ok(m) = Message::parse(data) else {
                    continue;
                };
                if m.xid != xid || m.msg_type != MSG_REPLY {
                    continue;
                }
                match judge(&m) {
                    Verdict::Wait => {}
                    Verdict::Done(r) => return Ok(Outcome::Done(r)),
                    Verdict::Abort => return Ok(Outcome::Aborted),
                }
            }
            attempt = attempt.saturating_add(1);
        }
    }

    fn judge_reply(duid: &[u8], iaid: u32, m: &Message<'_>) -> Verdict<Lease6> {
        match analyse(m, duid, iaid, SystemTime::now()) {
            Ok(offer) => Verdict::Done(offer.lease),
            Err(ReplyError::Status(STATUS_NO_BINDING | STATUS_NO_PREFIX_AVAIL)) => Verdict::Abort,
            Err(e) => {
                debug!(error = %e, "reply not usable");
                Verdict::Wait
            }
        }
    }

    /// Request the offered prefixes; `None` when the server does not grant them.
    async fn request(&mut self, offer: &Offer) -> Result<Option<Lease6>, Stop> {
        let nets = offer.lease.nets();
        let server = offer.lease.server_id.clone();
        let duid = self.duid.clone();
        let iaid = self.iaid;
        let outcome = self
            .exchange(
                MSG_REQUEST,
                Some(&server),
                &nets,
                REQ_TIMING,
                |m| match analyse(m, &duid, iaid, SystemTime::now()) {
                    Ok(o) if o.lease.server_id == server => Verdict::Done(o.lease),
                    Err(ReplyError::Status(STATUS_NO_PREFIX_AVAIL)) => Verdict::Abort,
                    _ => Verdict::Wait,
                },
            )
            .await?;
        Ok(match outcome {
            Outcome::Done(l) => Some(l),
            Outcome::TimedOut | Outcome::Aborted => None,
        })
    }

    /// Renew and rebind until the lease is over (`Ok(())`).
    async fn maintain(&mut self, mut cur: Lease6) -> Result<(), Stop> {
        loop {
            let at = Instant::now();
            let valid = secs(cur.shortest_valid());
            if let Some(d) = secs(cur.t1) {
                self.pause(d).await?;
            } else {
                stopped(&mut self.shutdown).await;
                return Err(Stop);
            }
            let nets = cur.nets();
            let server = cur.server_id.clone();
            let duid = self.duid.clone();
            let iaid = self.iaid;
            let renew = Timing {
                irt: REN_IRT,
                mrt: REN_MAX_RT,
                mrc: 0,
                mrd: secs(cur.t2).map(|t2| t2.saturating_sub(at.elapsed())),
            };
            let renewed = match self
                .exchange(MSG_RENEW, Some(&server), &nets, renew, |m| {
                    Self::judge_reply(&duid, iaid, m)
                })
                .await?
            {
                Outcome::Done(l) => Some(l),
                Outcome::Aborted => return Ok(()),
                Outcome::TimedOut => None,
            };
            let next = if let Some(l) = renewed {
                l
            } else {
                {
                    let rebind = Timing {
                        irt: REN_IRT,
                        mrt: REN_MAX_RT,
                        mrc: 0,
                        mrd: valid.map(|v| v.saturating_sub(at.elapsed())),
                    };
                    match self
                        .exchange(MSG_REBIND, None, &nets, rebind, |m| {
                            Self::judge_reply(&duid, iaid, m)
                        })
                        .await?
                    {
                        Outcome::Done(l) => l,
                        Outcome::Aborted | Outcome::TimedOut => return Ok(()),
                    }
                }
            };
            let same = next.nets() == cur.nets();
            let event = if same {
                Dhcp6Event::Renewed(next.clone())
            } else {
                Dhcp6Event::Bound(next.clone())
            };
            self.emit(event).await?;
            cur = next;
        }
    }
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
    const SERVER_A: [u8; 6] = [0, 3, 0, 1, 0xaa, 0xaa];
    const SERVER_B: [u8; 6] = [0, 3, 0, 1, 0xbb, 0xbb];

    fn net(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    fn duid() -> Vec<u8> {
        duid_ll(MAC)
    }

    /// What a test server grants.
    #[derive(Clone)]
    struct Grant {
        server: [u8; 6],
        preference: u8,
        prefixes: Vec<(u32, u32, &'static str, u8)>,
        t1: u32,
        t2: u32,
        status: Option<u16>,
        ia_status: Option<u16>,
        dns: Vec<Ipv6Addr>,
    }

    impl Grant {
        fn new() -> Self {
            Self {
                server: SERVER_A,
                preference: 0,
                prefixes: vec![(100, 200, "2001:db8:1::", 56)],
                t1: 50,
                t2: 80,
                status: None,
                ia_status: None,
                dns: vec!["2001:db8::53".parse().unwrap()],
            }
        }

        fn encode(&self, kind: u8, xid: [u8; 3], client: &[u8]) -> Vec<u8> {
            let mut p = vec![kind];
            p.extend_from_slice(&xid);
            put_option(&mut p, OPT_CLIENTID, client);
            put_option(&mut p, OPT_SERVERID, &self.server);
            put_option(&mut p, OPT_PREFERENCE, &[self.preference]);
            if let Some(s) = self.status {
                put_option(&mut p, OPT_STATUS_CODE, &s.to_be_bytes());
            }
            let mut ia = Vec::new();
            ia.extend_from_slice(&iaid(MAC).to_be_bytes());
            ia.extend_from_slice(&self.t1.to_be_bytes());
            ia.extend_from_slice(&self.t2.to_be_bytes());
            for (pref, valid, addr, len) in &self.prefixes {
                let mut v = Vec::new();
                v.extend_from_slice(&pref.to_be_bytes());
                v.extend_from_slice(&valid.to_be_bytes());
                v.push(*len);
                v.extend_from_slice(&addr.parse::<Ipv6Addr>().unwrap().octets());
                put_option(&mut ia, OPT_IAPREFIX, &v);
            }
            if let Some(s) = self.ia_status {
                put_option(&mut ia, OPT_STATUS_CODE, &s.to_be_bytes());
            }
            put_option(&mut p, OPT_IA_PD, &ia);
            let dns: Vec<u8> = self.dns.iter().flat_map(Ipv6Addr::octets).collect();
            if !dns.is_empty() {
                put_option(&mut p, OPT_DNS_SERVERS, &dns);
            }
            p
        }
    }

    fn analyse_grant(g: &Grant) -> Result<Offer, ReplyError> {
        let bytes = g.encode(MSG_REPLY, [1, 2, 3], &duid());
        let m = Message::parse(&bytes).unwrap();
        analyse(&m, &duid(), iaid(MAC), SystemTime::UNIX_EPOCH)
    }

    #[test]
    fn duid_and_iaid_come_from_the_hardware_address() {
        assert_eq!(duid(), vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 1]);
        assert_eq!(iaid(MAC), 1);
    }

    #[test]
    fn a_solicit_carries_client_id_ia_pd_and_the_prefix_hint() {
        let req = Request {
            kind: MSG_SOLICIT,
            xid: [9, 8, 7],
            duid: &duid(),
            server_id: None,
            iaid: 1,
            prefixes: &[],
            hint: Some(56),
            elapsed: 0,
        };
        let bytes = req.encode();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!((m.msg_type, m.xid), (MSG_SOLICIT, [9, 8, 7]));
        assert_eq!(m.option(OPT_CLIENTID), Some(duid().as_slice()));
        assert_eq!(m.option(OPT_SERVERID), None);
        assert_eq!(m.option(OPT_ORO), Some(&OPT_DNS_SERVERS.to_be_bytes()[..]));
        let ia = m.option(OPT_IA_PD).unwrap();
        // IAID, T1, T2, then one IAPREFIX with lifetimes 0, length 56 and the zero prefix
        assert_eq!(ia.get(..4), Some(&1u32.to_be_bytes()[..]));
        let subs = options(ia.get(12..).unwrap()).unwrap();
        assert_eq!(subs.len(), 1);
        let (code, v) = subs[0];
        assert_eq!(code, OPT_IAPREFIX);
        assert_eq!(v.len(), 25);
        assert_eq!(v.get(8), Some(&56));
        assert!(v.get(9..).unwrap().iter().all(|b| *b == 0));
    }

    #[test]
    fn a_request_names_the_offered_prefixes_instead_of_the_hint() {
        let prefixes = [net("2001:db8:1::/56")];
        let req = Request {
            kind: MSG_REQUEST,
            xid: [0; 3],
            duid: &duid(),
            server_id: Some(&SERVER_A),
            iaid: 1,
            prefixes: &prefixes,
            hint: Some(48),
            elapsed: 7,
        };
        let bytes = req.encode();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.option(OPT_SERVERID), Some(&SERVER_A[..]));
        assert_eq!(m.option(OPT_ELAPSED_TIME), Some(&7u16.to_be_bytes()[..]));
        let ia = m.option(OPT_IA_PD).unwrap();
        let subs = options(ia.get(12..).unwrap()).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].1.get(8), Some(&56));
        assert_eq!(
            subs[0].1.get(9..),
            Some(&"2001:db8:1::".parse::<Ipv6Addr>().unwrap().octets()[..])
        );
    }

    #[test]
    fn truncated_and_oversized_messages_are_refused() {
        assert_eq!(Message::parse(&[]).unwrap_err(), ParseError::Truncated);
        assert_eq!(
            Message::parse(&[7, 1, 2]).unwrap_err(),
            ParseError::Truncated
        );
        // an option announcing more bytes than there are
        assert_eq!(
            Message::parse(&[7, 1, 2, 3, 0, 1, 0, 9, 0]).unwrap_err(),
            ParseError::BadOption(1)
        );
        // half an option header
        assert_eq!(
            Message::parse(&[7, 1, 2, 3, 0]).unwrap_err(),
            ParseError::BadOption(0)
        );
        let mut many = vec![7, 1, 2, 3];
        for _ in 0..=MAX_OPTIONS {
            many.extend_from_slice(&[0, 99, 0, 0]);
        }
        assert_eq!(
            Message::parse(&many).unwrap_err(),
            ParseError::TooManyOptions
        );
    }

    #[test]
    fn a_good_reply_becomes_a_lease() {
        let offer = analyse_grant(&Grant::new()).unwrap();
        let lease = offer.lease;
        assert_eq!(
            lease.prefixes,
            vec![DelegatedPrefix {
                prefix: net("2001:db8:1::/56"),
                preferred_secs: 100,
                valid_secs: 200,
            }]
        );
        assert_eq!((lease.t1, lease.t2), (50, 80));
        assert_eq!(lease.dns, vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(lease.server_id, SERVER_A.to_vec());
    }

    #[test]
    fn replies_for_other_clients_or_without_a_server_are_refused() {
        let g = Grant::new();
        let bytes = g.encode(MSG_REPLY, [0; 3], &[0, 3, 0, 1, 9, 9, 9, 9, 9, 9]);
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(
            analyse(&m, &duid(), iaid(MAC), SystemTime::UNIX_EPOCH).unwrap_err(),
            ReplyError::WrongClient
        );
        // another IAID
        let bytes = g.encode(MSG_REPLY, [0; 3], &duid());
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(
            analyse(&m, &duid(), iaid(MAC) + 1, SystemTime::UNIX_EPOCH).unwrap_err(),
            ReplyError::NoPrefix
        );
        // no server identifier
        let mut p = vec![MSG_REPLY, 0, 0, 0];
        put_option(&mut p, OPT_CLIENTID, &duid());
        let m = Message::parse(&p).unwrap();
        assert_eq!(
            analyse(&m, &duid(), iaid(MAC), SystemTime::UNIX_EPOCH).unwrap_err(),
            ReplyError::NoServerId
        );
    }

    #[test]
    fn status_codes_refuse_the_reply() {
        let mut g = Grant::new();
        g.status = Some(STATUS_NO_BINDING);
        assert_eq!(
            analyse_grant(&g).unwrap_err(),
            ReplyError::Status(STATUS_NO_BINDING)
        );
        let mut g = Grant::new();
        g.ia_status = Some(STATUS_NO_PREFIX_AVAIL);
        assert_eq!(
            analyse_grant(&g).unwrap_err(),
            ReplyError::Status(STATUS_NO_PREFIX_AVAIL)
        );
        // success (0) is not an error
        let mut g = Grant::new();
        g.status = Some(0);
        g.ia_status = Some(0);
        assert!(analyse_grant(&g).is_ok());
    }

    #[test]
    fn unusable_prefixes_are_skipped_and_without_any_the_reply_fails() {
        for bad in [
            (100, 200, "2001:db8:1::", 65), // too long to split into /64s
            (100, 200, "2001:db8:1::", 0),  // not a prefix
            (300, 200, "2001:db8:1::", 56), // preferred longer than valid
            (0, 0, "2001:db8:1::", 56),     // withdrawn
            (100, 200, "fe80::", 64),       // link-local
            (100, 200, "ff02::", 64),       // multicast
            (100, 200, "::", 56),           // unspecified
        ] {
            let mut g = Grant::new();
            g.prefixes = vec![bad];
            assert_eq!(
                analyse_grant(&g).unwrap_err(),
                ReplyError::NoPrefix,
                "{bad:?}"
            );
        }
        let mut g = Grant::new();
        g.prefixes = vec![(100, 200, "fe80::", 64), (100, 200, "2001:db8:2::", 60)];
        let offer = analyse_grant(&g).unwrap();
        assert_eq!(offer.lease.nets(), vec![net("2001:db8:2::/60")]);
    }

    #[test]
    fn host_bits_of_a_delegated_prefix_are_cleared() {
        let mut g = Grant::new();
        g.prefixes = vec![(100, 200, "2001:db8:1:5::1", 56)];
        assert_eq!(
            analyse_grant(&g).unwrap().lease.nets(),
            vec![net("2001:db8:1::/56")]
        );
    }

    #[test]
    fn zero_or_inconsistent_renewal_times_are_derived_from_the_lifetimes() {
        let mut g = Grant::new();
        g.t1 = 0;
        g.t2 = 0;
        let l = analyse_grant(&g).unwrap().lease;
        assert_eq!((l.t1, l.t2), (50, 80));
        // T1 after T2: both are ignored
        let mut g = Grant::new();
        g.t1 = 90;
        g.t2 = 60;
        let l = analyse_grant(&g).unwrap().lease;
        assert_eq!((l.t1, l.t2), (50, 80));
        // a tiny T1 is raised to the floor, but never above T2
        let mut g = Grant::new();
        g.t1 = 1;
        g.t2 = 100;
        assert_eq!(analyse_grant(&g).unwrap().lease.t1, MIN_T1);
        g.t2 = 10;
        assert_eq!(analyse_grant(&g).unwrap().lease.t1, 10);
    }

    #[test]
    fn infinite_lifetimes_stay_infinite() {
        let mut g = Grant::new();
        g.prefixes = vec![(INFINITE, INFINITE, "2001:db8:1::", 56)];
        g.t1 = 0;
        g.t2 = 0;
        let l = analyse_grant(&g).unwrap().lease;
        assert_eq!((l.t1, l.t2), (INFINITE, INFINITE));
        assert_eq!(secs(l.t1), None);
        assert_eq!(secs(l.shortest_valid()), None);
    }

    #[test]
    fn only_a_few_usable_dns_servers_are_kept() {
        let mut g = Grant::new();
        g.dns = [
            "2001:db8::1",
            "fe80::1",
            "::",
            "ff02::1",
            "fd00::2",
            "2001:db8::3",
            "2001:db8::4",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let dns: Vec<String> = analyse_grant(&g)
            .unwrap()
            .lease
            .dns
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(dns, ["2001:db8::1", "fd00::2", "2001:db8::3"]);
    }

    #[test]
    fn a_delegated_prefix_is_split_into_64s_in_order() {
        let p = |s: &str| DelegatedPrefix {
            prefix: net(s),
            preferred_secs: 1,
            valid_secs: 2,
        };
        let got: Vec<String> = split_into_64s(&[p("2001:db8:1::/56")], 3)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            got,
            ["2001:db8:1::/64", "2001:db8:1:1::/64", "2001:db8:1:2::/64"]
        );
        // a /64 holds one subnet however many are wanted
        assert_eq!(
            split_into_64s(&[p("2001:db8:1::/64")], 4),
            vec![net("2001:db8:1::/64")]
        );
        // a /62 holds four
        assert_eq!(split_into_64s(&[p("2001:db8:1::/62")], 99).len(), 4);
        // several prefixes continue where the previous one ended
        let two = split_into_64s(&[p("2001:db8:1::/63"), p("2001:db8:9::/64")], 9);
        assert_eq!(
            two,
            vec![
                net("2001:db8:1::/64"),
                net("2001:db8:1:1::/64"),
                net("2001:db8:9::/64")
            ]
        );
        assert_eq!(split_into_64s(&[p("2001:db8:1::/56")], 0).len(), 0);
    }

    #[test]
    fn retransmission_delays_double_with_jitter_and_are_capped() {
        let s = Duration::from_secs;
        let ms = Duration::from_millis;
        assert_eq!(retransmit_delay(None, s(1), s(120), 0), s(1));
        assert_eq!(retransmit_delay(None, s(1), s(120), 100), ms(1100));
        assert_eq!(retransmit_delay(None, s(1), s(120), -100), ms(900));
        assert_eq!(retransmit_delay(Some(s(2)), s(1), s(120), 0), s(4));
        // beyond MRT the delay is MRT itself (plus jitter)
        assert_eq!(retransmit_delay(Some(s(100)), s(1), s(120), 0), s(120));
        assert_eq!(
            retransmit_delay(Some(s(100)), s(1), s(120), 100),
            ms(132_000)
        );
        // the jitter factor is clamped
        assert_eq!(retransmit_delay(None, s(10), s(120), 5000), s(11));
    }

    type Handler = Box<dyn FnMut(&Message<'_>) -> Vec<Vec<u8>> + Send>;

    /// In-memory network: every datagram the client sends is shown to `handler`, whose
    /// replies are queued for `recv`.
    struct Fake {
        handler: Mutex<Handler>,
        queue: Mutex<VecDeque<Vec<u8>>>,
        notify: Notify,
        /// `(message type, has a server id)` of everything sent.
        sent: Mutex<Vec<(u8, bool)>>,
    }

    impl Fake {
        fn new(handler: Handler) -> Arc<Self> {
            Arc::new(Self {
                handler: Mutex::new(handler),
                queue: Mutex::default(),
                notify: Notify::new(),
                sent: Mutex::default(),
            })
        }

        fn kinds(&self) -> Vec<u8> {
            self.sent.lock().unwrap().iter().map(|(k, _)| *k).collect()
        }

        fn sent(&self) -> Vec<(u8, bool)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Transport for Arc<Fake> {
        async fn send(&self, payload: &[u8]) -> io::Result<()> {
            let msg = Message::parse(payload).map_err(io::Error::other)?;
            let replies = (self.handler.lock().unwrap())(&msg);
            self.sent
                .lock()
                .unwrap()
                .push((msg.msg_type, msg.option(OPT_SERVERID).is_some()));
            self.queue.lock().unwrap().extend(replies);
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

    /// A server that answers Solicit with an Advertise and Request / Renew / Rebind with a
    /// Reply, using `grant`, for `replies_left` replies and then stays silent.
    fn server(grant: Grant, mut replies_left: u32) -> Handler {
        Box::new(move |m| {
            let answer = match m.msg_type {
                MSG_SOLICIT => MSG_ADVERTISE,
                MSG_REQUEST | MSG_RENEW | MSG_REBIND => {
                    if replies_left == 0 {
                        return vec![];
                    }
                    replies_left = replies_left.saturating_sub(1);
                    MSG_REPLY
                }
                _ => return vec![],
            };
            vec![grant.encode(answer, m.xid, &duid())]
        })
    }

    struct Running {
        events: mpsc::Receiver<Dhcp6Event>,
        shutdown: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    fn start(fake: &Arc<Fake>) -> Running {
        let (tx, events) = mpsc::channel(16);
        let (shutdown, rx) = watch::channel(false);
        let f = Arc::clone(fake);
        let spec = Dhcp6ClientSpec {
            link: "eth1".into(),
            identity_link: "eth1".into(),
            prefix_len_hint: Some(56),
        };
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

    #[tokio::test(start_paused = true)]
    async fn acquires_a_prefix_then_renews_it_at_t1() {
        let fake = Fake::new(server(Grant::new(), u32::MAX));
        let mut run = start(&fake);
        let Some(Dhcp6Event::Bound(lease)) = run.events.recv().await else {
            unreachable!("expected Bound");
        };
        assert_eq!(lease.nets(), vec![net("2001:db8:1::/56")]);
        assert_eq!(fake.kinds(), vec![MSG_SOLICIT, MSG_REQUEST]);
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Renewed(_))
        ));
        assert_eq!(fake.sent().get(2), Some(&(MSG_RENEW, true)));
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_different_prefix_in_a_renewal_is_a_new_binding() {
        let first = Grant::new();
        let mut second = Grant::new();
        second.prefixes = vec![(100, 200, "2001:db8:7::", 56)];
        let handler: Handler = Box::new(move |m| {
            let (answer, grant) = match m.msg_type {
                MSG_SOLICIT => (MSG_ADVERTISE, &first),
                MSG_REQUEST => (MSG_REPLY, &first),
                MSG_RENEW => (MSG_REPLY, &second),
                _ => return vec![],
            };
            vec![grant.encode(answer, m.xid, &duid())]
        });
        let fake = Fake::new(handler);
        let mut run = start(&fake);
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Bound(_))
        ));
        let Some(Dhcp6Event::Bound(l)) = run.events.recv().await else {
            unreachable!("a changed prefix is a Bound, not a Renewed");
        };
        assert_eq!(l.nets(), vec![net("2001:db8:7::/56")]);
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_best_preference_wins_and_is_the_one_requested() {
        let mut low = Grant::new();
        low.preference = 1;
        let mut high = Grant::new();
        high.preference = 100;
        high.server = SERVER_B;
        let handler: Handler = Box::new(move |m| match m.msg_type {
            MSG_SOLICIT => vec![
                low.encode(MSG_ADVERTISE, m.xid, &duid()),
                high.encode(MSG_ADVERTISE, m.xid, &duid()),
            ],
            MSG_REQUEST => {
                let id = m.option(OPT_SERVERID).unwrap().to_vec();
                assert_eq!(
                    id,
                    SERVER_B.to_vec(),
                    "the Request goes to the preferred server"
                );
                vec![high.encode(MSG_REPLY, m.xid, &duid())]
            }
            _ => vec![],
        });
        let fake = Fake::new(handler);
        let mut run = start(&fake);
        let Some(Dhcp6Event::Bound(l)) = run.events.recv().await else {
            unreachable!("expected Bound");
        };
        assert_eq!(l.server_id, SERVER_B.to_vec());
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_advertise_without_a_prefix_is_retried_not_requested() {
        let mut none = Grant::new();
        none.ia_status = Some(STATUS_NO_PREFIX_AVAIL);
        let fake = Fake::new(server(none, u32::MAX));
        let run = start(&fake);
        tokio::time::sleep(Duration::from_secs(60)).await;
        let kinds = fake.kinds();
        assert!(kinds.len() >= 3, "Solicit is retransmitted: {kinds:?}");
        assert!(kinds.iter().all(|k| *k == MSG_SOLICIT), "{kinds:?}");
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_server_at_renew_is_tried_again_by_rebinding_without_its_id() {
        // answers the Request and the Rebind; the Renews go unanswered
        let grant = Grant::new();
        let handler: Handler = Box::new(move |m| match m.msg_type {
            MSG_SOLICIT => vec![grant.encode(MSG_ADVERTISE, m.xid, &duid())],
            MSG_REQUEST | MSG_REBIND => vec![grant.encode(MSG_REPLY, m.xid, &duid())],
            _ => vec![],
        });
        let fake = Fake::new(handler);
        let mut run = start(&fake);
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Bound(_))
        ));
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Renewed(_))
        ));
        let sent = fake.sent();
        assert!(sent.iter().any(|(k, _)| *k == MSG_RENEW), "{sent:?}");
        assert_eq!(sent.last(), Some(&(MSG_REBIND, false)));
        assert!(
            sent.iter()
                .filter(|(k, _)| *k == MSG_RENEW)
                .all(|(_, id)| *id)
        );
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_lease_is_lost_when_nothing_answers_until_it_expires_then_it_solicits_again() {
        let fake = Fake::new(server(Grant::new(), 1)); // only the Request is answered
        let mut run = start(&fake);
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Bound(_))
        ));
        let began = Instant::now();
        assert_eq!(run.events.recv().await, Some(Dhcp6Event::Lost));
        // the valid lifetime is 200s
        let waited = began.elapsed();
        assert!(
            (Duration::from_secs(199)..=Duration::from_secs(202)).contains(&waited),
            "{waited:?}"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
        let solicits = fake
            .kinds()
            .into_iter()
            .filter(|k| *k == MSG_SOLICIT)
            .count();
        assert_eq!(solicits, 2, "a fresh Solicit follows the loss");
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_binding_that_the_server_forgot_ends_the_lease_at_once() {
        let grant = Grant::new();
        let mut forgot = Grant::new();
        forgot.status = Some(STATUS_NO_BINDING);
        let handler: Handler = Box::new(move |m| match m.msg_type {
            MSG_SOLICIT => vec![grant.encode(MSG_ADVERTISE, m.xid, &duid())],
            MSG_REQUEST => vec![grant.encode(MSG_REPLY, m.xid, &duid())],
            MSG_RENEW => vec![forgot.encode(MSG_REPLY, m.xid, &duid())],
            _ => vec![],
        });
        let fake = Fake::new(handler);
        let mut run = start(&fake);
        assert!(matches!(
            run.events.recv().await,
            Some(Dhcp6Event::Bound(_))
        ));
        let began = Instant::now();
        assert_eq!(run.events.recv().await, Some(Dhcp6Event::Lost));
        assert!(
            began.elapsed() < Duration::from_secs(60),
            "{:?}",
            began.elapsed()
        );
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn replies_with_a_wrong_transaction_id_or_client_are_ignored() {
        let grant = Grant::new();
        let handler: Handler = Box::new(move |m| {
            let bad_xid = [m.xid[0].wrapping_add(1), m.xid[1], m.xid[2]];
            match m.msg_type {
                MSG_SOLICIT => vec![
                    grant.encode(MSG_ADVERTISE, bad_xid, &duid()),
                    grant.encode(MSG_ADVERTISE, m.xid, &[0, 3, 0, 1, 1, 1, 1, 1, 1, 1]),
                ],
                _ => vec![],
            }
        });
        let fake = Fake::new(handler);
        let mut run = start(&fake);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(run.events.try_recv().is_err());
        assert!(fake.kinds().iter().all(|k| *k == MSG_SOLICIT));
        run.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_client_stops_on_shutdown_and_when_the_receiver_is_gone() {
        let fake = Fake::new(server(Grant::new(), u32::MAX));
        let run = start(&fake);
        run.stop().await;

        let fake = Fake::new(server(Grant::new(), u32::MAX));
        let Running {
            events,
            shutdown,
            task,
        } = start(&fake);
        drop(events);
        task.await.unwrap();
        drop(shutdown);
    }
}
