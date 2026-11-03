//! `DHCPv4` wire format (RFC 2131 / 2132 / 3442). Pure: no I/O, no panics.
//!
//! Only Ethernet (`htype 1`, `hlen 6`) is supported. Option overload (52) is not
//! interpreted; the `sname` and `file` fields are skipped. Parsing accepts messages
//! up to [`MAX_MESSAGE_LEN`] bytes (the option area is bounded after every option);
//! encoding stays within the BOOTP-minimum [`MAX_OPTIONS_LEN`]. Repeated options are
//! concatenated before they are interpreted (RFC 3396). A malformed non-essential
//! option (subnet mask, routers, DNS) is skipped, not fatal.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::model::MacAddr;

pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Bytes before the magic cookie (`op` .. `file`).
pub const FIXED_LEN: usize = 236;
/// Fixed header plus magic cookie.
pub const HEADER_LEN: usize = 240;
/// Largest option area produced by [`Message::encode`].
pub const MAX_OPTIONS_LEN: usize = 576;
/// Largest message accepted by [`Message::parse`] (an Ethernet MTU of options and
/// header); the option area is bounded to what remains after the header.
pub const MAX_MESSAGE_LEN: usize = 1500;
/// Encoded messages are padded to this size (BOOTP minimum).
const MIN_ENCODED_LEN: usize = 300;
const BROADCAST_FLAG: u16 = 0x8000;

pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_DOMAIN: u8 = 15;
pub const OPT_BROADCAST: u8 = 28;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST: u8 = 55;
pub const OPT_MESSAGE: u8 = 56;
pub const OPT_T1: u8 = 58;
pub const OPT_T2: u8 = 59;
pub const OPT_VENDOR_CLASS: u8 = 60;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_CLASSLESS_ROUTES: u8 = 121;
const OPT_PAD: u8 = 0;
const OPT_END: u8 = 255;

/// Failure to parse or encode a DHCP message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("message truncated")]
    Truncated,
    #[error("unsupported hardware type {htype} / length {hlen}")]
    NotEthernet { htype: u8, hlen: u8 },
    #[error("bad op {0}")]
    BadOp(u8),
    #[error("bad magic cookie")]
    BadMagic,
    #[error("option area too long")]
    OptionsTooLong,
    #[error("malformed option {0}")]
    BadOption(u8),
    #[error("option {0} longer than 255 bytes")]
    OptionTooLong(u8),
}

/// BOOTP `op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Request,
    Reply,
}

/// Option 53 values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }
}

/// One entry of option 121.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClasslessRoute {
    pub dest: Ipv4Net,
    pub gateway: Ipv4Addr,
}

/// The options this client understands or sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub msg_type: Option<MessageType>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub lease_time: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
    pub server_id: Option<Ipv4Addr>,
    pub requested_ip: Option<Ipv4Addr>,
    pub classless_routes: Vec<ClasslessRoute>,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
    pub param_request: Vec<u8>,
    /// Option 56 (human readable reason, typically in a NAK).
    pub message: Option<String>,
}

/// A `DHCPv4` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub op: Op,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub options: Options,
}

impl Message {
    /// A client `BOOTREQUEST` with all addresses zero.
    pub fn new_client(xid: u32, chaddr: MacAddr, msg_type: MessageType) -> Self {
        Self {
            op: Op::Request,
            xid,
            secs: 0,
            broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            options: Options {
                msg_type: Some(msg_type),
                ..Options::default()
            },
        }
    }

    /// Serialize. Fails only if an option is oversized or the option area would
    /// exceed [`MAX_OPTIONS_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut buf = Vec::with_capacity(MIN_ENCODED_LEN);
        buf.push(match self.op {
            Op::Request => 1,
            Op::Reply => 2,
        });
        buf.extend_from_slice(&[1, 6, 0]);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        let flags = if self.broadcast { BROADCAST_FLAG } else { 0 };
        buf.extend_from_slice(&flags.to_be_bytes());
        for ip in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            buf.extend_from_slice(&ip.octets());
        }
        buf.extend_from_slice(&self.chaddr.octets());
        buf.resize(FIXED_LEN, 0); // chaddr padding, sname, file
        buf.extend_from_slice(&MAGIC_COOKIE);

        let mut o = Vec::new();
        let opts = &self.options;
        if let Some(t) = opts.msg_type {
            put(&mut o, OPT_MSG_TYPE, &[t.code()])?;
        }
        if let Some(id) = &opts.client_id {
            put(&mut o, OPT_CLIENT_ID, id)?;
        }
        if let Some(ip) = opts.requested_ip {
            put(&mut o, OPT_REQUESTED_IP, &ip.octets())?;
        }
        if let Some(ip) = opts.server_id {
            put(&mut o, OPT_SERVER_ID, &ip.octets())?;
        }
        if let Some(h) = &opts.hostname {
            put(&mut o, OPT_HOSTNAME, h.as_bytes())?;
        }
        if let Some(v) = &opts.vendor_class {
            put(&mut o, OPT_VENDOR_CLASS, v.as_bytes())?;
        }
        if !opts.param_request.is_empty() {
            put(&mut o, OPT_PARAM_REQUEST, &opts.param_request)?;
        }
        if let Some(ip) = opts.subnet_mask {
            put(&mut o, OPT_SUBNET_MASK, &ip.octets())?;
        }
        put_ips(&mut o, OPT_ROUTER, &opts.routers)?;
        put_ips(&mut o, OPT_DNS, &opts.dns)?;
        if let Some(d) = &opts.domain {
            put(&mut o, OPT_DOMAIN, d.as_bytes())?;
        }
        for (code, v) in [
            (OPT_LEASE_TIME, opts.lease_time),
            (OPT_T1, opts.t1),
            (OPT_T2, opts.t2),
        ] {
            if let Some(v) = v {
                put(&mut o, code, &v.to_be_bytes())?;
            }
        }
        if let Some(m) = &opts.message {
            put(&mut o, OPT_MESSAGE, m.as_bytes())?;
        }
        if !opts.classless_routes.is_empty() {
            let mut data = Vec::new();
            for r in &opts.classless_routes {
                let len = r.dest.prefix_len();
                data.push(len);
                let sig = usize::from(len).div_ceil(8);
                data.extend(r.dest.network().octets().iter().take(sig));
                data.extend_from_slice(&r.gateway.octets());
            }
            put(&mut o, OPT_CLASSLESS_ROUTES, &data)?;
        }
        o.push(OPT_END);
        if o.len() > MAX_OPTIONS_LEN {
            return Err(WireError::OptionsTooLong);
        }
        buf.extend_from_slice(&o);
        if buf.len() < MIN_ENCODED_LEN {
            buf.resize(MIN_ENCODED_LEN, 0);
        }
        Ok(buf)
    }

    /// Parse a datagram. Never panics; every malformed input is an error.
    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let op = match byte(buf, 0)? {
            1 => Op::Request,
            2 => Op::Reply,
            other => return Err(WireError::BadOp(other)),
        };
        let (htype, hlen) = (byte(buf, 1)?, byte(buf, 2)?);
        if htype != 1 || hlen != 6 {
            return Err(WireError::NotEthernet { htype, hlen });
        }
        if buf.get(FIXED_LEN..HEADER_LEN) != Some(&MAGIC_COOKIE[..]) {
            return Err(WireError::BadMagic);
        }
        let options = parse_options(buf.get(HEADER_LEN..).ok_or(WireError::Truncated)?)?;
        Ok(Self {
            op,
            xid: u32::from_be_bytes(array(buf, 4)?),
            secs: u16::from_be_bytes(array(buf, 8)?),
            broadcast: u16::from_be_bytes(array(buf, 10)?) & BROADCAST_FLAG != 0,
            ciaddr: Ipv4Addr::from(array::<4>(buf, 12)?),
            yiaddr: Ipv4Addr::from(array::<4>(buf, 16)?),
            siaddr: Ipv4Addr::from(array::<4>(buf, 20)?),
            giaddr: Ipv4Addr::from(array::<4>(buf, 24)?),
            chaddr: MacAddr(array(buf, 28)?),
            options,
        })
    }
}

fn byte(buf: &[u8], off: usize) -> Result<u8, WireError> {
    buf.get(off).copied().ok_or(WireError::Truncated)
}

fn array<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N], WireError> {
    buf.get(off..)
        .and_then(|s| s.first_chunk::<N>())
        .copied()
        .ok_or(WireError::Truncated)
}

fn put(out: &mut Vec<u8>, code: u8, data: &[u8]) -> Result<(), WireError> {
    let len = u8::try_from(data.len()).map_err(|_| WireError::OptionTooLong(code))?;
    out.push(code);
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

fn put_ips(out: &mut Vec<u8>, code: u8, ips: &[Ipv4Addr]) -> Result<(), WireError> {
    if ips.is_empty() {
        return Ok(());
    }
    let data: Vec<u8> = ips.iter().flat_map(Ipv4Addr::octets).collect();
    put(out, code, &data)
}

fn parse_options(opts: &[u8]) -> Result<Options, WireError> {
    // RFC 3396: instances of one option are concatenated, then interpreted once.
    // The option bytes seen are bounded below, so this buffer is bounded too.
    let mut raw: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut rest = opts;
    loop {
        if opts.len().saturating_sub(rest.len()) > MAX_MESSAGE_LEN - HEADER_LEN {
            return Err(WireError::OptionsTooLong);
        }
        let Some((&code, tail)) = rest.split_first() else {
            break; // no END marker: tolerated
        };
        match code {
            OPT_PAD => {
                rest = tail;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let (&len, tail) = tail.split_first().ok_or(WireError::Truncated)?;
        let (data, tail) = tail
            .split_at_checked(usize::from(len))
            .ok_or(WireError::Truncated)?;
        match raw.iter_mut().find(|(c, _)| *c == code) {
            Some((_, all)) => all.extend_from_slice(data),
            None => raw.push((code, data.to_vec())),
        }
        rest = tail;
    }
    let mut o = Options::default();
    for (code, data) in &raw {
        apply_option(&mut o, *code, data)?;
    }
    Ok(o)
}

fn ipv4(code: u8, data: &[u8]) -> Result<Ipv4Addr, WireError> {
    let a: [u8; 4] = data.try_into().map_err(|_| WireError::BadOption(code))?;
    Ok(Ipv4Addr::from(a))
}

fn ipv4_list(code: u8, data: &[u8]) -> Result<Vec<Ipv4Addr>, WireError> {
    if data.is_empty() || !data.len().is_multiple_of(4) {
        return Err(WireError::BadOption(code));
    }
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(Ipv4Addr::from)
        .collect())
}

fn secs(code: u8, data: &[u8]) -> Result<u32, WireError> {
    let a: [u8; 4] = data.try_into().map_err(|_| WireError::BadOption(code))?;
    Ok(u32::from_be_bytes(a))
}

/// Printable text from a server-supplied option: trailing NULs trimmed, control
/// characters dropped, invalid UTF-8 replaced.
fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .trim_end_matches('\0')
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

fn apply_option(o: &mut Options, code: u8, data: &[u8]) -> Result<(), WireError> {
    match code {
        // non-essential: a bad length drops the option, not the whole message
        OPT_SUBNET_MASK => o.subnet_mask = ipv4(code, data).ok(),
        OPT_ROUTER => o.routers = ipv4_list(code, data).unwrap_or_default(),
        OPT_DNS => o.dns = ipv4_list(code, data).unwrap_or_default(),
        OPT_HOSTNAME => o.hostname = Some(text(data)),
        OPT_DOMAIN => {
            let d = text(data);
            let ok = !d.is_empty()
                && d.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
            o.domain = ok.then_some(d);
        }
        OPT_REQUESTED_IP => o.requested_ip = Some(ipv4(code, data)?),
        OPT_LEASE_TIME => o.lease_time = Some(secs(code, data)?),
        OPT_MSG_TYPE => {
            let [t] = data else {
                return Err(WireError::BadOption(code));
            };
            o.msg_type = Some(MessageType::from_code(*t).ok_or(WireError::BadOption(code))?);
        }
        OPT_SERVER_ID => o.server_id = Some(ipv4(code, data)?),
        OPT_PARAM_REQUEST => o.param_request = data.to_vec(),
        OPT_MESSAGE => o.message = Some(text(data)),
        OPT_T1 => o.t1 = Some(secs(code, data)?),
        OPT_T2 => o.t2 = Some(secs(code, data)?),
        OPT_VENDOR_CLASS => o.vendor_class = Some(text(data)),
        OPT_CLIENT_ID => o.client_id = Some(data.to_vec()),
        OPT_CLASSLESS_ROUTES => o.classless_routes = parse_classless(data)?,
        _ => {}
    }
    Ok(())
}

/// Decode option 121 (RFC 3442): `{prefix_len, ceil(prefix_len/8) octets, router}`.
fn parse_classless(mut data: &[u8]) -> Result<Vec<ClasslessRoute>, WireError> {
    let bad = || WireError::BadOption(OPT_CLASSLESS_ROUTES);
    let mut routes = Vec::new();
    while let Some((&len, tail)) = data.split_first() {
        if len > 32 {
            return Err(bad());
        }
        let (sig, tail) = tail
            .split_at_checked(usize::from(len).div_ceil(8))
            .ok_or_else(bad)?;
        let (gw, tail) = tail.split_at_checked(4).ok_or_else(bad)?;
        let mut octets = [0u8; 4];
        for (dst, src) in octets.iter_mut().zip(sig) {
            *dst = *src;
        }
        let dest = Ipv4Net::new(Ipv4Addr::from(octets), len)
            .map_err(|_| bad())?
            .trunc();
        routes.push(ClasslessRoute {
            dest,
            gateway: ipv4(OPT_CLASSLESS_ROUTES, gw)?,
        });
        data = tail;
    }
    Ok(routes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MAC: MacAddr = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);

    fn discover() -> Message {
        let mut m = Message::new_client(0xdead_beef, MAC, MessageType::Discover);
        m.broadcast = true;
        m.options.client_id = Some(vec![1, 2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        m.options.hostname = Some("flint2".into());
        m.options.vendor_class = Some("ferritewrt".into());
        m.options.param_request = vec![1, 3, 6, 15, 28, 51, 58, 59, 121];
        m
    }

    /// Hand-built OFFER bytes, independent of `encode`.
    fn raw_offer(options: &[u8]) -> Vec<u8> {
        let mut b = vec![2, 1, 6, 0];
        b.extend_from_slice(&0xdead_beef_u32.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x80, 0]); // secs, flags=broadcast
        b.extend_from_slice(&[0, 0, 0, 0]); // ciaddr
        b.extend_from_slice(&[192, 168, 1, 50]); // yiaddr
        b.extend_from_slice(&[192, 168, 1, 1]); // siaddr
        b.extend_from_slice(&[0, 0, 0, 0]); // giaddr
        b.extend_from_slice(&MAC.octets());
        b.resize(FIXED_LEN, 0);
        b.extend_from_slice(&MAGIC_COOKIE);
        b.extend_from_slice(options);
        b
    }

    #[test]
    fn discover_round_trips() {
        let m = discover();
        let bytes = m.encode().unwrap();
        assert_eq!(bytes.len(), MIN_ENCODED_LEN);
        assert_eq!(bytes.get(236..240), Some(&MAGIC_COOKIE[..]));
        assert_eq!(Message::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn discover_has_required_options() {
        let o = discover().encode().unwrap();
        let opts = &o[HEADER_LEN..];
        assert_eq!(&opts[..3], &[53, 1, 1]);
        assert!(opts.windows(2).any(|w| w == [55, 9]));
        assert!(opts.contains(&OPT_END));
    }

    #[test]
    fn parses_captured_style_offer() {
        let opts = [
            53, 1, 2, // OFFER
            54, 4, 192, 168, 1, 1, // server id
            51, 4, 0, 0, 0x0e, 0x10, // 3600
            58, 4, 0, 0, 0x07, 0x08, // 1800
            59, 4, 0, 0, 0x0c, 0x4e, // 3150
            1, 4, 255, 255, 255, 0, // mask
            3, 8, 192, 168, 1, 1, 192, 168, 1, 2, // routers
            6, 4, 1, 1, 1, 1, // dns
            15, 8, b'l', b'a', b'n', b'.', b'o', b'r', b'g', 0, // domain NUL-padded
            0, 0, // pad
            255,
        ];
        let m = Message::parse(&raw_offer(&opts)).unwrap();
        assert_eq!(m.op, Op::Reply);
        assert_eq!(m.xid, 0xdead_beef);
        assert!(m.broadcast);
        assert_eq!(m.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(m.chaddr, MAC);
        let o = m.options;
        assert_eq!(o.msg_type, Some(MessageType::Offer));
        assert_eq!(o.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(o.lease_time, Some(3600));
        assert_eq!(o.t1, Some(1800));
        assert_eq!(o.t2, Some(3150));
        assert_eq!(o.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(o.routers.len(), 2);
        assert_eq!(o.dns, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(o.domain.as_deref(), Some("lan.org"));
    }

    #[test]
    fn decodes_option_121() {
        // RFC 3442: default via 10.0.0.1; 10.0.0.0/8 via 10.0.0.2; 192.168.1.0/24 via 10.0.0.3
        let data = [
            0, 10, 0, 0, 1, // 0.0.0.0/0
            8, 10, 10, 0, 0, 2, // 10/8
            24, 192, 168, 1, 10, 0, 0, 3, // 192.168.1/24
        ];
        let mut opts = vec![53, 1, 5, 121, u8::try_from(data.len()).unwrap()];
        opts.extend_from_slice(&data);
        opts.push(255);
        let m = Message::parse(&raw_offer(&opts)).unwrap();
        let r = m.options.classless_routes;
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].dest, "0.0.0.0/0".parse::<Ipv4Net>().unwrap());
        assert_eq!(r[0].gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(r[1].dest, "10.0.0.0/8".parse::<Ipv4Net>().unwrap());
        assert_eq!(r[2].dest, "192.168.1.0/24".parse::<Ipv4Net>().unwrap());
        assert_eq!(r[2].gateway, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn malformed_option_121_is_rejected() {
        for data in [
            &[33u8, 1, 2, 3, 4, 5, 6, 7, 8][..],
            &[24, 1, 2][..],
            &[8, 10, 1, 2][..],
        ] {
            let mut opts = vec![121, u8::try_from(data.len()).unwrap()];
            opts.extend_from_slice(data);
            opts.push(255);
            assert_eq!(
                Message::parse(&raw_offer(&opts)),
                Err(WireError::BadOption(121)),
                "{data:?}"
            );
        }
    }

    #[test]
    fn classless_routes_round_trip_through_encode() {
        let mut m = Message::new_client(1, MAC, MessageType::Request);
        m.op = Op::Reply;
        m.options.classless_routes = vec![
            ClasslessRoute {
                dest: "172.16.0.0/12".parse().unwrap(),
                gateway: Ipv4Addr::new(10, 0, 0, 9),
            },
            ClasslessRoute {
                dest: "10.1.2.3/32".parse().unwrap(),
                gateway: Ipv4Addr::new(10, 0, 0, 1),
            },
        ];
        assert_eq!(Message::parse(&m.encode().unwrap()).unwrap(), m);
    }

    #[test]
    fn truncated_packets_are_errors() {
        let full = discover().encode().unwrap();
        for n in 0..HEADER_LEN {
            assert_eq!(Message::parse(&full[..n]), Err(WireError::Truncated), "{n}");
        }
        // option header cut after the code, and data cut short
        let mut b = raw_offer(&[53]);
        assert_eq!(Message::parse(&b), Err(WireError::Truncated));
        b = raw_offer(&[53, 1]);
        assert_eq!(Message::parse(&b), Err(WireError::Truncated));
        b = raw_offer(&[6, 8, 1, 1, 1, 1]);
        assert_eq!(Message::parse(&b), Err(WireError::Truncated));
    }

    #[test]
    fn rejects_bad_header_fields() {
        let mut b = raw_offer(&[255]);
        b[0] = 9;
        assert_eq!(Message::parse(&b), Err(WireError::BadOp(9)));
        let mut b = raw_offer(&[255]);
        b[1] = 6;
        assert!(matches!(
            Message::parse(&b),
            Err(WireError::NotEthernet { .. })
        ));
        let mut b = raw_offer(&[255]);
        b[236] = 0;
        assert_eq!(Message::parse(&b), Err(WireError::BadMagic));
    }

    #[test]
    fn rejects_malformed_essential_options() {
        for opts in [
            &[51u8, 2, 0, 1][..],
            &[54, 3, 1, 2, 3][..],
            &[53, 1, 0][..],
            &[53, 1, 9][..],
            &[53, 2, 1, 1][..],
        ] {
            assert!(
                matches!(
                    Message::parse(&raw_offer(opts)),
                    Err(WireError::BadOption(_))
                ),
                "{opts:?}"
            );
        }
    }

    #[test]
    fn malformed_non_essential_options_are_skipped_not_fatal() {
        // mask not 4 bytes, routers 0 / 5 bytes, dns 6 bytes: dropped; the rest survives
        let opts = [
            53, 1, 2, // OFFER
            1, 3, 255, 255, 255, // bad mask
            3, 0, // empty routers
            6, 6, 1, 1, 1, 1, 2, 2, // dns not a multiple of 4
            54, 4, 192, 168, 1, 1, // server id
            255,
        ];
        let o = Message::parse(&raw_offer(&opts)).unwrap().options;
        assert_eq!(o.subnet_mask, None);
        assert!(o.routers.is_empty() && o.dns.is_empty());
        assert_eq!(o.msg_type, Some(MessageType::Offer));
        assert_eq!(o.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
        let o = Message::parse(&raw_offer(&[53, 1, 2, 3, 5, 1, 2, 3, 4, 5, 255]))
            .unwrap()
            .options;
        assert_eq!(o.routers, Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn repeated_options_are_concatenated_rfc3396() {
        // option 121 split in the middle of a route across two instances
        let data = [
            0, 10, 0, 0, 1, // 0.0.0.0/0 via 10.0.0.1
            24, 192, 168, 1, 10, 0, 0, 3, // 192.168.1/24 via 10.0.0.3
        ];
        let (a, b) = data.split_at(3);
        let mut opts = vec![53, 1, 5, 121, 3];
        opts.extend_from_slice(a);
        opts.extend_from_slice(&[6, 4, 1, 1, 1, 1]); // another option in between
        opts.extend_from_slice(&[121, u8::try_from(b.len()).unwrap()]);
        opts.extend_from_slice(b);
        opts.extend_from_slice(&[6, 4, 8, 8, 8, 8, 255]);
        let o = Message::parse(&raw_offer(&opts)).unwrap().options;
        assert_eq!(o.classless_routes.len(), 2);
        assert_eq!(o.classless_routes[0].gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            o.classless_routes[1].dest,
            "192.168.1.0/24".parse::<Ipv4Net>().unwrap()
        );
        assert_eq!(
            o.dns,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
    }

    #[test]
    fn option_area_is_bounded_by_the_mtu_not_by_576() {
        let unknown = |n: usize| {
            let mut opts = Vec::new();
            for _ in 0..n {
                opts.extend_from_slice(&[200, 148]);
                opts.extend(std::iter::repeat_n(7u8, 148));
            }
            opts.push(255);
            opts
        };
        // 8 x 150 = 1200 bytes (> 576) fits in a 1500 byte message
        assert!(Message::parse(&raw_offer(&unknown(8))).is_ok());
        // 9 x 150 = 1350 does not (the bound is checked after each option)
        assert_eq!(
            Message::parse(&raw_offer(&unknown(9))),
            Err(WireError::OptionsTooLong)
        );
        // a long run of pads is bounded too
        let pads = vec![0u8; 1300];
        assert_eq!(
            Message::parse(&raw_offer(&pads)),
            Err(WireError::OptionsTooLong)
        );
    }

    #[test]
    fn trailing_padding_after_end_is_ignored() {
        let mut opts = vec![53, 1, 2, 255];
        opts.extend(std::iter::repeat_n(0u8, 1000));
        assert!(Message::parse(&raw_offer(&opts)).is_ok());
    }

    #[test]
    fn encode_rejects_oversized_options() {
        let mut m = discover();
        m.options.hostname = Some("h".repeat(256));
        assert_eq!(m.encode(), Err(WireError::OptionTooLong(OPT_HOSTNAME)));
        let mut m = discover();
        m.options.hostname = Some("h".repeat(255));
        m.options.vendor_class = Some("v".repeat(255));
        m.options.client_id = Some(vec![0; 100]);
        assert_eq!(m.encode(), Err(WireError::OptionsTooLong));
    }

    #[test]
    fn nak_message_text_is_sanitised() {
        let opts = [
            53, 1, 6, 56, 8, b'n', b'o', 0x1b, b'!', b' ', b'x', 0, 0, 255,
        ];
        let m = Message::parse(&raw_offer(&opts)).unwrap();
        assert_eq!(m.options.msg_type, Some(MessageType::Nak));
        assert_eq!(m.options.message.as_deref(), Some("no! x"));
    }

    #[test]
    fn invalid_domain_is_dropped_not_fatal() {
        let opts = [53, 1, 2, 15, 3, b'a', b'/', b'b', 255];
        let m = Message::parse(&raw_offer(&opts)).unwrap();
        assert_eq!(m.options.domain, None);
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1200)) {
            let _ = Message::parse(&bytes);
        }

        #[test]
        fn mutated_valid_packet_never_panics(
            flips in proptest::collection::vec((0usize..300, any::<u8>()), 0..12),
            cut in 0usize..320,
        ) {
            let mut b = discover().encode().unwrap();
            for (i, v) in flips {
                if let Some(slot) = b.get_mut(i) {
                    *slot = v;
                }
            }
            b.truncate(cut.max(1));
            let _ = Message::parse(&b);
        }

        #[test]
        fn garbage_options_after_valid_header_never_panic(
            opts in proptest::collection::vec(any::<u8>(), 0..700),
        ) {
            let _ = Message::parse(&raw_offer(&opts));
        }

        #[test]
        fn classless_routes_round_trip(
            routes in proptest::collection::vec((any::<u32>(), 0u8..=32, any::<u32>()), 0..8),
        ) {
            let mut m = Message::new_client(7, MAC, MessageType::Request);
            m.options.classless_routes = routes
                .into_iter()
                .map(|(d, len, g)| ClasslessRoute {
                    dest: Ipv4Net::new(Ipv4Addr::from(d), len).unwrap().trunc(),
                    gateway: Ipv4Addr::from(g),
                })
                .collect();
            prop_assert_eq!(Message::parse(&m.encode().unwrap()).unwrap(), m);
        }
    }
}
