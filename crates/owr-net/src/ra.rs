//! IPv6 Router Advertisements for the LAN bridges (RFC 4861): an on-link SLAAC prefix and
//! the router's DNS address (RDNSS, RFC 8106).
//!
//! The router has no IPv6 uplink yet, so it never offers itself as a default router (router
//! lifetime 0, as RFC 7084 G-4 requires without an upstream default route): hosts configure
//! an address from the prefix and learn the DNS server, and keep using IPv4 to reach the
//! internet. M and O are clear because there is no `DHCPv6` server; RDNSS carries DNS.
//!
//! Pure: packet building, solicitation checks and the send schedule ([`Pacer`]). The socket
//! lives in `linux::ra`.

use std::net::Ipv6Addr;
use std::time::Duration;

use ipnet::Ipv6Net;
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

/// `ICMPv6` type of a Router Solicitation.
pub const ROUTER_SOLICITATION: u8 = 133;
/// `ICMPv6` type of a Router Advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;

/// Prefix length SLAAC needs (RFC 4862 with the RFC 4291 interface identifier).
pub const SLAAC_PREFIX_LEN: u8 = 64;
/// At most this many RDNSS addresses are advertised.
pub const MAX_DNS: usize = 3;

/// Valid lifetime of the advertised prefix.
pub const PREFIX_VALID: Duration = Duration::from_hours(24);
/// Preferred lifetime of the advertised prefix.
pub const PREFIX_PREFERRED: Duration = Duration::from_hours(4);

/// `MaxRtrAdvInterval` (RFC 4861 6.2.1 default).
pub const MAX_RTR_ADV_INTERVAL: Duration = Duration::from_mins(10);
/// `MinRtrAdvInterval`: one third of the maximum, rounded down to whole seconds.
pub const MIN_RTR_ADV_INTERVAL: Duration = Duration::from_secs(200);
/// The first few advertisements go out at most this far apart (RFC 4861 10).
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);
/// How many advertisements count as "the first few".
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;
/// Minimum gap between two multicast advertisements (RFC 4861 10).
pub const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);
/// Upper bound of the random delay before answering a solicitation (RFC 4861 10).
pub const MAX_RA_DELAY: Duration = Duration::from_millis(500);
/// RDNSS lifetime: the upper bound RFC 8106 5.1 recommends (2 x `MaxRtrAdvInterval`).
pub const RDNSS_LIFETIME: Duration = Duration::from_mins(20);

const OPT_PREFIX_INFORMATION: u8 = 3;
const OPT_RDNSS: u8 = 25;
/// On-link (L) and autonomous address-configuration (A) flags of a prefix option.
const PREFIX_FLAGS_ON_LINK_AUTONOMOUS: u8 = 0xc0;
/// Length of the fixed Router Advertisement header.
const RA_HEADER_LEN: usize = 16;
/// Length of the fixed Router Solicitation header.
const RS_HEADER_LEN: usize = 8;

/// What to advertise on one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaSpec {
    /// Interface the advertisements go out on (a LAN or VLAN bridge).
    pub link: String,
    /// On-link prefix hosts configure addresses from; a /64.
    pub prefix: Ipv6Net,
    /// DNS servers announced with RDNSS (at most [`MAX_DNS`]); empty means no RDNSS option.
    pub dns: Vec<Ipv6Addr>,
}

/// An [`RaSpec`] that cannot be advertised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RaSpecError {
    #[error("{link}: prefix {prefix} is not a /64 (SLAAC needs one)")]
    PrefixLength { link: String, prefix: Ipv6Net },
    #[error("{link}: prefix {prefix} is not a unicast prefix")]
    PrefixScope { link: String, prefix: Ipv6Net },
    #[error("{link}: {count} DNS servers; at most {MAX_DNS} are advertised")]
    TooManyDns { link: String, count: usize },
    #[error("{link}: DNS server {addr} is not a unicast address")]
    DnsScope { link: String, addr: Ipv6Addr },
}

fn is_unicast(addr: Ipv6Addr) -> bool {
    !(addr.is_unspecified() || addr.is_loopback() || addr.is_multicast())
}

impl RaSpec {
    /// Check that hosts can use what this spec advertises.
    pub fn validate(&self) -> Result<(), RaSpecError> {
        let link = || self.link.clone();
        if self.prefix.prefix_len() != SLAAC_PREFIX_LEN {
            return Err(RaSpecError::PrefixLength {
                link: link(),
                prefix: self.prefix,
            });
        }
        let net = self.prefix.network();
        if !is_unicast(net) || net.is_unicast_link_local() {
            return Err(RaSpecError::PrefixScope {
                link: link(),
                prefix: self.prefix,
            });
        }
        if self.dns.len() > MAX_DNS {
            return Err(RaSpecError::TooManyDns {
                link: link(),
                count: self.dns.len(),
            });
        }
        if let Some(addr) = self.dns.iter().copied().find(|a| !is_unicast(*a)) {
            return Err(RaSpecError::DnsScope { link: link(), addr });
        }
        Ok(())
    }
}

/// Whole seconds of `d`, saturated to the 32-bit lifetime fields.
fn secs_u32(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

/// The Router Advertisement for `spec`, from the `ICMPv6` type on. The checksum is left zero:
/// the kernel fills it in on raw `ICMPv6` sockets. Call [`RaSpec::validate`] first; the
/// packet carries at most [`MAX_DNS`] DNS servers whatever the spec holds.
pub fn router_advertisement(spec: &RaSpec) -> Vec<u8> {
    let mut p = Vec::with_capacity(RA_HEADER_LEN + 32 + 8 + 16 * MAX_DNS);
    // type, code, checksum, cur hop limit (0: unspecified), flags (M = O = 0),
    // router lifetime (0: not a default router), reachable time, retrans timer.
    p.extend_from_slice(&[ROUTER_ADVERTISEMENT, 0, 0, 0, 0, 0, 0, 0]);
    p.extend_from_slice(&[0; 8]);

    // Prefix Information (RFC 4861 4.6.2): 4 units of 8 octets.
    p.extend_from_slice(&[
        OPT_PREFIX_INFORMATION,
        4,
        spec.prefix.prefix_len(),
        PREFIX_FLAGS_ON_LINK_AUTONOMOUS,
    ]);
    p.extend_from_slice(&secs_u32(PREFIX_VALID).to_be_bytes());
    p.extend_from_slice(&secs_u32(PREFIX_PREFERRED).to_be_bytes());
    p.extend_from_slice(&[0; 4]);
    p.extend_from_slice(&spec.prefix.network().octets());

    // RDNSS (RFC 8106 5.1): 1 + 2 units per address.
    let dns: Vec<Ipv6Addr> = spec.dns.iter().copied().take(MAX_DNS).collect();
    if let Ok(count) = u8::try_from(dns.len())
        && count > 0
    {
        p.extend_from_slice(&[OPT_RDNSS, count.saturating_mul(2).saturating_add(1), 0, 0]);
        p.extend_from_slice(&secs_u32(RDNSS_LIFETIME).to_be_bytes());
        for addr in dns {
            p.extend_from_slice(&addr.octets());
        }
    }
    p
}

/// Whether `packet` (`ICMPv6`, from the type on) is a well-formed Router Solicitation
/// (RFC 4861 6.1.1: type, code, length, and options that each have a non-zero length and
/// fit). The kernel has already checked the checksum. The hop limit of 255 cannot be checked
/// through this socket; a forged off-link solicitation can at most make the router send one
/// multicast advertisement on the link, at most every [`MIN_DELAY_BETWEEN_RAS`].
pub fn is_router_solicitation(packet: &[u8]) -> bool {
    let (Some(&ROUTER_SOLICITATION), Some(0)) = (packet.first(), packet.get(1).copied()) else {
        return false;
    };
    let Some(mut options) = packet.get(RS_HEADER_LEN..) else {
        return false;
    };
    while !options.is_empty() {
        let units = options.get(1).copied().map_or(0, usize::from);
        let Some(rest) = units.checked_mul(8).and_then(|len| {
            (len > 0).then_some(())?;
            options.get(len..)
        }) else {
            return false;
        };
        options = rest;
    }
    true
}

/// When the next advertisement on one link is due (RFC 4861 6.2.4 and 6.2.6).
///
/// Unsolicited advertisements go out at random intervals between [`MIN_RTR_ADV_INTERVAL`]
/// and [`MAX_RTR_ADV_INTERVAL`], the first [`MAX_INITIAL_RTR_ADVERTISEMENTS`] at most
/// [`MAX_INITIAL_RTR_ADVERT_INTERVAL`] apart. A solicitation brings the next one forward to
/// a random delay of up to [`MAX_RA_DELAY`], but never sooner than [`MIN_DELAY_BETWEEN_RAS`]
/// after the previous one. Every advertisement is multicast.
#[derive(Debug, Clone)]
pub struct Pacer {
    next: Instant,
    last_sent: Option<Instant>,
    sent: u32,
}

impl Pacer {
    /// The first advertisement is due immediately.
    pub fn new(now: Instant) -> Self {
        Self {
            next: now,
            last_sent: None,
            sent: 0,
        }
    }

    /// When the next advertisement is due.
    pub fn due(&self) -> Instant {
        self.next
    }

    /// An advertisement went out at `now`: schedule the next unsolicited one.
    pub fn sent(&mut self, now: Instant, rng: &mut impl Rng) {
        self.sent = self.sent.saturating_add(1);
        self.last_sent = Some(now);
        let mut interval = Duration::from_millis(
            rng.random_range(millis(MIN_RTR_ADV_INTERVAL)..=millis(MAX_RTR_ADV_INTERVAL)),
        );
        if self.sent < MAX_INITIAL_RTR_ADVERTISEMENTS {
            interval = interval.min(MAX_INITIAL_RTR_ADVERT_INTERVAL);
        }
        self.next = later(now, interval);
    }

    /// A solicitation arrived at `now`.
    pub fn solicited(&mut self, now: Instant, rng: &mut impl Rng) {
        let delay = Duration::from_millis(rng.random_range(0..=millis(MAX_RA_DELAY)));
        let mut at = later(now, delay);
        if let Some(last) = self.last_sent {
            at = at.max(later(last, MIN_DELAY_BETWEEN_RAS));
        }
        self.next = self.next.min(at);
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `at + d`, or `at` itself in the (unreachable) case that the sum overflows.
fn later(at: Instant, d: Duration) -> Instant {
    at.checked_add(d).unwrap_or(at)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    fn spec(dns: &[&str]) -> RaSpec {
        RaSpec {
            link: "br-lan".to_owned(),
            prefix: "fd12:3456:789a::/64".parse().unwrap(),
            dns: dns.iter().map(|d| d.parse().unwrap()).collect(),
        }
    }

    fn be32(p: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(p[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn advertisement_layout_matches_rfc_4861_and_8106() {
        let p = router_advertisement(&spec(&["fd12:3456:789a::1"]));
        assert_eq!(p.len(), 16 + 32 + 24);
        // Header: type, code, zero checksum, hop limit, flags, router lifetime 0, timers 0.
        assert_eq!(
            &p[..16],
            &[134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // Prefix information.
        assert_eq!(&p[16..20], &[3, 4, 64, 0xc0]);
        assert_eq!(be32(&p, 20), 86_400);
        assert_eq!(be32(&p, 24), 14_400);
        assert_eq!(be32(&p, 28), 0);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&p[32..48]).unwrap()),
            "fd12:3456:789a::".parse::<Ipv6Addr>().unwrap()
        );
        // RDNSS with one address: length 3, lifetime 1200 s.
        assert_eq!(&p[48..52], &[25, 3, 0, 0]);
        assert_eq!(be32(&p, 52), 1200);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&p[56..72]).unwrap()),
            "fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn the_prefix_is_masked_and_rdnss_is_omitted_without_dns() {
        let mut s = spec(&[]);
        s.prefix = "fd12:3456:789a:0:dead::1/64".parse().unwrap();
        let p = router_advertisement(&s);
        assert_eq!(p.len(), 16 + 32);
        assert_eq!(&p[32..40], &[0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0]);
        assert!(p[40..48].iter().all(|b| *b == 0));
    }

    #[test]
    fn rdnss_carries_at_most_three_addresses() {
        let p = router_advertisement(&spec(&["fd00::1", "fd00::2", "fd00::3", "fd00::4"]));
        assert_eq!(p[49], 7);
        assert_eq!(p.len(), 16 + 32 + 8 + 48);
    }

    #[test]
    fn validation_rejects_what_hosts_cannot_use() {
        assert_eq!(spec(&["fd00::1"]).validate(), Ok(()));
        let mut s = spec(&[]);
        s.prefix = "fd12:3456:789a::/48".parse().unwrap();
        assert!(matches!(
            s.validate(),
            Err(RaSpecError::PrefixLength { .. })
        ));
        for bad in ["fe80::/64", "ff02::/64", "::/64"] {
            s.prefix = bad.parse().unwrap();
            assert!(
                matches!(s.validate(), Err(RaSpecError::PrefixScope { .. })),
                "{bad}"
            );
        }
        let many = spec(&["fd00::1", "fd00::2", "fd00::3", "fd00::4"]);
        assert!(matches!(
            many.validate(),
            Err(RaSpecError::TooManyDns { count: 4, .. })
        ));
        for bad in ["::", "::1", "ff02::1"] {
            assert!(
                matches!(spec(&[bad]).validate(), Err(RaSpecError::DnsScope { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn solicitations_are_recognised_and_malformed_ones_rejected() {
        let bare = [133, 0, 0x12, 0x34, 0, 0, 0, 0];
        assert!(is_router_solicitation(&bare));
        // With a source link-layer address option (type 1, one unit).
        let mut with_sll = bare.to_vec();
        with_sll.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
        assert!(is_router_solicitation(&with_sll));

        assert!(!is_router_solicitation(&[]));
        assert!(!is_router_solicitation(&bare[..7]), "short");
        assert!(
            !is_router_solicitation(&[134, 0, 0, 0, 0, 0, 0, 0]),
            "an RA"
        );
        assert!(
            !is_router_solicitation(&[133, 1, 0, 0, 0, 0, 0, 0]),
            "code 1"
        );
        let mut zero_len = bare.to_vec();
        zero_len.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!is_router_solicitation(&zero_len), "option length 0");
        let mut overlong = bare.to_vec();
        overlong.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0]);
        assert!(!is_router_solicitation(&overlong), "option past the end");
        let mut truncated = bare.to_vec();
        truncated.push(1);
        assert!(!is_router_solicitation(&truncated), "half an option header");
    }

    #[test]
    fn the_first_advertisements_come_quickly_then_slow_down() {
        for seed in 0..200 {
            let mut rng = StdRng::seed_from_u64(seed);
            let t0 = Instant::now();
            let mut pacer = Pacer::new(t0);
            assert_eq!(pacer.due(), t0, "first one immediately");
            let mut now = t0;
            for n in 1..=5u32 {
                pacer.sent(now, &mut rng);
                let gap = pacer.due() - now;
                if n < MAX_INITIAL_RTR_ADVERTISEMENTS {
                    assert!(gap <= MAX_INITIAL_RTR_ADVERT_INTERVAL, "seed {seed} n {n}");
                } else {
                    assert!(
                        (MIN_RTR_ADV_INTERVAL..=MAX_RTR_ADV_INTERVAL).contains(&gap),
                        "seed {seed} n {n}: {gap:?}"
                    );
                }
                now = pacer.due();
            }
        }
    }

    #[test]
    fn a_solicitation_brings_the_next_advertisement_forward_but_rate_limited() {
        for seed in 0..200 {
            let mut rng = StdRng::seed_from_u64(seed);
            let t0 = Instant::now();
            let mut pacer = Pacer::new(t0);
            for _ in 0..MAX_INITIAL_RTR_ADVERTISEMENTS {
                pacer.sent(t0, &mut rng);
            }
            let unsolicited = pacer.due();

            // Right after an advertisement: held back to 3 s after it.
            let mut early = pacer.clone();
            early.solicited(t0 + Duration::from_secs(1), &mut rng);
            assert_eq!(early.due(), t0 + MIN_DELAY_BETWEEN_RAS, "seed {seed}");

            // Later: answered within 500 ms.
            let rs_at = t0 + Duration::from_secs(60);
            pacer.solicited(rs_at, &mut rng);
            assert!(
                pacer.due() >= rs_at && pacer.due() <= rs_at + MAX_RA_DELAY,
                "seed {seed}"
            );
            assert!(pacer.due() < unsolicited);

            // A solicitation never postpones an advertisement that is already due sooner.
            let mut soon = Pacer::new(t0);
            soon.solicited(t0, &mut rng);
            assert_eq!(soon.due(), t0);
        }
    }
}
