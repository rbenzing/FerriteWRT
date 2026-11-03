//! Small value types shared by the config model: secrets, MAC addresses, port ranges and
//! the humantime duration codec.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A value could not be parsed from its textual form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(String);

impl ParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// A secret string (password hash, Wi-Fi passphrase, `PPPoE` password).
///
/// `Debug` never prints the value, and the memory is zeroed on drop. It serializes
/// transparently because the on-disk config must hold the real value; use
/// [`crate::redact`] before handing a config to an API client. Equality is constant-time
/// in the contents so comparing a candidate against a stored secret does not leak a prefix.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for Secret {}

impl Secret {
    /// The placeholder written by [`crate::redact`].
    pub const REDACTED: &'static str = "***";

    /// Borrow the secret value. Callers must not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Is this the [`Secret::REDACTED`] placeholder rather than a real value?
    pub fn is_redacted(&self) -> bool {
        self.0 == Self::REDACTED
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// An Ethernet MAC address, written `aa:bb:cc:dd:ee:ff` (lowercase on output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Group (multicast/broadcast) bit set.
    pub fn is_multicast(&self) -> bool {
        self.0.first().is_some_and(|b| b & 1 == 1)
    }

    /// All-zero address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for MacAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let err = || {
            ParseError::new(format!(
                "invalid MAC address '{s}', expected aa:bb:cc:dd:ee:ff"
            ))
        };
        let mut bytes = [0u8; 6];
        let mut count = 0usize;
        for part in s.split(':') {
            let slot = bytes.get_mut(count).ok_or_else(err)?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err());
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| err())?;
            count = count.saturating_add(1);
        }
        if count == 6 {
            Ok(Self(bytes))
        } else {
            Err(err())
        }
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An inclusive TCP/UDP port range. Serialized as `"80"` or `"8000-8010"`; a bare TOML
/// integer is accepted on input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// A range covering exactly one port.
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// `start >= 1` and `start <= end`.
    pub fn is_valid(&self) -> bool {
        self.start >= 1 && self.start <= self.end
    }

    /// True if the two ranges share at least one port.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let port = |p: &str| {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::new(format!("invalid port range '{s}'")));
            }
            p.parse::<u16>()
                .map_err(|_| ParseError::new(format!("port out of range in '{s}'")))
        };
        let range = match s.split_once('-') {
            Some((a, b)) => Self {
                start: port(a)?,
                end: port(b)?,
            },
            None => Self::single(port(s)?),
        };
        if range.is_valid() {
            Ok(range)
        } else {
            Err(ParseError::new(format!(
                "invalid port range '{s}': need 1 <= start <= end"
            )))
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Num(u16),
            Text(String),
        }
        match Repr::deserialize(d)? {
            Repr::Num(p) => Ok(Self::single(p)),
            Repr::Text(t) => t.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// serde codec for `std::time::Duration` as a humantime string (`"12h"`, `"30m"`).
pub(crate) mod duration_str {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&humantime::format_duration(*d))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid duration '{s}': {e}")))
    }
}
