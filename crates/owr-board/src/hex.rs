//! Serde helpers for sizes/offsets written either as integers or as strings such as `"0x80000"`.
//!
//! Accepted text forms are exactly `0x[0-9a-fA-F]+` (the `0X` prefix is tolerated too) and
//! `[0-9]+`: no sign, no whitespace, no separators.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

struct HexOrInt(u64);

impl<'de> Deserialize<'de> for HexOrInt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl Visitor<'_> for V {
            type Value = HexOrInt;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a non-negative integer or a string like \"0x1f\" or \"4096\"")
            }

            fn visit_u64<E: de::Error>(self, n: u64) -> Result<HexOrInt, E> {
                Ok(HexOrInt(n))
            }

            fn visit_i64<E: de::Error>(self, n: i64) -> Result<HexOrInt, E> {
                u64::try_from(n)
                    .map(HexOrInt)
                    .map_err(|_| E::custom(format!("negative value {n} is not allowed")))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<HexOrInt, E> {
                parse_u64(s).map(HexOrInt).map_err(E::custom)
            }
        }

        d.deserialize_any(V)
    }
}

/// Parse `"0x1f"` as hex and a plain digit string as decimal. The error says what was wrong.
pub(crate) fn parse_u64(s: &str) -> Result<u64, String> {
    if s.starts_with('-') {
        return Err(format!("negative value {s:?} is not allowed"));
    }
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (s, 10),
    };
    // `from_str_radix` also accepts a leading '+', so check the digits ourselves.
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(format!(
            "invalid integer {s:?} (expected decimal digits or 0x-prefixed hex digits, \
             without sign or whitespace)"
        ));
    }
    u64::from_str_radix(digits, radix).map_err(|_| format!("integer {s:?} does not fit in 64 bits"))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    HexOrInt::deserialize(d).map(|h| h.0)
}

/// Same as [`deserialize`] for `Option<u64>` fields (use together with `#[serde(default)]`).
pub(crate) mod opt {
    use super::{Deserialize, Deserializer, HexOrInt};

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        Ok(Option::<HexOrInt>::deserialize(d)?.map(|h| h.0))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_u64;

    #[test]
    fn parses_hex_and_decimal() {
        assert_eq!(parse_u64("0x80000"), Ok(524_288));
        assert_eq!(parse_u64("0X10"), Ok(16));
        assert_eq!(parse_u64("0xFf"), Ok(255));
        assert_eq!(parse_u64("4096"), Ok(4096));
        assert_eq!(parse_u64("0"), Ok(0));
    }

    #[test]
    fn rejects_signs_whitespace_and_garbage_with_a_clear_message() {
        for bad in [
            "", "0x", "0xzz", "+1", "0x+1", "0x-1", " 1", "1 ", "0x 1", "1_000", "1.5", "0b11",
        ] {
            let err = parse_u64(bad).unwrap_err();
            assert!(err.contains("expected decimal digits"), "{bad:?}: {err}");
        }
        for neg in ["-1", "-0x10"] {
            let err = parse_u64(neg).unwrap_err();
            assert!(err.contains("negative"), "{neg:?}: {err}");
        }
        let err = parse_u64("0x1ffffffffffffffff").unwrap_err();
        assert!(err.contains("64 bits"), "{err}");
    }
}
