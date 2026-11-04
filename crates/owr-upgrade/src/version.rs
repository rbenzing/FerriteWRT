//! Release versions: `MAJOR.MINOR.PATCH[-PRERELEASE]` without a leading `v`, ordered by
//! [Semantic Versioning 2.0.0](https://semver.org) precedence (build metadata is not part of
//! the format).

use std::cmp::Ordering;
use std::fmt;

/// A parsed release version. Ordering is semver precedence: `1.2.3-rc.1 < 1.2.3 < 1.2.4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Dot-separated pre-release identifiers; empty for a release.
    pub pre: Vec<String>,
}

impl Version {
    /// Strict parse; `None` for anything that is not `MAJOR.MINOR.PATCH[-pre]`.
    pub fn parse(s: &str) -> Option<Self> {
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let pre = match pre {
            None => Vec::new(),
            Some(p) => {
                let ids: Vec<String> = p.split('.').map(str::to_owned).collect();
                let ok = ids.iter().all(|id| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
                if !ok {
                    return None;
                }
                ids
            }
        };
        Some(Self {
            major: number(major)?,
            minor: number(minor)?,
            patch: number(patch)?,
            pre,
        })
    }
}

/// A version component: ASCII digits only (no sign, no whitespace).
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `MAJOR.MINOR.PATCH[-prerelease]`, no leading `v`.
pub fn valid_version(s: &str) -> bool {
    Version::parse(s).is_some()
}

/// Semver precedence of two pre-release identifiers: numeric ones compare numerically and
/// sort before alphanumeric ones, which compare in ASCII order.
fn cmp_identifier(a: &str, b: &str) -> Ordering {
    let numeric = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
    match (numeric(a), numeric(b)) {
        // Numeric identifiers: longer (without leading zeros, semver forbids them) is larger.
        (true, true) => a
            .trim_start_matches('0')
            .len()
            .cmp(&b.trim_start_matches('0').len())
            .then_with(|| a.trim_start_matches('0').cmp(b.trim_start_matches('0'))),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release ranks above its pre-releases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = cmp_identifier(a, b);
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parses_and_displays() {
        assert_eq!(v("0.2.1").to_string(), "0.2.1");
        assert_eq!(v("1.0.0-rc.1").to_string(), "1.0.0-rc.1");
        for bad in [
            "",
            "v1.2.3",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1..3",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3-a b",
            "+1.2.3",
            " 1.2.3",
            "1.2.3+build",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn orders_by_semver_precedence() {
        // The precedence example from semver.org, item 11.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in chain.windows(2) {
            let [a, b] = pair else { unreachable!() };
            assert!(v(a) < v(b), "{a} < {b}");
        }
        assert!(v("0.10.0") > v("0.9.9"), "numeric, not lexical");
        assert_eq!(v("0.2.1").cmp(&v("0.2.1")), Ordering::Equal);
    }
}
