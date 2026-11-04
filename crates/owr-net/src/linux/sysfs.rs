//! Interface index and hardware address of one link, from `/sys/class/net`.

use std::io;
use std::path::PathBuf;

use crate::model::MacAddr;

/// Longest interface name the kernel accepts (`IFNAMSIZ` - 1).
const MAX_IFNAME: usize = 15;

fn attribute(link: &str, name: &str) -> io::Result<String> {
    let valid = !link.is_empty()
        && link.len() <= MAX_IFNAME
        && link != "."
        && link != ".."
        && !link.contains(['/', '\0']);
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {link:?}"),
        ));
    }
    let path: PathBuf = ["/sys/class/net", link, name].iter().collect();
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

/// The kernel's index of `link`.
pub fn ifindex(link: &str) -> io::Result<u32> {
    attribute(link, "ifindex")?
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{link} ifindex: {e}")))
}

/// The hardware address of `link`.
pub fn mac(link: &str) -> io::Result<MacAddr> {
    attribute(link, "address")?
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{link} address: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_has_index_one_and_a_zero_address() {
        assert_eq!(ifindex("lo").unwrap(), 1);
        assert_eq!(mac("lo").unwrap(), MacAddr([0; 6]));
    }

    #[test]
    fn names_that_leave_the_directory_are_refused() {
        for bad in ["", ".", "..", "../lo", "lo/..", "a\0b", "sixteen-chars-xx"] {
            let err = ifindex(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
        assert_eq!(
            ifindex("owr-no-such0").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
