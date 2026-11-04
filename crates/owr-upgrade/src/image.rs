//! Reader for `OpenWrt`'s `sysupgrade.bin` on eMMC boards.
//!
//! `scripts/sysupgrade-tar.sh` writes a GNU tar holding one directory
//! `sysupgrade-<board>/` with `CONTROL` (`BOARD=<board>`), `kernel` (the FIT image) and
//! `root` (the squashfs). Vendor metadata (GL.iNet's `fwtool` trailer) may follow the
//! end-of-archive block; it is ignored. Anything else is rejected: this reader only has to
//! understand the images our own build produces, and every other shape is a reason to stop.

use std::io::{self, Read, Seek, SeekFrom};

const BLOCK: u64 = 512;
/// More members than a sysupgrade tar ever has; bounds the work on hostile input.
const MAX_MEMBERS: usize = 8;
const MAX_CONTROL: u64 = 4096;

/// A file inside the image: where its bytes are and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Byte offset of the data in the image file.
    pub offset: u64,
    pub size: u64,
}

/// What a sysupgrade image contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysupgradeImage {
    /// `BOARD=` of `CONTROL`: the `OpenWrt` device name (our board's `[openwrt] profile`).
    pub board: String,
    pub kernel: Member,
    pub root: Member,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageError {
    #[error("cannot read the image: {0}")]
    Io(String),
    #[error("not a sysupgrade image: {0}")]
    Format(String),
}

impl From<io::Error> for ImageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

fn format(msg: impl Into<String>) -> ImageError {
    ImageError::Format(msg.into())
}

/// Bytes `range` of a header block.
fn field(h: &[u8; 512], start: usize, len: usize) -> &[u8] {
    h.get(start..start.saturating_add(len)).unwrap_or(&[])
}

/// A NUL-terminated (or full-width) text field.
fn text(raw: &[u8]) -> Result<&str, ImageError> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    std::str::from_utf8(raw.get(..end).unwrap_or(&[]))
        .map_err(|_| format("member name is not UTF-8"))
}

/// A tar numeric field: octal digits, optionally padded with spaces/NULs. Base-256 (GNU's
/// encoding for values that do not fit) is rejected: no member of ours is that large.
fn octal(raw: &[u8]) -> Result<u64, ImageError> {
    let digits = raw
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| (b'0'..=b'7').contains(&b))
        .collect::<Vec<u8>>();
    let rest_ok = raw
        .iter()
        .skip_while(|&&b| b == b' ')
        .skip(digits.len())
        .all(|&b| b == 0 || b == b' ');
    if digits.is_empty() || !rest_ok {
        return Err(format("malformed numeric field in a tar header"));
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        acc.checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(d.wrapping_sub(b'0'))))
            .ok_or_else(|| format("numeric field overflows"))
    })
}

fn checksum_ok(h: &[u8; 512]) -> Result<bool, ImageError> {
    let stored = octal(field(h, 148, 8))?;
    let sum = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(b)
            }
        })
        .sum::<u64>();
    Ok(sum == stored)
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

/// A validated tar header.
#[derive(Debug)]
struct Header {
    name: String,
    size: u64,
    kind: Kind,
}

/// Checksum, magic (GNU `ustar  \0` or POSIX `ustar\000`), name, size and type of one
/// non-zero header block.
fn parse_header(h: &[u8; 512]) -> Result<Header, ImageError> {
    if !checksum_ok(h)? {
        return Err(format("tar header checksum mismatch"));
    }
    let magic = field(h, 257, 8);
    let posix = magic == b"ustar\x0000";
    if !posix && magic != b"ustar  \0" {
        return Err(format("not a ustar/GNU tar header"));
    }
    let mut name = text(field(h, 0, 100))?.to_owned();
    if posix {
        let prefix = text(field(h, 345, 155))?;
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
    }
    let size = octal(field(h, 124, 12))?;
    let kind = match h.get(156) {
        Some(b'0' | 0) => Kind::File,
        Some(b'5') => Kind::Dir,
        _ => return Err(format(format!("{name}: unsupported member type"))),
    };
    Ok(Header { name, size, kind })
}

/// Read and validate the image. `r` is positioned anywhere; the length is taken from it.
pub fn read<R: Read + Seek>(r: &mut R) -> Result<SysupgradeImage, ImageError> {
    let len = r.seek(SeekFrom::End(0))?;
    let mut pos = 0u64;
    let mut dir: Option<String> = None;
    let mut control: Option<Member> = None;
    let mut kernel: Option<Member> = None;
    let mut root: Option<Member> = None;
    let mut members = 0usize;

    loop {
        let data = pos
            .checked_add(BLOCK)
            .filter(|&d| d <= len)
            .ok_or_else(|| format("truncated: no end-of-archive block"))?;
        let mut h = [0u8; 512];
        r.seek(SeekFrom::Start(pos))?;
        r.read_exact(&mut h)?;
        if h.iter().all(|&b| b == 0) {
            break;
        }
        members = members.saturating_add(1);
        if members > MAX_MEMBERS {
            return Err(format("too many members"));
        }
        let Header { name, size, kind } = parse_header(&h)?;
        let end = data
            .checked_add(size)
            .filter(|&e| e <= len)
            .ok_or_else(|| format(format!("{name}: extends past the end of the file")))?;

        match kind {
            Kind::Dir => {
                let d = name
                    .strip_suffix('/')
                    .filter(|d| d.starts_with("sysupgrade-") && !d.contains('/'))
                    .ok_or_else(|| format(format!("unexpected directory {name:?}")))?;
                if dir.replace(d.to_owned()).is_some() || size != 0 {
                    return Err(format("more than one sysupgrade directory"));
                }
            }
            Kind::File => {
                let (parent, file) = name
                    .split_once('/')
                    .ok_or_else(|| format(format!("unexpected file {name:?}")))?;
                if dir.as_deref() != Some(parent) {
                    return Err(format(format!(
                        "{name:?} is outside the sysupgrade directory"
                    )));
                }
                let slot = match file {
                    "CONTROL" => &mut control,
                    "kernel" => &mut kernel,
                    "root" => &mut root,
                    _ => return Err(format(format!("unexpected file {name:?}"))),
                };
                if slot.replace(Member { offset: data, size }).is_some() {
                    return Err(format(format!("duplicate member {name:?}")));
                }
            }
        }
        // Data is padded to whole blocks.
        pos = end
            .checked_next_multiple_of(BLOCK)
            .ok_or_else(|| format("offset overflow"))?;
    }

    let dir = dir.ok_or_else(|| format("no sysupgrade-<board>/ directory"))?;
    let dir_board = dir.strip_prefix("sysupgrade-").unwrap_or_default();
    let control = control.ok_or_else(|| format("no CONTROL file"))?;
    let kernel = kernel
        .filter(|m| m.size > 0)
        .ok_or_else(|| format("no kernel"))?;
    let root = root
        .filter(|m| m.size > 0)
        .ok_or_else(|| format("no root filesystem"))?;
    if control.size > MAX_CONTROL {
        return Err(format("CONTROL is too large"));
    }
    let mut buf = vec![0u8; usize::try_from(control.size).unwrap_or(0)];
    r.seek(SeekFrom::Start(control.offset))?;
    r.read_exact(&mut buf)?;
    let control_text = std::str::from_utf8(&buf).map_err(|_| format("CONTROL is not UTF-8"))?;
    let board = control_text
        .lines()
        .find_map(|l| l.strip_prefix("BOARD="))
        .ok_or_else(|| format("CONTROL has no BOARD= line"))?;
    if board != dir_board {
        return Err(format(format!(
            "CONTROL says BOARD={board}, directory is {dir}/"
        )));
    }
    Ok(SysupgradeImage {
        board: board.to_owned(),
        kernel,
        root,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    use std::io::Cursor;

    use super::*;

    /// One tar header, GNU (`ustar  \0`) or POSIX (`ustar\000`) flavour.
    fn header(name: &str, size: usize, typeflag: u8, gnu: bool) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[156] = typeflag;
        h[257..265].copy_from_slice(if gnu { b"ustar  \0" } else { b"ustar\x0000" });
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    /// A tar of `(name, data)` entries; `None` data = directory. Two zero blocks at the end.
    pub(crate) fn tar(entries: &[(&str, Option<&[u8]>)], gnu: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            match data {
                None => out.extend_from_slice(&header(name, 0, b'5', gnu)),
                Some(d) => {
                    out.extend_from_slice(&header(name, d.len(), b'0', gnu));
                    out.extend_from_slice(d);
                    out.resize(out.len().div_ceil(512) * 512, 0);
                }
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// A well-formed image for `board` with the given kernel and root bytes.
    pub(crate) fn image(board: &str, kernel: &[u8], root: &[u8]) -> Vec<u8> {
        let dir = format!("sysupgrade-{board}/");
        let control = format!("BOARD={board}\n");
        tar(
            &[
                (&dir, None),
                (&format!("{dir}CONTROL"), Some(control.as_bytes())),
                (&format!("{dir}kernel"), Some(kernel)),
                (&format!("{dir}root"), Some(root)),
            ],
            true,
        )
    }

    fn read_bytes(bytes: &[u8]) -> Result<SysupgradeImage, ImageError> {
        read(&mut Cursor::new(bytes))
    }

    #[test]
    fn reads_members_and_their_offsets() {
        let bytes = image("glinet_gl-mt6000", b"KERNEL", b"ROOTFS-BYTES");
        let img = read_bytes(&bytes).unwrap();
        assert_eq!(img.board, "glinet_gl-mt6000");
        let at = |m: Member| {
            let start = usize::try_from(m.offset).unwrap();
            &bytes[start..start + usize::try_from(m.size).unwrap()]
        };
        assert_eq!(at(img.kernel), b"KERNEL");
        assert_eq!(at(img.root), b"ROOTFS-BYTES");
    }

    #[test]
    fn vendor_trailer_after_the_archive_is_ignored() {
        let mut bytes = image("b", b"k", b"r");
        bytes.extend_from_slice(b"{\"metadata_version\":\"1.1\"}FWx0trailer");
        assert!(read_bytes(&bytes).is_ok());
    }

    #[test]
    fn posix_headers_are_accepted() {
        let bytes = tar(
            &[
                ("sysupgrade-b/", None),
                ("sysupgrade-b/CONTROL", Some(b"BOARD=b\n")),
                ("sysupgrade-b/kernel", Some(b"k")),
                ("sysupgrade-b/root", Some(b"r")),
            ],
            false,
        );
        assert_eq!(read_bytes(&bytes).unwrap().board, "b");
    }

    #[test]
    fn rejects_malformed_images() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("not a tar", vec![b'x'; 2048]),
            (
                "board mismatch",
                tar(
                    &[
                        ("sysupgrade-a/", None),
                        ("sysupgrade-a/CONTROL", Some(b"BOARD=b\n")),
                        ("sysupgrade-a/kernel", Some(b"k")),
                        ("sysupgrade-a/root", Some(b"r")),
                    ],
                    true,
                ),
            ),
            (
                "no kernel",
                tar(
                    &[
                        ("sysupgrade-b/", None),
                        ("sysupgrade-b/CONTROL", Some(b"BOARD=b\n")),
                        ("sysupgrade-b/root", Some(b"r")),
                    ],
                    true,
                ),
            ),
            (
                "extra file",
                tar(
                    &[
                        ("sysupgrade-b/", None),
                        ("sysupgrade-b/CONTROL", Some(b"BOARD=b\n")),
                        ("sysupgrade-b/kernel", Some(b"k")),
                        ("sysupgrade-b/root", Some(b"r")),
                        ("sysupgrade-b/dtb", Some(b"d")),
                    ],
                    true,
                ),
            ),
            (
                "path escape",
                tar(&[("sysupgrade-b/", None), ("../kernel", Some(b"k"))], true),
            ),
            (
                "duplicate root",
                tar(
                    &[
                        ("sysupgrade-b/", None),
                        ("sysupgrade-b/CONTROL", Some(b"BOARD=b\n")),
                        ("sysupgrade-b/kernel", Some(b"k")),
                        ("sysupgrade-b/root", Some(b"r")),
                        ("sysupgrade-b/root", Some(b"r")),
                    ],
                    true,
                ),
            ),
        ];
        for (what, bytes) in cases {
            assert!(read_bytes(&bytes).is_err(), "{what} must be rejected");
        }
    }

    #[test]
    fn rejects_corrupt_header_and_truncation() {
        let good = image("b", b"kernel", b"root");
        let mut bad_sum = good.clone();
        bad_sum[0] ^= 1;
        assert_eq!(
            read_bytes(&bad_sum),
            Err(ImageError::Format("tar header checksum mismatch".into()))
        );
        // Cut inside the root member: its declared size runs past the end.
        let truncated = &good[..good.len() - 1024 - 256];
        assert!(read_bytes(truncated).is_err());
        // Remove the end-of-archive blocks.
        let no_end = &good[..good.len() - 1024];
        assert!(read_bytes(no_end).is_err());
    }
}
