//! The partition writes of an upgrade, in order.
//!
//! Same order as `OpenWrt`'s `emmc_upgrade_tar` (`package/base-files/files/lib/upgrade/emmc.sh`):
//! invalidate the kernel, write the root filesystem, write the kernel. An interruption
//! therefore leaves either the old system or a kernel the bootloader refuses, never a new
//! kernel on a half-written root; recovery is then the bootloader's (on the reference board,
//! the GL.iNet U-Boot web recovery). The data partition (settings) is not part of the plan.

use owr_board::{PartitionRole, Storage};

use crate::image::{Member, SysupgradeImage};

/// Bytes zeroed at the start of the kernel partition before the root filesystem is written:
/// enough to destroy the FIT header, so a half-finished upgrade does not boot.
pub const INVALIDATE_LEN: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStep {
    /// Zero the first `len` bytes of the partition labelled `partition`.
    Invalidate { partition: String, len: u64 },
    /// Copy `member` of the image file to the start of the partition labelled `partition`,
    /// then read it back and compare.
    Copy { partition: String, member: Member },
}

impl WriteStep {
    pub fn partition(&self) -> &str {
        match self {
            Self::Invalidate { partition, .. } | Self::Copy { partition, .. } => partition,
        }
    }

    /// Bytes the step writes from the start of its partition.
    pub fn write_len(&self) -> u64 {
        match self {
            Self::Invalidate { len, .. } => *len,
            Self::Copy { member, .. } => member.size,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("the board describes no {0} partition")]
    NoPartition(&'static str),
    #[error("the board describes more than one {0} partition")]
    Ambiguous(&'static str),
    #[error("{partition}: the image needs {needed} bytes, the partition holds {size}")]
    TooLarge {
        partition: String,
        needed: u64,
        size: u64,
    },
    #[error("{0}: partition size unknown")]
    UnknownSize(String),
}

fn partition<'a>(
    storage: &'a Storage,
    role: &PartitionRole,
    what: &'static str,
) -> Result<&'a str, PlanError> {
    let mut found = storage.partitions.iter().filter(|p| p.role == *role);
    match (found.next(), found.next()) {
        (Some(p), None) => Ok(&p.name),
        (None, _) => Err(PlanError::NoPartition(what)),
        (Some(_), Some(_)) => Err(PlanError::Ambiguous(what)),
    }
}

/// The ordered writes that install `image` on a board with this storage layout.
pub fn write_plan(storage: &Storage, image: &SysupgradeImage) -> Result<Vec<WriteStep>, PlanError> {
    let kernel = partition(storage, &PartitionRole::Kernel, "kernel")?;
    let rootfs = partition(storage, &PartitionRole::Rootfs, "rootfs")?;
    Ok(vec![
        WriteStep::Invalidate {
            partition: kernel.to_owned(),
            len: INVALIDATE_LEN,
        },
        WriteStep::Copy {
            partition: rootfs.to_owned(),
            member: image.root,
        },
        WriteStep::Copy {
            partition: kernel.to_owned(),
            member: image.kernel,
        },
    ])
}

/// Check every step against the partition sizes (bytes) before anything is written.
pub fn check_fit(
    steps: &[WriteStep],
    size_of: impl Fn(&str) -> Option<u64>,
) -> Result<(), PlanError> {
    for step in steps {
        let name = step.partition();
        let size = size_of(name).ok_or_else(|| PlanError::UnknownSize(name.to_owned()))?;
        if step.write_len() > size {
            return Err(PlanError::TooLarge {
                partition: name.to_owned(),
                needed: step.write_len(),
                size,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> Storage {
        owr_board::builtin("glinet_gl-mt6000").unwrap().storage
    }

    fn img() -> SysupgradeImage {
        SysupgradeImage {
            board: "glinet_gl-mt6000".into(),
            kernel: Member {
                offset: 1536,
                size: 6_000_000,
            },
            root: Member {
                offset: 6_001_664,
                size: 20_000_000,
            },
        }
    }

    #[test]
    fn reference_board_plan_matches_openwrt_order() {
        let steps = write_plan(&storage(), &img()).unwrap();
        assert_eq!(
            steps,
            vec![
                WriteStep::Invalidate {
                    partition: "kernel".into(),
                    len: INVALIDATE_LEN
                },
                WriteStep::Copy {
                    partition: "rootfs".into(),
                    member: img().root
                },
                WriteStep::Copy {
                    partition: "kernel".into(),
                    member: img().kernel
                },
            ]
        );
    }

    #[test]
    fn plan_needs_exactly_one_kernel_and_rootfs() {
        let mut s = storage();
        s.partitions.retain(|p| p.role != PartitionRole::Kernel);
        assert_eq!(
            write_plan(&s, &img()),
            Err(PlanError::NoPartition("kernel"))
        );
        let mut s = storage();
        let extra = s
            .partitions
            .iter()
            .find(|p| p.role == PartitionRole::Rootfs)
            .unwrap()
            .clone();
        s.partitions.push(extra);
        assert_eq!(write_plan(&s, &img()), Err(PlanError::Ambiguous("rootfs")));
    }

    #[test]
    fn fit_is_checked_for_every_partition() {
        let steps = write_plan(&storage(), &img()).unwrap();
        let mib = |n: u64| n * 1024 * 1024;
        assert_eq!(
            check_fit(&steps, |p| Some(if p == "kernel" {
                mib(32)
            } else {
                mib(64)
            })),
            Ok(())
        );
        assert_eq!(
            check_fit(&steps, |p| Some(if p == "kernel" {
                mib(32)
            } else {
                mib(16)
            })),
            Err(PlanError::TooLarge {
                partition: "rootfs".into(),
                needed: 20_000_000,
                size: mib(16)
            })
        );
        assert_eq!(
            check_fit(&steps, |p| (p == "kernel").then_some(mib(32))),
            Err(PlanError::UnknownSize("rootfs".into()))
        );
    }
}
