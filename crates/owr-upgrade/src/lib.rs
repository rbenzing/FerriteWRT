//! Firmware upgrade for `FerriteWRT`.
//!
//! An upgrade is a *bundle*: three files of a published release,
//! `ferritewrt-<board>-v<version>-sysupgrade.bin`, `SHA256SUMS` and `SHA256SUMS.sig`. The
//! signature covers `SHA256SUMS`, which binds the image's name (board and version) to its
//! hash. [`bundle::verify`] checks all of it against the release public key baked into the
//! image; [`plan::write_plan`] turns a verified image into the ordered partition writes.
//!
//! This crate is pure: it reads files but never touches block devices. The writes run in
//! `owr-init`, which owns the boot and the shutdown of every other process.
//!
//! The release side of the same contract (hashing, signing) is `owr release` in `owr-cli`,
//! which uses [`release`] so the format exists once.

pub mod apply;
pub mod bundle;
pub mod image;
pub mod plan;
pub mod release;
pub mod version;

pub use apply::ApplyError;
pub use bundle::{BundleError, Expect, Verified};
pub use image::{ImageError, Member, SysupgradeImage};
pub use plan::{PlanError, WriteStep};
pub use version::Version;
