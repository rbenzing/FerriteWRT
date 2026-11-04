# owr-upgrade

Firmware upgrades for FerriteWRT: the release signature contract, a reader for the
sysupgrade image, bundle verification, the partition write plan and its executor.
Pure `std` I/O; everything is tested on the host, with regular files standing in for
partitions.

## The bundle

An upgrade is three files of a published release, in one directory:

| File | Role |
|---|---|
| `ferritewrt-<board>-v<version>-sysupgrade.bin` | the image (OpenWrt's sysupgrade tar) |
| `SHA256SUMS` | hashes of every release file |
| `SHA256SUMS.sig` | ed25519 signature over `SHA256SUMS` (`ferritewrt-sig/1`) |

`bundle::verify` checks, in this order, and stops at the first failure:

1. the signature over `SHA256SUMS`, against the release public key the running image
   ships (`/usr/share/ferritewrt/release.pub`, from `keys/release.pub`);
2. exactly one `ferritewrt-<this board>-v<version>-sysupgrade.bin` is listed;
3. the image's SHA-256 matches the signed line;
4. the image is a sysupgrade tar of the expected shape (`image`): one
   `sysupgrade-<board>/` directory with `CONTROL`, `kernel` and `root`, header checksums
   and bounds checked; a vendor metadata trailer after the archive is ignored;
5. `CONTROL`'s `BOARD=` is this board's OpenWrt profile (the signed name alone is not
   trusted for this);
6. the version is not older than the running one, unless a downgrade is requested
   (semver precedence, `version`).

## Writing

`plan::write_plan` uses the order of OpenWrt's `emmc_upgrade_tar`: zero the first 4 KiB of
the kernel partition, write the root filesystem, write the kernel. An interruption leaves
either the old system or a kernel the bootloader refuses; never a new kernel on a
half-written root. `plan::check_fit` checks every write against the partition sizes before
the first byte is written. `apply::execute` writes each step, flushes it and reads it back
before the next one.

There is no second slot: the reference board's partition table has one kernel and one
rootfs partition, so a failed write is recovered through the bootloader (GL.iNet U-Boot web
recovery on the Flint 2, see `docs/BUILD.md`). A/B would need a different partition layout.

Settings survive: `apply::prune_upper` reduces the overlay's upper layer to
`/etc/ferritewrt` (minus `board.toml`, which is image content), so nothing of the old image
(changed binaries, whiteouts, a stale descriptor or key) shadows the new one.

## Who calls it

* `owr-init` handles the `upgrade <dir>` control request: it stages the bundle into
  `/run/ferritewrt/upgrade` (0700, so the uploader cannot swap files after verification),
  verifies and plans while everything still runs, and answers only then. The writes happen
  in its shutdown, after every other process is gone, with init locked in memory
  (`mlockall`) because it runs from the root filesystem being replaced.
* `owr upgrade <dir>` sends that request; `owr upgrade --check <dir>` runs the verification
  anywhere.
* `owr-api` accepts the three files over HTTPS and forwards the same request.
* `owr release` (`owr-cli`) writes the signature format through [`release`].
