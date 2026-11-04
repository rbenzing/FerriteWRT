# owr-init

PID 1 for FerriteWRT routers. Replaces procd, logd, fstools `mount_root` and the gpio-button
hotplug handler. Pure state machines live in the library (host-tested); the Linux glue is in
`src/linux/`. Panics are forbidden: every error is logged and boot continues or falls back to a
rescue shell (a panic in PID 1 is a kernel panic). That includes `print!`/`eprintln!` (they panic
on EIO): use `linux::console_log`; clippy denies `print_stderr`/`print_stdout`.

## Boot sequence
1. Mount proc (`hidepid=2`), sysfs, devtmpfs, devpts (`gid=5,mode=620,ptmxmode=666`), `/run` and
   `/tmp` (tmpfs, `noexec,nosuid,nodev`), cgroup2, securityfs (no debugfs).
2. `/dev/console` becomes stdio; journal + tracing start; `/dev/watchdog` is opened and petted.
3. Load `/etc/ferritewrt/board.toml`; mount the data partition (`PARTLABEL=rootfs_data`, resolved via
   `/sys/class/block/*/uevent`, restricted to the board's storage device, ambiguous labels are an
   error) at `/overlay`. `mkfs.f2fs` runs only if the first 64 KiB are all `0x00` or all `0xFF`
   (blank); any other content that is not the expected filesystem (btrfs, xfs, LUKS, squashfs are
   named in the message) is refused: data preserved, failsafe boot.
4. Failsafe decision (below); overlay `lowerdir=/ upperdir=/overlay/upper` on `/mnt`, move the
   pseudo filesystems in, `pivot_root` (old root at `/rom`). The image must ship `/mnt /overlay /rom`.
5. Hostname from `config.toml` `[system] hostname` (default `ferritewrt`), then the event loop:
   `kmodloader` (oneshot, 60 s limit, failure ignored) -> uevent coldplug -> `owr-apply boot`
   (oneshot, 120 s limit, failure logged at error level and visible as `failures` in `status`, but
   never blocking) -> dnsmasq, `owr-netd` (`owr-apply netd`: WAN DHCP client, IPv6 router
   advertisements), hostapd per radio (`dropbear -F -R` if
   `/etc/ferritewrt/ssh.enabled` exists). `owr-api` depends on `kmodloader` only, so the management
   UI is reachable even when apply fails. Services whose rendered config is missing are skipped.

Booted from an initramfs (`/` in `/proc/self/mountinfo` is tmpfs, ramfs or rootfs, or cannot be
determined): the data partition is never touched (no probe, mkfs, overlay or pivot); init runs on
the RAM root, persistence is off. The kernel command line is not used for this: the GL-MT6000 DTS
appends `root=PARTLABEL=rootfs` to the initramfs boot too.

## Failsafe
Entered (first match) when: the reset button is pressed within 2 s of the `gpio-keys` device being
opened (LED fast-blinks as prompt; a key already held at power-on is not detectable without an
ioctl); cmdline has `owr.failsafe=1`; `/etc/ferritewrt/failsafe` exists (one-shot, consumed); 3
consecutive boots did not reach "running" within 120 s (`/etc/ferritewrt/bootcount`, reset to 0 once
running); or the data partition failed. Failsafe skips the persistent overlay (tmpfs upper layer;
config untouched) and runs only `kmodloader` plus a console `/bin/sh` (also used if
`/sbin/owr-apply` is missing). Console programs run under `setsid -c` (busybox `setsid` must be in
the image) so Ctrl-C does not reach init; without it they share init's session.
Long-press reset = factory reset: marker `/overlay/.factory-reset`, wiped at next boot. Refused with
an error in the journal during failsafe (the overlay there is a tmpfs) and without a data partition.

## Watchdog
Dedicated thread writes `\0` every 10 s. It stops (hardware reset) if the main loop is silent for
90 s, or, **only while the boot has not yet reached running and a boot counter exists**
(`watchdog::should_inhibit`), a service is `failed` (10 failures within 5 min) or the boot is
overdue (120 s). That is the only case where the reset provably ends in failsafe after 3 boots.
Once running (counter back at 0) a failed service is only logged at error level and drives the
failsafe LED pattern; without a boot counter (initramfs, no data partition) health never resets the
board. None of this applies in failsafe. Clean shutdown writes `V` (magic close) first.

## Supervision
Restart `never|on-failure|always`, backoff 500 ms x2 up to 30 s, SIGTERM then SIGKILL after
`stop_timeout_ms` (5 s), then SIGKILL to the service's whole process group; crash loop (10
failures in 5 min) -> `failed`, never a reboot. A `restart = always` service that exits 0 within
10 s of its start counts as a failure; a spawn failure of a `restart = never` service leaves it
stopped. Children get `PATH=/usr/sbin:/usr/bin:/sbin:/bin` only, their own process group,
stdout/stderr into the journal.
Kernel: keep `CONFIG_FW_LOADER_USER_HELPER` off (firmware is loaded from `/lib/firmware` directly).

Shutdown stops services in dependency waves (nothing-depends-on-it first, wait, then its
dependencies), then SIGTERMs every remaining process, SIGKILLs after 2 s, syncs and unmounts.
A reboot/poweroff request waits (max 1 s) until its reply is written.

## Control socket (`/run/ferritewrt/init.sock`, 0600)
One request line (max 256 bytes) per connection, max 64 connections:
`status` (JSON), `restart <name>`, `reload <name>` (SIGHUP), `journal <since_seq> <limit>`
(NDJSON, limit <= 1000, reply capped at 1 MiB, streamed entry by entry, max 4 concurrent journal
requests), `reboot`, `poweroff`, `upgrade <dir> [downgrade] [wipe]`. Replies are `{"ok":true}` or `{"ok":false,"error":"..."}`.
`status` services carry `name, state, pid, since_unix, restarts` (the `owr-api` DTO) plus
`failures, oneshot, healthy`; journal entries are `{seq, ts_ms, prio, source, msg}` with `source`
one of `"kernel"`, `"init"`, `"service:<name>"`. Journal: 1 MiB / 8192 entries in RAM; persisted to
`/etc/ferritewrt/journal/journal.{0,1}` (512 KiB each) every 5 min, on failure and at shutdown.
`upgrade` (absolute path of `[A-Za-z0-9._/-]`, no `..`) copies the bundle into `/run/ferritewrt/upgrade` (0700), verifies it against `/usr/share/ferritewrt/release.pub` and plans the writes (`owr-upgrade`) before answering; it is refused in failsafe and without the data partition. The reply may take up to 60 s. On `ok` the runtime stops like a reboot; `shutdown::finish`, after the process sweep, prunes the overlay to `/etc/ferritewrt`, writes the factory-reset marker if `wipe`, locks init in memory (`mlockall`), writes kernel and rootfs with read-back and reboots. Nothing is written if a preparation step fails; a failed write is reported on the console (bootloader recovery).
Client: `owr_init::client` (pure std, sync; `InitClient` is unix-only, the framing and reply parsers build on every host)
is what `owr-api` and `owr status` use: one connection per call, 2 s timeouts, replies capped at 1 MiB, service names
validated with the same rule as init (`ClientError::{BadName, UnknownService, Refused, ..}`).

## Sandboxed daemons
dnsmasq and `hostapd-phy<N>` carry `ServiceSpec::sandbox` (profiles in
`src/sandbox.rs`). The supervisor creates the files a profile writes (empty, 0644) and the
directories it owns (0700), then starts `owr-init --sandbox <profile> -- <exec>`. The launcher
(`src/linux/sandbox.rs`) drops every capability outside the profile from the bounding set,
clears the ambient set, sets `no_new_privs`, applies a Landlock ruleset (ABI v5: read and
execute `/bin /sbin /usr /lib`, read `/proc /sys`, every `/etc` entry except `ferritewrt`, a few
`/dev` nodes, plus the profile's own files) and a seccomp filter returning `EPERM` for
module, mount, namespace, kexec, reboot, ptrace, bpf, `io_uring`, keyring and clock syscalls,
then execs the daemon. It fails closed (exit 126, reason in the service's journal); a kernel
without Landlock is reported and tolerated. Profile paths that do not exist are reported and
get no rule. `/etc/ferritewrt/sandbox.off` turns confinement off at the next service start.
The profiles come from the daemons' documentation and our rendered configs, not a trace on
the router: first hardware boots should watch these services' journals.

Linux test `linux::sandbox::tests::confined_process_is_restricted` (root only) re-runs the
test binary as a confined child and checks its bounding set, `no_new_privs`, seccomp mode, a
refused `mount` and a refused write outside the profile.

## Adding a service
Add a `ServiceSpec` in `src/services.rs::build_services` (absolute `exec`, `restart`,
`depends_on`, optional `condition_path_exists`, `health`) and a test next to the others. A
service that parses untrusted input gets a profile in `src/sandbox.rs`.

## Test mode (Linux dev box, no root needed)
```
owr-init --test-mode /tmp/owr [--services services.toml]
```
No mounts, watchdog, kmsg or uevent; run dir, `init.sock` and `journal/` live in the directory.
`services.toml` uses `[[service]]` tables with the `ServiceSpec` keys (`restart = "on-failure"`,
`health = { tcp-port = 80 }`, `[service.backoff]`). SIGTERM stops services and exits 0.
```
[[service]]
name = "sleeper"
exec = ["/bin/sleep", "1000"]
restart = "always"
```
