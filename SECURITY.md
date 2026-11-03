# Security model

## Threat model

Assets: the LAN behind the router, the router's configuration (contains Wi-Fi
passphrases and password hashes), and the integrity of the firmware itself.

Adversaries, strongest first:

1. **WAN attacker**: arbitrary packets to the WAN port. Must not reach any listening
   service, must not be able to crash the control plane, must not forward into the LAN.
2. **LAN/Wi-Fi guest**: a device on a guest VLAN or an isolated AP. Must not reach the
   management API, other clients, or the main LAN.
3. **LAN user without credentials**: can reach the management API over TLS. Must not
   be able to enumerate users, brute-force passwords, or trigger state changes
   (CSRF/XSS) through a logged-in admin's browser.
4. **Viewer-role account**: read-only. Must not be able to change anything or read
   secrets.
5. **Malicious firmware image**: must not be accepted by the upgrader without a valid
   signature (phase 2; the stock bootloader is out of scope).

Out of scope: physical access (UART, eMMC), supply-chain compromise of the Linux
kernel or the kept C daemons, and side channels on the SoC.

## Defaults that enforce the model

- **No inbound WAN**: the firewall's `wan` zone policy is `drop` for input and
  forward; only DHCP client replies, essential ICMPv6 and rate-limited echo are
  accepted. `ct state invalid` is dropped. Port forwards are explicit per-rule.
- **Management plane is LAN-only, HTTPS-only**: the API binds to the LAN bridge
  address, serves TLS 1.2/1.3 with a locally generated P-256 certificate whose SHA-256
  fingerprint is shown in the UI for pinning. No plaintext HTTP in production.
- **Authentication**: argon2id password hashes (OWASP parameters), no default
  password (first boot forces setup with a 12+ character minimum), constant-time
  verification path for unknown users, per-user and per-IP rate limits, sessions in
  `Secure; HttpOnly; SameSite=Strict` cookies with idle and absolute TTLs, CSRF
  double-submit token on every mutating request, `Origin`/`Sec-Fetch-Site` checked.
- **Browser hardening**: strict Content Security Policy (`'self'` only, no inline
  scripts or styles), `frame-ancestors 'none'`, `nosniff`, no referrer, HSTS.
- **Least privilege in the UI**: `viewer` role is read-only and secrets are redacted
  from every API response.
- **Auditability**: every mutating request appends `{time, actor, ip, method, path,
  outcome}` to an append-only audit log. Bodies and secrets are never logged.
- **Memory safety**: all first-party code is `#![forbid(unsafe_code)]`; the dependency
  graph contains no C or assembly (enforced by `deny.toml`); release builds keep
  integer overflow checks and abort on panic; input sizes are bounded everywhere
  (HTTP bodies, netlink dumps, journal, hostapd replies).
- **Kernel hardening** (see `build/openwrt/kernel-config.fragment`): stack protector
  strong, ARM64 pointer authentication and BTI, init-on-alloc, seccomp, Landlock +
  Yama, hardened usercopy/freelists, KASLR, no `/dev/mem`, no `/proc/kcore`, no kexec.
- **No shell in the control plane**: nothing in FerriteWRT spawns a shell or interprets
  strings as commands; daemons are exec'd directly with cleared environments.
- **No package manager**: the image is immutable; updates are whole signed images.

## Reporting

Open an issue marked `security` or contact the maintainers privately. Please include
the firmware version from the About page.
