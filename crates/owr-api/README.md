# owr-api

HTTPS management API and static web UI host. Replaces uhttpd + rpcd + the LuCI backend.
One axum router, rustls (graviola provider, no ring/aws-lc), Argon2id passwords, RBAC,
CSRF, rate limiting and an audit log. It talks to the system only through the
`SystemBackend` trait (`src/backend.rs`); `real::RealBackend` (Linux) implements it on top of the other crates.

## Run in development (works on Windows too)

```
cargo run -p owr-api -- --dev                       # http://127.0.0.1:8080, mock Flint 2 backend
cargo run -p owr-api -- --dev --ui-dir crates/owr-api/ui   # serve UI from disk, no rebuild needed
cargo run -p owr-api -- --dev --tls-dir ./tls       # https with a generated self-signed cert
```

`--dev` starts with no users: open the UI (or `POST /api/v1/setup`) to create the admin.
Without `--dev` the binary is the production server (Linux only; elsewhere it prints `production backend requires Linux` and exits 2), see below.
The UI is embedded with `include_dir!` at compile time; touch `src/ui.rs` to re-embed.

## Responses

`{"ok": true, "data": ...}` or `{"ok": false, "error": {"code", "message", "details?"}}`.
Backend errors map to 503 / 422 / 400 (`Refused`: the message is for the user, e.g. why an upgrade
bundle failed verification) / 404 / 500; validation details are
`{"errors": [{"path": "wireless.aps[0].ssid", "message": "..."}]}`.

## Endpoints (`/api/v1`)

| Method and path | Role | Notes |
|---|---|---|
| `GET /health`, `GET /setup/status` | public | `{needs_setup}` |
| `POST /setup` `{username,password}` | public | only while no users exist; 409 afterwards |
| `POST /auth/login` `{username,password}` | public | sets cookie, returns `{user,role,csrf}`; 429 + `Retry-After` |
| `GET /auth/session`, `POST /auth/logout`, `POST /auth/password` `{current,new}` | any | `logout`/`password` allowed for viewers |
| `GET /board /system/status /network/status /wireless/status /dhcp/leases /services /users` | any | |
| `GET /config`, `POST /config/validate`, `PUT /config` | read: any, write: admin | GET is redacted (`"***"`) |
| `GET /firewall/preview` | any | `text/plain` nft ruleset |
| `GET /logs?since=&limit=` | any | `limit` clamped to 1..=500 (default 100) |
| `POST /services/{name}/{restart\|reload}`, `POST /system/reboot` | admin | |
| `PUT /users/{name}` `{role,enabled,password?}`, `DELETE /users/{name}` | admin | not self, never the last admin |
| `GET /system/backup`, `POST /system/restore` | admin | octet-stream; restore body <= 1 MiB, logs everyone out |
| `PUT /system/upgrade/files/{name}` | admin | raw body streamed to the upload dir; `name` is `SHA256SUMS` (<= 64 KiB), `SHA256SUMS.sig` (<= 4 KiB) or `ferritewrt-*-sysupgrade.bin` (<= 128 MiB), else 400; too large -> 413 and nothing kept; an image replaces older images; `{name,size}` |
| `DELETE /system/upgrade/files` | admin | removes every upload, `{cleared}` |
| `POST /system/upgrade/check` `{allow_downgrade?}` | admin | verifies the uploads (signature, hash, image, board, version): `{image,version,board,running,downgrade}`; a bad bundle is 400 with the reason |
| `POST /system/upgrade` `{allow_downgrade?,wipe_settings?}` | admin | hands the uploads to init (which verifies again, writes the image, reboots): `{upgrading:true}`; init's refusal is 400 with its reason |

Everything else under `/api` is a JSON 404. Any other path serves the UI (SPA fallback to `index.html`).

## Auth model

* Session cookie `owr_session` (32 random bytes, base64url), `HttpOnly; SameSite=Strict; Path=/`,
  plus `Secure` when TLS is on; no `Max-Age`/`Expires` (a browser-session cookie). Stored server-side
  keyed by SHA-256 of the token; the idle TTL slides on every authenticated request, 24 h absolute,
  max 64 sessions (least recently used evicted), purged every 60 s.
* Every non-GET needs `X-CSRF-Token` equal to the `csrf` from login/session (constant-time compare).
  Mutating requests with `Sec-Fetch-Site` other than same-origin/none, or an `Origin` that differs
  from `Host`, are rejected. No CORS.
* Viewer = GET only (plus logout and own password change). Role/disable/password changes revoke sessions.
* Login: 5 failures per username or per client IP (IPv6: /64) in 5 minutes -> 429. Verification is
  serialised and unknown users verify against a dummy hash. Passwords: 12-256 chars, not the
  username, not a common password; Argon2id m=19456 KiB, t=2, p=1.

## Hardening

Headers on every response: `Content-Security-Policy` (self only, no inline), `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
`Permissions-Policy`, and `Strict-Transport-Security: max-age=86400` (TLS only; one day because the
self-signed certificate is regenerated on factory reset). API responses are `Cache-Control: no-store`;
UI files are `no-cache` with an `ETag` (`If-None-Match` incl. `*` and `W/` tags), so upgrades show at once.
A missing file with an extension (`/js/x.js`) is a 404; only extension-less paths fall back to `index.html`.
Limits: 256 KiB bodies (1 MiB restore, per-file limits for upgrade uploads), 30 s request timeout (240 s
for `/system/upgrade*`: large uploads, hashing, init staging), 10 s header/handshake timeout, 128 connections
(16 per client address, IPv6 per /64), 5 min maximum connection lifetime (bounds stalled writers).
Mutating backend calls run in a detached task, so a client disconnect or the timeout cannot abort them
half-way; the request is then audited as `aborted`.
Audit (flash friendly): authenticated mutating calls (and backup downloads) and login/setup successes
append `{ts,actor,ip,method,path,outcome}` with fsync; failed logins and unauthenticated noise (404s,
cross-site, CSRF rejections) are written at most once per second per client (`rejected`/`denied`). The
file is rotated at 512 KiB to `<name>.1` (one previous generation). Bodies, cookies and tokens are never
logged. Backend error text (`Unavailable`/`Internal`) is logged, never sent to clients.

## TLS

`tls::ensure_cert(dir, extra_sans)` creates `server.key` (0600) and `server.crt` (0644) on first use: P-256,
CN `ferritewrt`, SAN `ferritewrt.lan`, `ferritewrt` plus `extra_sans` (IPs become IP SANs; `--dev` passes
`127.0.0.1`, production passes the LAN address), 10 years. An existing certificate is reused as is. Loading
a key that group/others can read chmods it to 0600 and warns. `tls::fingerprint_sha256` gives the pin.

## Plugging in a backend

Implement `owr_api::SystemBackend` (object safe, `BoxFuture` methods; see `MockBackend` for a complete
example) and call `owr_api::serve(ServerConfig { bind, tls, session_ttl, backend, ui_enabled, ui_dir,
audit_log_path, upload_dir })`. Contract: `config()` returns redacted JSON and `save_config` treats `"***"` as
"keep the stored secret"; `verify_password` owns the hashes and must do equal work for unknown users;
`set_user(.., None)` keeps the existing hash; `set_password` changes only the hash (self-service change,
so a stale session cannot revert a role edit); `restore` may not remove the last enabled admin;
`upgrade_check` refuses a bad bundle with `BackendError::Refused` (shown to the user) and changes nothing;
`upgrade` returns once init accepted (init's refusal is `Refused`).
`owr_api::router(&cfg)` returns the router without a socket.

## Production wiring (`src/real.rs`, Linux only)

```
owr-api [--bind ADDR] [--tls-dir D] [--run-dir D] [--init-sock P] [--nft P] [--board P] [--config P] [--ui-dir D]
```

Defaults come from `owr_common::paths`: board `/etc/ferritewrt/board.toml`, config `/etc/ferritewrt/config.toml`,
run dir `/run/ferritewrt` (init socket `<run>/init.sock`, leases `<run>/dhcp.leases`, hostapd sockets
`<run>/hostapd`, firmware uploads `<run>/upgrade-upload`, emptied at start), release key
`/usr/share/ferritewrt/release.pub`, TLS dir `/etc/ferritewrt/tls`, audit log `/etc/ferritewrt/audit.log`, nft `/usr/sbin/nft`.
Startup: load the board; load the config (writes the board defaults if there is none, like `owr-apply boot`);
`bind` defaults to `network.lan.ipv4` host address on `services.api.port` (443), or `0.0.0.0:443` with a warning
when the config is unusable; the certificate is created in `--tls-dir` with the LAN address and the hostname as
extra SANs and its SHA-256 fingerprint is printed; the session TTL is `services.api.session_ttl`.

`RealBackend::new(RealConfig { board_path, config_path, run_dir, init_sock, nft_bin, leases_file,
hostapd_ctrl_dir, release_key })` implements `SystemBackend`:

| call | how |
|---|---|
| `board`, `status` | loaded board as JSON; `/proc/{sys/kernel/hostname,uptime,loadavg,meminfo}`, CPU temperature from the thermal zones (first zone typed `cpu*`, else the first readable), firmware `{CARGO_PKG_VERSION, $OWR_BUILD or "dev"}` |
| `config`, `validate_config` | `Store::load_for` -> `owr_config::redact`; validation = schema (serde errors sanitised) + `validate_against(board)` + `owr_apply::build_plans` (so what cannot be applied is rejected before saving) + leftover `"***"` placeholders |
| `save_config` | unredact against the stored config (`secrets` module, shared with the mock), validate, `Store::save_for`, `Applier::apply` (production: `owr_apply::run::apply_all`), then `InitClient::restart` for `hostapd-<phy>` / `dnsmasq` / `owr-netd` whose files changed. The `users` section is ignored with a warning (use `/users`). Restart problems (unknown service, init down) are warnings; an apply error is `Internal` (details logged; a partial outcome is summarised and its daemons are still restarted), the config stays saved |
| `restore`, `backup` | raw `config.toml` bytes; restore = `Config::from_toml_str` + board validation + mapping check + at least one enabled admin, then save/apply/restart as above |
| `network_status` | one rtnetlink dump (`owr_net::linux::observe`): board ports with their role, plus bridges; WAN from the persisted lease `<run>/lease-<wan netdev>.json` (DHCP) or the config (static), else the observed address and default route |
| `wireless_status` | every configured radio; per AP (`wlan<N>`, `wlan<N>-<k>`) hostapd `STATUS` + stations over the control sockets (blocking, in `spawn_blocking`); hostnames from the lease file by MAC |
| `dhcp_leases` | dnsmasq lease file, IPv4 lines only, at most 4096 lines |
| `firewall_preview` | `build_plans` -> `owr_fw::render` |
| `logs`, `services`, `service_action`, `reboot` | `owr_init::client::InitClient` (journal timestamps are converted from boot-relative to wall-clock milliseconds) |
| `upgrade_check` | `owr_upgrade::bundle::verify` (in `spawn_blocking`: it hashes the image) against `release_key`, the board id/profile and `CARGO_PKG_VERSION`; `BundleError` -> `Refused`, an unreadable key -> `Internal` |
| `upgrade` | `InitClient::upgrade` with the upload dir; `ClientError::Refused` -> `Refused`, init down -> `Unavailable` |
| users | stored in `config.toml`; `set_user`/`set_password`/`delete_user` read-modify-write under the same mutex as `save_config`/`restore` and refuse to leave no enabled admin; `verify_password` runs Argon2id in `spawn_blocking` against the stored hash (dummy hash for unknown users) |

The pure parts (`procfs`: /proc and lease parsers; `view`: observed state -> DTOs; `document`, `secrets`)
are tested on every host; `tests/real.rs` runs `RealBackend` on Linux against a temp dir, a fake init socket
and a recording no-op `Applier` (`save_config` is not run against netlink/nft in tests).
