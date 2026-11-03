# owr-api web UI

Plain HTML5 + CSS + vanilla ES2022 modules. No build step, no npm, no frameworks, no external
resources. It is embedded in the firmware and served by `owr-api` (`index.html` for every
non-`/api` path: SPA fallback) under this CSP:

    default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:

so there are no inline scripts, inline styles, inline event handlers, `eval`, CDNs or web fonts.
Dynamic state is expressed with classes, SVG attributes and `<progress>`; handlers are attached
with `addEventListener` (via `h()`); all dynamic text goes through text nodes (never `innerHTML`).

Static files the server must serve (correct MIME types, `icons.svg` as `image/svg+xml`):
`index.html`, `styles.css`, `favicon.svg`, `icons.svg`, `js/**/*.js` (`text/javascript`).

## Layout

| File | Purpose |
|---|---|
| `index.html` | shell: nav, `<main>`, unsaved-changes bar, toast region, `<script type=module>` |
| `styles.css` | one stylesheet; theme = custom properties on `:root`, dark/light via `prefers-color-scheme` |
| `icons.svg` | icon sprite, used as `<use href="/icons.svg#i-NAME">` |
| `js/app.js` | hash router, session bootstrap, nav, unsaved-changes bar (check / apply / discard) |
| `js/api.js` | fetch wrapper: JSON, `X-CSRF-Token` on mutations, 401 -> login, `ApiError`, path normalisation |
| `js/state.js` | store: session, board, config draft + dirty flag, `apply()` |
| `js/ui.js` | `h()`/`svg()`, bound form controls + validation rules, toast, `<dialog>` confirm, `poll()`, tables, formatters, signal bars |
| `js/data.js` | IANA zone subset, regulatory countries |
| `js/pages/*.js` | one module per page; `export default async function (root, signal)` |

## Pages (hash routes)

| Route | Module | Notes |
|---|---|---|
| `#/setup` | `setup.js` | first boot (when `needs_setup`): admin + strength meter, country, SSID/passphrase (WPA2/3 mixed pre-selected), WAN type |
| `#/login` | `login.js` | |
| `#/` | `dashboard.js` | front-panel SVG from `GET /board` + `/network/status`, tiles, radios, log tail; 5 s poll with backoff, paused when hidden |
| `#/network` | `network.js` | LAN, WAN (dhcp/static/pppoe, MAC clone, MTU), port roles (exactly one WAN), VLANs |
| `#/wireless` | `wireless.js` | radio cards (channels/width limited by board), APs, live clients |
| `#/firewall` | `firewall.js` | WAN policy, port forwards, rules, hardware offload, ruleset preview |
| `#/dhcp` | `dhcp.js` | leases (+ "make static"), static leases, upstream DNS, local domain, rebind protection |
| `#/system` | `system.js` | settings, users, my password, services, backup/restore, reboot, firmware info |
| `#/logs` | `logs.js` | live tail, level + source filters, pause, copy |
| `#/about` | `about.js` | hardware sheet rendered from board JSON |

## How editing works

`GET /config` is deep-copied into `state.draft`. Forms bind to the draft by dotted path
(`field(state.draft, 'network.lan.ipv4', {...})`), validate client-side on input/blur and on
Apply, and flag the dirty state through a document-level `owr:edit` event. The persistent bar
offers **Discard**, **Check** (`POST /config/validate`) and **Apply** (confirm, `PUT /config`, then
reload `/config`, show the apply result, re-render). Secrets are `"***"` in the redacted config and
are sent back unchanged. A 422 maps `details[].path` (`a.b[0].c`, `a/b/0/c` and `a.b.0.c` are all
accepted) onto inputs through their `data-path` attribute; unmatched details go to a toast and the
bar's problem list. Users, my password, services, backup/restore and reboot call their own
endpoints immediately (their containers are marked `data-local` so the global Apply ignores them).

## API assumptions beyond the contract

- `PUT /config` result may contain `{applied:[...], warnings:[...]}`; both optional (shown if present).
- `PUT /config` accepts a *full* document; `GET /config` is usable right after `POST /auth/login`
  during setup (the wizard does `POST /setup`, `POST /auth/login`, then `PUT /config`).
- Enums follow `crates/owr-config/src/model.rs` (constants at the top of the page modules): firewall
  `proto` (`tcp|udp|tcp_udp` for forwards, `any|tcp|udp|icmp` for rules), rule `direction`
  (`wan_in` = from the internet, `lan_out` = LAN to internet), `action` (`accept|drop|reject`),
  log level (`error|warn|info|debug`), user roles (`admin|viewer`), WAN proto and AP security
  are tagged objects (`{type:"dhcp"|"static"|"pppoe"}`, `{type:"open"|"wpa2_psk"|"wpa3_sae"|"wpa2_wpa3_mixed", passphrase}`),
  radio `channel` is `"auto"` or an integer and `width_mhz` is mandatory. Unknown values coming
  from the server are still displayed.
- `GET /board` has the shape of `boards/<id>.toml` (`board`, `soc`, `memory`, `storage`,
  `ethernet.ports[]`, `wifi.radios[]`, `leds`, `buttons`, `usb`). Login/session responses are
  `{user:{name,role,enabled}, role, csrf}`.
- Applying: a failing `PUT /config` keeps the draft and shows the error; once it succeeded the dirty
  flag is cleared, and if the follow-up reload fails the UI says so (with the new LAN address when it
  changed) instead of reporting an error.
- `wan_port` is a number for a single port, a string such as `"8000-8100"` for a range.
- `network.wan.proto.ipv4` (static) and `vlans[].ipv4` are CIDR like `network.lan.ipv4`;
  DHCP `start` is a host offset; `lease` is a string like `12h` (a numeric lease is also handled).
- `GET /logs?since=N` returns entries with `seq > N`; `/system/status` may carry
  `tls_fingerprint` (or `tls.fingerprint`) which the system page shows.
- Network interfaces are matched to board ports by `name` or the board's `netdev`.

## Self-checks

No browser is needed for the basics:

    for f in js/*.js js/pages/*.js; do node --check "$f"; done
    grep -rnE 'onclick=|style="|innerHTML|eval\(' . ; grep -rn '<script' --include=*.html .

(only `index.html` may contain a `<script>`, and it must have `src`).
