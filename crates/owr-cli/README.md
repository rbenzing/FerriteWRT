# owr-cli

`owr`: the FerriteWRT command-line tool. Pure commands work on any OS; `status` needs the router.

## Global options

| option | meaning |
|---|---|
| `--board <path>` | board descriptor (default `/etc/ferritewrt/board.toml`); give it before the subcommand (`owr release manifest` has its own `--board <id>`) |
| `--board-id <id>` | use a descriptor compiled into the binary (`owr board list`); excludes `--board` |
| `--config <path>` | config file (default `/etc/ferritewrt/config.toml`) |

## Commands

| command | does |
|---|---|
| `board show \| validate <file> \| list` | inspect board descriptors |
| `config validate [--file f]` | print every issue as `path: message`; exit 1 if any |
| `config defaults` | default config for the board as TOML (no board option: Flint 2) |
| `config show [--json]` | the config with secrets replaced by `***` |
| `config init` | write the default config if missing; prints `created` or `exists` |
| `config set-password <user>` | read one line from stdin, store an argon2id hash; creates the user as admin |
| `render <net\|fw\|wifi\|dnsmasq\|netd\|sysctl> [--json] [--reveal-secrets]` | what `owr-apply` would apply |
| `check` | validate config against the board, build all plans, print a summary; exit 1 on failure |
| `status [--json]` | service table from init over `/run/ferritewrt/init.sock` |
| `upgrade <dir> [--downgrade] [--wipe-settings]` | hand a release bundle (sysupgrade image, `SHA256SUMS`, `SHA256SUMS.sig`) to init, which verifies it, writes it and reboots; settings are kept unless `--wipe-settings` |
| `upgrade --check <dir> [--pubkey f]` | the same verification (signature, hash, board, version) anywhere; changes nothing |
| `release keygen | sums | manifest | sign | verify | show` | build, sign and verify release artifacts (see "Release signing") |

`render`: `fw` and `dnsmasq` print text; `net`, `netd` and `sysctl` print JSON; `wifi` prints one
`# --- <phy> ---` hostapd.conf per radio (`--json`: the radio plans). Wi-Fi passphrases are
printed as `***` unless `--reveal-secrets`. Without a config file `render` uses the board defaults.

Exit codes: 0 ok, 1 issues found or error, 2 `status` or `upgrade` (without `--check`) on a non-router host.

## Offline bootstrap

```sh
owr config defaults > config.toml          # first config from the builtin Flint 2 descriptor
$EDITOR config.toml
owr --board-id glinet_gl-mt6000 config validate --file config.toml   # e.g. "network.wan.port: unknown port ..."
owr --board-id glinet_gl-mt6000 --config config.toml check          # also builds the fw/net/wifi plans
owr --board-id glinet_gl-mt6000 --config config.toml render fw      # inspect the nft script
owr --board-id glinet_gl-mt6000 --config config.toml config set-password admin < pw.txt
```

On a router whose UI is unreachable, `owr config set-password admin` resets
the admin password (12..=256 characters, like the API); the config is saved atomically, mode 0600.
Avoid putting the password on a command line (shell history, process list): pipe it from a
restricted file or `read -rs`.

## Release signing

`owr release ...` produces and checks the files that make a release trustworthy. The formats
below are a contract: other tools rely on the exact bytes. The parser and verifier live in `crates/owr-upgrade` (`release`), shared with the router's upgrade path.

| file | content |
|---|---|
| `SHA256SUMS` | `sha256sum` output: one `<64 lowercase hex>␣␣<filename>\n` line per file, filenames without directories, sorted bytewise by filename, LF line endings. Covers every regular file in the directory except `SHA256SUMS` and `SHA256SUMS.sig` (so it covers `manifest.json`). |
| `SHA256SUMS.sig` | exactly three LF-terminated lines: `ferritewrt-sig/1`, `key: <64 hex = ed25519 public key>`, `sig: <base64 (standard alphabet, with padding) of the 64-byte ed25519 signature over the exact bytes of SHA256SUMS>` |
| `keys/release.pub` | one line: the 64-hex-char public key and LF |
| private key | never a file in the repository: the 32-byte seed as 64 hex characters in the environment variable `OWR_RELEASE_KEY` (CI secret), or a mode-0600 file given with `--key-file` for local use |
| `manifest.json` | see below |

`manifest.json`:

```json
{"schema":1,"project":"ferritewrt","version":"0.1.0","board":"glinet_gl-mt6000",
 "git":{"ferritewrt":"<sha>","openwrt":"<sha>"},"kernel":"6.18.x or unknown","built_utc":"<RFC 3339>",
 "artifacts":[{"name":"...","kind":"factory|sysupgrade|initramfs|binaries|other","size":123,"sha256":"<hex>"}]}
```

(`owr` writes it pretty-printed.) `artifacts` is sorted by name and lists every file in the
directory except `manifest.json`, `SHA256SUMS` and `SHA256SUMS.sig`. `kind` comes from the file
name: `-factory.bin`, `-sysupgrade.bin`, `-initramfs-kernel.bin` (or any `initramfs` name),
`.tar.gz`/`.tar.zst` (`binaries`), else `other`.

Order of operations: `manifest`, then `sums`, then `sign`.

```
owr release keygen > keys/release.pub      # stdout: public key; stderr: OWR_RELEASE_KEY=<seed> (CI secret)
owr release keygen --out ./keys-private    # alternatively release.pub + release.key (0600); loud warning
owr release manifest dir --version 0.1.0 --board glinet_gl-mt6000 \
    [--openwrt-rev S] [--ferritewrt-rev S] [--kernel 6.18.3] [--built-utc 2026-01-02T03:04:05Z]
owr release sums dir                       # writes dir/SHA256SUMS, prints it
OWR_RELEASE_KEY=<seed> owr release sign dir [--key-file f] [--force]
owr release verify dir-or-files... --pubkey keys/release.pub [--allow-missing]
owr release show dir
```

* `sums` streams every file through SHA-256 (1 MiB buffer); names with control characters,
  `/` or `\` are rejected.
* `sign` refuses to overwrite `SHA256SUMS.sig` without `--force`, checks that `SHA256SUMS` is
  well formed, never echoes the key, and zeroizes the seed. A `--key-file` that is
  group/world accessible is refused on Unix. `keygen --out` never overwrites existing files.
* `verify` takes a directory (all listed files) or individual files (only those). `--pubkey` is
  64 hex characters or a `release.pub` file; the key named in `SHA256SUMS.sig` is compared to it
  in constant time and the signature is checked with strict ed25519 verification. Only after
  that are files hashed. Output is one line per file: `ok  <name>`, `FAIL <name>`,
  `missing <name>` (a listed file that is absent: exit 1 unless `--allow-missing`) and
  `extra <name>` (present but not listed: ignored). If `manifest.json` is listed and its hash
  matched, its artifacts are cross-checked against `SHA256SUMS` (hash) and the files (size).
  Exit 0 only when the signature and every checked hash match.
