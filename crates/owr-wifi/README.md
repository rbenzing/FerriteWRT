# owr-wifi

Wi-Fi domain model -> `hostapd.conf`, hostapd control client, sysfs phy discovery.
Replaces OpenWrt's `wifi-scripts`. Does not depend on `owr-config`; `owr-apply` maps
config into `RadioPlan`s.

## Model

`RadioPlan` (one per phy: band, channel, width, country, standards, quirks) owns 1..=8
`ApPlan`s (ifname, ssid, hidden, `Security`, bridge, isolation, max clients, bssid).
Passphrases are `Zeroizing<String>`; `Debug` prints `<redacted>`.
`RadioPlan::validate()` returns every `Issue`; `render_hostapd()` validates first and
never emits output for an invalid plan. Output is deterministic (insta snapshots).

## Mapping (model -> hostapd.conf)

| Model | Keys |
|---|---|
| band | `hw_mode=g/a`, `ieee80211h=1` (5g), `op_class` (6g) |
| channel Auto / Fixed(n) | `channel=0` (+`acs_exclude_dfs=1` on 5g) / `channel=n` |
| width, N | `ht_capab` (`[HT40+/-]`, GI, STBC, LDPC, AMSDU) |
| width, Ac (5g) | `vht_oper_chwidth` 0/1/2, `vht_oper_centr_freq_seg0_idx` (Fixed only), `vht_capab` |
| Ax | `he_oper_chwidth`, `he_oper_centr_freq_seg0_idx`, beamforming, `he_bss_color` (FNV-1a of first SSID) |
| Be | `ieee80211be=1` only |
| quirks.mt76 | full VHT beamforming caps + `he_mu_beamformer=1`; else conservative set |
| first AP / others | `interface=` / `bss=` |
| ssid, hidden, bridge, isolate, max_clients, mac | `ssid`, `ignore_broadcast_ssid=1`, `bridge`, `ap_isolate=1`, `max_num_sta`, `bssid` |
| Open | `wpa=0 ieee80211w=0` |
| Wpa2Psk | `WPA-PSK`, `ieee80211w=1`, `wpa_passphrase`, `wpa_disable_eapol_key_retries=1` |
| Wpa3Sae | `SAE`, `ieee80211w=2`, `sae_password`, `sae_require_mfp=1`, `sae_pwe=2` |
| Wpa2Wpa3Mixed | `WPA-PSK SAE`, `ieee80211w=1`, `sae_require_mfp=1`, both passphrase keys, `sae_pwe=2`, `wpa_disable_eapol_key_retries=1` |

`ctrl_interface=<RUN_DIR>/hostapd` (`ctrl_dir()`) is emitted in every BSS block (one socket per ifname).

## Linux-only (`sys`)

- `discover_phys()` / `phy_for_index(idx)`: `/sys/class/ieee80211/*` (`index`, `device/driver`, `macaddress`).
- `sys::ctrl::HostapdCtl`: `ping`, `status`, `stations` over `UnixDatagram`; 2 s timeout, 64 KiB reply cap,
  512 stations max (truncated with a warning), 10 s overall budget for the station walk.
  Client sockets are bound in `<run_dir>/hostapd-cli/` (0700; stale `cli-*` swept on connect). A timeout
  poisons the client (`ReplyError::Desynced`) until reconnect; queued datagrams are drained before each
  request. Parsers live in portable `reply` and are host-tested.
- `write_config(plan, run_dir)`: atomic 0600 write of `hostapd-<phy>.conf`; `Outcome::Written` means restart hostapd.

## Limits

- Max 8 BSS per radio (mt7915 hardware allows 16). 2g width <= 40; 160 needs Ac/Ax.
- `txpower_dbm` has no hostapd key; the applier must set it via nl80211.
- 160 MHz only on 5g blocks 36-64 and 100-128; 80 MHz not on channels 165+.
- 6g: minimal (op_class, HE); no PSC/SAE-only enforcement. Be: flag only.
- No 802.1X/enterprise, WPS, 802.11r/k/v, or MAC filtering.
- `sys` tests need Linux; on other hosts they are only type-checked via the musl target.
