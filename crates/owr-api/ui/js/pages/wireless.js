/* pages/wireless.js - #/wireless: radios, Wi-Fi networks (APs) and live client tables.
 *
 * Radio limits (bands, max width, standards) come from GET /board (wifi.radios), channel lists
 * from the band. Radios/APs edit the config draft; the clients table polls /wireless/status
 * every 5 s and resolves names through /dhcp/leases.
 */
import { api } from '../api.js';
import { state, loadBoard, ensureConfig } from '../state.js';
import {
  h, field, card, pageHeader, table, badge, btn, dynamic, banner, confirmDialog, edited, poll, rules, strengthMeter,
  signalBars, fmtBand, fmtRate, fmtDuration,
} from '../ui.js';
import { COUNTRIES } from '../data.js';

const range = (a, b, s = 1) => Array.from({ length: Math.floor((b - a) / s) + 1 }, (_, i) => a + i * s);
const CHANNELS = { '2g': range(1, 13), '5g': [...range(36, 64, 4), ...range(100, 144, 4), ...range(149, 177, 4)] };
const WIDTHS = [20, 40, 80, 160];
const GEN = { n: 'Wi-Fi 4 (n)', ac: 'Wi-Fi 5 (ac)', ax: 'Wi-Fi 6 (ax)' };
const SECURITY = [
  { value: 'wpa2_wpa3_mixed', label: 'WPA2 + WPA3 (recommended)' },
  { value: 'wpa3_sae', label: 'WPA3 only' },
  { value: 'wpa2_psk', label: 'WPA2 only (older devices)' },
  { value: 'open', label: 'Open (no password)' },
];
// '***' is the redacted stored passphrase: sent back unchanged, the server keeps the real one.
const passphraseRule = (v) => (v === '***' ? null : rules.wpaPassphrase(v));

export default async function wireless(root, signal) {
  const [board] = await Promise.all([loadBoard(), ensureConfig()]);
  const cfg = state.draft;
  const wl = cfg.wireless;
  const boardRadio = (id) => board.wifi?.radios?.find((r) => r.id === id);
  const bandOf = (r) => boardRadio(r.id)?.band ?? (typeof r.channel === 'number' && r.channel <= 14 ? '2g' : '5g');
  const radioLabel = (r) => `${fmtBand(bandOf(r))} (${r.id})`;
  const leases = await api.get('/dhcp/leases').catch(() => []);
  const hostByMac = Object.fromEntries(leases.map((l) => [l.mac.toLowerCase(), l.hostname]));
  const liveLines = {};

  /* radios */
  function radioCard(r, i) {
    const br = boardRadio(r.id);
    const band = bandOf(r);
    const P = `wireless.radios.${i}`;
    const F = (k, o) => field(cfg, `${P}.${k}`, o);
    const maxW = br?.max_width_mhz ?? 80;
    const widths = WIDTHS.filter((w) => w <= maxW); // width_mhz is mandatory: the radio must have one of these
    liveLines[r.id] = h('p', { class: 'muted' }, 'Current state: loading...');
    return card(radioLabel(r), [
      h('p', (br?.standards ?? []).map((s) => [badge(GEN[s] ?? s), ' '])),
      liveLines[r.id],
      F('enabled', { label: 'Turn on', type: 'toggle' }),
      F('channel', {
        label: 'Channel', type: 'select', cast: (v) => (v === 'auto' ? v : Number(v)),
        options: [{ value: 'auto', label: 'Automatic (recommended)' }, ...(CHANNELS[band] ?? []).map((c) => ({ value: c, label: String(c) }))],
        hint: band === '2g' ? '2.4 GHz channels 1 to 13. 1, 6 and 11 overlap least.' : '5 GHz channels (UNII bands). DFS channels 52 to 144 may pause briefly for radar checks.',
      }),
      F('width_mhz', {
        label: 'Channel width', type: 'select', cast: Number, required: true, validate: (w) => (widths.includes(w) ? null : `Choose a width up to ${maxW} MHz.`), hint: `Wider is faster but more prone to interference. This radio supports up to ${maxW} MHz.`,
        options: widths.map((w) => ({ value: w, label: `${w} MHz` })),
      }),
      F('country', {
        label: 'Country', type: 'select', hint: 'Regulatory domain: sets allowed channels and power.',
        options: Object.entries(COUNTRIES).map(([value, label]) => ({ value, label: `${label} (${value})` })),
      }),
      F('txpower_dbm', { label: 'Transmit power (dBm)', type: 'number', optional: true, min: 1, max: 30, validate: rules.int(1, 30), hint: 'Optional. Empty = maximum allowed for the country.' }),
    ]);
  }

  /* networks */
  const netOptions = () => [{ value: 'lan', label: 'Home network (LAN)' }, ...cfg.network.vlans.map((v) => ({ value: v.name, label: `VLAN ${v.name}` }))];

  function addAp() {
    wl.aps.push({
      radio: wl.radios[0]?.id, ssid: 'New network', hidden: false, security: { type: 'wpa2_wpa3_mixed', passphrase: '' },
      network: 'lan', isolate_clients: false,
    });
    edited();
    apBox.refresh();
  }

  async function removeAp(i) {
    const ok = await confirmDialog({
      title: `Remove "${wl.aps[i].ssid}"?`, danger: true, confirmText: 'Remove',
      message: 'Devices using this Wi-Fi network will be disconnected once you apply.',
    });
    if (!ok) return;
    wl.aps.splice(i, 1);
    edited();
    apBox.refresh();
  }

  function apCard(ap, i) {
    const P = `wireless.aps.${i}`;
    const F = (k, o) => field(cfg, `${P}.${k}`, o);
    const secBox = dynamic(() => {
      if (ap.security.type === 'open') return h('p', { class: 'muted' }, 'Anyone in range can join and see unencrypted traffic.');
      const meter = strengthMeter();
      const pw = ap.security.passphrase ?? '';
      meter.update(pw === '***' ? '' : pw);
      return h('div', [
        F('security.passphrase', {
          label: 'Wi-Fi password', type: 'password', required: true, validate: passphraseRule,
          hint: 'Shown as *** once saved; leave it to keep the current password. 8 to 63 printable ASCII characters, no |.', onChange: (v) => meter.update(v === '***' ? '' : v),
        }),
        meter.el,
      ]);
    });
    return h('div', { class: 'subcard' }, [
      h('header', { class: 'card-head' }, [h('h3', ap.ssid || 'Wi-Fi network'), btn('Remove', () => removeAp(i), { variant: 'danger small', icon: 'trash' })]),
      F('ssid', { label: 'Network name', required: true, validate: rules.ssid, hint: 'SSID, up to 32 bytes (non-ASCII characters use 2 to 4 bytes each).' }),
      F('radio', { label: 'Band', type: 'select', options: wl.radios.map((r) => ({ value: r.id, label: radioLabel(r) })) }),
      F('security.type', {
        label: 'Security', type: 'select', options: SECURITY,
        onChange(type) {
          ap.security = type === 'open' ? { type } : { type, passphrase: ap.security.passphrase ?? '' };
          secBox.refresh();
        },
      }),
      secBox,
      F('network', { label: 'Connects to', type: 'select', options: netOptions(), hint: 'Which network these devices join. Use a VLAN for guests.' }),
      F('hidden', { label: 'Hide network name', type: 'toggle', hint: 'Not broadcast; devices must type the name. Does not add real security.' }),
      F('isolate_clients', { label: 'Keep devices apart', type: 'toggle', hint: 'Client isolation: devices on this Wi-Fi cannot talk to each other.' }),
      F('max_clients', { label: 'Device limit', type: 'number', optional: true, min: 1, max: 512, validate: rules.int(1, 512), hint: 'Optional. Empty = no limit.' }),
    ]);
  }

  const apBox = dynamic(() => h('div', [
    wl.aps.length === 0 && banner('warn', 'No Wi-Fi networks are configured: Wi-Fi is effectively off.'),
    wl.aps.map(apCard),
    btn('Add Wi-Fi network', addAp, { icon: 'plus' }),
  ]));

  /* live clients */
  const clientsBox = h('div', { class: 'dyn' }, h('div', { class: 'skeleton block' }));
  function showStatus(st) {
    for (const r of st.radios) {
      if (liveLines[r.id]) liveLines[r.id].textContent = r.enabled ? `Running on channel ${r.channel}, ${r.width_mhz} MHz, ${r.txpower_dbm} dBm.` : 'Currently off.';
    }
    clientsBox.replaceChildren(...(st.aps.length === 0 ? [h('p', { class: 'muted' }, 'No Wi-Fi networks are running.')] : st.aps.map((ap) => h('div', [
      h('h3', [ap.ssid, ' ', h('small', { class: 'muted' }, `${ap.ifname}, ${ap.radio}, ${ap.clients.length} connected`)]),
      table(['Device', 'MAC address', 'Signal', 'Speed (rx / tx)', 'Connected for'], ap.clients.map((c) => [
        c.hostname || hostByMac[c.mac.toLowerCase()] || 'Unknown device', c.mac,
        [signalBars(c.signal_dbm), ` ${c.signal_dbm} dBm`], `${fmtRate(c.rx_rate_kbps)} / ${fmtRate(c.tx_rate_kbps)}`, fmtDuration(c.connected_secs),
      ]), { empty: 'No devices connected.' }),
    ]))));
  }

  root.append(
    pageHeader('Wi-Fi', 'Radios, Wi-Fi networks and connected devices. Changes apply with the bar at the bottom.'),
    h('div', { class: 'grid' }, wl.radios.map(radioCard)),
    card('Wi-Fi networks', apBox, { sub: 'Each network (SSID) runs on one radio. Create one per band, or add a guest network on a VLAN.' }),
    card('Connected devices', clientsBox, { sub: 'Live, refreshes every 5 seconds.' }),
  );
  poll(async () => { const st = await api.get('/wireless/status'); if (!signal.aborted) showStatus(st); }, { signal });
}
