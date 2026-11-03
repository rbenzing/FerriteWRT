/* pages/setup.js - #/setup: first-boot wizard (shown while GET /setup/status says needs_setup).
 *
 * One page, three numbered sections: administrator, Wi-Fi, internet. "Finish" runs
 *   POST /setup (create admin) -> POST /auth/login -> PUT /config (country, Wi-Fi, WAN)
 * Retrying after a failure skips the steps that already succeeded (created / signed in are
 * tracked separately, and the sign-in retries with the credentials the admin was created with).
 * Wizard fields use the real config paths as error paths so 422 details land next to them.
 */
import { api } from '../api.js';
import { state, startSession, loadConfig, apply } from '../state.js';
import { h, field, card, pageHeader, btn, toast, withBusy, rules, strengthMeter, validateScope, showFieldErrors } from '../ui.js';
import { COUNTRIES } from '../data.js';
import { wanProto } from './network.js';

const SECURITY = [
  { value: 'wpa2_wpa3_mixed', label: 'WPA2 + WPA3 (recommended, works with older devices)' },
  { value: 'wpa3_sae', label: 'WPA3 only (newest devices)' },
  { value: 'wpa2_psk', label: 'WPA2 only (oldest devices)' },
];

/** 16 unambiguous characters in groups of four, from the browser CSPRNG. */
function randomPassphrase() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const chars = Array.from(bytes, (b) => alphabet[b % alphabet.length]);
  return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join('')).join('-');
}

export default async function setup(root) {
  const region = (navigator.language ?? '').split('-')[1]?.toUpperCase();
  const wiz = {
    username: 'admin', password: '', confirm: '',
    country: region in COUNTRIES ? region : 'US',
    ssid: '', passphrase: '', security: 'wpa2_wpa3_mixed',
    wan: { proto: { type: 'dhcp' } },
  };
  let created = null; // credentials POST /setup succeeded with
  let signedIn = false;

  const meter = strengthMeter();
  const pass = field(wiz, 'password', {
    label: 'Password', type: 'password', required: true, autocomplete: 'new-password',
    hint: 'At least 12 characters. A few random words or a password manager entry works well.',
    validate: rules.minLen(12), onChange: (v) => meter.update(v),
  });
  const wifiPass = field(wiz, 'passphrase', {
    label: 'Wi-Fi password', type: 'password', required: true, errPath: 'wireless.aps.0.security.passphrase',
    validate: rules.wpaPassphrase, hint: '8 to 63 printable ASCII characters (letters, digits, symbols; no accents). The character | is not allowed.',
  });
  const gen = btn('Suggest a strong password', () => {
    wiz.passphrase = randomPassphrase();
    const input = wifiPass.ctl.input;
    input.value = wiz.passphrase;
    wifiPass.ctl.reveal(true); // show it so it can be written down; keeps the eye toggle in sync
    input.dispatchEvent(new Event('input'));
  }, { variant: 'ghost small' });

  async function finish(button) {
    if (!validateScope(root)) return toast('Please fix the highlighted fields.', 'error');
    await withBusy(button, async () => {
      try {
        if (!created) {
          const creds = { username: wiz.username, password: wiz.password };
          await api.post('/setup', creds);
          created = creds;
        }
        if (!signedIn) {
          await startSession(await api.post('/auth/login', created, { quiet401: true }));
          signedIn = true;
        }
        const cfg = state.draft ?? (await loadConfig());
        const sec = { type: wiz.security, passphrase: wiz.passphrase };
        for (const r of cfg.wireless.radios) { r.country = wiz.country; r.enabled = true; r.width_mhz ??= 20; }
        if (cfg.wireless.aps.length) {
          for (const ap of cfg.wireless.aps) Object.assign(ap, { ssid: wiz.ssid, security: { ...sec } });
        } else {
          cfg.wireless.aps = cfg.wireless.radios.map((r) => ({ radio: r.id, ssid: wiz.ssid, hidden: false, security: { ...sec }, network: 'lan', isolate_clients: false }));
        }
        cfg.network.wan.proto = wiz.wan.proto;
        await apply();
        toast('Setup complete. Welcome!', 'success');
        location.hash = '#/';
        location.reload(); // re-run bootstrap: setup is over, session is live
      } catch (e) {
        if (e.status === 422) {
          const rest = showFieldErrors(root, e.details);
          toast(rest.length ? rest.map((d) => `${d.path}: ${d.message}`).join('; ') : 'Please fix the highlighted fields.', 'error');
        } else {
          toast(e.message, 'error');
        }
      }
    });
  }

  const submit = btn('Finish setup', null, { variant: 'primary', type: 'submit' });
  root.append(
    pageHeader('Welcome - let us set up your router', 'Three quick steps. You can change everything later.'),
    h('form', { novalidate: true, onsubmit: (e) => { e.preventDefault(); finish(submit); } }, [
      card('1. Administrator', [
        field(wiz, 'username', { label: 'Username', required: true, autocomplete: 'username', validate: rules.len(1, 32) }),
        pass,
        meter.el,
        field(wiz, 'confirm', { label: 'Repeat password', type: 'password', required: true, autocomplete: 'new-password', validate: rules.same(() => wiz.password, 'Passwords do not match.') }),
      ]),
      card('2. Wi-Fi', [
        field(wiz, 'country', { label: 'Country', type: 'select', errPath: 'wireless.radios.0.country', hint: 'Sets the legal channels and power for Wi-Fi.', options: Object.entries(COUNTRIES).map(([value, label]) => ({ value, label })) }),
        field(wiz, 'ssid', { label: 'Wi-Fi name', required: true, errPath: 'wireless.aps.0.ssid', validate: rules.ssid, hint: 'SSID, up to 32 bytes. Both bands share this name.' }),
        wifiPass,
        h('div', { class: 'row' }, [h('span'), gen]),
        field(wiz, 'security', { label: 'Security', type: 'select', errPath: 'wireless.aps.0.security.type', options: SECURITY }),
      ]),
      card('3. Internet connection', wanProto(wiz.wan), { sub: 'Most people can keep "Automatic". You can change this later.' }),
      h('div', { class: 'actions' }, submit),
    ]),
  );
  root.querySelector('input').focus();
}
