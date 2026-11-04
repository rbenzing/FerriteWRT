/* pages/system.js - #/system: settings (config draft), users, my password, services, backup/restore, firmware upgrade, reboot, firmware info.
 *
 * Only the first card edits the config draft (applied with the global bar). Everything else
 * calls its own endpoint immediately, after a confirmation where it is destructive.
 */
import { api } from '../api.js';
import { state, ensureConfig, loadConfig, rerender } from '../state.js';
import {
  h, field, control, card, pageHeader, table, badge, kv, btn, dynamic, banner, modal, confirmDialog, toast, handleError, withBusy,
  validateScope, strengthMeter, rules, fmtDuration, fmtTime,
} from '../ui.js';
import { ZONES } from '../data.js';

const ROLES = ['admin', 'viewer'];
const LOG_LEVELS = ['error', 'warn', 'info', 'debug'];
const userName = /^[a-z][a-z0-9_-]{0,31}$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default async function system(root, signal) {
  const cfg = await ensureConfig();
  const me = state.session?.name;

  /* ----- settings (draft) ----- */
  const settings = card('Settings', [
    h('datalist', { id: 'zones' }, ZONES.map((z) => h('option', { value: z }))),
    field(cfg, 'system.hostname', { label: 'Router name', required: true, validate: rules.hostname, hint: 'Hostname, how the router appears on the network.' }),
    field(cfg, 'system.timezone', { label: 'Time zone', required: true, list: 'zones', hint: 'Start typing a city, e.g. Europe/Berlin. IANA name.' }),
    field(cfg, 'system.ntp_servers', { label: 'Time servers', type: 'lines', hint: 'NTP servers, one per line.', validate: rules.each(rules.len(1, 253)) }),
    field(cfg, 'system.log_level', { label: 'Log detail', type: 'select', options: LOG_LEVELS, hint: '"debug" is very chatty; use it only while troubleshooting.' }),
  ], { sub: 'Applied with the bar at the bottom.' });

  /* ----- users (immediate) ----- */
  const usersBox = dynamic(() => h('p', { class: 'muted' }, 'Loading...'));
  let users = null; // last loaded list; null until the first load succeeds
  async function loadUsers() {
    try {
      users = await api.get('/users');
      usersBox.replaceChildren(table(['User', 'Role', 'Enabled', ''], users.map(userRow), { caption: 'Users' }));
    } catch (e) { usersBox.replaceChildren(banner('error', e.message)); }
  }

  function userRow(u) {
    const row = { role: u.role, enabled: u.enabled };
    const cells = h('div', { class: 'row-actions' });
    const save = btn('Save', (e) => withBusy(e.currentTarget, async () => {
      try { await api.put(`/users/${encodeURIComponent(u.name)}`, row); toast(`Saved ${u.name}.`, 'success'); } catch (err) { handleError(err, cells); }
    }), { variant: 'small' });
    const reset = btn('Reset password', () => resetPassword(u), { variant: 'small' });
    const remove = btn('Delete', async () => {
      const ok = await confirmDialog({ title: `Delete ${u.name}?`, message: 'This user will no longer be able to sign in.', confirmText: 'Delete', danger: true });
      if (!ok) return;
      try { await api.del(`/users/${encodeURIComponent(u.name)}`); toast(`Deleted ${u.name}.`, 'success'); loadUsers(); } catch (err) { handleError(err); }
    }, { variant: 'danger small', icon: 'trash', disabled: u.name === me, title: u.name === me ? 'You cannot delete your own account' : undefined });
    cells.append(save, reset, remove);
    return [
      h('strong', u.name),
      control(row, 'role', { aria: `Role of ${u.name}`, type: 'select', options: ROLES }),
      control(row, 'enabled', { aria: `${u.name} enabled`, type: 'toggle', disabled: u.name === me }),
      cells,
    ];
  }

  async function resetPassword(u) {
    const f = { password: '' };
    const meter = strengthMeter();
    const body = h('div', [
      h('p', `Choose a new password for ${u.name}.`),
      field(f, 'password', { label: 'New password', type: 'password', required: true, autocomplete: 'new-password', validate: rules.minLen(12), hint: 'At least 12 characters.', onChange: (v) => meter.update(v) }),
      meter.el,
    ]);
    const v = await modal({
      title: 'Reset password', body, check: () => validateScope(body),
      actions: [{ label: 'Cancel', value: 'no', variant: 'ghost' }, { label: 'Set password', value: 'ok', variant: 'primary' }],
    });
    if (v !== 'ok') return;
    try {
      await api.put(`/users/${encodeURIComponent(u.name)}`, { role: u.role, enabled: u.enabled, password: f.password });
      toast(`Password for ${u.name} changed.`, 'success');
    } catch (e) { handleError(e); }
  }

  // The add-user form is rebuilt from `nu` (not form.reset()), so every control, including the
  // role select, shows the model's defaults again after a successful add.
  const nu = { name: '', password: '', role: 'viewer' };
  const buildAddUser = () => {
    const meter = strengthMeter();
    meter.update(nu.password);
    const addBtn = btn('Add user', null, { type: 'submit', variant: 'primary', icon: 'plus' });
    const form = h('form', {
      class: 'subcard', novalidate: true, 'data-local': true,
      async onsubmit(e) {
        e.preventDefault();
        if (!validateScope(form)) return;
        await withBusy(addBtn, async () => {
          try {
            await api.put(`/users/${encodeURIComponent(nu.name)}`, { role: nu.role, enabled: true, password: nu.password });
            toast(`Added ${nu.name}.`, 'success');
            Object.assign(nu, { name: '', password: '', role: 'viewer' });
            loadUsers();
            addUser.refresh();
            addUser.querySelector('input')?.focus();
          } catch (err) { handleError(err, form); }
        });
      },
    }, [
      h('h3', 'Add a user'),
      field(nu, 'name', { label: 'Username', required: true, autocomplete: 'off', validate: [(v) => (userName.test(v) ? null : 'Lowercase letters, digits, - and _; start with a letter.'), nameFree] }),
      field(nu, 'password', { label: 'Password', type: 'password', required: true, validate: rules.minLen(12), hint: 'At least 12 characters.', onChange: (v) => meter.update(v) }),
      meter.el,
      field(nu, 'role', { label: 'Role', type: 'select', options: ROLES, hint: 'Admins can change settings; viewers can only look.' }),
      h('div', { class: 'actions' }, addBtn),
    ]);
    return form;
  };
  // PUT /users/:name is an upsert, so an existing name would silently overwrite that account.
  const nameFree = (v) => {
    if (!users) return 'The user list has not loaded yet; try again in a moment.';
    return users.some((u) => u.name === v) ? `A user named "${v}" already exists. Pick another name.` : null;
  };
  const addUser = dynamic(buildAddUser);

  /* ----- my password ----- */
  const pw = { current: '', new: '', confirm: '' };
  const pwMeter = strengthMeter();
  const pwBtn = btn('Change password', null, { type: 'submit', variant: 'primary' });
  const pwForm = h('form', {
    novalidate: true, 'data-local': true,
    async onsubmit(e) {
      e.preventDefault();
      if (!validateScope(pwForm)) return;
      await withBusy(pwBtn, async () => {
        try {
          await api.post('/auth/password', { current: pw.current, new: pw.new });
          toast('Your password was changed.', 'success');
          pwForm.reset();
          Object.assign(pw, { current: '', new: '', confirm: '' });
          pwMeter.update('');
        } catch (err) { handleError(err, pwForm); }
      });
    },
  }, [
    field(pw, 'current', { label: 'Current password', type: 'password', required: true, autocomplete: 'current-password' }),
    field(pw, 'new', { label: 'New password', type: 'password', required: true, autocomplete: 'new-password', validate: rules.minLen(12), hint: 'At least 12 characters.', onChange: (v) => pwMeter.update(v) }),
    pwMeter.el,
    field(pw, 'confirm', { label: 'Repeat new password', type: 'password', required: true, autocomplete: 'new-password', validate: rules.same(() => pw.new, 'Passwords do not match.') }),
    h('div', { class: 'actions' }, pwBtn),
  ]);

  /* ----- services ----- */
  const svcBox = dynamic(() => h('p', { class: 'muted' }, 'Loading...'));
  async function loadServices() {
    try {
      const list = await api.get('/services');
      const now = Date.now() / 1000;
      svcBox.replaceChildren(table(['Service', 'State', 'PID', 'Running for', 'Restarts', ''], list.map((s) => [
        h('strong', s.name), badge(s.state, s.state === 'running' ? 'ok' : 'bad'), s.pid ?? '-', s.since_unix ? fmtDuration(now - s.since_unix) : '-', s.restarts ?? 0,
        btn('Restart', () => restartService(s), { variant: 'small', icon: 'refresh' }),
      ]), { caption: 'Services' }));
    } catch (e) { svcBox.replaceChildren(banner('error', e.message)); }
  }

  async function restartService(s) {
    const message = [`Restart "${s.name}" now?`];
    if (/api|web/.test(s.name)) message.push('This page will be unavailable for a few seconds.');
    if (!(await confirmDialog({ title: 'Restart service', message, confirmText: 'Restart', danger: true }))) return;
    try {
      await api.post(`/services/${encodeURIComponent(s.name)}/restart`);
      toast(`${s.name} restarted.`, 'success');
    } catch (e) { handleError(e); }
    loadServices();
  }

  /* ----- backup / restore / reboot ----- */
  const file = h('input', { type: 'file', accept: '.toml,text/plain', id: 'restore-file', 'aria-label': 'Backup file to restore' });
  const restoreBtn = btn('Restore', () => restore(restoreBtn), { icon: 'upload', variant: 'danger' });
  async function restore(button) {
    const f = file.files[0];
    if (!f) return toast('Choose a backup file first.', 'error');
    if (f.size > 1024 * 1024) return toast('That file is too large to be a backup.', 'error');
    const ok = await confirmDialog({
      title: 'Restore this backup?', danger: true, confirmText: 'Restore',
      message: [`"${f.name}" will replace ALL current settings, including passwords and Wi-Fi keys.`, 'The router applies it immediately and your unsaved edits are lost.'],
    });
    if (!ok) return;
    await withBusy(button, async () => {
      try {
        await api.upload('/system/restore', await f.text(), 'application/toml');
        toast('Backup restored.', 'success');
        file.value = '';
        await loadConfig();
        rerender();
      } catch (e) { handleError(e); }
    });
  }

  async function reboot(button) {
    const ok = await confirmDialog({
      title: 'Restart the router?', danger: true, confirmText: 'Restart',
      message: ['The internet and Wi-Fi go down for about a minute.', state.dirty ? 'Your unsaved changes will be lost.' : ''].filter(Boolean),
    });
    if (!ok) return;
    try { await withBusy(button, () => api.post('/system/reboot')); } catch (e) { return handleError(e); }
    root.replaceChildren(pageHeader('Restarting...'), banner('info', 'The router is restarting. This page reconnects automatically.'));
    await reconnect(8000);
  }

  /** After a restart: wait `firstMs`, then poll until the router answers and reload the page. */
  async function reconnect(firstMs) {
    await sleep(firstMs);
    while (!signal.aborted) {
      try { await api.get('/system/status'); location.reload(); return; } catch { await sleep(4000); }
    }
  }

  /* ----- firmware upgrade (admins) -----
   * Choose the release files -> clear old uploads, PUT each one (progress per file) -> POST check
   * -> inline confirmation (reset settings, allow downgrade when older) -> POST /system/upgrade. */
  const IMAGE_NAME = /^ferritewrt-.+-sysupgrade\.bin$/;
  const RELEASE_HINT = 'SHA256SUMS, SHA256SUMS.sig and ferritewrt-<board>-v<version>-sysupgrade.bin';
  const fwPicker = h('input', { type: 'file', multiple: true, id: 'fw-files', 'aria-label': 'Firmware release files' });
  const fwCheckBtn = btn('Upload and check', () => uploadAndCheck(), { icon: 'upload', variant: 'primary' });
  const fwBox = h('div', { 'aria-live': 'polite' });

  /** The three release files out of the picker's selection, or an error message. */
  function releaseFiles(list) {
    const files = [...list];
    const sums = files.find((f) => f.name === 'SHA256SUMS');
    const sig = files.find((f) => f.name === 'SHA256SUMS.sig');
    const images = files.filter((f) => IMAGE_NAME.test(f.name));
    if (!sums || !sig || images.length !== 1 || files.length !== 3) return { error: `Choose exactly the three release files: ${RELEASE_HINT}.` };
    return { files: [sums, sig, images[0]] };
  }

  async function uploadAndCheck() {
    const { files, error } = releaseFiles(fwPicker.files);
    if (error) return fwBox.replaceChildren(banner('error', error));
    await withBusy(fwCheckBtn, async () => {
      const rows = files.map((f) => ({ f, bar: h('progress', { max: f.size || 1, value: 0 }), note: h('span', { class: 'muted' }, ' waiting') }));
      fwBox.replaceChildren(kv(rows.map((r) => [r.f.name, [r.bar, r.note]])));
      try {
        await api.del('/system/upgrade/files');
        for (const r of rows) {
          r.note.textContent = ' uploading';
          await api.putFile(`/system/upgrade/files/${encodeURIComponent(r.f.name)}`, r.f, (sent, total) => {
            r.bar.max = total || 1;
            r.bar.value = sent;
            r.note.textContent = ` ${Math.floor((100 * sent) / (total || 1))}%`;
          });
          r.bar.value = r.bar.max;
          r.note.textContent = ' uploaded';
        }
        fwBox.append(h('p', { class: 'muted' }, 'Checking the signature and the image...'));
        const info = await api.post('/system/upgrade/check', { allow_downgrade: true });
        fwBox.replaceChildren(confirmUpgrade(info));
      } catch (e) {
        fwBox.append(banner('error', e.message));
      }
    });
  }

  function confirmUpgrade(info) {
    const wipe = h('input', { type: 'checkbox', id: 'fw-wipe' });
    const allow = info.downgrade ? h('input', { type: 'checkbox', id: 'fw-downgrade' }) : null;
    const problem = h('div');
    const installBtn = btn('Install firmware', () => install(), { variant: 'danger', icon: 'upload', disabled: !!allow });
    allow?.addEventListener('change', () => { installBtn.disabled = !allow.checked; });
    const cancelBtn = btn('Cancel', async () => {
      fwBox.replaceChildren();
      fwPicker.value = '';
      try { await api.del('/system/upgrade/files'); } catch (e) { handleError(e); }
    }, { variant: 'ghost' });

    async function install() {
      problem.replaceChildren();
      try {
        await withBusy(installBtn, () => api.post('/system/upgrade', { allow_downgrade: !!allow?.checked, wipe_settings: wipe.checked }));
      } catch (e) { return problem.replaceChildren(banner('error', e.message)); }
      root.replaceChildren(pageHeader('Installing firmware...'), banner('warn', [
        `The router is writing FerriteWRT ${info.version} and will then restart. This takes a few minutes. Do not unplug the power.`,
        wipe.checked
          ? ' All settings are being reset: afterwards, connect to the router\'s factory address and set it up again.'
          : ' This page reconnects automatically when the router is back.',
      ].join('')));
      if (!wipe.checked) await reconnect(60000);
    }

    return h('div', { class: 'subcard' }, [
      h('p', h('strong', `FerriteWRT ${info.version} for ${info.board} (running ${info.running}), signature verified.`)),
      h('p', { class: 'muted' }, info.image),
      allow && banner('warn', `${info.version} is older than the running ${info.running}. Downgrading can lose settings that the older version does not understand.`),
      allow && h('p', h('label', { class: 'chk' }, [allow, 'Allow downgrade'])),
      h('p', h('label', { class: 'chk' }, [wipe, 'Reset all settings (factory defaults, including users and Wi-Fi)'])),
      h('p', 'Installing stops the router\'s services, writes the new firmware and restarts. Internet and Wi-Fi are down for a few minutes.'),
      problem,
      h('div', { class: 'actions' }, [cancelBtn, installBtn]),
    ]);
  }

  const firmwareCard = state.session?.role === 'admin' && card('Firmware upgrade', h('div', { 'data-local': true }, [
    h('p', { class: 'muted' }, `Choose the three files of a FerriteWRT release at once: ${RELEASE_HINT}. They are checked before anything is installed.`),
    h('div', { class: 'row-actions' }, [fwPicker, fwCheckBtn]),
    fwBox,
  ]));

  /* ----- firmware info ----- */
  const infoBox = dynamic(() => h('p', { class: 'muted' }, 'Loading...'));
  api.get('/system/status').then((s) => {
    const fp = s.tls_fingerprint ?? s.tls?.fingerprint ?? s.tls?.sha256;
    infoBox.replaceChildren(kv([
      ['Model', `${s.board.vendor} ${s.board.model}`], ['Board id', s.board.id],
      ['Firmware', `${s.firmware.version} (build ${s.firmware.build})`], ['Router time', fmtTime(s.time_unix)],
      ['Running for', fmtDuration(s.uptime_secs)], fp && ['HTTPS certificate fingerprint', h('code', fp)],
    ].filter(Boolean)));
  }).catch((e) => infoBox.replaceChildren(banner('error', e.message)));

  root.append(
    pageHeader('System & users', 'Router settings, accounts, maintenance.'),
    h('div', { class: 'grid' }, [settings, card('Firmware & hardware', infoBox)]),
    card('Users', [usersBox, addUser], { sub: 'User changes are saved immediately.' }),
    card('Change my password', pwForm),
    card('Services', svcBox, { actions: [btn('Refresh', loadServices, { icon: 'refresh', variant: 'ghost small' })], sub: 'Background programs the router runs.' }),
    card('Backup & restore', [
      h('p', { class: 'muted' }, 'A backup is a text file with all settings. It contains password hashes and Wi-Fi keys: store it safely.'),
      h('p', h('a', { class: 'btn', href: '/api/v1/system/backup', download: 'router-backup.toml' }, 'Download backup')),
      h('div', { class: 'row-actions' }, [file, restoreBtn]),
    ]),
    ...(firmwareCard ? [firmwareCard] : []),
    card('Restart', [h('p', { class: 'muted' }, 'Restart the router, for example after a firmware problem.'), btn('Restart router', (e) => reboot(e.currentTarget), { icon: 'power', variant: 'danger' })]),
  );
  loadUsers();
  loadServices();
}
