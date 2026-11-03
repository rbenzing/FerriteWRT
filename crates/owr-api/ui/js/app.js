/* app.js - entry point: hash router, session bootstrap, navigation, unsaved-changes bar.
 *
 * Routes are "#/path". Each page module in pages/ default-exports
 *   async function render(root, signal)
 * where `root` is a fresh element for that navigation and `signal` aborts when the user
 * navigates away (stop timers/polls on it). Pages are loaded lazily with import().
 * Guards: needs_setup -> #/setup; no session -> #/login.
 */
import { api, onAuthLost } from './api.js';
import { state, subscribe, touch, startSession, clearSession, discard, validateDraft, apply, setErrors, rerender } from './state.js';
import { h, icon, btn, banner, skeleton, toast, confirmDialog, withBusy, validateScope, handleError, getPath } from './ui.js';

const ROUTES = {
  '/': { label: 'Home', hint: 'Dashboard', icon: 'home', load: () => import('./pages/dashboard.js') },
  '/network': { label: 'Internet & network', hint: 'LAN, WAN, ports, VLANs', icon: 'network', load: () => import('./pages/network.js') },
  '/wireless': { label: 'Wi-Fi', hint: 'Radios, networks, clients', icon: 'wifi', load: () => import('./pages/wireless.js') },
  '/firewall': { label: 'Firewall', hint: 'Port forwarding, rules', icon: 'shield', load: () => import('./pages/firewall.js') },
  '/dhcp': { label: 'Devices & DHCP', hint: 'Leases, DNS', icon: 'devices', load: () => import('./pages/dhcp.js') },
  '/system': { label: 'System & users', hint: 'Settings, backup, reboot', icon: 'cog', load: () => import('./pages/system.js') },
  '/logs': { label: 'Event log', hint: 'Live system log', icon: 'logs', load: () => import('./pages/logs.js') },
  '/about': { label: 'About this router', hint: 'Hardware sheet', icon: 'info', load: () => import('./pages/about.js') },
  '/setup': { label: 'Setup', bare: true, public: true, load: () => import('./pages/setup.js') },
  '/login': { label: 'Sign in', bare: true, public: true, load: () => import('./pages/login.js') },
};

const $ = (id) => document.getElementById(id);
const main = $('main');
let controller = null;
let booted = false;
let needsSetup = false;
let bootPromise = null; // shared by overlapping route() calls so bootstrap runs once
let shownPath = null; // route currently rendered; focus/announce only when it changes

const currentPath = () => {
  const p = location.hash.startsWith('#/') ? location.hash.slice(1).split('?')[0] : '/';
  return ROUTES[p] ? p : '/';
};
const go = (path) => { location.hash = `#${path}`; };

/* ---------- navigation chrome ---------- */

$('nav').append(h('ul', Object.entries(ROUTES).filter(([, r]) => !r.bare).map(([path, r]) =>
  h('li', h('a', { href: `#${path}`, 'data-route': path }, [icon(r.icon), h('span', [r.label, h('small', r.hint)])])))));

function renderChrome() {
  const path = currentPath();
  document.querySelectorAll('#nav a').forEach((a) => {
    if (a.dataset.route === path) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  $('user').textContent = state.session ? `${state.session.name} (${state.session.role})` : '';
  $('logout').hidden = !state.session;
  const host = getPath(state.config, 'system.hostname');
  $('hostname').textContent = host ? `${host} - ${state.board?.board?.model ?? ''}` : '';
}

$('skip').addEventListener('click', (e) => { e.preventDefault(); main.focus(); });

$('logout').addEventListener('click', async () => {
  if (state.dirty && !(await confirmDialog({ title: 'Sign out?', message: 'You have unsaved changes that will be lost.', confirmText: 'Sign out', danger: true }))) return;
  await api.post('/auth/logout').catch(() => {});
  clearSession();
  go('/login');
});

/* ---------- session / router ---------- */

async function bootstrap() {
  needsSetup = (await api.get('/setup/status')).needs_setup;
  if (!needsSetup) {
    try {
      await startSession(await api.get('/auth/session', { quiet401: true }));
    } catch (e) {
      if (e.status !== 401) throw e;
    }
  }
  booted = true;
}

onAuthLost(() => {
  if (!state.session) return;
  clearSession();
  toast('Your session ended. Please sign in again.', 'info');
  go('/login');
});

async function route() {
  controller?.abort();
  controller = new AbortController();
  const { signal } = controller;
  try {
    if (!booted) await (bootPromise ??= bootstrap().finally(() => { bootPromise = null; }));
  } catch (e) {
    if (signal.aborted) return; // a newer navigation owns the page now
    main.replaceChildren(banner('error', e.message), btn('Retry', rerender, { variant: 'primary' }));
    return;
  }
  if (signal.aborted) return;
  const path = currentPath();
  if (needsSetup && path !== '/setup') return go('/setup');
  if (!needsSetup && path === '/setup') return go('/');
  if (!state.session && !ROUTES[path].public) return go('/login');
  if (state.session && path === '/login') return go('/');

  const r = ROUTES[path];
  document.body.classList.toggle('bare', !!r.bare);
  document.title = `${r.label} - FerriteWRT`;
  renderChrome();
  const root = h('div', { class: 'page' }, skeleton());
  main.replaceChildren(root);
  try {
    const mod = await r.load();
    if (signal.aborted) return;
    root.replaceChildren();
    await mod.default(root, signal);
  } catch (e) {
    if (signal.aborted) return;
    root.replaceChildren(banner('error', `Could not load this page: ${e.message}`), btn('Try again', rerender, { variant: 'primary' }));
  }
  if (signal.aborted) return;
  renderChrome();
  if (path !== shownPath) { // real navigation (not a re-render after apply/discard): move focus + announce
    shownPath = path;
    $('announcer').textContent = r.label;
    if (!main.contains(document.activeElement) || document.activeElement === main) {
      const heading = root.querySelector('h1');
      heading?.setAttribute('tabindex', '-1');
      (heading ?? main).focus({ preventScroll: true });
    }
  }
}

window.addEventListener('hashchange', route);

/* ---------- unsaved changes bar ---------- */

const bar = $('dirtybar');
let barKey = '';

function renderBar() {
  const key = `${state.dirty}|${state.errors.map((d) => `${d.path}: ${d.message}`).join('\n')}`;
  if (key === barKey) return;
  barKey = key;
  bar.hidden = !state.dirty;
  document.body.classList.toggle('has-bar', state.dirty);
  if (!state.dirty) { bar.replaceChildren(); return; }
  bar.replaceChildren(h('div', { class: 'bar-inner' }, [
    h('span', { class: 'bar-msg' }, 'You have unsaved changes. They only take effect once applied.'),
    h('div', { class: 'bar-actions' }, [
      btn('Discard', onDiscard, { variant: 'ghost' }),
      btn('Check', (e) => onCheck(e.currentTarget), { variant: 'secondary' }),
      btn('Apply changes', (e) => onApply(e.currentTarget), { variant: 'primary' }),
    ]),
    state.errors.length > 0 && h('details', { class: 'bar-errors', open: true }, [
      h('summary', `${state.errors.length} problem${state.errors.length > 1 ? 's' : ''} found`),
      h('ul', state.errors.map((d) => h('li', `${d.path}: ${d.message}`))),
    ]),
  ]));
}

async function onDiscard() {
  if (!(await confirmDialog({ title: 'Discard changes?', message: 'All edits since the last apply will be lost.', confirmText: 'Discard', danger: true }))) return;
  discard();
  rerender();
}

const pageScope = () => main.querySelector('.page') ?? main;

async function onCheck(button) {
  if (!validateScope(pageScope())) return toast('Please fix the highlighted fields first.', 'error');
  await withBusy(button, async () => {
    try {
      await validateDraft();
      setErrors([]);
      toast('The configuration is valid.', 'success');
    } catch (e) {
      setErrors(e.details);
      handleError(e, pageScope());
    }
  });
}

/** Apply result: show whatever the server reports ({applied?:[], warnings?:[]}), else a plain success. */
function summarize(res) {
  const list = (a) => a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(', ');
  const parts = ['Changes applied.'];
  if (Array.isArray(res?.applied) && res.applied.length) parts.push(`Updated: ${list(res.applied)}.`);
  if (Array.isArray(res?.warnings) && res.warnings.length) parts.push(`Warnings: ${list(res.warnings)}.`);
  return { text: parts.join(' '), warn: !!res?.warnings?.length };
}

async function onApply(button) {
  if (!validateScope(pageScope())) return toast('Please fix the highlighted fields first.', 'error');
  const lanChanged = getPath(state.draft, 'network.lan.ipv4') !== getPath(state.config, 'network.lan.ipv4');
  const apiChanged = JSON.stringify(state.draft.services?.api) !== JSON.stringify(state.config.services?.api);
  const message = ['The router will reconfigure its network, Wi-Fi and firewall now. Connections may drop for a few seconds.'];
  if (lanChanged) message.push('You are changing the router address: reconnect at the new address afterwards.');
  if (apiChanged) message.push('You are changing the management interface: this page may stop responding until you reconnect.');
  if (!(await confirmDialog({ title: 'Apply changes?', message, confirmText: 'Apply' }))) return;
  const newLan = String(getPath(state.draft, 'network.lan.ipv4')).split('/')[0];
  const port = state.draft.services?.api?.port;
  await withBusy(button, async () => {
    let applied;
    try {
      applied = await apply();
    } catch (e) { // the PUT failed: nothing was applied, keep the draft and show why
      setErrors(e.details);
      handleError(e, pageScope());
      return;
    }
    const { text, warn } = summarize(applied.result);
    if (applied.reloadError) { // applied, but the new state could not be read back
      if (lanChanged) toast(`Settings applied. Reconnect at https://${newLan}${port && port !== 443 ? `:${port}` : ''}/`, 'success', 20000);
      else toast(`${text} The new settings could not be reloaded (${applied.reloadError.message}); reload this page.`, 'warn', 12000);
      return;
    }
    toast(text, warn ? 'warn' : 'success', 8000);
    rerender();
  });
}

subscribe(renderBar);
subscribe(renderChrome);
document.addEventListener('owr:edit', touch);
window.addEventListener('beforeunload', (e) => { if (state.dirty) e.preventDefault(); });

route();
