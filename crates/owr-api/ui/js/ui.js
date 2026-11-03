/* ui.js - DOM helpers and widgets shared by every page.
 *
 *  - h()/svg(): element builders (text goes through text nodes: never innerHTML)
 *  - control()/field()/checks(): inputs bound to an object by dotted path, with
 *    client-side validation (rules) and server 422 error display (showFieldErrors)
 *  - toast(), modal(), confirmDialog(), poll(), table(), card() ... small components
 *  - formatters (bytes, durations, rates) and signalBars()
 * Edits dispatch a document-level "owr:edit" event so state.js can recompute the dirty flag
 * without this module depending on it. No DOM access happens at import time.
 */
import { normalizePath } from './api.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const LATE = new Set(['value', 'checked', 'indeterminate']); // set as properties after children exist

/* ---------- element builders ---------- */

function append(el, children) {
  for (const c of [children].flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

function build(el, attrs, children) {
  const late = [];
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (LATE.has(k)) late.push([k, v]);
    else el.setAttribute(k, v === true ? '' : v);
  }
  append(el, children);
  for (const [k, v] of late) el[k] = v;
  return el;
}

const isChildren = (a) => a instanceof Node || Array.isArray(a) || typeof a === 'string' || typeof a === 'number';

/** h('div', {class:'x', onclick: fn}, [children]); attrs may be omitted. */
export function h(tag, attrs, children) {
  if (isChildren(attrs)) [attrs, children] = [null, attrs];
  return build(document.createElement(tag), attrs, children);
}

export function svg(tag, attrs, children) {
  if (isChildren(attrs)) [attrs, children] = [null, attrs];
  return build(document.createElementNS(SVG_NS, tag), attrs, children);
}

export const icon = (name) =>
  svg('svg', { class: 'icon', 'aria-hidden': 'true' }, svg('use', { href: `/icons.svg#i-${name}` }));

/* ---------- object paths ---------- */

/**
 * Paths are dotted ("network.lan.ipv4", "vlans.0.id"); a segment that itself contains dots or
 * brackets is written in brackets ("roles[lan.1]").
 */
const segments = (p) => (p.match(/[^.[\]]+|\[[^\]]*\]/g) ?? []).map((s) => (s[0] === '[' ? s.slice(1, -1) : s));

export const getPath = (o, p) => segments(p).reduce((a, k) => a?.[k], o);

export function setPath(o, p, v) {
  const ks = segments(p);
  const last = ks.pop();
  const t = ks.reduce((a, k) => (a[k] ??= {}), o);
  if (v === undefined) delete t[last];
  else t[last] = v;
}

export const edited = () => document.dispatchEvent(new CustomEvent('owr:edit'));

/* ---------- validation rules: (value) => message | null ---------- */

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const isEmpty = (v) => v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0);

/** Textual IPv6 (including "::" compression and a trailing embedded IPv4), no zone or prefix. */
function isIpv6(s) {
  if (!/^[0-9a-f:.]+$/i.test(s)) return false;
  const sides = s.split('::');
  if (sides.length > 2) return false;
  const parts = sides.map((x) => (x === '' ? [] : x.split(':')));
  const groups = parts.flat();
  const v4Allowed = parts.at(-1).length > 0; // an embedded IPv4 must end the address
  let count = 0;
  for (const [i, g] of groups.entries()) {
    if (v4Allowed && i === groups.length - 1 && g.includes('.')) {
      if (!IPV4.test(g)) return false;
      count += 2;
    } else if (/^[0-9a-f]{1,4}$/i.test(g)) count += 1;
    else return false;
  }
  return sides.length === 2 ? count <= 7 : count === 8;
}

export const ipv4ToInt = (s) => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);

/** "a.b.c.d/p" -> {addr, prefix, net, last} (integers) or null. */
export function parseCidr(v) {
  const [a, m, ...rest] = String(v).split('/');
  if (rest.length || !IPV4.test(a) || !/^\d{1,2}$/.test(m ?? '') || +m > 32) return null;
  const prefix = Number(m);
  const size = 2 ** (32 - prefix);
  const addr = ipv4ToInt(a);
  const net = addr - (addr % size);
  return { addr, prefix, net, last: net + size - 1 };
}

export const cidrOverlap = (a, b) => a.net <= b.last && b.net <= a.last;
export const cidrHas = (c, addr) => addr >= c.net && addr <= c.last;

/** Router interface address with prefix, like the server: prefix min..=30, a usable unicast host. */
const interfaceCidr = (min) => (v) => {
  const c = parseCidr(v);
  const msg = `Use address/prefix with a prefix from /${min} to /30, for example 192.168.8.1/24.`;
  if (!c || c.prefix < min || c.prefix > 30) return msg;
  const first = Math.floor(c.addr / 2 ** 24);
  if (c.addr === c.net || c.addr === c.last) return 'Use a host address, not the network or broadcast address.';
  if (first === 0 || first === 127 || first >= 224 || (first === 169 && Math.floor(c.addr / 65536) % 256 === 254)) return 'Use a private unicast address.';
  return null;
};

export const rules = {
  required: (v) => (isEmpty(v) ? 'This field is required.' : null),
  ipv4: (v) => (IPV4.test(v) ? null : 'Enter an IPv4 address such as 192.168.8.1.'),
  ip: (v) => (IPV4.test(v) || isIpv6(String(v)) ? null : 'Enter an IPv4 or IPv6 address.'),
  ipv4Cidr: interfaceCidr(8), // LAN and VLAN interfaces: /8../30
  ipv4CidrWan: interfaceCidr(1), // static WAN: /1../30
  ipCidr(v) { // firewall source: network with mandatory prefix (/0../32 or /0../128)
    const [a, m, ...rest] = String(v).split('/');
    const ok = !rest.length && /^\d{1,3}$/.test(m ?? '') && (IPV4.test(a) ? +m <= 32 : isIpv6(a) && +m <= 128);
    return ok ? null : 'Use address/prefix, for example 10.0.0.0/24 (or 10.0.0.5/32 for one device).';
  },
  mac(v) {
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(v)) return 'Use the form aa:bb:cc:dd:ee:ff.';
    if (parseInt(v.slice(0, 2), 16) & 1) return 'Multicast addresses cannot be used; the first byte must be even.';
    return /^[0:]+$/.test(v) ? 'The all-zero address cannot be used.' : null;
  },
  hostname: (v) => (/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(v) ? null : 'Letters, digits and hyphens only (max 63).'),
  domain: (v) => (/^([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$/.test(v) ? null : 'Enter a domain such as lan.'),
  itemName: (v) => (/^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/.test(v) ? null : 'Start with a letter or digit; letters, digits, . _ - (max 32).'),
  int: (min, max) => (v) => (Number.isInteger(v) && v >= min && v <= max ? null : `Enter a whole number from ${min} to ${max}.`),
  len: (min, max) => (v) => (String(v).length >= min && String(v).length <= max ? null : `Use ${min} to ${max} characters.`),
  minLen: (n) => (v) => (String(v).length >= n ? null : `Use at least ${n} characters.`),
  /** SSID: 1 to 32 UTF-8 bytes (not characters), no control characters. */
  ssid(v) {
    const n = new TextEncoder().encode(String(v)).length;
    if (/[\u0000-\u001f\u007f]/.test(v)) return 'Control characters are not allowed.';
    return n >= 1 && n <= 32 ? null : `Use 1 to 32 bytes (currently ${n}); accented and other non-ASCII characters take 2 to 4 bytes each.`;
  },
  /** WPA passphrase: 8 to 63 printable ASCII characters, and no "|". */
  wpaPassphrase(v) {
    if (String(v).includes('|')) return 'The character | is not allowed.';
    return /^[\x20-\x7e]{8,63}$/.test(v) ? null : 'Use 8 to 63 printable ASCII characters (no accents or emoji).';
  },
  each: (rule) => (v) => [v].flat().map(rule).find(Boolean) ?? null,
  portSpec(v) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(String(v));
    const ok = m && +m[1] >= 1 && +m[1] <= 65535 && (!m[2] || (+m[2] <= 65535 && +m[2] >= +m[1]));
    return ok ? null : 'Use a port (80) or a range (8000-8100).';
  },
  same: (other, msg) => (v) => (v === other() ? null : msg),
};

/** "80" -> 80, "8000-8100" stays a string. */
export const castPortSpec = (s) => (/^\d+$/.test(s) ? Number(s) : s);

/* ---------- field errors ---------- */

export function setFieldError(el, msg) {
  const box = el.closest('.ctl')?.querySelector('.err');
  if (box) box.textContent = msg ?? '';
  if (msg) el.setAttribute('aria-invalid', 'true');
  else el.removeAttribute('aria-invalid');
}

export function clearFieldErrors(scope) {
  scope.querySelectorAll('[aria-invalid]').forEach((el) => setFieldError(el, null));
}

/** Map server 422 details onto fields (by data-path). Returns the details that matched no field. */
export function showFieldErrors(scope, details = []) {
  clearFieldErrors(scope);
  const rest = [];
  for (const d of details) {
    const el = scope.querySelector(`[data-path="${CSS.escape(normalizePath(d.path))}"]`);
    if (!el) { rest.push(d); continue; }
    const prev = el.closest('.ctl')?.querySelector('.err')?.textContent;
    setFieldError(el, prev && el.hasAttribute('aria-invalid') ? `${prev} ${d.message}` : d.message);
  }
  const first = scope.querySelector('[aria-invalid="true"]');
  first?.scrollIntoView({ block: 'center' });
  (first?.matches('input,select,textarea') ? first : first?.querySelector('input'))?.focus({ preventScroll: true });
  return rest;
}

/**
 * Run every field's validator inside scope; focus the first failure. Containers marked
 * data-local (forms that call their own endpoint, not the config draft) are skipped unless
 * they are the scope itself.
 */
export function validateScope(scope) {
  let first = null;
  for (const el of scope.querySelectorAll('[data-path]')) {
    const local = el.closest('[data-local]');
    if (local && local !== scope && scope.contains(local)) continue;
    if (el._validate?.() && !first) first = el;
  }
  first?.scrollIntoView({ block: 'center' });
  first?.focus?.({ preventScroll: true });
  return !first;
}

/** Toast an error; for 422 mark the fields instead of only toasting. */
export function handleError(e, scope) {
  if (e.status === 422 && scope) {
    const rest = showFieldErrors(scope, e.details);
    toast(rest.length ? rest.map((d) => `${d.path}: ${d.message}`).join('; ') : 'Please fix the highlighted fields.', 'error');
  } else {
    toast(e.message || String(e), 'error');
  }
}

/* ---------- bound controls ---------- */

let uid = 0;

/**
 * control(root, path, opts) -> div.ctl (with .input) bound to getPath(root, path).
 * opts: type text|number|password|toggle|select|list|lines, options, min, max, step, optional,
 *   required, validate (fn|fn[]), cast (string -> value), hint, aria, list (datalist id),
 *   errPath (data-path override for server errors), onChange(value) (every edit), onCommit(value, error)
 *   (on the change event only: blur / Enter / select; error = validation message or null),
 *   text (toggle label), autocomplete (passwords default to new-password: pass current-password
 *   only for a sign-in field). Password controls expose ctl.reveal(show).
 */
export function control(root, path, o = {}) {
  const id = o.id ?? `f${++uid}`;
  const type = o.type ?? 'text';
  const cur = getPath(root, path);
  const err = h('div', { class: 'err', id: `${id}-err`, role: 'alert' });
  const hint = o.hint ? h('div', { class: 'hint', id: `${id}-hint` }, o.hint) : null;
  const base = {
    id,
    'data-path': o.errPath ?? path,
    'aria-label': o.aria,
    'aria-required': o.required ? 'true' : null,
    'aria-describedby': `${id}-err${hint ? ` ${id}-hint` : ''}`,
    disabled: o.disabled,
    placeholder: o.placeholder,
    list: o.list,
    autocomplete: o.autocomplete ?? (type === 'password' ? 'new-password' : 'off'),
  };
  const emptyToUndef = (s) => (o.optional && s === '' ? undefined : o.cast ? o.cast(s) : s);
  let input, widget, read, reveal;

  if (type === 'toggle') {
    input = h('input', { ...base, type: 'checkbox', role: 'switch', checked: !!cur });
    widget = h('label', { class: 'toggle' }, [input, h('span', { class: 'track', 'aria-hidden': 'true' }), o.text && h('span', o.text)]);
    read = () => input.checked;
  } else if (type === 'select') {
    const opts = o.options.map((x) => (typeof x === 'object' ? x : { value: x, label: x }));
    if (cur != null && !opts.some((x) => String(x.value) === String(cur))) opts.push({ value: cur, label: String(cur) });
    input = h('select', { ...base, value: cur == null ? '' : String(cur) }, opts.map((x) => h('option', { value: x.value }, x.label)));
    read = () => emptyToUndef(input.value);
  } else if (type === 'number') {
    input = h('input', { ...base, type: 'number', inputmode: 'numeric', min: o.min, max: o.max, step: o.step ?? 1, value: cur ?? '' });
    read = () => (input.value === '' ? (o.optional ? undefined : '') : Number(input.value));
  } else if (type === 'password') {
    input = h('input', { ...base, type: 'password', spellcheck: 'false', value: cur ?? '' });
    const eye = h('button', {
      type: 'button', class: 'btn ghost icon-only', 'aria-label': 'Show password', 'aria-pressed': 'false',
      onclick: () => reveal(input.type === 'password'),
    }, icon('eye'));
    reveal = (show) => {
      input.type = show ? 'text' : 'password';
      eye.setAttribute('aria-pressed', String(show));
      eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    };
    widget = h('div', { class: 'with-btn' }, [input, eye]);
    read = () => input.value;
  } else if (type === 'lines') {
    input = h('textarea', { ...base, rows: o.rows ?? 3, spellcheck: 'false', value: (cur ?? []).join('\n') });
    read = () => input.value.split('\n').map((s) => s.trim()).filter(Boolean);
  } else if (type === 'list') {
    input = h('input', { ...base, type: 'text', value: (cur ?? []).join(', ') });
    read = () => input.value.split(/[\s,]+/).filter(Boolean);
  } else {
    input = h('input', { ...base, type: 'text', value: cur ?? '' });
    read = () => emptyToUndef(input.value);
  }

  const rulesList = [o.required && rules.required, ...[o.validate].flat()].filter(Boolean);
  const validate = () => {
    const v = read();
    let msg = null;
    for (const c of rulesList) {
      if (isEmpty(v) && c !== rules.required) continue;
      msg = c(v);
      if (msg) break;
    }
    setFieldError(input, msg);
    return msg;
  };
  input._validate = validate;

  const live = type === 'toggle' || type === 'select' ? 'change' : 'input';
  input.addEventListener(live, () => {
    setPath(root, path, read());
    if (live === 'change' || input.hasAttribute('aria-invalid')) validate();
    o.onChange?.(read());
    edited();
  });
  if (live === 'input') input.addEventListener('change', validate);
  if (o.onCommit) input.addEventListener('change', () => o.onCommit(read(), validate()));

  const ctl = h('div', { class: 'ctl' }, [widget ?? input, hint, err]);
  ctl.input = input;
  ctl.reveal = reveal;
  return ctl;
}

/** Group of checkboxes bound to an array at `path`. options: [{value,label,disabled}|string]. */
export function checks(root, path, options, o = {}) {
  const id = `f${++uid}`;
  const sel = new Set(getPath(root, path) ?? []);
  const vals = options.map((x) => x.value ?? x);
  const group = h('div', {
    class: 'checks', role: 'group', id, 'data-path': o.errPath ?? path, 'aria-label': o.aria ?? o.label, 'aria-describedby': `${id}-err`,
  }, options.map((x) => {
    const v = x.value ?? x;
    const cb = h('input', {
      type: 'checkbox', checked: sel.has(v), disabled: x.disabled, 'data-path': `${o.errPath ?? path}[${v}]`,
      onchange() {
        if (cb.checked) sel.add(v); else sel.delete(v);
        setPath(root, path, vals.filter((y) => sel.has(y)));
        o.onChange?.();
        edited();
      },
    });
    return h('label', { class: 'chk' }, [cb, x.label ?? v]);
  }));
  const ctl = h('div', { class: 'ctl' }, [group, h('div', { class: 'err', id: `${id}-err`, role: 'alert' })]);
  ctl.input = group;
  return ctl;
}

/** Labelled form row: <label> + control (or checks when opts.checks is given). */
export function field(root, path, o = {}) {
  const ctl = o.checks ? checks(root, path, o.checks, o) : control(root, path, o);
  const row = h('div', { class: 'row' }, [
    h('label', { for: ctl.input.id }, [o.label, o.required && h('span', { class: 'req', 'aria-hidden': 'true' }, ' *')]),
    ctl,
  ]);
  row.ctl = ctl;
  return row;
}

/* ---------- small components ---------- */

export function btn(label, onclick, o = {}) {
  return h('button', {
    type: o.type ?? 'button', class: `btn ${o.variant ?? ''}${label ? '' : ' icon-only'}`, onclick,
    disabled: o.disabled, 'aria-label': o.aria, title: o.title,
  }, [o.icon && icon(o.icon), label]);
}

export async function withBusy(button, fn) {
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try { return await fn(); } finally { button.disabled = false; button.removeAttribute('aria-busy'); }
}

export const card = (title, body, o = {}) =>
  h('section', { class: 'card', id: o.id }, [
    h('header', { class: 'card-head' }, [h('h2', title), o.actions && h('div', { class: 'card-actions' }, o.actions)]),
    o.sub && h('p', { class: 'muted' }, o.sub),
    body,
  ]);

export const pageHeader = (title, sub) => h('div', { class: 'page-head' }, [h('h1', title), sub && h('p', { class: 'muted' }, sub)]);
export const banner = (kind, text) => h('div', { class: `banner ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, text);
export const badge = (text, kind = '') => h('span', { class: `badge ${kind}` }, text);
export const kv = (pairs) => h('dl', { class: 'kv' }, pairs.flatMap(([k, v]) => [h('dt', k), h('dd', v ?? '-')]));
export const skeleton = (n = 3) => h('div', { class: 'skeleton-page', 'aria-hidden': 'true' }, Array.from({ length: n }, () => h('div', { class: 'skeleton block' })));

export function table(head, rows, { empty = 'Nothing to show.', caption } = {}) {
  return h('div', { class: 'table-wrap' }, h('table', [
    caption && h('caption', { class: 'sr' }, caption),
    h('thead', h('tr', head.map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', rows.length
      ? rows.map((r) => h('tr', r.map((c) => h('td', c))))
      : h('tr', h('td', { colspan: head.length, class: 'muted' }, empty))),
  ]));
}

/** Container rebuilt by refresh(); keyboard focus is restored by data-path. */
export function dynamic(build) {
  const box = h('div', { class: 'dyn' });
  box.refresh = () => {
    const p = box.contains(document.activeElement) ? document.activeElement.getAttribute('data-path') : null;
    box.replaceChildren(build());
    if (p) box.querySelector(`[data-path="${CSS.escape(p)}"]`)?.focus();
  };
  box.refresh();
  return box;
}

export function toast(msg, kind = 'info', ms = kind === 'error' ? 9000 : 4500) {
  const el = h('div', { class: `toast ${kind}` }, [
    h('span', msg),
    h('button', { type: 'button', class: 'btn ghost small', 'aria-label': 'Dismiss', onclick: () => el.remove() }, 'x'),
  ]);
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), ms);
}

/**
 * modal({title, body, actions:[{label,value,variant,autofocus}], check}) -> Promise<value|''>.
 * check(dialog) runs before an action with value "ok" closes the dialog; return false to keep it open.
 */
export function modal({ title, body, actions, check }) {
  const tid = `m${++uid}`;
  const dlg = h('dialog', { class: 'modal', 'aria-labelledby': tid }, h('form', {
    method: 'dialog',
    onsubmit(e) { if (check && e.submitter?.value === 'ok' && !check(dlg)) e.preventDefault(); },
  }, [
    h('h2', { id: tid }, title),
    h('div', { class: 'modal-body' }, body),
    h('div', { class: 'actions' }, actions.map((a) =>
      h('button', { type: 'submit', value: a.value, class: `btn ${a.variant ?? ''}`, autofocus: a.autofocus }, a.label))),
  ]));
  document.body.append(dlg);
  return new Promise((resolve) => {
    dlg.addEventListener('close', () => { resolve(dlg.returnValue); dlg.remove(); });
    dlg.showModal();
  });
}

export async function confirmDialog({ title, message, confirmText = 'Confirm', danger = false }) {
  const v = await modal({
    title,
    body: [].concat(message).map((m) => h('p', m)),
    actions: [
      { label: 'Cancel', value: 'no', variant: 'ghost', autofocus: danger },
      { label: confirmText, value: 'ok', variant: danger ? 'danger' : 'primary', autofocus: !danger },
    ],
  });
  return v === 'ok';
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard.', 'success');
  } catch {
    toast('Copy failed; select the text and copy it manually.', 'error');
  }
}

/**
 * poll(fn, {every, max, signal, onError}): run fn now and every `every` ms; exponential backoff
 * (up to `max`) while fn throws; paused while the tab is hidden; stops when signal aborts.
 */
export function poll(fn, { every = 5000, max = 60000, signal, onError } = {}) {
  let delay = every;
  let timer = null;
  let running = false;
  const schedule = () => { if (!signal.aborted && !document.hidden) timer = setTimeout(tick, delay); };
  async function tick() {
    timer = null;
    if (signal.aborted || document.hidden || running) return;
    running = true;
    try { await fn(); delay = every; } catch (e) { delay = Math.min(delay * 2, max); onError?.(e, delay); }
    running = false;
    schedule();
  }
  const onVis = () => { if (!document.hidden && !timer && !running) tick(); };
  document.addEventListener('visibilitychange', onVis);
  signal.addEventListener('abort', () => { clearTimeout(timer); document.removeEventListener('visibilitychange', onVis); });
  tick();
}

/* ---------- widgets ---------- */

export function strength(pw) {
  if (!pw) return { score: 0, label: '' };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  let score = pw.length < 8 ? 0 : pw.length < 12 ? 1 : pw.length < 16 ? 2 : 3;
  if (pw.length >= 12 && classes >= 3) score = Math.min(4, score + 1);
  return { score, label: ['Too short', 'Weak', 'Fair', 'Good', 'Strong'][score] };
}

/** Password strength meter: {el, update(pw)}. */
export function strengthMeter() {
  const bar = h('progress', { max: 4, value: 0, 'aria-label': 'Password strength' });
  const text = h('span', { class: 'muted' });
  return {
    el: h('div', { class: 'meter' }, [bar, text]),
    update(pw) { const s = strength(pw); bar.value = s.score; text.textContent = s.label; },
  };
}

export function signalBars(dbm) {
  const lvl = dbm == null ? 0 : dbm >= -55 ? 4 : dbm >= -65 ? 3 : dbm >= -75 ? 2 : dbm >= -85 ? 1 : 0;
  return h('span', { class: `bars lvl${lvl}`, role: 'img', 'aria-label': `Signal ${dbm ?? 'unknown'} dBm` },
    [1, 2, 3, 4].map((i) => h('i', { class: i <= lvl ? 'on' : '' })));
}

export const PRIO = ['emerg', 'alert', 'crit', 'err', 'warn', 'notice', 'info', 'debug'];

export function logRow(e) {
  const p = PRIO[e.prio] ?? String(e.prio);
  return h('div', { class: `log p-${p}` }, [
    h('time', fmtClock(e.ts_ms)), ' ', h('span', { class: 'lvl' }, p), ' ', h('span', { class: 'src' }, e.source), ' ', h('span', e.msg),
  ]);
}

/* ---------- formatters ---------- */

export function fmtBytes(n) {
  if (n == null) return '-';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(n < 10 ? 2 : 1) : n} ${u[i]}`;
}

export function fmtDuration(s) {
  if (s == null) return '-';
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}

export const fmtRate = (kbps) => (kbps == null ? '-' : kbps >= 1000 ? `${(kbps / 1000).toFixed(kbps >= 10000 ? 0 : 1)} Mbit/s` : `${kbps} kbit/s`);
export const fmtSpeed = (mbps) => (mbps == null ? '-' : mbps >= 1000 ? `${mbps / 1000}G` : `${mbps}M`);
export const fmtTime = (unix) => (unix ? new Date(unix * 1000).toLocaleString() : '-');
export const fmtClock = (ms) => new Date(ms).toLocaleTimeString([], { hour12: false });

export const fmtBand = (b) => ({ '2g': '2.4 GHz', '5g': '5 GHz', '6g': '6 GHz' })[b] ?? b ?? '-';
