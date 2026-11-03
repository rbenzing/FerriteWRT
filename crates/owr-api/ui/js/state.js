/* state.js - tiny shared store: session, board descriptor, config draft + dirty flag, apply().
 *
 * The config draft is a deep copy of the server config. Pages bind their inputs to
 * `state.draft` (via ui.js control()/field()), so edits survive navigation and feed the
 * persistent "unsaved changes" bar. After apply()/discard() the draft object is replaced,
 * so callers must re-render the current page (see rerender()).
 */
import { api, setCsrf } from './api.js';

export const state = {
  session: null, // {name, role, enabled}
  board: null, // GET /board
  config: null, // last config known to the server (redacted)
  draft: null, // editable copy
  dirty: false,
  errors: [], // last 422 details from apply/validate
};

const listeners = new Set();
export const subscribe = (fn) => { listeners.add(fn); return () => listeners.delete(fn); };
const emit = () => listeners.forEach((fn) => fn(state));

/** Stable stringify (sorted keys) so key order never causes false "dirty". */
const canon = (v) => JSON.stringify(v, (_k, x) =>
  (x && typeof x === 'object' && !Array.isArray(x)
    ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)))
    : x));

/** Recompute the dirty flag after any edit. */
export function touch() {
  state.dirty = !!state.draft && canon(state.draft) !== canon(state.config);
  if (!state.dirty) state.errors = [];
  emit();
}

export const rerender = () => window.dispatchEvent(new HashChangeEvent('hashchange'));

export async function loadBoard() {
  state.board ??= await api.get('/board');
  return state.board;
}

/**
 * The server omits empty lists (serde `skip_serializing_if`), so make sure every list the
 * pages iterate exists. Empty lists are dropped again on serialisation by the server, so
 * round-tripping them is harmless.
 */
export function normalizeConfig(cfg) {
  const ensure = (obj, key) => {
    if (obj && !Array.isArray(obj[key])) obj[key] = [];
  };
  cfg.system ??= {};
  cfg.network ??= {};
  cfg.wireless ??= {};
  cfg.firewall ??= {};
  cfg.dhcp ??= {};
  cfg.services ??= {};
  ensure(cfg, 'users');
  ensure(cfg.system, 'ntp_servers');
  ensure(cfg.network, 'vlans');
  cfg.network.lan ??= {};
  ensure(cfg.network.lan, 'ports');
  ensure(cfg.wireless, 'radios');
  ensure(cfg.wireless, 'aps');
  ensure(cfg.firewall, 'port_forwards');
  ensure(cfg.firewall, 'rules');
  ensure(cfg.dhcp, 'static_leases');
  ensure(cfg.dhcp, 'dns_servers');
  cfg.services.ssh ??= {};
  ensure(cfg.services.ssh, 'authorized_keys');
  for (const v of cfg.network.vlans) ensure(v, 'ports');
  return cfg;
}

export async function loadConfig() {
  state.config = normalizeConfig(await api.get('/config'));
  state.draft = structuredClone(state.config);
  touch();
  return state.draft;
}

export async function ensureConfig() {
  return state.draft ?? loadConfig();
}

export async function startSession({ user, csrf }) {
  state.session = user;
  setCsrf(csrf);
  await Promise.allSettled([loadBoard(), loadConfig()]); // pages report their own load errors
  emit();
}

export function clearSession() {
  Object.assign(state, { session: null, config: null, draft: null, dirty: false, errors: [] });
  setCsrf(null);
  emit();
}

export function discard() {
  state.draft = structuredClone(state.config);
  touch();
}

export const validateDraft = () => api.post('/config/validate', state.draft);

/**
 * PUT the draft, then reload the server's view. A failing PUT throws (nothing was applied).
 * Once the PUT succeeded the draft is the running config, so the dirty flag is cleared right away;
 * a failing reload (e.g. the LAN address just changed) is returned as {reloadError} instead of
 * thrown, and the local copy stands in for the server's until the next load.
 * Returns {result, reloadError}.
 */
export async function apply() {
  const result = await api.put('/config', state.draft);
  state.config = structuredClone(state.draft);
  state.errors = [];
  touch();
  try {
    await loadConfig();
    return { result, reloadError: null };
  } catch (reloadError) {
    return { result, reloadError };
  }
}

export function setErrors(details) {
  state.errors = details ?? [];
  emit();
}
