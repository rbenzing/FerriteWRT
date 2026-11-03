/* api.js - fetch wrapper for the owr-api JSON API.
 *
 * Every response is {ok:true,data} | {ok:false,error:{code,message,details?}}.
 * - mutating calls carry the session's CSRF token in X-CSRF-Token
 * - failures are normalised into ApiError (status 0 = network failure)
 * - a 401 calls the handler registered with onAuthLost() (the app routes to login)
 * - 422 `details` ([{path,message}]) are exposed as err.details; use normalizePath()
 *   to match them against form fields.
 * This module has no DOM access at import time, so its helpers are unit-testable in Node.
 */
const BASE = '/api/v1';
let csrf = null;
let authLost = () => {};

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = Array.isArray(details) ? details : [];
  }
}

export const setCsrf = (token) => { csrf = token; };
export const onAuthLost = (fn) => { authLost = fn; };

/** "a.b[0].c" or "/a/b/0/c" -> "a.b.0.c" (the form used in data-path attributes). */
export function normalizePath(p) {
  return String(p ?? '').replace(/\[(\d+)\]/g, '.$1').replace(/\//g, '.').replace(/^\.+/, '');
}

/**
 * request(method, path, {body, raw, contentType, quiet401})
 * - body: JSON-serialised; raw: sent as-is with contentType (restore upload)
 * - quiet401: do not trigger authLost (login attempts, session probe)
 */
async function request(method, path, { body, raw, contentType = 'text/plain', quiet401 = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  let payload;
  if (raw !== undefined) {
    payload = raw;
    headers['Content-Type'] = contentType;
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
  }
  let res;
  try {
    res = await fetch(BASE + path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach the router. Check the connection and try again.');
  }
  if (res.status === 401 && !quiet401) authLost();
  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('json')) {
    const text = await res.text().catch(() => '');
    if (!res.ok) throw new ApiError(res.status, `http_${res.status}`, text.slice(0, 200) || res.statusText);
    return text; // e.g. /firewall/preview
  }
  let json;
  try {
    json = await res.json();
  } catch {
    throw new ApiError(res.status, 'bad_response', 'The router sent an unreadable response.');
  }
  if (!res.ok || json.ok === false) {
    const e = json.error ?? {};
    throw new ApiError(res.status, e.code ?? `http_${res.status}`, e.message ?? res.statusText, e.details);
  }
  return json.data;
}

export const api = {
  get: (path, o) => request('GET', path, o),
  post: (path, body, o) => request('POST', path, { ...o, body }),
  put: (path, body, o) => request('PUT', path, { ...o, body }),
  del: (path, o) => request('DELETE', path, o),
  upload: (path, raw, contentType) => request('POST', path, { raw, contentType }),
};
