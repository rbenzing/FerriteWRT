/* api.js - fetch wrapper for the owr-api JSON API.
 *
 * Every response is {ok:true,data} | {ok:false,error:{code,message,details?}}.
 * - mutating calls carry the session's CSRF token in X-CSRF-Token
 * - failures are normalised into ApiError (status 0 = network failure)
 * - a 401 calls the handler registered with onAuthLost() (the app routes to login)
 * - 422 `details` ([{path,message}]) are exposed as err.details; use normalizePath()
 *   to match them against form fields.
 * - putFile() uploads a File as a raw body with progress (XMLHttpRequest: fetch has no upload progress)
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

const NETWORK_ERROR = 'Cannot reach the router. Check the connection and try again.';

/** Request headers: JSON accepted, the CSRF token on mutations, the body's content type. */
function headersFor(method, contentType) {
  const headers = { Accept: 'application/json' };
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  if (contentType) headers['Content-Type'] = contentType;
  return headers;
}

/** A finished response (status, content type, body text) -> data, or throws ApiError. */
function settle(status, statusText, type, text) {
  const ok = status >= 200 && status < 300;
  if (!type.includes('json')) {
    if (!ok) throw new ApiError(status, `http_${status}`, text.slice(0, 200) || statusText);
    return text; // e.g. /firewall/preview
  }
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ApiError(status, 'bad_response', 'The router sent an unreadable response.');
  }
  if (!ok || json.ok === false) {
    const e = json.error ?? {};
    throw new ApiError(status, e.code ?? `http_${status}`, e.message ?? statusText, e.details);
  }
  return json.data;
}

/**
 * request(method, path, {body, raw, contentType, quiet401})
 * - body: JSON-serialised; raw: sent as-is with contentType (restore upload)
 * - quiet401: do not trigger authLost (login attempts, session probe)
 */
async function request(method, path, { body, raw, contentType = 'text/plain', quiet401 = false } = {}) {
  let payload;
  let type;
  if (raw !== undefined) {
    payload = raw;
    type = contentType;
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    type = 'application/json';
  }
  let res;
  try {
    res = await fetch(BASE + path, { method, headers: headersFor(method, type), body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch {
    throw new ApiError(0, 'network', NETWORK_ERROR);
  }
  if (res.status === 401 && !quiet401) authLost();
  const text = await res.text().catch(() => '');
  return settle(res.status, res.statusText, res.headers.get('content-type') ?? '', text);
}

/**
 * PUT a File/Blob as the raw request body (application/octet-stream), calling
 * onProgress(sentBytes, totalBytes) while it uploads. XMLHttpRequest because fetch() cannot
 * report upload progress; errors are the same ApiError as everywhere else.
 */
function putFile(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', BASE + path);
    for (const [k, v] of Object.entries(headersFor('PUT', 'application/octet-stream'))) xhr.setRequestHeader(k, v);
    xhr.upload.addEventListener('progress', (e) => onProgress?.(e.loaded, e.lengthComputable ? e.total : file.size));
    xhr.addEventListener('load', () => {
      if (xhr.status === 401) authLost();
      try {
        resolve(settle(xhr.status, xhr.statusText, xhr.getResponseHeader('content-type') ?? '', xhr.responseText));
      } catch (e) { reject(e); }
    });
    for (const ev of ['error', 'abort', 'timeout']) xhr.addEventListener(ev, () => reject(new ApiError(0, 'network', NETWORK_ERROR)));
    xhr.send(file);
  });
}

export const api = {
  get: (path, o) => request('GET', path, o),
  post: (path, body, o) => request('POST', path, { ...o, body }),
  put: (path, body, o) => request('PUT', path, { ...o, body }),
  del: (path, o) => request('DELETE', path, o),
  upload: (path, raw, contentType) => request('POST', path, { raw, contentType }),
  putFile,
};
