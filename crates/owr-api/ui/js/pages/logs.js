/* pages/logs.js - #/logs: live log tail with level/source filters, pause and copy.
 * Fetches /logs?since=<last seq> every 2 s (paused while the tab is hidden or "Pause" is on).
 * A log restart (newest seq < last seen seq) resets the view. Entries are kept client-side
 * (bounded) so changing a filter re-renders without refetching.
 */
import { api } from '../api.js';
import { h, control, btn, pageHeader, card, poll, logRow, copyText, icon, PRIO } from '../ui.js';

const MAX = 1000;
const LEVELS = [
  { value: 7, label: 'Everything' }, { value: 6, label: 'Information and above' }, { value: 5, label: 'Notices and above' },
  { value: 4, label: 'Warnings and errors' }, { value: 3, label: 'Errors only' },
];

export default async function logs(root, signal) {
  const f = { level: 7, source: '' };
  let entries = [];
  let lastSeq = 0;
  let paused = false;

  const sources = h('datalist', { id: 'log-sources' });
  const seen = new Set();
  const box = h('div', { class: 'logbox tall', role: 'log', tabindex: '0', 'aria-label': 'System log', 'aria-live': 'off' });
  const match = (e) => e.prio <= f.level && (!f.source || e.source.toLowerCase().includes(f.source.toLowerCase()));
  const atBottom = () => box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  const render = () => { box.replaceChildren(...entries.filter(match).map(logRow)); box.scrollTop = box.scrollHeight; };

  /** The router restarted: its sequence numbers start over, so forget what we have. */
  function restart() {
    lastSeq = 0;
    entries = [];
    box.replaceChildren();
  }

  function add(list) {
    if (list.length && Math.max(...list.map((e) => e.seq)) < lastSeq) restart();
    const fresh = list.filter((e) => e.seq > lastSeq).sort((a, b) => a.seq - b.seq);
    if (!fresh.length) return;
    lastSeq = fresh.at(-1).seq;
    const follow = atBottom();
    entries.push(...fresh);
    for (const e of fresh) {
      if (e.source && !seen.has(e.source)) { seen.add(e.source); sources.append(h('option', { value: e.source })); }
    }
    if (entries.length > MAX) { entries = entries.slice(-MAX); render(); return; }
    box.append(...fresh.filter(match).map(logRow));
    if (follow) box.scrollTop = box.scrollHeight;
  }

  const pauseBtn = btn('Pause', () => {
    paused = !paused;
    pauseBtn.replaceChildren(icon(paused ? 'play' : 'pause'), paused ? 'Resume' : 'Pause');
    pauseBtn.setAttribute('aria-pressed', String(paused));
  }, { icon: 'pause', variant: 'secondary' });
  pauseBtn.setAttribute('aria-pressed', 'false');

  const text = () => entries.filter(match).map((e) => `${new Date(e.ts_ms).toISOString()} ${PRIO[e.prio] ?? e.prio} ${e.source}: ${e.msg}`).join('\n');

  root.append(
    pageHeader('Event log', 'What the router has been doing, newest at the bottom.'),
    sources,
    card('Log', [
      h('div', { class: 'toolbar' }, [
        h('label', { class: 'inline' }, ['Show ', control(f, 'level', { type: 'select', cast: Number, options: LEVELS, onChange: render })]),
        h('label', { class: 'inline' }, ['Source ', control(f, 'source', { list: 'log-sources', placeholder: 'any, e.g. owr-api', onChange: render })]),
        pauseBtn,
        btn('Copy', () => copyText(text()), { icon: 'copy', variant: 'secondary' }),
      ]),
      box,
    ]),
  );
  poll(async () => {
    if (paused) return;
    const list = await api.get(lastSeq ? `/logs?since=${lastSeq}&limit=500` : '/logs?limit=300');
    if (signal.aborted) return;
    add(list);
    if (!list.length && lastSeq) { // idle: the server only returns seq > since, so probe for a restart
      const [newest] = await api.get('/logs?limit=1');
      if (!signal.aborted && newest && newest.seq < lastSeq) restart(); // next poll reloads from scratch
    }
  }, { every: 2000, max: 30000, signal });
}
