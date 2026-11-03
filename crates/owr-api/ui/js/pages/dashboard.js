/* pages/dashboard.js - #/ : front panel, status tiles, radios summary, recent log.
 *
 * The front panel is built from GET /board (ethernet.ports) - port names are never hard-coded -
 * and coloured from GET /network/status. Refreshes every 5 s via poll() (backoff on errors,
 * paused while the tab is hidden). The DOM is built once with fixed-size skeleton tiles and
 * only text/classes are updated afterwards, so nothing jumps.
 */
import { api } from '../api.js';
import { state, loadBoard } from '../state.js';
import {
  h, svg, card, pageHeader, table, badge, poll, logRow, fmtBytes, fmtDuration, fmtSpeed, fmtBand, fmtClock,
} from '../ui.js';

const PORT_W = 84, PORT_H = 62, GAP = 14, PAD = 22, HEIGHT = 150;

/** SVG rear panel. Returns {el, update(interfaces)}. */
function frontPanel(board, cfg) {
  const ports = board.ethernet.ports;
  const width = PAD * 2 + ports.length * PORT_W + (ports.length - 1) * GAP;
  const net = cfg?.network;
  const roleLabel = (p) => {
    if (!net) return p.role.toUpperCase();
    if (net.wan.port === p.name) return 'WAN';
    const v = net.vlans?.find((x) => x.ports.includes(p.name));
    return v ? `VLAN ${v.name}` : 'LAN';
  };
  const nodes = ports.map((p, i) => {
    const x = PAD + i * (PORT_W + GAP);
    const title = svg('title');
    const speed = svg('text', { class: 'fp-speed', x: x + PORT_W / 2, y: 46 + PORT_H / 2 + 6 });
    const a = svg('a', { href: '#/network', class: 'port', 'aria-label': p.name }, [
      title,
      svg('text', { class: 'fp-name', x: x + PORT_W / 2, y: 36 }, p.name.replace(/(\D)(\d)/, '$1 $2').toUpperCase()),
      svg('rect', { class: 'fp-port', x, y: 46, width: PORT_W, height: PORT_H, rx: 6 }),
      speed,
      svg('text', { class: 'fp-role', x: x + PORT_W / 2, y: 46 + PORT_H + 22 }, roleLabel(p)),
    ]);
    return { p, a, title, speed };
  });
  const el = svg('svg', { viewBox: `0 0 ${width} ${HEIGHT}`, class: 'frontpanel', role: 'group', 'aria-label': 'Rear panel of the router' }, [
    svg('rect', { class: 'fp-body', x: 1, y: 1, width: width - 2, height: HEIGHT - 2, rx: 10 }),
    nodes.map((n) => n.a),
  ]);
  return {
    el,
    update(interfaces = []) {
      for (const { p, a, title, speed } of nodes) {
        const i = interfaces.find((x) => x.name === p.name || x.name === p.netdev);
        const up = !!i?.carrier;
        a.setAttribute('class', `port ${up ? 'up' : 'down'}`);
        speed.textContent = fmtSpeed(up ? i.speed_mbps : p.speed_mbps);
        const label = up ? `${p.name}: connected at ${i.speed_mbps} Mbit/s` : `${p.name}: no cable (supports up to ${p.speed_mbps} Mbit/s)`;
        title.textContent = label;
        a.setAttribute('aria-label', `${label}. Open network settings.`);
      }
    },
  };
}

export default async function dashboard(root, signal) {
  const board = await loadBoard();
  const panel = frontPanel(board, state.config);
  const tiles = {};
  const tile = (key, label, bar) => {
    const value = h('div', { class: 'tile-value' });
    const sub = h('div', { class: 'tile-sub' });
    const meter = bar && h('progress', { max: 100, value: 0, 'aria-label': label });
    tiles[key] = { el: h('div', { class: 'tile skeleton' }, [h('div', { class: 'tile-label' }, label), value, meter, sub]), value, sub, meter };
    return tiles[key].el;
  };
  const set = (key, value, sub = '', pct) => {
    const t = tiles[key];
    t.el.classList.remove('skeleton');
    t.value.textContent = value;
    t.sub.textContent = sub;
    if (t.meter && pct != null) t.meter.value = pct;
  };

  const updated = h('span', { class: 'muted' }, 'Loading...');
  const conn = h('span', { class: 'conn', role: 'status' });
  const radios = h('div', { class: 'dyn' }, h('div', { class: 'skeleton block' }));
  const tail = h('div', { class: 'logbox small', role: 'log', 'aria-label': 'Recent events', 'aria-live': 'off' });

  root.append(
    pageHeader('Home', 'Live overview of your router.'),
    card('Rear ports', [panel.el, h('p', { class: 'muted legend' }, [badge('Cable connected', 'ok'), ' ', badge('No cable'), ' Select a port to open network settings.'])]),
    h('div', { class: 'tiles' }, [
      tile('wan', 'Internet'), tile('clients', 'Wi-Fi devices'), tile('temp', 'CPU temperature'),
      tile('mem', 'Memory in use', true), tile('load', 'CPU load'), tile('uptime', 'Running for'),
    ]),
    h('div', { class: 'grid' }, [card('Wi-Fi radios', radios), card('Recent events', [tail, h('p', [h('a', { href: '#/logs' }, 'Open full log')])])]),
    h('p', { class: 'status-line' }, [updated, ' ', conn]),
  );

  function showSystem(s) {
    const used = s.mem.total_kib - s.mem.available_kib;
    set('mem', `${fmtBytes(used * 1024)} of ${fmtBytes(s.mem.total_kib * 1024)}`, `${Math.round((used / s.mem.total_kib) * 100)}% used`, (used / s.mem.total_kib) * 100);
    set('uptime', fmtDuration(s.uptime_secs), `${s.hostname}, ${new Date(s.time_unix * 1000).toLocaleTimeString()}`);
    set('load', s.load.map((x) => x.toFixed(2)).join('  '), '1 / 5 / 15 minutes');
    const c = s.cpu_temp_mc == null ? null : s.cpu_temp_mc / 1000;
    set('temp', c == null ? 'n/a' : `${c.toFixed(0)}°C`, c == null ? '' : c >= 85 ? 'Hot - check ventilation' : 'Normal');
    tiles.temp.el.classList.toggle('warn', c != null && c >= 85);
  }

  function showNetwork(n) {
    panel.update(n.interfaces);
    if (n.wan) set('wan', n.wan.addr ?? '-', `${n.wan.proto}, gateway ${n.wan.gateway ?? '-'}, up ${fmtDuration(n.wan.uptime_secs)}`);
    else set('wan', 'Not connected', 'No internet link detected');
  }

  function showWireless(w) {
    set('clients', String(w.aps.reduce((n, ap) => n + ap.clients.length, 0)), `${w.aps.length} Wi-Fi network${w.aps.length === 1 ? '' : 's'}`);
    radios.replaceChildren(table(['Radio', 'Channel', 'Width', 'Power', 'Networks'], w.radios.map((r) => [
      [h('strong', fmtBand(r.band)), ' ', r.enabled ? null : badge('off')],
      r.channel ?? '-', r.width_mhz ? `${r.width_mhz} MHz` : '-', r.txpower_dbm != null ? `${r.txpower_dbm} dBm` : '-',
      w.aps.filter((a) => a.radio === r.id).map((a) => `${a.ssid} (${a.clients.length})`).join(', ') || '-',
    ]), { empty: 'No radios reported.' }));
  }

  async function refresh() {
    const results = await Promise.allSettled([
      api.get('/system/status'), api.get('/network/status'), api.get('/wireless/status'), api.get('/logs?limit=8'),
    ]);
    const [sys, net, wl, logs] = results;
    if (results.every((r) => r.status === 'rejected')) throw sys.reason;
    if (signal.aborted) return;
    if (sys.status === 'fulfilled') showSystem(sys.value);
    if (net.status === 'fulfilled') showNetwork(net.value);
    if (wl.status === 'fulfilled') showWireless(wl.value);
    if (logs.status === 'fulfilled') tail.replaceChildren(...[...logs.value].sort((a, b) => a.seq - b.seq).map(logRow));
    updated.textContent = `Updated ${fmtClock(Date.now())}`;
    conn.textContent = '';
  }

  poll(refresh, {
    signal,
    onError: (e, delay) => { conn.textContent = `Connection problem: ${e.message} Retrying in ${Math.round(delay / 1000)} s.`; },
  });
}
