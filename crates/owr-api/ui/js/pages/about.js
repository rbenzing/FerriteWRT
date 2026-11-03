/* pages/about.js - #/about: hardware spec sheet rendered entirely from GET /board
 * (same shape as boards/<id>.toml). Missing sections are skipped, so other boards render too. */
import { api } from '../api.js';
import { loadBoard } from '../state.js';
import { h, card, pageHeader, table, kv, badge, fmtBytes, fmtSpeed, fmtBand } from '../ui.js';

const dash = (v) => (v === undefined || v === null || v === '' ? '-' : v);
const yesNo = (v) => (v ? 'Yes' : 'No');
const hexSize = (s) => { const n = Number.parseInt(s, 16); return Number.isFinite(n) ? fmtBytes(n) : '-'; };
const badges = (list) => h('span', (list ?? []).map((x) => [badge(x), ' ']));

export default async function about(root) {
  const b = await loadBoard();
  const status = await api.get('/system/status').catch(() => null);
  const eth = b.ethernet ?? {};
  const sw = eth.switch;

  root.append(
    pageHeader('About this router', 'Hardware specification, generated from the board description.'),
    h('div', { class: 'grid' }, [
      card('Overview', kv([
        ['Vendor', b.board?.vendor], ['Model', b.board?.model], ['Board id', h('code', dash(b.board?.id))],
        ['Compatible', badges(b.board?.compatible)],
        status && ['Firmware', `${status.firmware.version} (build ${status.firmware.build})`],
      ].filter(Boolean))),
      card('Processor & memory', kv([
        ['SoC', b.soc?.family], ['CPU', `${dash(b.soc?.cores)} x ${dash(b.soc?.cpu)} (${dash(b.soc?.arch)})`],
        ['Features', badges(b.soc?.features)], ['Memory', b.memory?.ram_mib ? `${b.memory.ram_mib} MiB RAM` : '-'],
        ['Serial console', b.console ? `${b.console.device} at ${b.console.baud} baud` : '-'],
      ])),
      card('Storage', kv([
        ['Type', b.storage?.kind?.toUpperCase()], ['Device', h('code', dash(b.storage?.device))],
        ['Root file system', h('code', dash(b.storage?.root))],
        ['Settings storage', `${dash(b.storage?.overlay)} (${dash(b.storage?.overlay_fs)})`],
      ])),
      card('USB', (b.usb?.controllers ?? []).length
        ? table(['Controller', 'USB version', 'Power switch GPIO'], b.usb.controllers.map((c, i) => [`#${i + 1}`, c.version, dash(c.vbus_gpio)]))
        : h('p', { class: 'muted' }, 'No USB ports.')),
    ]),
    card('Ethernet ports', [
      sw && kv([['Switch chip', `${sw.driver}${sw.dsa ? ' (DSA)' : ''}`], ['Link to the CPU', `${fmtSpeed(sw.cpu_link_mbps)} via ${sw.cpu_netdev}`]]),
      table(['Port', 'Network device', 'Default role', 'Speed', 'Switch port', 'PHY', 'MAC offset'], (eth.ports ?? []).map((p) => [
        h('strong', p.name.toUpperCase()), h('code', p.netdev), p.role, fmtSpeed(p.speed_mbps), dash(p.switch_port),
        p.phy ? `${p.phy.kind} @ ${p.phy.mdio_addr}` : 'built into the switch', `+${dash(p.mac_offset)}`,
      ]), { caption: 'Ethernet ports' }),
    ]),
    card('Wi-Fi', [
      h('p', { class: 'muted' }, `Driver: ${dash(b.wifi?.driver)}`),
      table(['Radio', 'PHY', 'Band', 'Max channel width', 'Standards', 'MAC offset'], (b.wifi?.radios ?? []).map((r) => [
        h('strong', r.id), `phy${dash(r.phy_index)}`, fmtBand(r.band), `${dash(r.max_width_mhz)} MHz`, badges((r.standards ?? []).map((s) => `802.11${s}`)), `+${dash(r.mac_offset)}`,
      ]), { caption: 'Radios' }),
    ]),
    h('div', { class: 'grid' }, [
      card('Lights', table(['LED', 'GPIO', 'Active low', 'Used for'], (b.leds ?? []).map((l) => [h('code', l.name), l.gpio, yesNo(l.active_low), badges(l.roles)]), { empty: 'No LEDs described.' })),
      card('Buttons', table(['Button', 'GPIO', 'Short press', 'Long press'], (b.buttons ?? []).map((x) => [
        h('strong', x.name), x.gpio, dash(x.short_press), x.long_press ? `${x.long_press} after ${x.long_press_secs} s` : '-',
      ]), { empty: 'No buttons described.' })),
    ]),
    card('Flash layout', table(['Partition', 'Role', 'Size'], (b.storage?.partitions ?? []).map((p) => [h('code', p.name), p.role, p.size ? hexSize(p.size) : 'rest of device']), { caption: 'Partitions' })),
  );
}
