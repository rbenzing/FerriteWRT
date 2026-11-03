/* pages/firewall.js - #/firewall: WAN policy, port forwards, traffic rules, offload, ruleset preview.
 *
 * Enumerations (protocols, directions, actions) are the constants below; a value coming from
 * the server that is not in a list is still shown (ui.js control() appends unknown current values).
 * The preview shows the ruleset generated from the *applied* config, not unsaved edits.
 */
import { api } from '../api.js';
import { ensureConfig } from '../state.js';
import { h, field, control, card, pageHeader, table, btn, dynamic, banner, edited, rules, castPortSpec } from '../ui.js';

const FORWARD_PROTOS = [{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'tcp_udp', label: 'TCP + UDP' }];
const RULE_PROTOS = [{ value: 'any', label: 'Any' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'Ping (ICMP)' }];
// owr-config Direction: wan_in = traffic arriving from the internet, lan_out = LAN traffic heading to the internet.
const DIRECTIONS = [
  { value: 'wan_in', label: 'Block/allow from the internet' }, { value: 'lan_out', label: 'Restrict LAN to internet' },
];
const PORT_PROTOS = ['tcp', 'udp']; // the only rule protocols a destination port applies to
const ACTIONS = [{ value: 'accept', label: 'Allow' }, { value: 'drop', label: 'Block silently' }, { value: 'reject', label: 'Block and tell sender' }];
const port = rules.int(1, 65535);

export default async function firewall(root) {
  const cfg = await ensureConfig();
  const fw = cfg.firewall;
  const leases = await api.get('/dhcp/leases').catch(() => []);
  const known = new Map();
  for (const s of cfg.dhcp?.static_leases ?? []) known.set(s.ip, s.hostname || s.mac);
  for (const l of leases) known.set(l.ip, l.hostname || l.mac);
  const hosts = h('datalist', { id: 'known-hosts' }, [...known].map(([ip, name]) => h('option', { value: ip }, name)));

  const cell = (path, o) => control(cfg, path, o);
  const del = (list, i, refresh) => btn('', () => { list.splice(i, 1); edited(); refresh(); }, { icon: 'trash', variant: 'danger small', aria: 'Remove this row' });

  const fwdBox = dynamic(() => table(
    ['Name', 'Protocol', 'Outside port(s)', 'Inside IP address', 'Inside port', 'On', ''],
    fw.port_forwards.map((_, i) => {
      const P = `firewall.port_forwards.${i}`;
      return [
        cell(`${P}.name`, { aria: 'Name', required: true, validate: rules.itemName }),
        cell(`${P}.proto`, { aria: 'Protocol', type: 'select', options: FORWARD_PROTOS }),
        cell(`${P}.wan_port`, { aria: 'Outside port or range', required: true, cast: castPortSpec, validate: rules.portSpec, placeholder: '80 or 8000-8100' }),
        cell(`${P}.dest_ip`, { aria: 'Inside IP address', required: true, list: 'known-hosts', validate: rules.ipv4, placeholder: '192.168.8.50' }),
        cell(`${P}.dest_port`, { aria: 'Inside port', type: 'number', required: true, min: 1, max: 65535, validate: port }),
        cell(`${P}.enabled`, { aria: 'Enabled', type: 'toggle' }),
        del(fw.port_forwards, i, () => fwdBox.refresh()),
      ];
    }),
    { empty: 'No port forwards. Add one to make a device on your network reachable from the internet.', caption: 'Port forwards' },
  ));

  const ruleBox = dynamic(() => table(
    ['Name', 'Direction', 'Protocol', 'From address', 'To port', 'Action', 'On', ''],
    fw.rules.map((rule, i) => {
      const P = `firewall.rules.${i}`;
      const hasPorts = PORT_PROTOS.includes(rule.proto);
      return [
        cell(`${P}.name`, { aria: 'Name', required: true, validate: rules.itemName }),
        cell(`${P}.direction`, { aria: 'Direction', type: 'select', options: DIRECTIONS }),
        cell(`${P}.proto`, {
          aria: 'Protocol', type: 'select', options: RULE_PROTOS,
          onChange(p) { if (!PORT_PROTOS.includes(p)) delete rule.dest_port; ruleBox.refresh(); }, // the server only allows a port with tcp/udp
        }),
        cell(`${P}.src`, { aria: 'From address', optional: true, validate: rules.ipCidr, placeholder: 'any, or 10.0.0.0/24' }),
        cell(`${P}.dest_port`, { aria: 'To port', optional: true, cast: castPortSpec, validate: rules.portSpec, placeholder: hasPorts ? 'any' : 'TCP/UDP only', disabled: !hasPorts }),
        cell(`${P}.action`, { aria: 'Action', type: 'select', options: ACTIONS }),
        cell(`${P}.enabled`, { aria: 'Enabled', type: 'toggle' }),
        del(fw.rules, i, () => ruleBox.refresh()),
      ];
    }),
    { empty: 'No custom rules.', caption: 'Traffic rules' },
  ));

  const addForward = () => {
    fw.port_forwards.push({ name: 'New forward', proto: 'tcp', wan_port: 8080, dest_ip: '192.168.8.100', dest_port: 80, enabled: true });
    edited();
    fwdBox.refresh();
  };
  const addRule = () => {
    fw.rules.push({ name: 'New rule', direction: 'wan_in', proto: 'tcp', action: 'drop', enabled: true });
    edited();
    ruleBox.refresh();
  };

  const code = h('pre', { class: 'code', tabindex: '0', 'aria-label': 'Generated firewall ruleset' }, 'Loading...');
  async function loadPreview() {
    code.textContent = 'Loading...';
    try { code.textContent = await api.get('/firewall/preview'); } catch (e) { code.textContent = `Could not load the ruleset: ${e.message}`; }
  }
  let loaded = false;
  const preview = h('details', {
    class: 'card',
    ontoggle(e) { if (e.target.open && !loaded) { loaded = true; loadPreview(); } },
  }, [
    h('summary', 'Preview ruleset (nftables)'),
    h('p', { class: 'muted' }, 'The ruleset the router is running now. Apply your changes first to see them here.'),
    btn('Reload', loadPreview, { icon: 'refresh', variant: 'ghost small' }),
    code,
  ]);

  root.append(
    pageHeader('Firewall', 'Control what can reach the router and your devices from the internet. Changes apply with the bar at the bottom.'),
    hosts,
    card('Protection', [
      field(cfg, 'firewall.default_wan_input', {
        label: 'Unsolicited traffic from the internet', type: 'select', hint: 'Default WAN input policy. "Block silently" is safest and hides your router from scans.',
        options: [{ value: 'drop', label: 'Block silently (recommended)' }, { value: 'reject', label: 'Block and tell the sender (reject)' }],
      }),
      field(cfg, 'firewall.hw_offload', {
        label: 'Hardware acceleration', type: 'toggle', hint: 'Hardware flow offload: the MT7986 packet engine routes established connections, giving full 2.5G speed at low CPU. Turn off if you use traffic shaping or see odd connection drops.',
      }),
    ]),
    card('Port forwarding', [
      banner('warn', 'Forwarding exposes a device to the internet. Only forward ports for services you trust and keep them updated.'),
      fwdBox, btn('Add port forward', addForward, { icon: 'plus' }),
    ], { sub: 'Let the internet reach a service on one of your devices.' }),
    card('Traffic rules', [ruleBox, btn('Add rule', addRule, { icon: 'plus' })], { sub: 'Allow or block specific traffic.' }),
    preview,
  );
}
