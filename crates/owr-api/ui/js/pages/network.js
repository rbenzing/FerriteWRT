/* pages/network.js - #/network: LAN, WAN, port roles and VLANs (edits the config draft).
 *
 * Port roles are derived from the config (wan.port, lan.ports, vlans[].ports) and written back
 * together by writeRoles(), so a port always belongs to exactly one of lan / wan / one VLAN.
 * Exports wanProto() for reuse by the first-boot wizard (pages/setup.js).
 */
import { api } from '../api.js';
import { state, loadBoard, ensureConfig } from '../state.js';
import {
  h, field, card, pageHeader, table, badge, btn, dynamic, control, toast, confirmDialog, edited, getPath, rules, fmtSpeed,
  parseCidr, cidrOverlap, cidrHas, ipv4ToInt,
} from '../ui.js';

const PROTO_TYPES = [
  { value: 'dhcp', label: 'Automatic (DHCP) - most home connections' },
  { value: 'static', label: 'Fixed IP address (static)' },
  { value: 'pppoe', label: 'Username and password (PPPoE) - DSL / some fibre' },
];

const PROTO_DEFAULTS = {
  dhcp: () => ({ type: 'dhcp' }),
  static: () => ({ type: 'static', ipv4: '', gateway: '', dns: [] }),
  pppoe: () => ({ type: 'pppoe', username: '', password: '' }),
};

/**
 * Connection-type selector plus the fields of the chosen type. `wan` is the config's wan object;
 * `subnetCheck` (optional) is an extra rule for the static address (overlap with other subnets).
 */
export function wanProto(wan, errBase = 'network.wan', subnetCheck = null) {
  const F = (path, o) => field(wan, path, { ...o, errPath: `${errBase}.${path}` });
  const gatewayInSubnet = (g) => {
    const net = parseCidr(wan.proto.ipv4);
    if (!net) return null; // the address field reports its own problem
    const ip = ipv4ToInt(g);
    if (!cidrHas(net, ip)) return `The gateway must be inside your network (${wan.proto.ipv4}).`;
    return ip === net.net || ip === net.last || ip === net.addr ? 'Use the provider\x27s gateway, not the network, broadcast or your own address.' : null;
  };
  const recheckGateway = () => {
    const gw = detail.querySelector(`[data-path="${errBase}.proto.gateway"]`);
    if (gw?.value) gw._validate();
  };
  const fields = {
    dhcp: () => F('proto.hostname', { label: 'Hostname to send', optional: true, validate: rules.hostname, hint: 'Optional. Only needed if your provider asks for it.' }),
    static: () => [
      F('proto.ipv4', { label: 'IP address / mask', required: true, validate: [rules.ipv4CidrWan, subnetCheck].filter(Boolean), onChange: recheckGateway, hint: 'From your provider, as address/prefix, e.g. 203.0.113.10/24' }),
      F('proto.gateway', { label: 'Gateway', required: true, validate: [rules.ipv4, gatewayInSubnet] }),
      F('proto.dns', { label: 'DNS servers', type: 'list', required: true, validate: rules.each(rules.ip), hint: 'Separate several with commas.' }),
    ],
    pppoe: () => [
      F('proto.username', { label: 'Username', required: true, autocomplete: 'off' }),
      F('proto.password', { label: 'Password', type: 'password', required: true, hint: 'Shown as *** once saved; leave it to keep the current password.' }),
      F('proto.service', { label: 'Service name', optional: true, hint: 'Optional.' }),
    ],
  };
  const detail = dynamic(() => h('div', fields[wan.proto.type]?.()));
  return h('div', [
    F('proto.type', {
      label: 'Connection type', type: 'select', options: PROTO_TYPES,
      onChange(t) { wan.proto = PROTO_DEFAULTS[t](); detail.refresh(); },
    }),
    detail,
  ]);
}

/* ---------- port roles ---------- */

/**
 * Per-VLAN editing state kept outside the config (the server rejects unknown keys):
 * key = stable id used as the port-role value, so renaming a VLAN never disturbs port roles;
 * applied = the name Wi-Fi networks currently point at (follows the name once a rename is committed).
 */
const vlanMeta = new WeakMap();
let vlanSeq = 0;
const meta = (v) => {
  if (!vlanMeta.has(v)) vlanMeta.set(v, { key: `vlan:${++vlanSeq}`, applied: v.name });
  return vlanMeta.get(v);
};

const rolesOf = (net, names) => Object.fromEntries(names.map((n) => {
  const vlan = net.vlans.find((v) => v.ports.includes(n));
  return [n, net.wan.port === n ? 'wan' : vlan ? meta(vlan).key : 'lan'];
}));

function writeRoles(net, names, r) {
  net.lan.ports = names.filter((n) => r[n] === 'lan');
  net.wan.port = names.find((n) => r[n] === 'wan');
  for (const v of net.vlans) v.ports = names.filter((n) => r[n] === meta(v).key);
}

/** DHCP pool fields for config object `root` at `base` (e.g. network.lan.dhcp). */
function dhcpFields(root, base) {
  const lease = getPath(root, `${base}.lease`);
  const num = rules.int(1, 65534);
  return [
    field(root, `${base}.start`, { label: 'First address', type: 'number', required: true, validate: num, hint: 'Host number where the pool starts, e.g. 100 gives 192.168.8.100.' }),
    field(root, `${base}.limit`, { label: 'Number of addresses', type: 'number', required: true, validate: num, hint: 'How many devices can get an address.' }),
    typeof lease === 'number'
      ? field(root, `${base}.lease`, { label: 'Lease time (seconds)', type: 'number', required: true, validate: rules.int(120, 31536000) })
      : field(root, `${base}.lease`, { label: 'Lease time', required: true, hint: 'How long a device keeps its address, e.g. 12h, 30m or 1d.', validate: (v) => (/^\d+[smhd]?$/.test(v) ? null : 'Use a number with s, m, h or d, for example 12h.') }),
  ];
}

export default async function network(root, signal) {
  const [board] = await Promise.all([loadBoard(), ensureConfig()]);
  const cfg = state.draft;
  const net = cfg.network;
  const ports = board.ethernet.ports;
  const names = ports.map((p) => p.name);
  const live = await api.get('/network/status').catch(() => null);
  if (signal.aborted) return;
  const iface = (p) => live?.interfaces.find((i) => i.name === p.name || i.name === p.netdev);
  const F = (path, o) => field(cfg, path, o);

  /** Rule: the subnet must not overlap the LAN, another VLAN or a static WAN address (like the server). `self` = 'lan' | 'wan' | vlan object. */
  const noOverlap = (self) => (value) => {
    const mine = parseCidr(value);
    if (!mine) return null;
    const others = [
      ['lan', 'the home network', net.lan.ipv4],
      ...net.vlans.map((v) => [v, `VLAN ${v.name}`, v.ipv4]),
      ['wan', 'the Internet connection', net.wan.proto.type === 'static' ? net.wan.proto.ipv4 : null],
    ];
    for (const [key, label, cidr] of others) {
      const other = key !== self && cidr ? parseCidr(cidr) : null;
      if (other && cidrOverlap(mine, other)) return `Overlaps ${label} (${cidr}).`;
    }
    return null;
  };

  /* LAN */
  const lanDhcp = dynamic(() => h('div', net.lan.dhcp.enabled ? dhcpFields(cfg, 'network.lan.dhcp') : null));
  const lan = card('Home network (LAN)', [
    F('network.lan.ipv4', { label: 'Router address', required: true, validate: [rules.ipv4Cidr, noOverlap('lan')], hint: 'LAN IP address and mask, e.g. 192.168.8.1/24. Changing it means reconnecting at the new address.' }),
    F('network.lan.dhcp.enabled', { label: 'Give addresses to devices', type: 'toggle', hint: 'DHCP server', onChange: lanDhcp.refresh }),
    lanDhcp,
    F('network.lan.ipv6', { label: 'IPv6 on the home network', type: 'select', hint: 'ULA = private IPv6 addresses for local use', options: [{ value: 'ula', label: 'Private addresses (ULA)' }, { value: 'disabled', label: 'Off' }] }),
  ]);

  /* WAN */
  const wanPort = dynamic(() => h('p', { class: 'muted' }, `Internet port: ${net.wan.port?.toUpperCase()}. Change which port is used in "Ports" below.`));
  const wan = card('Internet (WAN)', [
    wanPort,
    wanProto(net.wan, 'network.wan', noOverlap('wan')),
    F('network.wan.ipv6', { label: 'IPv6 from your provider', type: 'select', hint: 'DHCPv6', options: [{ value: 'dhcpv6', label: 'Automatic (DHCPv6)' }, { value: 'disabled', label: 'Off' }] }),
    F('network.wan.mac_override', { label: 'Clone a MAC address', optional: true, validate: rules.mac, hint: 'Optional. Use the MAC of your old router if your provider locks to it. Empty = factory address.' }),
    F('network.wan.mtu', { label: 'MTU', type: 'number', optional: true, min: 576, max: 9000, validate: rules.int(576, 9000), hint: 'Optional. Leave empty unless your provider tells you otherwise (PPPoE is usually 1492).' }),
  ]);

  /* Ports */
  const roleOptions = () => [
    { value: 'lan', label: 'Home network (LAN)' }, { value: 'wan', label: 'Internet (WAN)' },
    ...net.vlans.map((v) => ({ value: meta(v).key, label: `VLAN ${v.name}` })),
  ];
  function setRole(name, value) {
    const r = rolesOf(net, names);
    if (r[name] === 'wan' && value !== 'wan') {
      toast('Exactly one port must be the Internet (WAN) port. Pick another port as WAN instead.', 'error');
    } else {
      if (value === 'wan') for (const n of names) if (r[n] === 'wan') r[n] = 'lan';
      r[name] = value;
      writeRoles(net, names, r);
    }
    edited();
    portsBox.refresh();
    vlanBox.refresh();
    wanPort.refresh();
  }
  const portsBox = dynamic(() => {
    const r = rolesOf(net, names);
    return table(['Port', 'Speed', 'Link', 'Use as'], ports.map((p) => {
      const i = iface(p);
      return [
        h('strong', p.name.toUpperCase()),
        fmtSpeed(p.speed_mbps),
        i ? (i.carrier ? badge(`Up ${fmtSpeed(i.speed_mbps)}`, 'ok') : badge('No cable', '')) : '-',
        control(r, `[${p.name}]`, { type: 'select', options: roleOptions(), aria: `Use of port ${p.name}`, errPath: `ports[${p.name}]`, onChange: (v) => setRole(p.name, v) }),
      ];
    }), { caption: 'Ethernet ports' });
  });
  const portsCard = card('Ports', portsBox, { sub: 'Choose what each socket on the back is used for. Exactly one port is the Internet (WAN) port.' });

  /* VLANs */
  function removeVlan(i) {
    const v = net.vlans[i];
    confirmDialog({
      title: `Remove VLAN ${v.name}?`, danger: true, confirmText: 'Remove',
      message: 'Its ports move back to the home network and Wi-Fi networks using it move to the home network.',
    }).then((ok) => {
      if (!ok) return;
      for (const ap of cfg.wireless?.aps ?? []) if (ap.network === meta(v).applied || ap.network === v.name) ap.network = 'lan';
      net.vlans.splice(i, 1);
      writeRoles(net, names, rolesOf(net, names));
      edited();
      portsBox.refresh();
      vlanBox.refresh();
    });
  }

  function addVlan() {
    const id = Math.max(9, ...net.vlans.map((v) => v.id)) + 1;
    net.vlans.push({ name: `vlan${id}`, id, ports: [], ipv4: `192.168.${id % 256}.1/24`, isolated: true });
    edited();
    vlanBox.refresh();
  }

  function vlanCard(v, i) {
    const P = `network.vlans.${i}`;
    const Fv = (k, o) => field(cfg, `${P}.${k}`, o);
    const unique = (key, msg) => (x) => (net.vlans.some((o, j) => j !== i && o[key] === x) ? msg : null);
    const dh = { on: !!v.dhcp?.enabled };
    const title = h('h3', `VLAN ${v.name}`);
    const dhcpBox = dynamic(() => h('div', v.dhcp?.enabled ? dhcpFields(cfg, `${P}.dhcp`) : null));
    return h('div', { class: 'subcard' }, [
      h('header', { class: 'card-head' }, [title, btn('Remove', () => removeVlan(i), { variant: 'danger small', icon: 'trash' })]),
      Fv('name', {
        label: 'Name', required: true, validate: [rules.len(1, 12), (x) => (/^[a-z][a-z0-9_]*$/.test(x) && !['lan', 'wan'].includes(x) ? null : 'Lowercase letters, digits and underscore, starting with a letter; not "lan" or "wan".'), unique('name', 'Name already used.')],
        onChange(n) { title.textContent = `VLAN ${n}`; },
        // Wi-Fi networks follow a rename only once it is committed (blur/Enter) and valid, never per keystroke.
        onCommit(n, error) {
          const m = meta(v);
          if (error || n === m.applied) return;
          for (const ap of cfg.wireless?.aps ?? []) if (ap.network === m.applied) ap.network = n;
          m.applied = n;
          edited();
          portsBox.refresh();
        },
      }),
      Fv('id', { label: 'VLAN ID', type: 'number', required: true, min: 1, max: 4094, validate: [rules.int(1, 4094), unique('id', 'ID already used.')], hint: 'Tag number, 1 to 4094.' }),
      Fv('ports', {
        label: 'Ports', hint: 'Sockets that belong to this VLAN (untagged). A port can only be in one place.',
        checks: ports.map((p) => ({ value: p.name, label: `${p.name.toUpperCase()} (${fmtSpeed(p.speed_mbps)})`, disabled: p.name === net.wan.port })),
        onChange() {
          const r = rolesOf(net, names);
          for (const n of v.ports) r[n] = meta(v).key;
          writeRoles(net, names, r);
          portsBox.refresh();
          vlanBox.refresh();
        },
      }),
      Fv('ipv4', { label: 'Subnet', optional: true, validate: [rules.ipv4Cidr, noOverlap(v)], hint: 'Router address on this VLAN, e.g. 192.168.20.1/24. Empty = no routing.' }),
      field(dh, 'on', {
        label: 'Give addresses to devices', type: 'toggle', hint: 'DHCP server for this VLAN', errPath: `${P}.dhcp.enabled`,
        onChange(on) {
          v.dhcp ??= { enabled: false, start: 100, limit: 100, lease: net.lan.dhcp.lease };
          v.dhcp.enabled = on;
          dhcpBox.refresh();
        },
      }),
      dhcpBox,
      Fv('isolated', { label: 'Keep separate', type: 'toggle', hint: 'Isolated: devices here cannot reach other home networks.' }),
    ]);
  }

  const vlanBox = dynamic(() => h('div', [
    net.vlans.length === 0 && h('p', { class: 'muted' }, 'No VLANs yet. A VLAN splits some ports into a separate network, for example for guests or smart-home devices.'),
    net.vlans.map(vlanCard),
    btn('Add VLAN', addVlan, { icon: 'plus' }),
  ]));

  root.append(
    pageHeader('Internet & network', 'How the router connects to the internet and to your devices. Changes apply with the bar at the bottom.'),
    h('div', { class: 'grid' }, [lan, wan]),
    portsCard,
    card('VLANs', vlanBox, { sub: 'Optional separate networks.' }),
  );
}
