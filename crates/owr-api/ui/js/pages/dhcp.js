/* pages/dhcp.js - #/dhcp: active leases (with "make static"), static leases, upstream DNS, local domain. */
import { api } from '../api.js';
import { ensureConfig } from '../state.js';
import { h, field, control, card, pageHeader, table, btn, dynamic, edited, toast, handleError, rules, fmtDuration } from '../ui.js';

export default async function dhcp(root) {
  const cfg = await ensureConfig();
  const d = cfg.dhcp;
  let leases = await api.get('/dhcp/leases').catch((e) => { toast(`Could not load leases: ${e.message}`, 'error'); return []; });

  const isStatic = (mac) => d.static_leases.some((s) => s.mac.toLowerCase() === mac.toLowerCase());
  function makeStatic(l) {
    d.static_leases.push({ mac: l.mac, ip: l.ip, ...(l.hostname ? { hostname: l.hostname } : {}) });
    edited();
    staticBox.refresh();
    leaseBox.refresh();
    toast(`${l.hostname || l.mac} will always get ${l.ip} once you apply.`, 'success');
  }

  const leaseBox = dynamic(() => {
    const now = Date.now() / 1000;
    return table(['Device', 'IP address', 'MAC address', 'Expires in', ''], leases.map((l) => [
      l.hostname || 'Unknown device', l.ip, l.mac, l.expires_unix ? fmtDuration(l.expires_unix - now) : '-',
      isStatic(l.mac) ? h('span', { class: 'muted' }, 'Reserved') : btn('Make static', () => makeStatic(l), { variant: 'small', title: 'Always give this device this address' }),
    ]), { empty: 'No devices have an address right now.', caption: 'Active leases' });
  });

  const reload = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    try { leases = await api.get('/dhcp/leases'); leaseBox.refresh(); } catch (err) { handleError(err); } finally { b.disabled = false; }
  };

  const unique = (i, key, msg) => (v) => (d.static_leases.some((s, j) => j !== i && String(s[key]).toLowerCase() === String(v).toLowerCase()) ? msg : null);
  const staticBox = dynamic(() => table(['MAC address', 'Reserved IP address', 'Name', ''], d.static_leases.map((_, i) => {
    const P = `dhcp.static_leases.${i}`;
    return [
      control(cfg, `${P}.mac`, { aria: 'MAC address', required: true, validate: [rules.mac, unique(i, 'mac', 'MAC already reserved.')], placeholder: 'aa:bb:cc:dd:ee:ff' }),
      control(cfg, `${P}.ip`, { aria: 'Reserved IP address', required: true, validate: [rules.ipv4, unique(i, 'ip', 'IP already reserved.')], placeholder: '192.168.8.50' }),
      control(cfg, `${P}.hostname`, { aria: 'Name', optional: true, validate: rules.hostname }),
      btn('', () => { d.static_leases.splice(i, 1); edited(); staticBox.refresh(); leaseBox.refresh(); }, { icon: 'trash', variant: 'danger small', aria: 'Remove this reservation' }),
    ];
  }), { empty: 'No reservations.', caption: 'Static leases' }));

  root.append(
    pageHeader('Devices & DHCP', 'Who is on your network, and how names and addresses are handed out.'),
    card('Connected devices', leaseBox, { sub: 'Devices that currently hold an address from the router (DHCP leases).', actions: [btn('Refresh', reload, { icon: 'refresh', variant: 'ghost small' })] }),
    card('Reserved addresses', [
      staticBox,
      btn('Add reservation', () => { d.static_leases.push({ mac: '', ip: '' }); edited(); staticBox.refresh(); }, { icon: 'plus' }),
    ], { sub: 'Static leases: a device with a given MAC address always gets the same IP address.' }),
    card('Names and DNS', [
      field(cfg, 'dhcp.dns_servers', { label: 'Upstream DNS servers', type: 'list', validate: rules.each(rules.ip), hint: 'Leave empty to use the servers your provider gives. Separate several with commas, e.g. 1.1.1.1, 9.9.9.9.' }),
      field(cfg, 'dhcp.local_domain', { label: 'Local domain', required: true, validate: rules.domain, hint: 'Devices are reachable as name.<domain>, e.g. lan.' }),
      field(cfg, 'dhcp.rebind_protection', { label: 'Block DNS rebinding', type: 'toggle', hint: 'Rejects internet names that resolve to private addresses, a trick used to attack home networks. Turn off only if a service needs it.' }),
    ]),
  );
}
