// Full report: a self-contained, printable HTML document plus CSV / JSON exports.

import { toCsv } from './backend.js';
import { deviceKey, deviceList, displayName } from './inventory.js';

const labelOf = (inv, h) => inv?.devices[deviceKey(h)]?.label || '';
const knownOf = (inv, h) => !!inv?.devices[deviceKey(h)]?.trusted;

export const esc = (v) =>
  String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

export function formatBytes(n) {
  if (n == null || Number.isNaN(n)) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatDateTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'medium' });
}

export const portList = (h) => (h.open_ports || []).map((p) => `${p.port} ${p.service}`);

export function hostServices(h) {
  const out = new Set();
  for (const s of h.mdns?.services || []) out.add(s);
  if (h.upnp) out.add('UPnP');
  return [...out];
}

export function hostModel(h) {
  const u = h.upnp || {};
  const parts = [u.manufacturer, u.model_name, u.model_number].filter(Boolean);
  if (parts.length) return parts.join(' ');
  return h.mdns?.model || '';
}

// ------------------------------------------------------------------ CSV ---

export function networkCsv(scan, inv = null) {
  return toCsv(
    scan.hosts,
    [
      'ip',
      (h) => labelOf(inv, h) || h.display_name,
      'display_name',
      (h) => (knownOf(inv, h) ? 'Yes' : 'No'),
      'device_type',
      'mac_address',
      'vendor',
      (h) => (h.private_mac ? 'Yes' : 'No'),
      'hostname',
      'netbios_name',
      'workgroup',
      (h) => h.mdns?.hostname,
      hostModel,
      (h) => h.upnp?.device_type,
      hostServices,
      portList,
      (h) => (h.latency_ms != null ? h.latency_ms.toFixed(1) : ''),
      (h) => [...(h.found_by || [])],
      'interface',
      (h) => (h.smb1 == null ? '' : h.smb1 ? 'Yes' : 'No'),
    ],
    [
      'IP address',
      'Name',
      'Detected name',
      'Known',
      'Device type',
      'MAC address',
      'Vendor',
      'Private MAC',
      'DNS name',
      'NetBIOS name',
      'Workgroup',
      'mDNS host name',
      'Model',
      'UPnP device type',
      'Services',
      'Open ports',
      'Latency (ms)',
      'Found by',
      'Interface',
      'SMBv1 enabled',
    ],
  );
}

export function attachedCsv(a) {
  const rows = [];
  for (const u of a.usb_devices || [])
    rows.push({
      section: 'USB device',
      name: u.name,
      type: (u.functions || []).join('; '),
      connection: 'USB',
      manufacturer: u.vendor_name,
      details: `VID:PID ${u.vendor_id}:${u.product_id}${u.serial_number ? `; serial ${u.serial_number}` : ''}`,
      status: u.status,
    });
  for (const d of a.drives || [])
    rows.push({
      section: 'Physical drive',
      name: d.model,
      type: d.media_type,
      connection: d.is_external ? `External (${d.interface || ''})` : d.interface,
      manufacturer: '',
      details: `${formatBytes(d.size_bytes)}; letters ${(d.drive_letters || []).join(' ')}; serial ${d.serial_number || ''}`,
      status: d.status,
    });
  for (const v of a.volumes || [])
    rows.push({
      section: 'Volume',
      name: `${v.name} ${v.label || ''}`.trim(),
      type: v.kind,
      connection: v.network_path || v.physical_drive || '',
      manufacturer: '',
      details: `${v.file_system || ''}; ${formatBytes(v.free_bytes)} free of ${formatBytes(v.total_bytes)}`,
      status: '',
    });
  for (const p of a.printers || [])
    rows.push({
      section: 'Printer',
      name: p.name,
      type: p.driver,
      connection: p.is_network ? 'Network' : p.port,
      manufacturer: '',
      details: [p.is_default && 'Default', p.is_shared && 'Shared', p.location].filter(Boolean).join('; '),
      status: p.is_offline ? 'Offline' : p.status,
    });
  for (const m of a.monitors || [])
    rows.push({
      section: 'Monitor',
      name: m.name,
      type: '',
      connection: '',
      manufacturer: m.manufacturer,
      details: [m.serial_number && `serial ${m.serial_number}`, m.year_of_manufacture && `made ${m.year_of_manufacture}`].filter(Boolean).join('; '),
      status: '',
    });
  for (const d of a.devices || [])
    rows.push({
      section: d.is_peripheral ? 'Peripheral' : 'System device',
      name: d.name,
      type: d.category,
      connection: d.connection,
      manufacturer: d.manufacturer,
      details: [d.vendor_id && `VID:PID ${d.vendor_id}:${d.product_id || ''}`, d.device_id].filter(Boolean).join('; '),
      status: d.status,
    });
  return toCsv(
    rows,
    ['section', 'name', 'type', 'connection', 'manufacturer', 'details', 'status'],
    ['Section', 'Name', 'Type', 'Connection', 'Manufacturer', 'Details', 'Status'],
  );
}

// ----------------------------------------------------------------- HTML ---

const CSS = `
:root{--text:#0f172a;--muted:#64748b;--border:#e2e8f0;--accent:#0f766e;--bg:#fff;--alt:#f8fafc}
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,Roboto,sans-serif;color:var(--text);background:var(--bg);margin:0;padding:32px;line-height:1.45;font-size:14px}
header{border-bottom:3px solid var(--accent);padding-bottom:12px;margin-bottom:20px}
h1{margin:0 0 4px;font-size:24px}
h2{font-size:18px;margin:28px 0 10px;padding-bottom:4px;border-bottom:1px solid var(--border);color:var(--accent)}
h3{font-size:15px;margin:18px 0 8px}
.meta{color:var(--muted)}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.stat{border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.stat b{display:block;font-size:22px}
.stat span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;margin:6px 0 12px;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{background:var(--alt);font-weight:600}
tr:nth-child(even) td{background:var(--alt)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0}
.mono{font-family:Consolas,'Cascadia Mono',ui-monospace,monospace}
.note{color:var(--muted);font-size:12.5px;margin:4px 0}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;background:#ccfbf1;color:#134e4a;font-size:11px;margin:1px 2px 1px 0}
.device{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:8px 0;break-inside:avoid}
.device h3{margin:0 0 6px}
.tag.new{background:#fef3c7;color:#92400e}
.sev{display:inline-block;min-width:58px;text-align:center;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:700;margin-right:6px}
.sev-high .sev{background:#fee2e2;color:#b91c1c}.stat.sev-high b{color:#b91c1c}
.sev-medium .sev{background:#fef3c7;color:#b45309}.stat.sev-medium b{color:#b45309}
.sev-low .sev{background:#e0f2fe;color:#075985}.stat.sev-low b{color:#075985}
.sev-info .sev{background:#f1f5f9;color:#475569}
.finding{border:1px solid var(--border);border-left-width:4px;border-radius:6px;padding:8px 12px;margin:8px 0;break-inside:avoid}
.finding.sev-high{border-left-color:#dc2626}.finding.sev-medium{border-left-color:#d97706}.finding.sev-low{border-left-color:#0284c7}.finding.sev-info{border-left-color:#94a3b8}
.finding p{margin:4px 0}
footer{margin-top:32px;padding-top:10px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}
@media print{body{padding:0;font-size:11px}h2{break-after:avoid}.device{break-inside:avoid}}
`;

const dl = (pairs) =>
  `<dl>${pairs
    .filter(([, v]) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${Array.isArray(v) ? v.map(esc).join('<br>') : esc(v)}</dd>`)
    .join('')}</dl>`;

const table = (headers, rows) =>
  rows.length
    ? `<table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows
        .map((r) => `<tr>${r.map((c) => `<td>${c ?? ''}</td>`).join('')}</tr>`)
        .join('')}</tbody></table>`
    : '<p class="note">None found.</p>';

const tags = (list) => (list || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('');

const SEVS = ['High', 'Medium', 'Low', 'Info'];
const sevClass = (s) => 'sev-' + s.toLowerCase();

export function buildHtmlReport({ fingerprint, extras, interfaces, wifi, scan, attached, inventory, history, entry, findings, appVersion }) {
  const now = new Date();
  const generated = now.toLocaleString('en-AU', { dateStyle: 'full', timeStyle: 'medium' });
  const title = `Network and device report — ${fingerprint?.computer_name || 'this device'}`;
  const parts = [];

  // Summary.
  const stats = [];
  if (scan) stats.push([scan.hosts.length, 'Network devices']);
  if (scan) stats.push([new Set(scan.hosts.map((h) => h.device_type)).size, 'Device types']);
  if (entry && !entry.baseline) stats.push([entry.added.length, 'New since last scan']);
  if (findings) stats.push([findings.filter((f) => f.severity === 'High').length, 'High-risk issues', 'sev-high']);
  if (findings) stats.push([findings.filter((f) => f.severity === 'Medium').length, 'Medium-risk issues', 'sev-medium']);
  if (attached) stats.push([(attached.usb_devices || []).length, 'USB devices']);
  if (attached) stats.push([(attached.devices || []).filter((d) => d.is_peripheral).length, 'Peripherals']);
  if (attached) stats.push([(attached.volumes || []).length, 'Drives and volumes']);
  if (attached) stats.push([(attached.printers || []).length, 'Printers']);
  if (interfaces) stats.push([interfaces.filter((i) => i.is_up && i.ipv4.length).length, 'Active interfaces']);
  if (stats.length)
    parts.push(`<div class="summary">${stats.map(([n, l, c]) => `<div class="stat ${c || ''}"><b>${n}</b><span>${esc(l)}</span></div>`).join('')}</div>`);

  // This device.
  if (fingerprint) {
    parts.push('<h2>This device</h2>');
    parts.push(
      dl([
        ['Computer name', fingerprint.computer_name],
        ['Operating system', fingerprint.os],
        ['Processor architecture', fingerprint.processor_architecture],
        ['Processor', fingerprint.processor_model],
        ['Primary IP address', fingerprint.ip_address],
        ['Primary MAC address', fingerprint.mac_address],
        ['Collected', formatDateTime(fingerprint.system_time)],
      ]),
    );
    if (extras) {
      parts.push('<h3>Browser details</h3>');
      parts.push(dl(Object.entries(extras).map(([k, v]) => [k.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase()), v])));
    }
  }

  if (wifi) {
    parts.push('<h3>Wi-Fi connection</h3>');
    parts.push(dl(Object.entries(wifi)));
  }

  // Interfaces.
  if (interfaces?.length) {
    parts.push('<h2>Network interfaces</h2>');
    parts.push(
      table(
        ['Interface', 'Type', 'Status', 'IPv4', 'MAC address', 'Gateway', 'DNS servers', 'Speed'],
        interfaces
          .filter((i) => !i.is_loopback)
          .map((i) => [
            `<b>${esc(i.friendly_name || i.name)}</b>${i.description ? `<br><span class="note">${esc(i.description)}</span>` : ''}${i.is_default ? '<br><span class="tag">Default</span>' : ''}`,
            esc(i.kind),
            i.is_up ? 'Up' : 'Down',
            i.ipv4.map(esc).join('<br>'),
            `<span class="mono">${esc(i.mac_address || '')}</span>${i.vendor ? `<br><span class="note">${esc(i.vendor)}</span>` : ''}`,
            esc(i.gateway_ip || ''),
            i.dns_servers.map(esc).join('<br>'),
            i.speed_mbps ? `${i.speed_mbps} Mbps` : '',
          ]),
      ),
    );
  }

  // Network scan.
  if (scan) {
    parts.push('<h2>Devices on the network</h2>');
    parts.push(
      `<p class="meta">Scanned ${esc(scan.ranges.join(', '))} (${scan.addresses_scanned} addresses) on ${esc(formatDateTime(scan.started))} in ${scan.duration_seconds} s.</p>`,
    );
    for (const n of scan.notes || []) parts.push(`<p class="note">${esc(n)}</p>`);
    parts.push(
      table(
        ['IP address', 'Name', 'Type', 'Vendor', 'MAC address', 'Open ports'],
        scan.hosts.map((h) => [
          `<span class="mono">${esc(h.ip)}</span>`,
          `${esc(labelOf(inventory, h) || h.display_name)}${entry?.added?.includes(deviceKey(h)) ? ' <span class="tag new">New</span>' : ''}${knownOf(inventory, h) ? ' <span class="tag">Known</span>' : ''}`,
          esc(h.device_type),
          esc(h.vendor || ''),
          `<span class="mono">${esc(h.mac_address || '')}</span>`,
          (h.open_ports || []).map((p) => p.port).join(', '),
        ]),
      ),
    );
    parts.push('<h3>Device details</h3>');
    for (const h of scan.hosts) {
      parts.push(
        `<div class="device"><h3>${esc(labelOf(inventory, h) || h.display_name)} <span class="note">— ${esc(h.ip)}</span></h3>${dl([
          ['Device type', h.device_type],
          ['Detected name', labelOf(inventory, h) ? h.display_name : ''],
          ['Known device', inventory ? (knownOf(inventory, h) ? 'Yes' : 'No') : ''],
          ['IP address', h.ip],
          ['MAC address', h.mac_address ? `${h.mac_address}${h.private_mac ? ' (private / randomised)' : ''}` : ''],
          ['Vendor', h.vendor],
          ['DNS name', h.hostname],
          ['NetBIOS name', h.netbios_name],
          ['Workgroup / domain', h.workgroup],
          ['mDNS host name', h.mdns?.hostname],
          ['Model', hostModel(h)],
          ['Description', h.upnp?.model_description],
          ['Serial number', h.upnp?.serial_number],
          ['UPnP device type', h.upnp?.device_type],
          ['UPnP server', h.upnp?.server],
          ['Advertised services', hostServices(h)],
          ['Service names', [...(h.mdns?.instance_names || [])]],
          ['Other details', [...(h.mdns?.details || [])]],
          ['Open ports', portList(h)],
          ['SMBv1', h.smb1 == null ? '' : h.smb1 ? 'Enabled (obsolete)' : 'Off'],
          ['Response time', h.latency_ms != null ? `${h.latency_ms.toFixed(1)} ms` : ''],
          ['Found by', [...(h.found_by || [])].join(', ')],
          ['Interface', h.interface],
        ])}</div>`,
      );
    }
  }

  // Security.
  if (findings) {
    parts.push('<h2>Security checks</h2>');
    parts.push('<p class="meta">Services on the network that are unencrypted, obsolete or often attacked. Found by looking at open ports and announcements only; nothing was changed on any device.</p>');
    const c = Object.fromEntries(SEVS.map((s) => [s, findings.filter((f) => f.severity === s).length]));
    parts.push('<div class="summary">' + SEVS.map((s) => '<div class="stat ' + sevClass(s) + '"><b>' + c[s] + '</b><span>' + s + '</span></div>').join('') + '</div>');
    if (!findings.length) parts.push('<p>No risky services were found on the scanned devices.</p>');
    for (const f of findings)
      parts.push(
        '<div class="finding ' + sevClass(f.severity) + '"><div><span class="sev">' + esc(f.severity) + '</span><b>' + esc(f.title) + '</b> <span class="note">— ' +
          esc(f.device) + ' (' + esc(f.ip) + ')</span></div><p>' + esc(f.detail) + '</p><p><b>What to do:</b> ' + esc(f.advice) + '</p></div>',
      );
  }

  // Inventory and history.
  if (inventory && Object.keys(inventory.devices).length) {
    const online = new Set(entry?.keys || []);
    const all = deviceList(inventory);
    parts.push('<h2>Your devices (' + all.length + ')</h2>');
    parts.push('<p class="meta">Every device seen in any scan, with the names you gave them.</p>');
    parts.push(
      table(
        ['Name', 'Known', 'Type', 'Last IP address', 'MAC address', 'First seen', 'Last seen'],
        all.map((d) => [
          '<b>' + esc(displayName(d)) + '</b>' + (d.label && d.name ? '<br><span class="note">' + esc(d.name) + '</span>' : ''),
          d.trusted ? 'Yes' : 'No',
          esc(d.device_type || ''),
          '<span class="mono">' + esc(d.ip || '') + '</span>',
          '<span class="mono">' + esc(d.mac || '') + '</span>',
          esc(formatDateTime(d.first_seen)),
          online.has(d.key) ? '<span class="tag">Online now</span>' : esc(formatDateTime(d.last_seen)),
        ]),
      ),
    );
  }
  if (history?.length) {
    const name = (k) => esc(displayName(inventory?.devices[k] || { key: k }));
    parts.push('<h2>Scan history</h2>');
    parts.push(
      table(
        ['Scanned', 'Networks', 'Devices', 'New', 'Not found'],
        history.slice(0, 25).map((e) => [
          esc(formatDateTime(e.started)) + (e.auto ? ' <span class="tag">Automatic</span>' : '') + (e.baseline ? ' <span class="tag">First scan</span>' : ''),
          esc(e.ranges.join(', ')),
          e.total,
          e.added.map(name).join(', '),
          e.missing.map(name).join(', '),
        ]),
      ),
    );
  }

  // Attached.
  if (attached) {
    parts.push('<h2>Attached devices</h2>');
    for (const n of attached.notes || []) parts.push(`<p class="note">${esc(n)}</p>`);

    parts.push('<h3>USB devices</h3>');
    parts.push(
      table(
        ['Device', 'Manufacturer', 'VID:PID', 'Functions', 'Serial number', 'Status'],
        (attached.usb_devices || []).map((u) => [
          `<b>${esc(u.name)}</b>`,
          esc(u.vendor_name || ''),
          `<span class="mono">${esc(u.vendor_id)}:${esc(u.product_id)}</span>`,
          (u.functions || []).map(esc).join('<br>'),
          `<span class="mono">${esc(u.serial_number || '')}</span>`,
          esc(u.status || ''),
        ]),
      ),
    );

    parts.push('<h3>Physical drives</h3>');
    parts.push(
      table(
        ['Model', 'Connection', 'Media', 'Size', 'Drive letters', 'Serial number', 'Status'],
        (attached.drives || []).map((d) => [
          `<b>${esc(d.model)}</b>`,
          `${esc(d.interface || '')}${d.is_external ? ' <span class="tag">External</span>' : ''}`,
          esc(d.media_type || ''),
          formatBytes(d.size_bytes),
          esc((d.drive_letters || []).join(' ')),
          `<span class="mono">${esc(d.serial_number || '')}</span>`,
          esc(d.status || ''),
        ]),
      ),
    );

    parts.push('<h3>Volumes and network drives</h3>');
    parts.push(
      table(
        ['Drive', 'Label', 'Type', 'File system', 'Size', 'Free', 'Source'],
        (attached.volumes || []).map((v) => [
          `<b>${esc(v.name)}</b>`,
          esc(v.label || ''),
          esc(v.kind),
          esc(v.file_system || ''),
          formatBytes(v.total_bytes),
          formatBytes(v.free_bytes),
          esc(v.network_path || v.physical_drive || ''),
        ]),
      ),
    );

    parts.push('<h3>Printers</h3>');
    parts.push(
      table(
        ['Printer', 'Driver', 'Port', 'Connection', 'Status'],
        (attached.printers || []).map((p) => [
          `<b>${esc(p.name)}</b>${p.is_default ? ' <span class="tag">Default</span>' : ''}${p.is_shared ? ' <span class="tag">Shared</span>' : ''}`,
          esc(p.driver || ''),
          `<span class="mono">${esc(p.port || '')}</span>`,
          p.is_network ? 'Network' : 'Local',
          esc(p.is_offline ? 'Offline' : p.status || ''),
        ]),
      ),
    );

    if ((attached.monitors || []).length) {
      parts.push('<h3>Monitors</h3>');
      parts.push(
        table(
          ['Monitor', 'Manufacturer code', 'Serial number', 'Year made'],
          attached.monitors.map((m) => [`<b>${esc(m.name)}</b>`, esc(m.manufacturer || ''), esc(m.serial_number || ''), esc(m.year_of_manufacture || '')]),
        ),
      );
    }

    const groups = groupBy((attached.devices || []).filter((d) => d.is_peripheral), (d) => d.category);
    parts.push('<h3>Peripherals by category</h3>');
    parts.push(
      table(
        ['Category', 'Device', 'Connection', 'Manufacturer', 'Status'],
        [...groups.entries()].flatMap(([cat, list]) =>
          list.map((d, i) => [i === 0 ? `<b>${esc(cat)}</b>` : '', esc(d.name), esc(d.connection), esc(d.manufacturer || ''), esc(d.status || '')]),
        ),
      ),
    );

    const all = groupBy(attached.devices || [], (d) => d.category);
    parts.push(`<h3>All Plug and Play devices (${(attached.devices || []).length})</h3>`);
    parts.push(
      table(
        ['Category', 'Device', 'Connection', 'Device ID'],
        [...all.entries()].flatMap(([cat, list]) =>
          list.map((d, i) => [i === 0 ? `<b>${esc(cat)}</b>` : '', esc(d.name), esc(d.connection), `<span class="mono">${esc(d.device_id || '')}</span>`]),
        ),
      ),
    );
  }

  return `<!doctype html>
<html lang="en-AU">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<header>
<h1>${esc(title)}</h1>
<div class="meta">Generated ${esc(generated)} by Network Fingerprint Collector${appVersion ? ` ${esc(appVersion)}` : ''}</div>
</header>
${parts.join('\n')}
<footer>© Copyright Peter Geffert ${now.getFullYear()}</footer>
</body>
</html>`;
}

export function groupBy(list, key) {
  const m = new Map();
  for (const item of list) {
    const k = key(item);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(item);
  }
  return new Map([...m.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

export { tags };
