import './style.css';
import { createBackend, fileStamp, toCsv } from './backend.js';
import {
  attachedCsv,
  buildHtmlReport,
  formatBytes,
  formatDateTime,
  groupBy,
  hostModel,
  hostServices,
  networkCsv,
} from './report.js';
import { deviceKey, deviceList, displayName, emptyInventory, isKnown, isNew, mergeScan, nameFor, touchDevice } from './inventory.js';
import { SEVERITIES, securityFindings, severityCounts } from './security.js';

/* global __APP_VERSION__ */
const APP_VERSION = __APP_VERSION__;
const $ = (id) => document.getElementById(id);

const LABELS = {
  computer_name: 'Computer name',
  os: 'OS',
  processor_architecture: 'Processor architecture',
  processor_model: 'Processor model',
  ip_address: 'IP address',
  mac_address: 'MAC address',
  system_time: 'System time',
  browser: 'Browser',
  language: 'Language',
  time_zone: 'Time zone',
  screen: 'Screen',
  device_memory: 'Device memory',
  online: 'Online',
  user_agent: 'User agent',
};

const label = (key) => LABELS[key] ?? key.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

const DEFAULT_SETTINGS = {
  interval: 0,
  notifyNew: true,
  notifyMissing: false,
  keepInTray: false,
  autoUpdate: true,
  lastAuto: 0,
  scheduleFrom: 0,
  ranges: null,
};

/** Everything collected this session; also the source for reports. */
const state = {
  fingerprint: null,
  extras: null,
  interfaces: null,
  wifi: null,
  scan: null,
  attached: null,
  scanning: false,
  inventory: emptyInventory(),
  history: [],
  settings: { ...DEFAULT_SETTINGS },
  /** History entry for the scan currently shown. */
  entry: null,
  findings: [],
};

// Remember the last scan and inventory between sessions.
const CACHE_KEY = 'fingerprint-collector.last';
function loadCache() {
  try {
    const c = JSON.parse(localStorage.getItem(CACHE_KEY) || '{}');
    state.scan = c.scan || null;
    state.attached = c.attached || null;
  } catch {
    /* ignore */
  }
}
function saveCache() {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ scan: state.scan, attached: state.attached }));
  } catch {
    /* storage full or unavailable */
  }
}

function setStatus(text, kind = 'info') {
  const el = $('status');
  el.textContent = text;
  el.dataset.kind = kind;
}

const errText = (e) => e?.message ?? String(e);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'value') el.value = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function renderPairs(dl, data) {
  dl.replaceChildren();
  for (const [key, value] of Object.entries(data)) {
    if (value == null || value === '' || (Array.isArray(value) && !value.length)) continue;
    const dd = h('dd', {}, Array.isArray(value) ? value.join(', ') : value);
    if (String(value).startsWith('N/A')) dd.classList.add('na');
    dl.append(h('dt', {}, label(key)), dd);
  }
}

let backend = null;

const persist = (name) => {
  const value = { devices: state.inventory, 'scan-history': state.history, settings: state.settings }[name];
  return backend.saveStore(name, value).catch((e) => setStatus(`Could not save ${name.replace('-', ' ')}: ${errText(e)}`, 'error'));
};

function listFormat(names, max = 4) {
  if (names.length <= max) return new Intl.ListFormat('en-AU').format(names);
  return `${names.slice(0, max).join(', ')} and ${names.length - max} more`;
}

// ----------------------------------------------------------------- Tabs ---

function setupTabs() {
  const tabs = [...document.querySelectorAll('[role=tab]')];
  const select = (tab) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', on);
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute('aria-controls')).hidden = !on;
    }
    try {
      localStorage.setItem('fingerprint-collector.tab', tab.id);
    } catch {
      /* ignore */
    }
  };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', (e) => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (d) {
        const next = tabs[(i + d + tabs.length) % tabs.length];
        select(next);
        next.focus();
      }
    });
  });
  let saved = null;
  try {
    saved = localStorage.getItem('fingerprint-collector.tab');
  } catch {
    /* ignore */
  }
  select(tabs.find((t) => t.id === saved) || tabs[0]);
  return { select: (id) => select($(id)) };
}

// ----------------------------------------------------------- This device ---

function renderHistory(rows) {
  const body = $('history');
  body.replaceChildren();
  $('history-count').textContent = rows.length ? `(${rows.length})` : '';
  $('export-btn').disabled = !rows.length;
  $('clear-btn').disabled = !rows.length;

  if (!rows.length) {
    body.append(h('tr', {}, h('td', { colspan: 7, class: 'empty' }, 'No fingerprints saved yet.')));
    return;
  }
  const labels = ['Time', 'Computer name', 'OS', 'Architecture', 'Processor', 'IP address', 'MAC address'];
  for (const r of [...rows].reverse()) {
    const cells = [
      formatDateTime(r.system_time),
      r.computer_name,
      r.os,
      r.processor_architecture,
      r.processor_model,
      r.ip_address,
      r.mac_address,
    ];
    body.append(h('tr', {}, cells.map((v, i) => h('td', { 'data-label': labels[i] }, v))));
  }
}

function renderInterfaces(list) {
  const box = $('interfaces');
  box.replaceChildren();
  const shown = list.filter((i) => !i.is_loopback && (i.ipv4.length || i.is_up));
  if (!shown.length) {
    box.append(h('p', { class: 'empty' }, 'No active network interfaces.'));
    return;
  }
  for (const i of shown) {
    const dl = h('dl', { class: 'result compact' });
    renderPairs(dl, {
      Type: i.kind,
      Status: i.is_up ? 'Up' : 'Down',
      IPv4: i.ipv4,
      IPv6: i.ipv6.slice(0, 2),
      'MAC address': i.mac_address ? `${i.mac_address}${i.vendor ? ` (${i.vendor})` : ''}` : null,
      Gateway: i.gateway_ip ? `${i.gateway_ip}${i.gateway_mac ? ` (${i.gateway_mac})` : ''}` : null,
      'DNS servers': i.dns_servers,
      Speed: i.speed_mbps ? `${i.speed_mbps} Mbps` : null,
      DHCP: i.dhcp == null ? null : i.dhcp ? 'Yes' : 'No',
      MTU: i.mtu,
    });
    box.append(
      h(
        'div',
        { class: 'mini-card' },
        h('div', { class: 'mini-head' }, h('b', {}, i.friendly_name || i.name), i.is_default ? h('span', { class: 'tag' }, 'Default') : null),
        i.description && i.description !== i.friendly_name ? h('div', { class: 'hint' }, i.description) : null,
        dl,
      ),
    );
  }
}

/** Wi-Fi details as label → value pairs (shared with the report). */
function wifiPairs(w) {
  if (!w) return {};
  const signal = [w.signal_percent != null ? `${w.signal_percent}%` : null, w.rssi_dbm != null ? `${w.rssi_dbm} dBm` : null].filter(Boolean).join(' · ');
  const rate = [w.rx_rate_mbps ? `${w.rx_rate_mbps} Mbps down` : null, w.tx_rate_mbps ? `${w.tx_rate_mbps} Mbps up` : null].filter(Boolean).join(' · ');
  return {
    'Network name': w.ssid,
    Status: w.state,
    Signal: signal,
    Band: [w.band, w.channel ? `channel ${w.channel}` : null, w.frequency_mhz ? `${w.frequency_mhz} MHz` : null].filter(Boolean).join(' · '),
    Standard: w.radio_type,
    'Link speed': rate,
    Security: [w.authentication, w.cipher].filter(Boolean).join(' · '),
    'Access point': w.bssid,
    'IP address': w.ip_address,
    Gateway: w.gateway,
    'DNS servers': w.dns_servers,
    Adapter: w.interface,
  };
}

function renderWifi() {
  const dl = $('wifi');
  const w = state.wifi;
  if (!w) {
    $('wifi-card').hidden = true;
    return;
  }
  $('wifi-card').hidden = false;
  renderPairs(dl, wifiPairs(w));
  if (w.note) dl.append(h('dt', {}, 'Note'), h('dd', { class: 'na' }, w.note));
}

// --------------------------------------------------------------- Network ---

let rangeOptions = [];

function renderRanges() {
  const box = $('range-list');
  box.replaceChildren();
  if (!rangeOptions.length) {
    box.append(h('p', { class: 'hint' }, 'No active network connection found. Enter a range below.'));
    return;
  }
  const saved = state.settings.ranges?.checked;
  const useSaved = saved && rangeOptions.some((r) => saved.includes(r.cidr));
  for (const r of rangeOptions) {
    box.append(
      h(
        'label',
        { class: 'range' },
        h('input', { type: 'checkbox', value: r.cidr, checked: useSaved ? saved.includes(r.cidr) : !r.is_virtual, onchange: saveRanges }),
        h('span', {}, h('b', {}, r.cidr), ` — ${r.interface} · ${r.hosts.toLocaleString('en-AU')} ${r.hosts === 1 ? 'address' : 'addresses'}`, r.is_virtual ? h('span', { class: 'tag muted' }, 'Virtual / VPN') : null),
        r.note ? h('small', { class: 'hint' }, r.note) : null,
      ),
    );
  }
}

function saveRanges() {
  state.settings.ranges = {
    checked: [...document.querySelectorAll('#range-list input:checked')].map((i) => i.value),
    custom: $('custom-range').value,
  };
  persist('settings');
}

function selectedRanges() {
  const picked = [...document.querySelectorAll('#range-list input:checked')].map((i) => i.value);
  const custom = $('custom-range')
    .value.split(/[,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return [...picked, ...custom];
}

const TYPE_ICONS = {
  'This device': '💻',
  'Router / gateway': '📡',
  Printer: '🖨️',
  Scanner: '🖨️',
  'NAS / network storage': '🗄️',
  'NAS / media server': '🗄️',
  'Media server': '🗄️',
  'Cast-enabled media device': '📺',
  'TV / media player': '📺',
  'Speaker / audio device': '🔊',
  'iPhone / iPad': '📱',
  'Phone / tablet': '📱',
  'Phone / tablet (private address)': '📱',
  'Apple TV / HomePod': '📺',
  'Apple computer / device': '💻',
  'IP camera / NVR': '📷',
  'Smart-home / IoT device': '💡',
  'Raspberry Pi': '🍓',
  'Windows computer': '💻',
  'Computer / file server': '💻',
  'Linux / network device': '🖧',
  'Network equipment': '🖧',
  'Games console / device': '🎮',
  'Device with web interface': '🌐',
  'Unknown device': '❔',
};

const SEVERITY_CLASS = { High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low', Info: 'sev-info' };

let typeFilter = null;
/** Set in main(): re-check one device. */
const actions = { recheck: async () => {} };
const openHosts = new Set();

function computeFindings() {
  state.findings = securityFindings(state.scan, state.entry, (x) => nameFor(state.inventory, x));
}

function renderScan() {
  const scan = state.scan;
  $('scan-results').hidden = !scan;
  renderSecurity();
  renderDevices();
  renderScanHistory();
  if (!scan) return;
  $('scan-total').textContent = `(${scan.hosts.length})`;
  $('scan-meta').textContent = `Scanned ${scan.ranges.join(', ')} — ${scan.addresses_scanned.toLocaleString('en-AU')} addresses on ${formatDateTime(scan.started)}, took ${scan.duration_seconds} s.`;
  $('scan-notes').replaceChildren(...(scan.notes || []).map((n) => h('p', { class: 'note' }, n)));

  // What changed since the last scan.
  const changes = $('scan-changes');
  changes.replaceChildren();
  const e = state.entry;
  if (e?.baseline) {
    changes.append(h('div', { class: 'notice' }, `First scan: ${e.total} devices added to “Your devices”. Later scans will point out new arrivals and anything that has gone missing.`));
  } else if (e && (e.added.length || e.missing.length)) {
    const name = (k) => displayName(state.inventory.devices[k] || { key: k });
    changes.append(
      h(
        'div',
        { class: 'notice changes' },
        e.added.length ? h('p', {}, h('b', {}, `✨ ${e.added.length} new: `), listFormat(e.added.map(name), 6)) : null,
        e.missing.length ? h('p', {}, h('b', {}, `${e.missing.length} not found this time: `), listFormat(e.missing.map(name), 6)) : null,
      ),
    );
  } else if (e) {
    changes.append(h('p', { class: 'hint' }, 'No new or missing devices since the last scan of these networks.'));
  }

  const chips = $('type-chips');
  chips.replaceChildren();
  const chip = (key, text, n) =>
    h(
      'button',
      {
        type: 'button',
        class: `chip${typeFilter === key ? ' on' : ''}`,
        onclick: () => {
          typeFilter = typeFilter === key ? null : key;
          renderScan();
        },
      },
      `${text} `,
      h('span', { class: 'count' }, n),
    );
  const newCount = scan.hosts.filter((x) => isNew(e, x)).length;
  const unknownCount = scan.hosts.filter((x) => !isKnown(state.inventory, x)).length;
  if (newCount) chips.append(chip('__new', '✨ New', newCount));
  if (unknownCount) chips.append(chip('__unknown', '❓ Not marked as known', unknownCount));
  for (const [name, list] of groupBy(scan.hosts, (x) => x.device_type)) chips.append(chip(name, `${TYPE_ICONS[name] || '❔'} ${name}`, list.length));
  renderHosts();
}

function webUrl(x) {
  const p = (x.open_ports || []).map((o) => o.port);
  const port = [443, 80, 8443, 8080, 5001, 5000].find((n) => p.includes(n));
  if (!port) return null;
  const https = [443, 8443, 5001].includes(port);
  return `${https ? 'https' : 'http'}://${x.ip}${port === (https ? 443 : 80) ? '' : `:${port}`}/`;
}

async function act(fn, ok) {
  try {
    const r = await fn();
    if (ok) setStatus(typeof ok === 'function' ? ok(r) : ok, 'success');
  } catch (e) {
    setStatus(errText(e), 'error');
  }
}

function hostActions(x) {
  const f = backend.features;
  const url = webUrl(x);
  const ports = (x.open_ports || []).map((o) => o.port);
  const buttons = [
    url && h('button', { type: 'button', onclick: () => act(() => backend.openUrl(url), `Opened ${url}`) }, '🌐 Open web page'),
    f.share && !x.is_self && (ports.includes(445) || ports.includes(139)) && h('button', { type: 'button', onclick: () => act(() => backend.openShare(x.ip), `Opening \\\\${x.ip}…`) }, '📁 Open shared folders'),
    f.rdp && !x.is_self && ports.includes(3389) && h('button', { type: 'button', onclick: () => act(() => backend.openRemoteDesktop(x.ip), `Starting Remote Desktop to ${x.ip}…`) }, '🖥️ Remote Desktop'),
    f.wake && x.mac_address && !x.is_self && h('button', { type: 'button', onclick: () => act(() => backend.wake(x.mac_address), (m) => `Wake-up packet sent to ${m}.`) }, '⏰ Wake'),
    h('button', { type: 'button', onclick: () => act(() => navigator.clipboard.writeText(x.ip), `Copied ${x.ip}`) }, '📋 Copy IP'),
    x.mac_address && h('button', { type: 'button', onclick: () => act(() => navigator.clipboard.writeText(x.mac_address), `Copied ${x.mac_address}`) }, '📋 Copy MAC'),
    backend.native && h('button', { type: 'button', disabled: state.scanning, onclick: () => actions.recheck(x.ip) }, '🔄 Check again'),
  ];
  return h('div', { class: 'host-actions' }, buttons);
}

function manageRow(x) {
  const key = deviceKey(x);
  const d = state.inventory.devices[key];
  if (!d) return null;
  return h(
    'div',
    { class: 'host-manage' },
    h(
      'label',
      {},
      h('span', {}, 'Your name for it'),
      h('input', {
        type: 'text',
        value: d.label || '',
        placeholder: x.display_name,
        maxlength: 80,
        onchange: (ev) => {
          d.label = ev.target.value.trim();
          persist('devices');
          renderScan();
        },
      }),
    ),
    h(
      'label',
      { class: 'check' },
      h('input', {
        type: 'checkbox',
        checked: d.trusted,
        onchange: (ev) => {
          d.trusted = ev.target.checked;
          persist('devices');
          renderScan();
        },
      }),
      ' Known device',
    ),
  );
}

function renderHosts() {
  const list = $('host-list');
  list.replaceChildren();
  const q = $('scan-filter').value.trim().toLowerCase();
  const inv = state.inventory;
  const hosts = state.scan.hosts.filter((x) => {
    if (typeFilter === '__new' && !isNew(state.entry, x)) return false;
    if (typeFilter === '__unknown' && isKnown(inv, x)) return false;
    if (typeFilter && !typeFilter.startsWith('__') && x.device_type !== typeFilter) return false;
    if (!q) return true;
    return [x.ip, nameFor(inv, x), x.display_name, x.device_type, x.vendor, x.mac_address, x.hostname, x.netbios_name, hostModel(x), ...hostServices(x)]
      .filter(Boolean)
      .some((v) => String(v).toLowerCase().includes(q));
  });
  if (!hosts.length) {
    list.append(h('p', { class: 'empty' }, 'No devices match.'));
    return;
  }
  for (const x of hosts) {
    const key = deviceKey(x);
    const name = nameFor(inv, x);
    const findings = state.findings.filter((f) => f.ip === x.ip && f.title !== 'New device joined the network');
    const details = h('dl', { class: 'result compact' });
    renderPairs(details, {
      'Device type': x.device_type,
      'Detected name': name !== x.display_name ? x.display_name : null,
      'IP address': x.ip,
      'MAC address': x.mac_address ? `${x.mac_address}${x.private_mac ? ' (private / randomised)' : ''}` : null,
      Vendor: x.vendor,
      'DNS name': x.hostname,
      'NetBIOS name': x.netbios_name,
      Workgroup: x.workgroup,
      'mDNS host name': x.mdns?.hostname,
      Model: hostModel(x),
      Description: x.upnp?.model_description,
      'Serial number': x.upnp?.serial_number,
      'UPnP device type': x.upnp?.device_type,
      'Advertised services': hostServices(x),
      'Service names': [...(x.mdns?.instance_names || [])],
      'Other details': [...(x.mdns?.details || [])],
      'Open ports': (x.open_ports || []).map((p) => `${p.port} (${p.service})`),
      'SMBv1': x.smb1 == null ? null : x.smb1 ? 'Enabled (obsolete)' : 'Off',
      'Response time': x.latency_ms != null ? `${x.latency_ms.toFixed(1)} ms` : null,
      'Found by': [...(x.found_by || [])],
      Interface: x.interface,
      'First seen': formatDateTime(inv.devices[key]?.first_seen),
    });
    const worst = findings.find((f) => f.severity === 'High' || f.severity === 'Medium');
    const el = h(
      'details',
      { class: 'host', open: openHosts.has(key) },
      h(
        'summary',
        {},
        h('span', { class: 'host-icon', 'aria-hidden': 'true' }, TYPE_ICONS[x.device_type] || '❔'),
        h(
          'span',
          { class: 'host-main' },
          h(
            'span',
            { class: 'host-title' },
            h('b', {}, name),
            isNew(state.entry, x) ? h('span', { class: 'tag new' }, 'New') : null,
            isKnown(inv, x) ? h('span', { class: 'tag muted' }, 'Known') : null,
            worst ? h('span', { class: `tag ${SEVERITY_CLASS[worst.severity]}` }, `⚠ ${findings.length} security ${findings.length === 1 ? 'issue' : 'issues'}`) : null,
          ),
          h('span', { class: 'host-sub' }, [x.device_type, x.vendor].filter(Boolean).join(' · ')),
        ),
        h('span', { class: 'host-ip mono' }, x.ip),
      ),
      h('div', { class: 'host-body' }, manageRow(x), hostActions(x), findings.length ? findingList(findings, false) : null, details),
    );
    el.addEventListener('toggle', () => (el.open ? openHosts.add(key) : openHosts.delete(key)));
    list.append(el);
  }
}

function findingList(findings, showDevice = true) {
  return h(
    'ul',
    { class: 'finding-list' },
    findings.map((f) =>
      h(
        'li',
        { class: `finding ${SEVERITY_CLASS[f.severity]}` },
        h('div', { class: 'finding-head' }, h('span', { class: `sev ${SEVERITY_CLASS[f.severity]}` }, f.severity), h('b', {}, f.title), showDevice ? h('span', { class: 'hint' }, ` — ${f.device} (${f.ip})`) : null),
        h('p', {}, f.detail),
        h('p', { class: 'advice' }, h('b', {}, 'What to do: '), f.advice),
      ),
    ),
  );
}

function renderSecurity() {
  const card = $('security-card');
  card.hidden = !state.scan;
  if (!state.scan) return;
  const f = state.findings;
  const c = severityCounts(f);
  $('security-total').textContent = `(${f.length})`;
  $('security-summary').replaceChildren(...SEVERITIES.map((s) => h('div', { class: `stat ${SEVERITY_CLASS[s]}` }, h('b', {}, c[s]), h('span', {}, s))));
  const box = $('security-list');
  box.replaceChildren();
  if (!f.length) box.append(h('p', { class: 'empty' }, '✓ No risky services were found on the scanned devices.'));
  else box.append(findingList(f));
}

function renderDevices() {
  const card = $('devices-card');
  const all = deviceList(state.inventory);
  card.hidden = !backend.native || !all.length;
  if (card.hidden) return;
  $('devices-total').textContent = `(${all.length})`;
  const q = $('devices-filter').value.trim().toLowerCase();
  const online = new Set(state.entry?.keys || []);
  const rows = all.filter((d) => !q || [d.label, d.name, d.ip, d.mac, d.vendor, d.device_type].filter(Boolean).some((v) => v.toLowerCase().includes(q)));
  const body = $('devices-list');
  body.replaceChildren();
  if (!rows.length) {
    body.append(h('tr', {}, h('td', { colspan: 7, class: 'empty' }, 'No devices match.')));
    return;
  }
  for (const d of rows) {
    const nameInput = h('input', {
      type: 'text',
      class: 'inline-input',
      value: d.label || '',
      placeholder: d.name || d.ip,
      'aria-label': `Name for ${d.name || d.ip}`,
      maxlength: 80,
      onchange: (ev) => {
        d.label = ev.target.value.trim();
        persist('devices');
        renderScan();
      },
    });
    body.append(
      h(
        'tr',
        {},
        h('td', { 'data-label': 'Device' }, nameInput, h('div', { class: 'hint' }, [d.device_type, d.vendor].filter(Boolean).join(' · '))),
        h(
          'td',
          { 'data-label': 'Known' },
          h('input', {
            type: 'checkbox',
            checked: d.trusted,
            'aria-label': 'Known device',
            onchange: (ev) => {
              d.trusted = ev.target.checked;
              persist('devices');
              renderScan();
            },
          }),
        ),
        h('td', { 'data-label': 'Last address', class: 'mono' }, d.ip || ''),
        h('td', { 'data-label': 'MAC address', class: 'mono' }, d.mac || ''),
        h('td', { 'data-label': 'First seen' }, formatDateTime(d.first_seen)),
        h('td', { 'data-label': 'Last seen' }, online.has(d.key) ? h('span', { class: 'tag' }, 'Online now') : formatDateTime(d.last_seen)),
        h(
          'td',
          { 'data-label': '', class: 'row-actions' },
          backend.features.wake && d.mac && !d.is_self && !online.has(d.key)
            ? h('button', { type: 'button', onclick: () => act(() => backend.wake(d.mac), (m) => `Wake-up packet sent to ${displayName(d)} (${m}).`) }, 'Wake')
            : null,
          h(
            'button',
            {
              type: 'button',
              class: 'danger',
              onclick: async () => {
                if (!(await backend.confirm(`Forget ${displayName(d)}? It will show as new if it is seen again.`))) return;
                delete state.inventory.devices[d.key];
                persist('devices');
                renderScan();
              },
            },
            'Forget',
          ),
        ),
      ),
    );
  }
}

function renderScanHistory() {
  const card = $('history-card');
  card.hidden = !backend.native || !state.history.length;
  if (card.hidden) return;
  $('history-total').textContent = `(${state.history.length})`;
  const name = (k) => displayName(state.inventory.devices[k] || { key: k });
  $('scan-history').replaceChildren(
    ...state.history.slice(0, 30).map((e) =>
      h(
        'details',
        { class: 'group' },
        h(
          'summary',
          {},
          formatDateTime(e.started),
          ` — ${e.total} devices`,
          e.added.length ? h('span', { class: 'tag new' }, `+${e.added.length} new`) : null,
          e.missing.length ? h('span', { class: 'tag muted' }, `−${e.missing.length} missing`) : null,
          e.auto ? h('span', { class: 'tag muted' }, 'Automatic') : null,
          e.baseline ? h('span', { class: 'tag muted' }, 'First scan') : null,
          e.cancelled ? h('span', { class: 'tag muted' }, 'Cancelled') : null,
        ),
        h(
          'div',
          { class: 'history-body' },
          h('p', { class: 'hint' }, `Networks: ${e.ranges.join(', ')}`),
          e.added.length ? h('p', {}, h('b', {}, 'New: '), e.added.map(name).join(', ')) : null,
          e.missing.length ? h('p', {}, h('b', {}, 'Not found: '), e.missing.map(name).join(', ')) : null,
          !e.added.length && !e.missing.length ? h('p', { class: 'hint' }, e.baseline ? 'Starting point for later comparisons.' : 'No changes.') : null,
        ),
      ),
    ),
  );
}

// -------------------------------------------------------------- Attached ---

function section(title, count, ...content) {
  return h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, title, ' ', h('span', { class: 'count' }, `(${count})`))), ...content);
}

function simpleTable(headers, rows) {
  if (!rows.length) return h('p', { class: 'empty' }, 'None found.');
  return h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      { class: 'stack' },
      h('thead', {}, h('tr', {}, headers.map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.map((r) => h('tr', {}, r.map((c, i) => h('td', { 'data-label': headers[i] }, c ?? ''))))),
    ),
  );
}

let showAllDevices = false;

function renderAttached() {
  const a = state.attached;
  const box = $('attached-sections');
  box.replaceChildren();
  $('attached-csv-btn').disabled = !a;
  if (!a) return;

  $('attached-meta').textContent = `Collected ${formatDateTime(a.collected)}.`;
  const peripherals = (a.devices || []).filter((d) => d.is_peripheral);
  $('attached-summary').replaceChildren(
    ...[
      [(a.usb_devices || []).length, 'USB devices'],
      [peripherals.length, 'Peripherals'],
      [(a.volumes || []).length, 'Drives and volumes'],
      [(a.printers || []).length, 'Printers'],
      [(a.monitors || []).length, 'Monitors'],
      [(a.devices || []).length, 'All devices'],
    ].map(([n, l]) => h('div', { class: 'stat' }, h('b', {}, n), h('span', {}, l))),
  );
  $('attached-notes').replaceChildren(...(a.notes || []).map((n) => h('p', { class: 'note' }, n)));

  box.append(
    section(
      'USB devices',
      (a.usb_devices || []).length,
      simpleTable(
        ['Device', 'Manufacturer', 'VID:PID', 'Functions', 'Serial number'],
        (a.usb_devices || []).map((u) => [h('b', {}, u.name), u.vendor_name || '', h('span', { class: 'mono' }, `${u.vendor_id}:${u.product_id}`), (u.functions || []).join(', '), u.serial_number || '']),
      ),
    ),
  );

  box.append(
    section(
      'Drives and volumes',
      (a.volumes || []).length,
      simpleTable(
        ['Drive', 'Label', 'Type', 'File system', 'Size', 'Free', 'Source'],
        (a.volumes || []).map((v) => [
          h('b', {}, v.name),
          v.label || '',
          v.kind,
          v.file_system || '',
          formatBytes(v.total_bytes),
          formatBytes(v.free_bytes),
          v.network_path || v.physical_drive || '',
        ]),
      ),
      (a.drives || []).length ? h('h3', {}, 'Physical drives') : null,
      (a.drives || []).length
        ? simpleTable(
            ['Model', 'Connection', 'Size', 'Drive letters', 'Serial number'],
            a.drives.map((d) => [
              h('b', {}, d.model),
              `${d.interface || ''}${d.is_external ? ' · External' : ''}`,
              formatBytes(d.size_bytes),
              (d.drive_letters || []).join(' '),
              d.serial_number || '',
            ]),
          )
        : null,
    ),
  );

  if ((a.printers || []).length || (a.monitors || []).length) {
    box.append(
      section(
        'Printers',
        (a.printers || []).length,
        simpleTable(
          ['Printer', 'Driver', 'Port', 'Connection', 'Status'],
          (a.printers || []).map((p) => [
            h('b', {}, p.name, p.is_default ? h('span', { class: 'tag' }, 'Default') : null),
            p.driver || '',
            h('span', { class: 'mono' }, p.port || ''),
            p.is_network ? 'Network' : 'Local',
            p.is_offline ? 'Offline' : p.status || '',
          ]),
        ),
      ),
    );
    if ((a.monitors || []).length)
      box.append(
        section(
          'Monitors',
          a.monitors.length,
          simpleTable(
            ['Monitor', 'Manufacturer code', 'Serial number', 'Year made'],
            a.monitors.map((m) => [h('b', {}, m.name), m.manufacturer || '', m.serial_number || '', m.year_of_manufacture || '']),
          ),
        ),
      );
  }

  const list = showAllDevices ? a.devices || [] : peripherals;
  const groups = groupBy(list, (d) => d.category);
  const toggle = h(
    'button',
    {
      type: 'button',
      onclick: () => {
        showAllDevices = !showAllDevices;
        renderAttached();
      },
    },
    showAllDevices ? 'Show peripherals only' : `Show all ${(a.devices || []).length} devices`,
  );
  const sec = section(showAllDevices ? 'All devices' : 'Peripherals', list.length);
  sec.querySelector('.card-head').append(toggle);
  for (const [cat, items] of groups) {
    sec.append(
      h(
        'details',
        { class: 'group', open: !showAllDevices },
        h('summary', {}, cat, ' ', h('span', { class: 'count' }, `(${items.length})`)),
        h(
          'ul',
          { class: 'device-list' },
          items.map((d) =>
            h(
              'li',
              {},
              h('span', {}, d.name),
              h('span', { class: 'hint' }, [d.connection, d.manufacturer, d.status && d.status !== 'OK' ? d.status : null].filter(Boolean).join(' · ')),
            ),
          ),
        ),
      ),
    );
  }
  box.append(sec);
}

// --------------------------------------------------------------- Reports ---

function renderChecklist() {
  const c = severityCounts(state.findings);
  const items = [
    ['This device', state.fingerprint ? `Collected ${formatDateTime(state.fingerprint.system_time)}` : 'Will be collected'],
    ['Network interfaces', state.interfaces ? `${state.interfaces.filter((i) => i.is_up && i.ipv4.length).length} active` : 'Will be collected'],
    ['Network devices', state.scan ? `${state.scan.hosts.length} devices, scanned ${formatDateTime(state.scan.started)}` : 'A scan will run'],
    ['Security checks', state.scan ? `${c.High} high, ${c.Medium} medium, ${c.Low} low` : 'Run with the scan'],
    ['Attached devices', state.attached ? `${(state.attached.devices || []).length} devices, collected ${formatDateTime(state.attached.collected)}` : 'Will be collected'],
  ];
  const native = backend?.native;
  $('report-checklist').replaceChildren(
    ...items
      .filter((_, i) => native || i === 0)
      .map(([t, s]) => h('li', { class: /^(Will|A scan|Run with)/.test(s) ? 'todo' : 'done' }, h('b', {}, t), h('span', {}, s))),
  );
  // This device is collected on demand at export time, so any data is enough.
  const ready = !!(state.fingerprint || state.scan || state.attached);
  $('report-html-btn').disabled = !ready;
  $('report-pdf-btn').disabled = !ready || !backend.features.pdf;
  $('report-json-btn').disabled = !ready;
  $('report-net-csv-btn').disabled = !state.scan;
  $('report-att-csv-btn').disabled = !state.attached;
}

function reportData() {
  return {
    fingerprint: state.fingerprint,
    extras: state.extras,
    interfaces: state.interfaces,
    wifi: state.wifi ? { ...wifiPairs(state.wifi), Note: state.wifi.note } : null,
    scan: state.scan,
    attached: state.attached,
    inventory: backend.native ? state.inventory : null,
    history: backend.native ? state.history : null,
    entry: state.entry,
    findings: state.scan ? state.findings : null,
    appVersion: APP_VERSION,
  };
}

// --------------------------------------------------------------- Settings ---

function nextAutoScan() {
  const mins = Number(state.settings.interval);
  if (!mins) return null;
  const from = Math.max(state.settings.lastAuto || 0, state.settings.scheduleFrom || 0) || Date.now();
  return new Date(from + mins * 60_000);
}

function renderSchedule() {
  const s = state.settings;
  $('set-interval').value = String(s.interval);
  $('set-notify-new').checked = s.notifyNew;
  $('set-notify-missing').checked = s.notifyMissing;
  $('set-tray').checked = s.keepInTray;
  $('set-auto-update').checked = s.autoUpdate;
  const next = nextAutoScan();
  const last = s.lastAuto ? `Last automatic scan ${formatDateTime(new Date(s.lastAuto).toISOString())}. ` : '';
  $('schedule-status').textContent = next
    ? `${last}Next automatic scan around ${next.toLocaleTimeString('en-AU', { hour: 'numeric', minute: '2-digit' })}${next.toDateString() !== new Date().toDateString() ? ` on ${next.toLocaleDateString('en-AU')}` : ''}.`
    : 'Automatic scans are off.';
}

// ------------------------------------------------------------------ Main ---

async function main() {
  const year = new Date().getFullYear();
  $('copyright').textContent = `© Copyright Peter Geffert ${year}`;
  backend = await createBackend();
  $('mode-label').textContent = backend.label;
  const tabs = setupTabs();
  const f = backend.features;

  // Saved data.
  const [inv, hist, settings] = await Promise.all(['devices', 'scan-history', 'settings'].map((n) => backend.loadStore(n).catch(() => null)));
  if (inv?.devices) state.inventory = inv;
  if (Array.isArray(hist)) state.history = hist;
  if (settings) state.settings = { ...DEFAULT_SETTINGS, ...settings };
  if (state.settings.ranges?.custom) $('custom-range').value = state.settings.ranges.custom;
  if (backend.native) loadCache();
  state.entry = state.history.find((e) => e.started === state.scan?.started) || null;
  computeFindings();

  // Platform-specific parts of the page.
  for (const el of document.querySelectorAll('.desktop-only')) el.hidden = !f.tray;
  for (const el of document.querySelectorAll('.mobile-only')) el.hidden = backend.info.os !== 'android';
  if (!backend.native) {
    $('schedule-card').hidden = true;
    $('clear-scan-history-btn').closest('.card').hidden = true;
  }
  $('report-pdf-hint').textContent =
    backend.info.os === 'windows' ? 'The full report as a PDF, ready to email or print.' : 'Opens the print dialog — choose “Save as PDF”.';
  $('about-text').textContent = `Network Fingerprint Collector ${APP_VERSION}. © Copyright Peter Geffert ${year}.`;

  // ---- This device
  const refreshHistory = async () => {
    try {
      renderHistory(await backend.history());
    } catch (e) {
      setStatus(`Could not load history: ${errText(e)}`, 'error');
    }
  };
  try {
    const where = await backend.storageLocation();
    $('csv-path').textContent = where;
    $('data-location').textContent = backend.native
      ? `Your device list, scan history, settings and fingerprint history are kept in ${where.replace(/^Saved to:\s*/, '').replace(/[\\/][^\\/]+$/, '')}`
      : where;
  } catch {
    /* non-critical */
  }
  await refreshHistory();

  const collect = async () => {
    const fp = await backend.collect();
    state.fingerprint = fp;
    renderPairs($('result'), fp);
    const extras = backend.extras();
    state.extras = extras;
    $('extras-wrap').hidden = !extras;
    if (extras) renderPairs($('extras'), extras);
    return fp;
  };

  $('collect-btn').addEventListener('click', async () => {
    const btn = $('collect-btn');
    btn.disabled = true;
    setStatus('Collecting fingerprint…');
    try {
      const fp = await collect();
      await backend.save(fp);
      setStatus('Fingerprint collected and saved.', 'success');
      await refreshHistory();
      renderChecklist();
    } catch (e) {
      setStatus(`Error during collection: ${errText(e)}`, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('export-btn').addEventListener('click', async () => {
    try {
      const text = await backend.historyCsv();
      if (!text) return;
      const where = await backend.saveFile(`network_fingerprints_${fileStamp()}.csv`, text, 'csv');
      if (where) setStatus(`Exported to ${where}`, 'success');
    } catch (e) {
      setStatus(`Export failed: ${errText(e)}`, 'error');
    }
  });

  $('clear-btn').addEventListener('click', async () => {
    if (!(await backend.confirm('Delete all saved fingerprints? This cannot be undone.'))) return;
    try {
      await backend.clear();
      setStatus('History cleared.');
      await refreshHistory();
    } catch (e) {
      setStatus(`Could not clear history: ${errText(e)}`, 'error');
    }
  });

  const loadInterfaces = async () => {
    state.interfaces = await backend.interfaces();
    renderInterfaces(state.interfaces);
  };
  const loadWifi = async () => {
    if (!f.wifi) return;
    try {
      state.wifi = await backend.wifi();
    } catch {
      state.wifi = null;
    }
    renderWifi();
  };
  $('wifi-btn').addEventListener('click', loadWifi);

  // ---- Network
  if (backend.native) {
    $('interfaces-card').hidden = false;
    $('interfaces-btn').addEventListener('click', () => loadInterfaces().catch((e) => setStatus(errText(e), 'error')));
    loadInterfaces().catch(() => {});
    loadWifi();
    backend
      .scanRanges()
      .then((r) => {
        rangeOptions = r;
        renderRanges();
      })
      .catch(() => renderRanges());
  } else {
    for (const id of ['native-only-network', 'native-only-attached']) {
      $(id).hidden = false;
      $(id).textContent = backend.nativeOnlyMessage;
    }
    $('scan-setup').hidden = true;
    $('scan-btn').disabled = true;
    $('attached-btn').disabled = true;
  }
  $('custom-range').addEventListener('change', saveRanges);

  const progress = (prefix, p) => {
    const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
    $(`${prefix}-phase`).textContent = p.phase;
    $(`${prefix}-count`).textContent = p.phase === 'Identifying devices' ? `${p.done} of ${p.total} devices` : `${p.found} found · ${pct}%`;
    $(`${prefix}-bar`).style.width = `${pct}%`;
  };

  let progressTarget = 'scan';
  await backend.onScanProgress((p) => progress(progressTarget, p));

  /** Run a scan with the progress bar showing; returns the raw result. */
  const scanWithProgress = async (ranges, target, message) => {
    progressTarget = target;
    state.scanning = true;
    $('scan-btn').disabled = true;
    $('build-report-btn').disabled = true;
    $('cancel-scan-btn').hidden = false;
    $(`${target}-progress`).hidden = false;
    progress(target, { phase: 'Starting…', done: 0, total: 1, found: 0 });
    setStatus(message);
    try {
      return await backend.scan(ranges);
    } finally {
      state.scanning = false;
      $('scan-btn').disabled = false;
      $('build-report-btn').disabled = false;
      $('cancel-scan-btn').hidden = true;
      $(`${target}-progress`).hidden = true;
    }
  };

  const alertChanges = async (entry, auto) => {
    if (!(auto || document.hidden)) return;
    const s = state.settings;
    const name = (k) => displayName(state.inventory.devices[k] || { key: k });
    try {
      if (s.notifyNew && entry.added.length) {
        const n = entry.added.length;
        await backend.notify(n === 1 ? 'New device on your network' : `${n} new devices on your network`, listFormat(entry.added.map(name)));
      }
      const gone = entry.missing.filter((k) => state.inventory.devices[k]?.trusted);
      if (s.notifyMissing && gone.length) {
        await backend.notify(gone.length === 1 ? 'A known device is missing' : `${gone.length} known devices are missing`, `${listFormat(gone.map(name))} didn’t answer the latest scan.`);
      }
    } catch {
      /* notifications are best-effort */
    }
  };

  const runScan = async (ranges, { target = 'scan', auto = false } = {}) => {
    const scan = await scanWithProgress(ranges, target, auto ? 'Running an automatic scan…' : 'Scanning the network…');
    state.scan = scan;
    typeFilter = null;
    state.entry = mergeScan(state.inventory, state.history, scan, { auto });
    computeFindings();
    saveCache();
    persist('devices');
    persist('scan-history');
    renderScan();
    renderChecklist();
    const e = state.entry;
    const c = severityCounts(state.findings);
    const extra = [e.added.length && `${e.added.length} new`, e.missing.length && `${e.missing.length} missing`, c.High && `${c.High} high-risk ${c.High === 1 ? 'issue' : 'issues'}`].filter(Boolean);
    setStatus(`Scan finished: ${scan.hosts.length} devices found${extra.length ? ` (${extra.join(', ')})` : ''}.`, 'success');
    alertChanges(e, auto);
  };

  /** Re-check one device and update it in place. */
  async function recheck(ip) {
    if (state.scanning) return;
    try {
      const r = await scanWithProgress([ip], 'scan', `Checking ${ip} again…`);
      const fresh = r.hosts.find((x) => x.ip === ip);
      if (!fresh) {
        setStatus(`${ip} didn’t answer. It may be asleep or have left the network.`, 'error');
        return;
      }
      const i = state.scan.hosts.findIndex((x) => x.ip === ip);
      if (i >= 0) state.scan.hosts[i] = fresh;
      else state.scan.hosts.push(fresh);
      touchDevice(state.inventory, fresh, r.started);
      persist('devices');
      computeFindings();
      saveCache();
      openHosts.add(deviceKey(fresh));
      renderScan();
      setStatus(`${nameFor(state.inventory, fresh)} is online (${fresh.open_ports.length} open ports).`, 'success');
    } catch (e) {
      setStatus(`Could not check ${ip}: ${errText(e)}`, 'error');
    }
  }

  actions.recheck = recheck;

  const defaultRanges = () => rangeOptions.filter((r) => !r.is_virtual).map((r) => r.cidr);

  const autoScan = async () => {
    if (state.scanning || !backend.native) return;
    const ranges = selectedRanges();
    state.settings.lastAuto = Date.now();
    persist('settings');
    renderSchedule();
    try {
      await runScan(ranges.length ? ranges : defaultRanges(), { auto: true });
    } catch (e) {
      setStatus(`Automatic scan failed: ${errText(e)}`, 'error');
    }
    renderSchedule();
  };

  $('scan-btn').addEventListener('click', async () => {
    const ranges = selectedRanges();
    if (!ranges.length) {
      setStatus('Choose at least one network or enter a range.', 'error');
      return;
    }
    try {
      await runScan(ranges);
    } catch (e) {
      setStatus(`Scan failed: ${errText(e)}`, 'error');
    }
  });
  $('cancel-scan-btn').addEventListener('click', () => {
    backend.cancelScan();
    setStatus('Cancelling the scan…');
  });
  $('scan-filter').addEventListener('input', () => state.scan && renderHosts());
  $('devices-filter').addEventListener('input', renderDevices);
  $('scan-csv-btn').addEventListener('click', () => exportFile(`network_devices_${fileStamp()}.csv`, networkCsv(state.scan, state.inventory), 'csv'));
  $('scan-json-btn').addEventListener('click', () => exportFile(`network_scan_${fileStamp()}.json`, JSON.stringify({ ...state.scan, security_findings: state.findings }, null, 2), 'json'));
  $('devices-csv-btn').addEventListener('click', () =>
    exportFile(
      `your_devices_${fileStamp()}.csv`,
      toCsv(
        deviceList(state.inventory),
        [displayName, 'name', (d) => (d.trusted ? 'Yes' : 'No'), 'device_type', 'vendor', 'ip', 'mac', 'first_seen', 'last_seen', 'seen_count'],
        ['Name', 'Detected name', 'Known', 'Device type', 'Vendor', 'Last IP address', 'MAC address', 'First seen', 'Last seen', 'Times seen'],
      ),
      'csv',
    ),
  );
  renderScan();
  await backend.onTrayScan(() => autoScan());

  // ---- Attached
  const loadAttached = async () => {
    $('attached-btn').disabled = true;
    setStatus('Reading attached devices…');
    try {
      state.attached = await backend.attached();
      saveCache();
      renderAttached();
      renderChecklist();
      setStatus(`Found ${(state.attached.devices || []).length} devices attached to this ${backend.info.os === 'android' ? 'device' : 'computer'}.`, 'success');
    } finally {
      $('attached-btn').disabled = !backend.native;
    }
  };
  $('attached-btn').addEventListener('click', () => loadAttached().catch((e) => setStatus(`Could not read attached devices: ${errText(e)}`, 'error')));
  $('attached-csv-btn').addEventListener('click', () => exportFile(`attached_devices_${fileStamp()}.csv`, attachedCsv(state.attached), 'csv'));
  renderAttached();

  // ---- Reports
  async function exportFile(name, text, ext) {
    try {
      const where = await backend.saveFile(name, text, ext);
      if (where) setStatus(`Saved ${where}`, 'success');
    } catch (e) {
      setStatus(`Could not save the file: ${errText(e)}`, 'error');
    }
  }

  $('build-report-btn').addEventListener('click', async () => {
    const btn = $('build-report-btn');
    btn.disabled = true;
    try {
      setStatus('Collecting this device…');
      const fp = await collect();
      await backend.save(fp).catch(() => {});
      await refreshHistory();
      if (backend.native) {
        setStatus('Reading network interfaces…');
        await loadInterfaces();
        await loadWifi();
        setStatus('Reading attached devices…');
        await loadAttached();
        if (!state.scan) await runScan(defaultRanges(), { target: 'report' });
      }
      renderChecklist();
      setStatus('Report ready. Choose a format to save it.', 'success');
    } catch (e) {
      setStatus(`Could not build the report: ${errText(e)}`, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  const ensureDevice = async () => {
    if (!state.fingerprint) await collect();
    if (backend.native && !state.interfaces) await loadInterfaces();
  };
  $('report-html-btn').addEventListener('click', async () => {
    await ensureDevice();
    exportFile(`network_report_${fileStamp()}.html`, buildHtmlReport(reportData()), 'html');
  });
  $('report-pdf-btn').addEventListener('click', async () => {
    const btn = $('report-pdf-btn');
    btn.disabled = true;
    try {
      await ensureDevice();
      setStatus('Creating the PDF…');
      const where = await backend.exportPdf(`network_report_${fileStamp()}.pdf`, buildHtmlReport(reportData()));
      if (where) setStatus(where === 'the print dialog' ? 'Choose “Save as PDF” in the print dialog.' : `Saved ${where}`, 'success');
      else setStatus('Ready.');
    } catch (e) {
      setStatus(`Could not create the PDF: ${errText(e)}`, 'error');
    } finally {
      btn.disabled = false;
    }
  });
  $('report-json-btn').addEventListener('click', async () => {
    await ensureDevice();
    const { appVersion, entry, ...data } = reportData();
    exportFile(`network_report_${fileStamp()}.json`, JSON.stringify({ generated: new Date().toISOString(), app_version: appVersion, ...data }, null, 2), 'json');
  });
  $('report-net-csv-btn').addEventListener('click', () => exportFile(`network_devices_${fileStamp()}.csv`, networkCsv(state.scan, state.inventory), 'csv'));
  $('report-att-csv-btn').addEventListener('click', () => exportFile(`attached_devices_${fileStamp()}.csv`, attachedCsv(state.attached), 'csv'));
  renderChecklist();

  // ---- Settings
  const saveSettings = () => {
    persist('settings');
    renderSchedule();
  };
  $('set-interval').addEventListener('change', (e) => {
    const mins = Number(e.target.value);
    state.settings.interval = mins;
    state.settings.scheduleFrom = Date.now(); // first automatic scan after one interval
    if (mins && f.tray && !state.settings.keepInTray) {
      state.settings.keepInTray = true;
      backend.setBackground(true);
      setStatus('Automatic scans are on. Closing the window now keeps the app running in the system tray.', 'success');
    }
    if (mins && state.settings.notifyNew) backend.notify('Automatic scans are on', 'You’ll be told here when a new device joins your network.').catch(() => {});
    saveSettings();
  });
  $('set-notify-new').addEventListener('change', (e) => {
    state.settings.notifyNew = e.target.checked;
    saveSettings();
  });
  $('set-notify-missing').addEventListener('change', (e) => {
    state.settings.notifyMissing = e.target.checked;
    saveSettings();
  });
  $('set-tray').addEventListener('change', (e) => {
    state.settings.keepInTray = e.target.checked;
    backend.setBackground(e.target.checked);
    saveSettings();
  });
  $('set-auto-update').addEventListener('change', (e) => {
    state.settings.autoUpdate = e.target.checked;
    saveSettings();
  });
  if (f.autostart) {
    backend
      .autostart()
      .then((on) => ($('set-autostart').checked = on))
      .catch(() => ($('set-autostart').disabled = true));
    $('set-autostart').addEventListener('change', async (e) => {
      try {
        const on = await backend.autostart(e.target.checked);
        e.target.checked = on;
        if (on && !state.settings.keepInTray) {
          state.settings.keepInTray = true;
          backend.setBackground(true);
          saveSettings();
        }
        setStatus(on ? 'Fingerprint Collector will start in the tray when you sign in.' : 'Fingerprint Collector won’t start when you sign in.', 'success');
      } catch (err) {
        e.target.checked = !e.target.checked;
        setStatus(`Could not change start-up setting: ${errText(err)}`, 'error');
      }
    });
  }
  if (f.tray) backend.setBackground(state.settings.keepInTray);

  $('clear-scan-history-btn').addEventListener('click', async () => {
    if (!(await backend.confirm('Clear the scan history? Your device list and names are kept.'))) return;
    state.history = [];
    state.entry = null;
    computeFindings();
    persist('scan-history');
    renderScan();
    setStatus('Scan history cleared.');
  });
  $('forget-devices-btn').addEventListener('click', async () => {
    if (!(await backend.confirm('Forget all devices, including the names you gave them? The next scan starts a new device list.'))) return;
    state.inventory = emptyInventory();
    persist('devices');
    renderScan();
    setStatus('All devices forgotten.');
  });
  renderSchedule();
  setInterval(() => {
    const next = nextAutoScan();
    if (next && Date.now() >= next.getTime()) autoScan();
    else renderSchedule();
  }, 30_000);

  // ---- Updates
  if (f.updater) {
    const banner = $('update-banner');
    const check = async (manual) => {
      if (manual) $('update-status').textContent = 'Checking for updates…';
      try {
        const u = await backend.checkUpdate();
        if (u) {
          $('update-text').textContent = `Version ${u.version} is available.`;
          banner.hidden = false;
          $('update-status').textContent = `Version ${u.version} is available.`;
        } else if (manual) {
          $('update-status').textContent = `You have the latest version (${APP_VERSION}).`;
        }
      } catch (e) {
        if (manual) $('update-status').textContent = /valid release JSON|404/i.test(errText(e)) ? 'Couldn’t find update information. Updates only work once the GitHub releases can be downloaded publicly.' : `Couldn’t check for updates: ${errText(e)}`;
      }
    };
    $('update-check-btn').addEventListener('click', () => check(true));
    $('update-dismiss-btn').addEventListener('click', () => (banner.hidden = true));
    $('update-install-btn').addEventListener('click', async () => {
      $('update-install-btn').disabled = true;
      try {
        await backend.installUpdate((pct) => ($('update-text').textContent = pct == null ? 'Downloading the update…' : `Downloading the update… ${pct}%`));
      } catch (e) {
        $('update-text').textContent = `The update failed: ${errText(e)}`;
        $('update-install-btn').disabled = false;
      }
    });
    if (state.settings.autoUpdate) check(false);
  }

  // Expose for automated checks.
  window.__fc = { state, tabs, backend };
}

main().catch((e) => setStatus(`Start-up error: ${errText(e)}`, 'error'));
