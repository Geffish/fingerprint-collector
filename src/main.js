import './style.css';
import { createBackend, fileStamp } from './backend.js';
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

const APP_VERSION = '1.0.0';
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

/** Everything collected this session; also the source for reports. */
const state = {
  fingerprint: null,
  extras: null,
  interfaces: null,
  scan: null,
  attached: null,
  scanning: false,
};

// Remember the last scan and inventory between sessions (convenience only).
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

// --------------------------------------------------------------- Network ---

let rangeOptions = [];

function renderRanges() {
  const box = $('range-list');
  box.replaceChildren();
  if (!rangeOptions.length) {
    box.append(h('p', { class: 'hint' }, 'No active network connection found. Enter a range below.'));
    return;
  }
  for (const r of rangeOptions) {
    box.append(
      h(
        'label',
        { class: 'range' },
        h('input', { type: 'checkbox', value: r.cidr, checked: !r.is_virtual }),
        h('span', {}, h('b', {}, r.cidr), ` — ${r.interface} · ${r.hosts.toLocaleString('en-AU')} addresses`, r.is_virtual ? h('span', { class: 'tag muted' }, 'Virtual / VPN') : null),
        r.note ? h('small', { class: 'hint' }, r.note) : null,
      ),
    );
  }
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

let typeFilter = null;

function renderScan() {
  const scan = state.scan;
  $('scan-results').hidden = !scan;
  if (!scan) return;
  $('scan-total').textContent = `(${scan.hosts.length})`;
  $('scan-meta').textContent = `Scanned ${scan.ranges.join(', ')} — ${scan.addresses_scanned.toLocaleString('en-AU')} addresses on ${formatDateTime(scan.started)}, took ${scan.duration_seconds} s.`;
  const notes = $('scan-notes');
  notes.replaceChildren(...(scan.notes || []).map((n) => h('p', { class: 'note' }, n)));

  const chips = $('type-chips');
  chips.replaceChildren();
  const counts = groupBy(scan.hosts, (x) => x.device_type);
  const chip = (name, n) =>
    h(
      'button',
      {
        type: 'button',
        class: `chip${typeFilter === name ? ' on' : ''}`,
        onclick: () => {
          typeFilter = typeFilter === name ? null : name;
          renderScan();
        },
      },
      `${TYPE_ICONS[name] || '❔'} ${name} `,
      h('span', { class: 'count' }, n),
    );
  for (const [name, list] of counts) chips.append(chip(name, list.length));
  renderHosts();
}

function renderHosts() {
  const list = $('host-list');
  list.replaceChildren();
  const q = $('scan-filter').value.trim().toLowerCase();
  const hosts = state.scan.hosts.filter((x) => {
    if (typeFilter && x.device_type !== typeFilter) return false;
    if (!q) return true;
    return [x.ip, x.display_name, x.device_type, x.vendor, x.mac_address, x.hostname, x.netbios_name, hostModel(x), ...hostServices(x)]
      .filter(Boolean)
      .some((v) => String(v).toLowerCase().includes(q));
  });
  if (!hosts.length) {
    list.append(h('p', { class: 'empty' }, 'No devices match.'));
    return;
  }
  for (const x of hosts) {
    const details = h('dl', { class: 'result compact' });
    renderPairs(details, {
      'Device type': x.device_type,
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
      'Response time': x.latency_ms != null ? `${x.latency_ms.toFixed(1)} ms` : null,
      'Found by': [...(x.found_by || [])],
      Interface: x.interface,
    });
    const webPort = (x.open_ports || []).find((p) => [80, 443, 8080, 8443].includes(p.port));
    list.append(
      h(
        'details',
        { class: 'host' },
        h(
          'summary',
          {},
          h('span', { class: 'host-icon', 'aria-hidden': 'true' }, TYPE_ICONS[x.device_type] || '❔'),
          h(
            'span',
            { class: 'host-main' },
            h('b', {}, x.display_name),
            h('span', { class: 'host-sub' }, [x.device_type, x.vendor].filter(Boolean).join(' · ')),
          ),
          h('span', { class: 'host-ip mono' }, x.ip),
        ),
        details,
        webPort && !x.is_self
          ? h('p', { class: 'hint' }, 'Web interface: ', h('span', { class: 'mono' }, `${webPort.port === 443 || webPort.port === 8443 ? 'https' : 'http'}://${x.ip}${[80, 443].includes(webPort.port) ? '' : `:${webPort.port}`}/`))
          : null,
      ),
    );
  }
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
  const items = [
    ['This device', state.fingerprint ? `Collected ${formatDateTime(state.fingerprint.system_time)}` : 'Will be collected'],
    ['Network interfaces', state.interfaces ? `${state.interfaces.filter((i) => i.is_up && i.ipv4.length).length} active` : 'Will be collected'],
    ['Network devices', state.scan ? `${state.scan.hosts.length} devices, scanned ${formatDateTime(state.scan.started)}` : 'A scan will run'],
    ['Attached devices', state.attached ? `${(state.attached.devices || []).length} devices, collected ${formatDateTime(state.attached.collected)}` : 'Will be collected'],
  ];
  const native = backend?.native;
  $('report-checklist').replaceChildren(
    ...items
      .filter((_, i) => native || i === 0)
      .map(([t, s]) => h('li', { class: s.startsWith('Will') || s.startsWith('A scan') ? 'todo' : 'done' }, h('b', {}, t), h('span', {}, s))),
  );
  // This device is collected on demand at export time, so any data is enough.
  const ready = !!(state.fingerprint || state.scan || state.attached);
  $('report-html-btn').disabled = !ready;
  $('report-json-btn').disabled = !ready;
  $('report-net-csv-btn').disabled = !state.scan;
  $('report-att-csv-btn').disabled = !state.attached;
}

function reportData() {
  return {
    fingerprint: state.fingerprint,
    extras: state.extras,
    interfaces: state.interfaces,
    scan: state.scan,
    attached: state.attached,
    appVersion: APP_VERSION,
  };
}

// ------------------------------------------------------------------ Main ---

let backend = null;

async function main() {
  $('copyright').textContent = `© Copyright Peter Geffert ${new Date().getFullYear()}`;
  backend = await createBackend();
  $('mode-label').textContent = backend.label;
  const tabs = setupTabs();
  if (backend.native) loadCache();

  // ---- This device
  const refreshHistory = async () => {
    try {
      renderHistory(await backend.history());
    } catch (e) {
      setStatus(`Could not load history: ${errText(e)}`, 'error');
    }
  };
  try {
    $('csv-path').textContent = await backend.storageLocation();
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

  // ---- Network
  if (backend.native) {
    $('interfaces-card').hidden = false;
    $('interfaces-btn').addEventListener('click', () => loadInterfaces().catch((e) => setStatus(errText(e), 'error')));
    loadInterfaces().catch(() => {});
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

  const progress = (prefix, p) => {
    const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
    $(`${prefix}-phase`).textContent = p.phase;
    $(`${prefix}-count`).textContent = p.phase === 'Identifying devices' ? `${p.done} of ${p.total} devices` : `${p.found} found · ${pct}%`;
    $(`${prefix}-bar`).style.width = `${pct}%`;
  };

  let progressTarget = 'scan';
  await backend.onScanProgress((p) => progress(progressTarget, p));

  const runScan = async (ranges, target = 'scan') => {
    progressTarget = target;
    state.scanning = true;
    $('scan-btn').disabled = true;
    $('build-report-btn').disabled = true;
    $('cancel-scan-btn').hidden = false;
    $(`${target}-progress`).hidden = false;
    progress(target, { phase: 'Starting…', done: 0, total: 1, found: 0 });
    setStatus('Scanning the network…');
    try {
      state.scan = await backend.scan(ranges);
      typeFilter = null;
      saveCache();
      renderScan();
      renderChecklist();
      setStatus(`Scan finished: ${state.scan.hosts.length} devices found.`, 'success');
    } finally {
      state.scanning = false;
      $('scan-btn').disabled = false;
      $('build-report-btn').disabled = false;
      $('cancel-scan-btn').hidden = true;
      $(`${target}-progress`).hidden = true;
    }
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
  $('scan-csv-btn').addEventListener('click', () => exportFile(`network_devices_${fileStamp()}.csv`, networkCsv(state.scan), 'csv'));
  $('scan-json-btn').addEventListener('click', () => exportFile(`network_scan_${fileStamp()}.json`, JSON.stringify(state.scan, null, 2), 'json'));
  renderScan();

  // ---- Attached
  const loadAttached = async () => {
    $('attached-btn').disabled = true;
    setStatus('Reading attached devices…');
    try {
      state.attached = await backend.attached();
      saveCache();
      renderAttached();
      renderChecklist();
      setStatus(`Found ${(state.attached.devices || []).length} devices attached to this computer.`, 'success');
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
        setStatus('Reading attached devices…');
        await loadAttached();
        if (!state.scan) {
          const defaults = rangeOptions.filter((r) => !r.is_virtual).map((r) => r.cidr);
          await runScan(defaults, 'report');
        }
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
  $('report-json-btn').addEventListener('click', async () => {
    await ensureDevice();
    const { appVersion, ...data } = reportData();
    exportFile(`network_report_${fileStamp()}.json`, JSON.stringify({ generated: new Date().toISOString(), app_version: appVersion, ...data }, null, 2), 'json');
  });
  $('report-net-csv-btn').addEventListener('click', () => exportFile(`network_devices_${fileStamp()}.csv`, networkCsv(state.scan), 'csv'));
  $('report-att-csv-btn').addEventListener('click', () => exportFile(`attached_devices_${fileStamp()}.csv`, attachedCsv(state.attached), 'csv'));
  renderChecklist();

  // Expose for automated checks.
  window.__fc = { state, tabs };
}

main().catch((e) => setStatus(`Start-up error: ${errText(e)}`, 'error'));
