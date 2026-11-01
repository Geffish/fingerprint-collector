// Two back ends behind one interface:
//  - Tauri (Windows / Android): native Rust commands, CSV in the app data folder,
//    network scanning and attached-device inventory.
//  - Web: what the browser exposes, history kept in localStorage.

export const FIELDS = [
  'computer_name',
  'os',
  'processor_architecture',
  'processor_model',
  'ip_address',
  'mac_address',
  'system_time',
];

export const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

/** Generic CSV writer: rows of objects, explicit column list. */
export function toCsv(rows, columns = FIELDS, headers = columns) {
  const esc = (v) => {
    const s = Array.isArray(v) ? v.join('; ') : String(v ?? '');
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.map(esc).join(',')];
  for (const r of rows) lines.push(columns.map((c) => esc(typeof c === 'function' ? c(r) : r[c])).join(','));
  return lines.join('\r\n') + '\r\n';
}

export function localIsoTime() {
  const d = new Date();
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}` +
    `T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}000`
  );
}

export function fileStamp() {
  return localIsoTime().slice(0, 16).replace('T', '_').replace(':', '');
}

const MIME = { csv: 'text/csv', html: 'text/html', json: 'application/json' };

/** Print an HTML document with the browser's print dialog (offers Save as PDF). */
function printHtml(html) {
  const frame = document.createElement('iframe');
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  frame.srcdoc = html;
  frame.onload = () => {
    frame.contentWindow.focus();
    frame.contentWindow.print();
    setTimeout(() => frame.remove(), 60_000);
  };
  document.body.appendChild(frame);
}

// ---------------------------------------------------------------- Tauri ---

async function tauriBackend() {
  const { invoke } = await import('@tauri-apps/api/core');
  const { listen } = await import('@tauri-apps/api/event');
  const { save, ask } = await import('@tauri-apps/plugin-dialog');
  const { writeTextFile } = await import('@tauri-apps/plugin-fs');
  const notification = await import('@tauri-apps/plugin-notification');
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  const info = await invoke('app_info');
  const desktop = info.desktop;
  const windows = info.os === 'windows';
  const android = info.os === 'android';

  let pendingUpdate = null;

  async function saveFile(defaultName, text, ext) {
    const path = await save({
      defaultPath: defaultName,
      filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
    });
    if (!path) return null;
    await writeTextFile(path, text);
    return path;
  }

  return {
    native: true,
    label: 'Native app — full system, network and device details',
    info,
    features: {
      wake: true,
      share: windows,
      rdp: windows,
      pdf: windows || android,
      wifi: windows || android,
      tray: desktop,
      autostart: desktop,
      updater: desktop,
      schedule: true,
    },
    collect: () => invoke('collect_fingerprint'),
    extras: () => null,
    save: (fingerprint) => invoke('save_fingerprint', { fingerprint }),
    history: () => invoke('load_history'),
    historyCsv: () => invoke('history_csv'),
    storageLocation: async () => `Saved to: ${await invoke('get_csv_path')}`,
    confirm: (message) => ask(message, { title: 'Fingerprint Collector', kind: 'warning' }),
    clear: () => invoke('clear_history'),
    interfaces: () => invoke('get_interfaces'),
    scanRanges: () => invoke('get_scan_ranges'),
    scan: (ranges) => invoke('scan_network', { ranges }),
    cancelScan: () => invoke('cancel_scan'),
    onScanProgress: (cb) => listen('scan-progress', (e) => cb(e.payload)),
    attached: () => invoke('get_attached_devices'),
    saveFile,
    loadStore: (name) => invoke('store_load', { name }),
    saveStore: (name, value) => invoke('store_save', { name, value }),
    wake: (mac) => invoke('wake_on_lan', { mac }),
    openShare: (ip) => invoke('open_share', { ip }),
    openRemoteDesktop: (ip) => invoke('open_remote_desktop', { ip }),
    openUrl: (url) => openUrl(url),
    wifi: () => invoke('get_wifi_info'),
    async exportPdf(name, html) {
      if (android) return invoke('export_pdf', { html, name, path: null });
      const path = await save({ defaultPath: name, filters: [{ name: 'PDF', extensions: ['pdf'] }] });
      if (!path) return null;
      return invoke('export_pdf', { html, name, path });
    },
    async notify(title, body) {
      let ok = await notification.isPermissionGranted();
      if (!ok) ok = (await notification.requestPermission()) === 'granted';
      if (ok) notification.sendNotification({ title, body });
      return ok;
    },
    setBackground: (enabled) => invoke('set_background_mode', { enabled }),
    onTrayScan: (cb) => listen('tray-scan', () => cb()),
    async autostart(enable) {
      const a = await import('@tauri-apps/plugin-autostart');
      if (enable === undefined) return a.isEnabled();
      await (enable ? a.enable() : a.disable());
      return a.isEnabled();
    },
    async checkUpdate() {
      const { check } = await import('@tauri-apps/plugin-updater');
      pendingUpdate = await check();
      return pendingUpdate ? { version: pendingUpdate.version, notes: pendingUpdate.body || '' } : null;
    },
    async installUpdate(onProgress) {
      if (!pendingUpdate) return;
      let total = 0;
      let got = 0;
      await pendingUpdate.downloadAndInstall((e) => {
        if (e.event === 'Started') total = e.data.contentLength || 0;
        if (e.event === 'Progress') got += e.data.chunkLength;
        onProgress?.(total ? Math.round((got / total) * 100) : null);
      });
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
    },
  };
}

// ------------------------------------------------------------------ Web ---

const STORAGE_KEY = 'fingerprint-collector.history';
const NOT_IN_BROWSER = 'N/A (not available in a browser)';

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

function writeStore(rows) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(rows));
    return true;
  } catch {
    return false;
  }
}

function parseUserAgent(ua) {
  const rules = [
    [/Windows NT 10\.0/, 'Windows 10/11'],
    [/Windows NT 6\.3/, 'Windows 8.1'],
    [/Windows NT 6\.1/, 'Windows 7'],
    [/Android ([\d.]+)/, 'Android $1'],
    [/iPhone OS ([\d_]+)/, 'iOS $1'],
    [/iPad.*OS ([\d_]+)/, 'iPadOS $1'],
    [/Mac OS X ([\d_]+)/, 'macOS $1'],
    [/CrOS/, 'ChromeOS'],
    [/Linux/, 'Linux'],
  ];
  for (const [re, name] of rules) {
    const m = ua.match(re);
    if (m) return name.replace('$1', (m[1] || '').replace(/_/g, '.'));
  }
  return 'Unknown';
}

function browserName(ua, uaData) {
  const brand = uaData?.brands?.find((b) => !/Not.?A.?Brand|Chromium/i.test(b.brand));
  if (brand) return `${brand.brand} ${brand.version}`;
  const rules = [
    [/Edg\/([\d.]+)/, 'Edge'],
    [/Firefox\/([\d.]+)/, 'Firefox'],
    [/Chrome\/([\d.]+)/, 'Chrome'],
    [/Version\/([\d.]+).*Safari/, 'Safari'],
  ];
  for (const [re, name] of rules) {
    const m = ua.match(re);
    if (m) return `${name} ${m[1].split('.')[0]}`;
  }
  return 'Unknown';
}

async function webCollect() {
  const ua = navigator.userAgent;
  const uaData = navigator.userAgentData;
  let hi = {};
  if (uaData?.getHighEntropyValues) {
    try {
      hi = await uaData.getHighEntropyValues(['platformVersion', 'architecture', 'bitness', 'model']);
    } catch {
      hi = {};
    }
  }

  let os = parseUserAgent(ua);
  if (hi.platform === 'Windows' && hi.platformVersion) {
    const major = parseInt(hi.platformVersion.split('.')[0], 10);
    os = `${major >= 13 ? 'Windows 11' : 'Windows 10'} (platform ${hi.platformVersion})`;
  } else if (hi.platform && hi.platformVersion) {
    os = `${hi.platform} ${hi.platformVersion}`;
  }

  const arch = hi.architecture ? `${hi.architecture}${hi.bitness ? `-${hi.bitness}` : ''}` : 'N/A';
  const cores = navigator.hardwareConcurrency;

  return {
    computer_name: hi.model ? hi.model : NOT_IN_BROWSER,
    os,
    processor_architecture: arch,
    processor_model: cores ? `${cores} logical processors` : 'N/A',
    ip_address: NOT_IN_BROWSER,
    mac_address: NOT_IN_BROWSER,
    system_time: localIsoTime(),
  };
}

function webExtras() {
  const ua = navigator.userAgent;
  const scr = window.screen;
  return {
    browser: browserName(ua, navigator.userAgentData),
    language: navigator.languages?.join(', ') || navigator.language,
    time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: `${scr.width} × ${scr.height} @ ${window.devicePixelRatio}x`,
    device_memory: navigator.deviceMemory ? `${navigator.deviceMemory} GB (approx.)` : 'N/A',
    online: navigator.onLine ? 'Yes' : 'No',
    user_agent: ua,
  };
}

function download(defaultName, text, ext) {
  const blob = new Blob([text], { type: `${MIME[ext] || 'text/plain'};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = defaultName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return defaultName;
}

const NATIVE_ONLY = 'Network scanning and attached devices need the Windows or Android app. Browsers cannot reach other devices or hardware.';

function webBackend() {
  return {
    native: false,
    label: 'Web version — limited to what your browser exposes',
    collect: webCollect,
    extras: webExtras,
    async save(fingerprint) {
      const rows = readStore();
      rows.push(fingerprint);
      if (!writeStore(rows)) throw new Error('Browser storage is unavailable, so the fingerprint was not saved.');
      return 'browser storage';
    },
    history: async () => readStore(),
    historyCsv: async () => {
      const rows = readStore();
      return rows.length ? toCsv(rows) : '';
    },
    storageLocation: async () =>
      'Saved in this browser only. Use Export CSV to keep a copy. Install the desktop or Android app for IP and MAC addresses.',
    confirm: async (message) => window.confirm(message),
    async clear() {
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* storage unavailable */
      }
    },
    interfaces: async () => [],
    scanRanges: async () => [],
    scan: async () => {
      throw new Error(NATIVE_ONLY);
    },
    cancelScan: async () => {},
    onScanProgress: async () => () => {},
    attached: async () => {
      throw new Error(NATIVE_ONLY);
    },
    saveFile: async (name, text, ext) => download(name, text, ext),
    info: { os: 'web', version: null, desktop: false },
    features: { pdf: true },
    loadStore: async (name) => {
      try {
        return JSON.parse(localStorage.getItem('fingerprint-collector.' + name) || 'null');
      } catch {
        return null;
      }
    },
    saveStore: async (name, value) => {
      try {
        localStorage.setItem('fingerprint-collector.' + name, JSON.stringify(value));
      } catch {
        /* storage unavailable */
      }
    },
    openUrl: async (url) => window.open(url, '_blank', 'noopener'),
    exportPdf: async (_name, html) => {
      printHtml(html);
      return 'the print dialog';
    },
    notify: async () => false,
    setBackground: async () => {},
    onTrayScan: async () => () => {},
    nativeOnlyMessage: NATIVE_ONLY,
  };
}

export async function createBackend() {
  return isTauri ? tauriBackend() : webBackend();
}
