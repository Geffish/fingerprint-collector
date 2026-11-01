// Every device ever seen on the network, the names and trust the user gave
// them, and a history of scans with what appeared and disappeared each time.

const HISTORY_LIMIT = 100;

/** Stable identity for a device: its MAC address, or its IP where the MAC is hidden (Android). */
export const deviceKey = (h) => (h.mac_address ? `mac:${h.mac_address.toUpperCase()}` : `ip:${h.ip}`);

export const emptyInventory = () => ({ version: 1, devices: {} });

const rangesKey = (ranges) => [...ranges].sort().join(',');

/**
 * Record a finished scan: add new devices, update known ones and work out
 * what is new and what has gone missing since the last scan of the same ranges.
 * Mutates `inv` and `history`; returns the new history entry.
 */
export function mergeScan(inv, history, scan, { auto = false } = {}) {
  const baseline = Object.keys(inv.devices).length === 0;
  const keys = [];
  const added = [];
  for (const h of scan.hosts) {
    const key = deviceKey(h);
    keys.push(key);
    let d = inv.devices[key];
    if (!d) {
      d = inv.devices[key] = { key, first_seen: scan.started, label: '', trusted: !!h.is_self, seen_count: 0 };
      added.push(key);
    }
    Object.assign(d, {
      mac: h.mac_address || d.mac || null,
      ip: h.ip,
      name: h.display_name,
      device_type: h.device_type,
      vendor: h.vendor || d.vendor || null,
      private_mac: !!h.private_mac,
      is_self: !!h.is_self,
      last_seen: scan.started,
    });
    d.seen_count = (d.seen_count || 0) + 1;
  }

  const prev = history.find((e) => e.ranges_key === rangesKey(scan.ranges) && !e.cancelled);
  const now = new Set(keys);
  const missing = scan.cancelled || !prev ? [] : prev.keys.filter((k) => !now.has(k) && inv.devices[k]);

  const entry = {
    started: scan.started,
    ranges: scan.ranges,
    ranges_key: rangesKey(scan.ranges),
    total: scan.hosts.length,
    keys,
    added: baseline ? [] : added,
    missing,
    baseline,
    auto,
    cancelled: !!scan.cancelled,
  };
  history.unshift(entry);
  history.length = Math.min(history.length, HISTORY_LIMIT);
  return entry;
}

/** Update the inventory from a single re-checked host, without a history entry. */
export function touchDevice(inv, h, when) {
  const d = inv.devices[deviceKey(h)];
  if (!d) return;
  Object.assign(d, { ip: h.ip, name: h.display_name, device_type: h.device_type, last_seen: when });
}

export const nameFor = (inv, h) => inv?.devices[deviceKey(h)]?.label || h.display_name;
export const isKnown = (inv, h) => !!inv?.devices[deviceKey(h)]?.trusted;
export const isNew = (entry, h) => !!entry?.added?.includes(deviceKey(h));

/** All devices, most recently seen first. */
export function deviceList(inv) {
  return Object.values(inv.devices).sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || '') || (a.label || a.name || '').localeCompare(b.label || b.name || ''));
}

export const displayName = (d) => d.label || d.name || d.ip || d.key;
