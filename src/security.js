// Security checks: services on the network that are unencrypted, obsolete or
// commonly abused, with plain-English advice. Nothing here logs in to or
// changes a device; it only looks at what the scan found.

import { deviceKey } from './inventory.js';

export const SEVERITIES = ['High', 'Medium', 'Low', 'Info'];
const ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

const has = (h, p) => (h.open_ports || []).some((o) => o.port === p);

const ADMIN_TYPES = new Set([
  'Router / gateway',
  'NAS / network storage',
  'NAS / media server',
  'Printer',
  'Scanner',
  'IP camera / NVR',
  'Network equipment',
  'Device with web interface',
  'Smart-home / IoT device',
]);

/** Rules applied to every host. Each returns a finding or null. */
const RULES = [
  (h) =>
    has(h, 23) && {
      severity: 'High',
      title: 'Telnet is open',
      detail: 'Telnet sends everything, including passwords, unencrypted, and is a common target for malware that takes over routers and cameras.',
      advice: 'Turn Telnet off in the device settings. Use SSH or the device’s web page instead.',
    },
  (h) =>
    h.smb1 === true && {
      severity: 'High',
      title: 'Obsolete SMBv1 file sharing is enabled',
      detail: 'SMB version 1 has serious known flaws and was used by the WannaCry and NotPetya ransomware to spread between computers.',
      advice: 'Turn off SMBv1 on this device. If it cannot be turned off (common on older NAS drives), update the firmware or consider replacing the device.',
    },
  (h) =>
    has(h, 5900) && {
      severity: 'High',
      title: 'VNC remote control is open',
      detail: 'VNC often uses weak or no passwords and usually isn’t encrypted. Anyone on the network may be able to see or control the screen.',
      advice: 'Turn VNC off if it isn’t needed, or set a strong password and limit who can connect.',
    },
  (h) =>
    has(h, 21) && {
      severity: 'Medium',
      title: 'FTP file transfer is open',
      detail: 'FTP sends user names, passwords and files unencrypted. Some devices also allow anonymous access.',
      advice: 'Turn FTP off, or use SFTP or FTPS if the device supports them.',
    },
  (h) =>
    has(h, 3389) && {
      severity: 'Medium',
      title: h.is_self ? 'This computer accepts Remote Desktop connections' : 'Remote Desktop is open',
      detail: 'Remote Desktop is a frequent target for password-guessing attacks, especially if it is reachable from the internet.',
      advice: 'Use a strong password, keep Network Level Authentication on, and never forward port 3389 on the router. Turn it off if it isn’t used.',
    },
  (h) =>
    has(h, 1883) && {
      severity: 'Medium',
      title: 'Unencrypted MQTT broker',
      detail: 'MQTT on port 1883 is unencrypted and many smart-home brokers accept connections without a password, letting anyone read or send device commands.',
      advice: 'Require a user name and password on the broker, and use MQTT over TLS (port 8883) where possible.',
    },
  (h) =>
    has(h, 554) && {
      severity: 'Medium',
      title: 'Camera or media stream is open (RTSP)',
      detail: 'RTSP streams from cameras can sometimes be watched without a password, or with the factory default one.',
      advice: 'Make sure the camera has its own strong password and the latest firmware. Don’t forward port 554 on the router.',
    },
  (h) =>
    h.is_gateway &&
    (h.upnp || (h.found_by || []).includes('UPnP')) && {
      severity: 'Low',
      title: 'UPnP is turned on at the router',
      detail: 'UPnP lets any device on the network open ports to the internet without asking. Malware can use it to expose devices.',
      advice: 'Turn UPnP off in the router settings unless something you use (some games consoles and video calls) needs it.',
    },
  (h) =>
    ADMIN_TYPES.has(h.device_type) &&
    (has(h, 80) || has(h, 8080)) &&
    !has(h, 443) &&
    !has(h, 8443) &&
    !has(h, 5001) && {
      severity: 'Low',
      title: 'Settings page is not encrypted',
      detail: 'The device’s web page uses plain HTTP, so the password you type to manage it can be read by others on the network.',
      advice: 'Turn on HTTPS in the device settings if it is offered, and use a password that you don’t use anywhere else.',
    },
  (h) =>
    [25, 110, 143].some((p) => has(h, p)) && {
      severity: 'Low',
      title: 'Unencrypted mail service',
      detail: 'SMTP, POP3 or IMAP without encryption can expose email and passwords on the network.',
      advice: 'Use the encrypted versions (ports 465/587, 995 and 993) and turn off the plain ones if possible.',
    },
  (h) =>
    has(h, 9100) && {
      severity: 'Info',
      title: 'Printing needs no password',
      detail: 'Port 9100 lets anyone on the network send print jobs to this printer. This is normal for home printers.',
      advice: 'Nothing to do on a home network. On shared networks, limit printing to known computers.',
    },
];

/**
 * @param scan        the latest scan
 * @param entry       the history entry for this scan (for new devices)
 * @param nameOf      (host) => display name, including user labels
 */
export function securityFindings(scan, entry, nameOf = (h) => h.display_name) {
  if (!scan) return [];
  const out = [];
  for (const h of scan.hosts) {
    for (const rule of RULES) {
      const f = rule(h);
      if (f) out.push({ ...f, ip: h.ip, device: nameOf(h), device_type: h.device_type });
    }
  }
  if (entry?.added?.length) {
    const byKey = new Map(scan.hosts.map((h) => [deviceKey(h), h]));
    for (const k of entry.added) {
      const h = byKey.get(k);
      if (!h) continue;
      out.push({
        severity: 'Medium',
        title: 'New device joined the network',
        detail: `${nameOf(h)} (${h.device_type}${h.vendor ? `, ${h.vendor}` : ''}) wasn’t seen in earlier scans.`,
        advice: 'If you recognise it, open it in the device list and tick “Known device”. If you don’t, check the router’s list of connected devices and change the Wi-Fi password if needed.',
        ip: h.ip,
        device: nameOf(h),
        device_type: h.device_type,
      });
    }
  }
  return out.sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
}

export function severityCounts(findings) {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) c[f.severity]++;
  return c;
}
