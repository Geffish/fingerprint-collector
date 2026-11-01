# Network Fingerprint Collector

Fingerprints the device it runs on, finds every device on the local network, lists everything attached to the computer, and writes it all up as a full report.

Built with [Tauri 2](https://tauri.app). One codebase produces a Windows app, an Android app and a web app.

## What it collects

| | Windows | Android | Web |
|---|---|---|---|
| **This device**: name, OS, processor, IP and MAC address, logged to CSV | ✔ | ✔ (Android hides the MAC address) | Browser-visible details only |
| **Network interfaces**: addresses, gateway, DNS, speed | ✔ | ✔ | — |
| **Network scan**: every device on the chosen ranges | ✔ | ✔ (no MAC addresses for other devices) | — |
| **Attached devices**: USB, drives, printers, monitors, peripherals | ✔ | Storage volumes only | — |
| **Wi-Fi connection**: network, signal, band, speed, security | ✔ | ✔ | — |
| **Device list and alerts**: names, known devices, new and missing devices | ✔ | ✔ | — |
| **Security checks**: risky and obsolete services | ✔ | ✔ | — |
| **Automatic scans** with notifications | ✔ (runs in the tray) | While the app is open | — |
| **Quick actions**: web page, shared folders, Remote Desktop, Wake-on-LAN | ✔ | Web page, Wake-on-LAN | — |
| **Full report**: HTML, PDF, JSON, CSV | ✔ | ✔ (PDF through the print dialog) | This device only |
| **Automatic updates** | ✔ | — | — |

### Network scan

The scanner checks each address in the chosen ranges (up to 4,096 per scan) and identifies whatever answers:

- **Discovery**: ARP (Windows), ICMP ping, TCP connect fallback, the OS neighbour cache, mDNS / Bonjour and SSDP / UPnP announcements.
- **Identity**: MAC address and maker (IEEE registry), DNS, NetBIOS and mDNS names, UPnP friendly name, manufacturer, model and serial number.
- **Services**: 33 common ports (web, SSH, SMB, RDP, printing, AirPlay, Chromecast, cameras, NAS, IoT and more) and advertised mDNS services.
- **Device type**: router, printer, NAS, TV, Cast device, phone, smart-home device, Windows PC and so on, inferred from all of the above.

Networks are found automatically. Virtual machine and VPN adapters are listed but not ticked. Networks larger than /24 default to the /24 around this device, and you can enter any other range (`192.168.1.0/24`, `10.0.0.1-50`).

Only scan networks you own or have permission to scan.

### Your devices, alerts and history

Every device found is added to **Your devices**, keyed by its MAC address (or IP address where Android hides the MAC). You can give each device your own name and tick **Known device** for the ones you recognise.

After each scan the app compares the result with the previous scan of the same networks and shows what is **new** and what is **missing**. The first scan is the starting point. Every scan is kept in **Scan history** (the last 100).

### Automatic scans and notifications

Settings → Automatic scans runs a scan every 15 minutes to every day, using the networks ticked on the Network tab. A notification appears when a new device joins, and optionally when a known device disappears.

On Windows the app can keep running in the system tray when its window is closed, and can start in the tray when you sign in. The tray icon has **Scan network now** and **Quit**. On Android, automatic scans run while the app is open.

### Security checks

Each scan is checked for services that are unencrypted, obsolete or often attacked, with plain-English advice:

- **High**: Telnet, SMBv1 file sharing (tested with a real SMB1 negotiation), VNC.
- **Medium**: FTP, Remote Desktop, unencrypted MQTT, open camera streams (RTSP), new devices.
- **Low**: UPnP on the router, settings pages without HTTPS, unencrypted mail.
- **Info**: printers that accept jobs from anyone.

The checks only look at what the scan found. They never log in to or change a device.

### Quick actions

Open a device's details for: **Open web page**, **Open shared folders** and **Remote Desktop** (Windows), **Wake** (Wake-on-LAN magic packet to every connected network), **Copy IP / MAC**, and **Check again** to re-scan just that device. Devices that are offline can also be woken from Your devices.

### Attached devices (Windows)

Read through Windows Management Instrumentation:

- **USB devices**: grouped by physical device, with manufacturer and product names from the USB ID database.
- **Drives**: physical drives (external and USB drives flagged, with their drive letters) and volumes, including mapped network drives.
- **Printers and monitors**: printers (local, USB, network) and monitors with model names.
- **Plug and Play**: every device, grouped by category, with a peripherals-only view.

On Android, the app lists USB devices plugged in through a USB OTG adapter and the storage volumes (internal, SD card, USB).

### Reports

**Reports → Build full report** collects anything still missing, then exports:

- **HTML report**: self-contained and printable. It includes the security checks, your devices and the scan history.
- **PDF report**: made with Microsoft Edge, Google Chrome or Brave on Windows; the Android and web versions open the print dialog, where you can choose Save as PDF.
- **JSON**: everything collected, for other tools.
- **CSV**: network devices and attached devices, one row per item.

## Where data is saved

- **Fingerprint history**: `network_fingerprints.csv` in the app data folder (Windows and Android) or browser storage (web). The columns match the original Python script.
- **Your devices, scan history and settings**: `devices.json`, `scan-history.json` and `settings.json` in the same app data folder.
- **Last scan and attached devices**: kept in the app so the Reports tab can use them after a restart.
- **Reports**: saved wherever you choose.

## Development

Requires Node.js, Rust, and, for Android, the Android SDK and NDK.

```sh
npm install
npm run tauri dev            # desktop app with hot reload
npm run dev                  # web version in the browser
```

## Building

```sh
npm run tauri build                          # Windows exe + NSIS + MSI → src-tauri/target/release/
npm run tauri android build -- --apk --target aarch64 --target armv7 --target x86_64
npm run build:web                            # web app → dist-web/
```

The Android release build is signed with the keystore described in
`~/.android-keystores/fingerprint-collector.secrets`. That file and the keystore are never committed.

### Updates

Windows builds are signed for the Tauri updater. Set the signing key before building:

```sh
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri-signing/fingerprint-collector.key)"
export $(cat ~/.tauri-signing/fingerprint-collector.secrets)   # TAURI_SIGNING_PRIVATE_KEY_PASSWORD
npm run tauri build
```

Each release needs a `latest.json` asset (version, notes, and the NSIS installer's URL and `.sig` signature). The app reads it from `releases/latest/download/latest.json`, so the release must be publicly downloadable for updates to work.

The web app deploys to GitHub Pages from `main` through `.github/workflows/pages.yml`.

Live scanner test against your own network:

```sh
cd src-tauri && cargo test --release live_scan -- --ignored --nocapture
```

### Android helper

`src-tauri/gen/android/app/src/main/java/com/geffert/fingerprintcollector/NetInfoPlugin.kt` is a small Kotlin plugin, called from Rust (`src-tauri/src/mobile.rs`). It provides Wi-Fi details, the multicast lock that mDNS and SSDP discovery need on Android, USB OTG devices, storage volumes and the print dialog.

## Data sources

- MAC vendor names: `src-tauri/data/oui.txt`, generated from the Wireshark `manuf` file (IEEE OUI, MA-M and MA-S registries).
- USB vendor and product names: `src-tauri/data/usb.txt`, generated from [linux-usb.org usb.ids](http://www.linux-usb.org/usb.ids).

## Legacy

The original Python CLI and Tkinter GUI are kept in [`legacy-python/`](legacy-python/).

---

© Copyright Peter Geffert 2026
