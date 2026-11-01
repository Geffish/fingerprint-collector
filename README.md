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
| **Full report**: HTML, JSON, CSV | ✔ | ✔ | This device only |

### Network scan

The scanner checks each address in the chosen ranges (up to 4,096 per scan) and identifies whatever answers:

- **Discovery**: ARP (Windows), ICMP ping, TCP connect fallback, the OS neighbour cache, mDNS / Bonjour and SSDP / UPnP announcements.
- **Identity**: MAC address and maker (IEEE registry), DNS, NetBIOS and mDNS names, UPnP friendly name, manufacturer, model and serial number.
- **Services**: 33 common ports (web, SSH, SMB, RDP, printing, AirPlay, Chromecast, cameras, NAS, IoT and more) and advertised mDNS services.
- **Device type**: router, printer, NAS, TV, Cast device, phone, smart-home device, Windows PC and so on, inferred from all of the above.

Networks are found automatically. Virtual machine and VPN adapters are listed but not ticked. Networks larger than /24 default to the /24 around this device, and you can enter any other range (`192.168.1.0/24`, `10.0.0.1-50`).

Only scan networks you own or have permission to scan.

### Attached devices (Windows)

Read through Windows Management Instrumentation:

- **USB devices**: grouped by physical device, with manufacturer and product names from the USB ID database.
- **Drives**: physical drives (external and USB drives flagged, with their drive letters) and volumes, including mapped network drives.
- **Printers and monitors**: printers (local, USB, network) and monitors with model names.
- **Plug and Play**: every device, grouped by category, with a peripherals-only view.

### Reports

**Reports → Build full report** collects anything still missing, then exports:

- **HTML report**: self-contained and printable (print to PDF from any browser).
- **JSON**: everything collected, for other tools.
- **CSV**: network devices and attached devices, one row per item.

## Where data is saved

- **Fingerprint history**: `network_fingerprints.csv` in the app data folder (Windows and Android) or browser storage (web). The columns match the original Python script.
- **Last scan and device list**: kept in the app so the Reports tab can use them after a restart.
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

The web app deploys to GitHub Pages from `main` through `.github/workflows/pages.yml`.

Live scanner test against your own network:

```sh
cd src-tauri && cargo test --release live_scan -- --ignored --nocapture
```

## Data sources

- MAC vendor names: `src-tauri/data/oui.txt`, generated from the Wireshark `manuf` file (IEEE OUI, MA-M and MA-S registries).
- USB vendor and product names: `src-tauri/data/usb.txt`, generated from [linux-usb.org usb.ids](http://www.linux-usb.org/usb.ids).

## Legacy

The original Python CLI and Tkinter GUI are kept in [`legacy-python/`](legacy-python/).

---

© Copyright Peter Geffert 2026
