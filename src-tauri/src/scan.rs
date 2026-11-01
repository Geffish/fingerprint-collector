//! Local network scan: find every device on the chosen IPv4 ranges and
//! identify it as well as the network allows.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::discovery::{self, MdnsInfo, UpnpInfo};
use crate::interfaces::{self, LocalNet};
use crate::oui;
use crate::probe::{self, Pinger, TcpResult};

pub const MAX_HOSTS: usize = 4096;

static RUNNING: AtomicBool = AtomicBool::new(false);
static CANCEL: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Host {
    pub ip: String,
    pub display_name: String,
    pub device_type: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub private_mac: bool,
    pub hostname: Option<String>,
    pub netbios_name: Option<String>,
    pub workgroup: Option<String>,
    pub mdns: Option<MdnsInfo>,
    pub upnp: Option<UpnpInfo>,
    pub open_ports: Vec<OpenPort>,
    pub latency_ms: Option<f64>,
    pub found_by: BTreeSet<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    pub interface: Option<String>,
    /// The file server still accepts the obsolete SMBv1 protocol.
    pub smb1: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub started: String,
    pub finished: String,
    pub duration_seconds: f64,
    pub ranges: Vec<String>,
    pub addresses_scanned: usize,
    pub hosts: Vec<Host>,
    pub notes: Vec<String>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Progress {
    phase: String,
    done: usize,
    total: usize,
    found: usize,
}

fn emit_event(app: &AppHandle, phase: &str, done: usize, total: usize, found: usize) {
    let _ = app.emit(
        "scan-progress",
        Progress { phase: phase.to_string(), done, total, found },
    );
}

// --------------------------------------------------------------- ranges ---

fn parse_range(text: &str) -> Result<Vec<Ipv4Addr>, String> {
    let t = text.trim();
    if let Some((ip, prefix)) = t.split_once('/') {
        let ip: Ipv4Addr = ip.trim().parse().map_err(|_| format!("“{t}” is not a valid address range"))?;
        let prefix: u32 = prefix.trim().parse().map_err(|_| format!("“{t}” has an invalid prefix"))?;
        if !(16..=32).contains(&prefix) {
            return Err(format!("“{t}”: prefix must be between /16 and /32"));
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let net = u32::from(ip) & mask;
        let size = 1u64 << (32 - prefix);
        if size as usize > MAX_HOSTS + 2 {
            return Err(format!("“{t}” has {size} addresses; the limit is {MAX_HOSTS} per scan"));
        }
        let (first, last) = if prefix >= 31 {
            (net as u64, net as u64 + size - 1)
        } else {
            (net as u64 + 1, net as u64 + size - 2)
        };
        return Ok((first..=last).map(|n| Ipv4Addr::from(n as u32)).collect());
    }
    if let Some((a, b)) = t.split_once('-') {
        let start: Ipv4Addr = a.trim().parse().map_err(|_| format!("“{t}” is not a valid address range"))?;
        let end: Ipv4Addr = match b.trim().parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(_) => {
                let last: u8 = b.trim().parse().map_err(|_| format!("“{t}” is not a valid address range"))?;
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            }
        };
        let (s, e) = (u32::from(start), u32::from(end));
        if e < s {
            return Err(format!("“{t}”: the end address is before the start"));
        }
        if (e - s) as usize >= MAX_HOSTS {
            return Err(format!("“{t}” has more than {MAX_HOSTS} addresses"));
        }
        return Ok((s..=e).map(Ipv4Addr::from).collect());
    }
    let ip: Ipv4Addr = t.parse().map_err(|_| format!("“{t}” is not a valid address or range"))?;
    Ok(vec![ip])
}

fn net_contains(net: &LocalNet, ip: Ipv4Addr) -> bool {
    let mask = if net.prefix == 0 { 0 } else { u32::MAX << (32 - net.prefix as u32) };
    u32::from(ip) & mask == u32::from(net.address) & mask
}

// ------------------------------------------------------- classification ---

fn has_port(h: &Host, p: u16) -> bool {
    h.open_ports.iter().any(|o| o.port == p)
}

fn classify(h: &Host) -> String {
    let vendor = h.vendor.clone().unwrap_or_default().to_lowercase();
    let services: Vec<String> = h
        .mdns
        .as_ref()
        .map(|m| m.services.iter().map(|s| s.to_lowercase()).collect())
        .unwrap_or_default();
    let svc = |s: &str| services.iter().any(|x| x.contains(s));
    let upnp_type = h
        .upnp
        .as_ref()
        .and_then(|u| u.device_type.clone())
        .unwrap_or_default()
        .to_lowercase();
    let model = h
        .upnp
        .as_ref()
        .and_then(|u| u.model_name.clone())
        .or_else(|| h.mdns.as_ref().and_then(|m| m.model.clone()))
        .unwrap_or_default()
        .to_lowercase();

    if h.is_self {
        return "This device".into();
    }
    if h.is_gateway || upnp_type.contains("internetgatewaydevice") {
        return "Router / gateway".into();
    }
    // NAS boxes often run a print server too, so check them before printers.
    let nas_vendor = ["synology", "qnap", "seagate", "segate", "western digital", "buffalo", "asustor", "terramaster", "drobo"]
        .iter()
        .any(|v| vendor.contains(v));
    let file_server = has_port(h, 445) || has_port(h, 548) || svc("smb") || svc("apple file sharing");
    if (nas_vendor && file_server) || svc("time machine") || has_port(h, 548) && has_port(h, 445) && !vendor.contains("apple") {
        return "NAS / network storage".into();
    }
    if svc("printer") || has_port(h, 9100) || (has_port(h, 631) || has_port(h, 515)) && !file_server || upnp_type.contains("printer") {
        return "Printer".into();
    }
    if svc("scanner") {
        return "Scanner".into();
    }
    if svc("google cast") || has_port(h, 8009) {
        return "Cast-enabled media device".into();
    }
    if svc("android tv") || svc("amazon fire tv") || upnp_type.contains("mediarenderer") || model.contains("tv") {
        return "TV / media player".into();
    }
    if svc("sonos") || svc("spotify connect") || svc("airplay audio") && !vendor.contains("apple") {
        return "Speaker / audio device".into();
    }
    if vendor.contains("apple") {
        if has_port(h, 62078) && !svc("smb") && !has_port(h, 22) {
            return "iPhone / iPad".into();
        }
        if svc("airplay") && !svc("smb") && !svc("ssh") {
            return "Apple TV / HomePod".into();
        }
        return "Apple computer / device".into();
    }
    if has_port(h, 62078) {
        return "iPhone / iPad".into();
    }
    if has_port(h, 554) || vendor.contains("hikvision") || vendor.contains("dahua") || vendor.contains("reolink") {
        return "IP camera / NVR".into();
    }
    if upnp_type.contains("mediaserver") && has_port(h, 5000) {
        return "NAS / media server".into();
    }
    if has_port(h, 32400) {
        return "Media server".into();
    }
    if svc("homekit") || svc("matter") || svc("hue") || svc("esphome") || svc("xiaomi") || has_port(h, 1883)
        || ["espressif", "tuya", "shelly", "sonoff", "itead", "lifx", "signify", "philips lighting", "nest", "ring", "wiz", "broadlink", "xiaomi", "amazon technologies"].iter().any(|v| vendor.contains(v))
    {
        return "Smart-home / IoT device".into();
    }
    if vendor.contains("raspberry") {
        return "Raspberry Pi".into();
    }
    if has_port(h, 3389) || has_port(h, 135) || h.netbios_name.is_some() && has_port(h, 445) {
        return "Windows computer".into();
    }
    if has_port(h, 445) || has_port(h, 139) || svc("smb") {
        return "Computer / file server".into();
    }
    if has_port(h, 22) && h.open_ports.len() <= 3 {
        return "Linux / network device".into();
    }
    if ["ubiquiti", "tp-link", "netgear", "cisco", "aruba", "mikrotik", "d-link", "zyxel", "eero", "huawei", "sagemcom", "technicolor", "arris", "linksys", "asustek"].iter().any(|v| vendor.contains(v)) && (has_port(h, 80) || has_port(h, 443)) {
        return "Network equipment".into();
    }
    if ["samsung", "lg electronics", "sony", "hisense", "tcl", "vizio", "roku"].iter().any(|v| vendor.contains(v)) && !h.open_ports.is_empty() {
        return "TV / media player".into();
    }
    if ["nintendo", "microsoft", "sony interactive"].iter().any(|v| vendor.contains(v)) && h.open_ports.is_empty() {
        return "Games console / device".into();
    }
    if h.private_mac && h.open_ports.is_empty() {
        return "Phone / tablet (private address)".into();
    }
    if ["samsung", "google", "oneplus", "xiaomi", "oppo", "motorola", "huawei", "vivo", "realme"].iter().any(|v| vendor.contains(v)) && h.open_ports.is_empty() {
        return "Phone / tablet".into();
    }
    if has_port(h, 80) || has_port(h, 443) || has_port(h, 8080) {
        return "Device with web interface".into();
    }
    "Unknown device".into()
}

fn display_name(h: &Host) -> String {
    if h.is_self {
        if let Some(n) = h.netbios_name.clone().or_else(|| h.hostname.clone()) {
            return n;
        }
    }
    h.upnp
        .as_ref()
        // A Wi-Fi Protected Setup sub-device is always called "WPS Access Point".
        .filter(|u| !u.device_type.as_deref().unwrap_or("").contains("WFADevice"))
        .and_then(|u| u.friendly_name.clone())
        .or_else(|| h.mdns.as_ref().and_then(|m| m.friendly_name.clone()))
        .or_else(|| h.mdns.as_ref().and_then(|m| m.instance_names.iter().next().cloned()))
        .or_else(|| h.netbios_name.clone())
        .or_else(|| h.mdns.as_ref().and_then(|m| m.hostname.clone()).filter(|n| !is_ip_name(n, &h.ip)))
        .or_else(|| h.hostname.clone().filter(|n| !is_ip_name(n, &h.ip)))
        .or_else(|| h.vendor.clone().filter(|v| !v.starts_with("Private")).map(|v| format!("{v} device")))
        .unwrap_or_else(|| h.ip.clone())
}

/// Auto-generated names such as "192-168-0-104" or "ip-192-168-0-104.lan".
fn is_ip_name(name: &str, ip: &str) -> bool {
    let dashed = ip.replace('.', "-");
    let n = name.to_ascii_lowercase();
    n.contains(&dashed) || n.starts_with(ip)
}

// ----------------------------------------------------------------- scan ---

pub fn run(emit: &(dyn Fn(&str, usize, usize, usize) + Sync), ranges: Vec<String>) -> Result<ScanResult, String> {
    let started_at = chrono::Local::now();
    let t0 = Instant::now();
    let mut notes = Vec::new();

    let nets = interfaces::local_nets();
    let ranges: Vec<String> = if ranges.iter().all(|r| r.trim().is_empty()) {
        interfaces::suggested_ranges().into_iter().filter(|r| !r.is_virtual).map(|r| r.cidr).collect()
    } else {
        ranges.into_iter().filter(|r| !r.trim().is_empty()).collect()
    };
    if ranges.is_empty() {
        return Err("No active network connection was found to scan.".into());
    }

    let mut targets: Vec<Ipv4Addr> = Vec::new();
    for r in &ranges {
        targets.extend(parse_range(r)?);
    }
    targets.sort();
    targets.dedup();
    if targets.len() > MAX_HOSTS {
        return Err(format!(
            "That is {} addresses; the limit is {MAX_HOSTS} per scan. Choose a smaller range.",
            targets.len()
        ));
    }
    let in_scope: std::collections::HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let local_ips: Vec<Ipv4Addr> = nets.iter().map(|n| n.address).collect();
    let gateways: Vec<Ipv4Addr> = nets.iter().filter_map(|n| n.gateway).collect();

    let hosts: Arc<Mutex<HashMap<Ipv4Addr, Host>>> = Arc::new(Mutex::new(HashMap::new()));
    let new_host = |ip: Ipv4Addr| Host {
        ip: ip.to_string(),
        is_self: local_ips.contains(&ip),
        is_gateway: gateways.contains(&ip),
        interface: nets.iter().find(|n| net_contains(n, ip)).map(|n| n.interface.clone()),
        ..Default::default()
    };

    // 1. Passive discovery runs alongside the sweep.
    let listen = Duration::from_secs(6);
    let ssdp_ips = local_ips.clone();
    let ssdp_handle = std::thread::spawn(move || discovery::ssdp(&ssdp_ips, listen, &CANCEL));
    let mdns_handle = std::thread::spawn(move || discovery::mdns(listen, &CANCEL));

    // 2. Sweep: ARP (Windows) + ICMP, with a TCP fallback where ARP is unavailable.
    let total = targets.len();
    let done = Arc::new(AtomicUsize::new(0));
    let queue = Arc::new(Mutex::new(targets.clone()));
    let workers = 128.min(total.max(1));
    let have_arp = cfg!(windows);
    emit("Sweeping addresses", 0, total, 0);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let hosts = Arc::clone(&hosts);
            let done = Arc::clone(&done);
            let nets = &nets;
            let new_host = &new_host;
            scope.spawn(move || {
                let pinger = Pinger::new();
                loop {
                    if CANCEL.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(ip) = queue.lock().unwrap().pop() else { break };
                    let on_link = nets.iter().any(|n| net_contains(n, ip));
                    let mut found_by = BTreeSet::new();
                    let mut mac = None;
                    let mut latency = None;

                    if have_arp && on_link {
                        if let Some(m) = probe::arp(ip) {
                            mac = Some(m);
                            found_by.insert("ARP".to_string());
                        }
                    }
                    if let Some(p) = &pinger {
                        if let Some(rtt) = p.ping(ip, Duration::from_millis(700)) {
                            latency = Some(rtt);
                            found_by.insert("Ping".to_string());
                        }
                    }
                    if found_by.is_empty() && (!have_arp || !on_link) {
                        for port in probe::LIVENESS_PORTS {
                            match probe::tcp(ip, *port, Duration::from_millis(250)) {
                                TcpResult::Open(rtt) => {
                                    latency.get_or_insert(rtt);
                                    found_by.insert("TCP".to_string());
                                    break;
                                }
                                TcpResult::Refused => {
                                    found_by.insert("TCP".to_string());
                                    break;
                                }
                                TcpResult::NoAnswer => {}
                            }
                        }
                    }

                    if !found_by.is_empty() {
                        let mut map = hosts.lock().unwrap();
                        let h = map.entry(ip).or_insert_with(|| new_host(ip));
                        h.found_by.extend(found_by);
                        if let Some(m) = mac {
                            h.mac_address = Some(oui::format_mac(&m));
                        }
                        h.latency_ms = latency.or(h.latency_ms);
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if d % 8 == 0 || d == total {
                        let found = hosts.lock().unwrap().len();
                        emit("Sweeping addresses", d, total, found);
                    }
                }
            });
        }
    });

    // 3. Merge passive discovery and the ARP cache.
    emit("Listening for device announcements", total, total, hosts.lock().unwrap().len());
    let upnp = ssdp_handle.join().unwrap_or_default();
    let mdns = mdns_handle.join().unwrap_or_default();
    {
        let mut map = hosts.lock().unwrap();
        for (ip, info) in upnp {
            if in_scope.contains(&ip) {
                let h = map.entry(ip).or_insert_with(|| new_host(ip));
                h.found_by.insert("UPnP".into());
                h.upnp = Some(info);
            }
        }
        for (ip, info) in mdns {
            if in_scope.contains(&ip) {
                let h = map.entry(ip).or_insert_with(|| new_host(ip));
                h.found_by.insert("mDNS".into());
                h.mdns = Some(info);
            }
        }
        for (ip, mac) in probe::arp_table() {
            if !in_scope.contains(&ip) || ip.is_multicast() || ip.is_broadcast() {
                continue;
            }
            let h = map.entry(ip).or_insert_with(|| new_host(ip));
            if h.found_by.is_empty() {
                h.found_by.insert("ARP cache".into());
            }
            h.mac_address.get_or_insert_with(|| oui::format_mac(&mac));
        }
        // This device's own address.
        for n in &nets {
            if in_scope.contains(&n.address) {
                let h = map.entry(n.address).or_insert_with(|| new_host(n.address));
                h.found_by.insert("Local interface".into());
                if let Some(m) = n.mac {
                    h.mac_address = Some(oui::format_mac(&m));
                }
            }
        }
    }

    // 4. Enrich every live host: ports, names.
    let live: Vec<Ipv4Addr> = {
        let mut v: Vec<_> = hosts.lock().unwrap().keys().copied().collect();
        v.sort();
        v
    };
    let enriched = Arc::new(AtomicUsize::new(0));
    let queue = Arc::new(Mutex::new(live.clone()));
    emit("Identifying devices", 0, live.len(), live.len());
    std::thread::scope(|scope| {
        for _ in 0..12.min(live.len().max(1)) {
            let queue = Arc::clone(&queue);
            let hosts = Arc::clone(&hosts);
            let enriched = Arc::clone(&enriched);
            let live_n = live.len();
            scope.spawn(move || loop {
                if CANCEL.load(Ordering::Relaxed) {
                    break;
                }
                let Some(ip) = queue.lock().unwrap().pop() else { break };

                let open: Vec<OpenPort> = std::thread::scope(|s| {
                    let handles: Vec<_> = probe::PORTS
                        .iter()
                        .map(|(port, name)| {
                            s.spawn(move || match probe::tcp(ip, *port, Duration::from_millis(600)) {
                                TcpResult::Open(_) => Some(OpenPort { port: *port, service: name.to_string() }),
                                _ => None,
                            })
                        })
                        .collect();
                    handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
                });
                let rdns = probe::reverse_dns(ip, Duration::from_secs(2));
                let nb = probe::netbios(ip, Duration::from_millis(800));
                let smb1 = open.iter().any(|p| p.port == 445).then(|| probe::smb1(ip, Duration::from_millis(1500))).flatten();

                {
                    let mut map = hosts.lock().unwrap();
                    if let Some(h) = map.get_mut(&ip) {
                        h.open_ports = open;
                        h.hostname = rdns;
                        h.smb1 = smb1;
                        if let Some(nb) = nb {
                            h.netbios_name = nb.name;
                            h.workgroup = nb.group;
                            if h.mac_address.is_none() {
                                h.mac_address = nb.mac.map(|m| oui::format_mac(&m));
                            }
                        }
                    }
                }
                let d = enriched.fetch_add(1, Ordering::Relaxed) + 1;
                emit("Identifying devices", d, live_n, live_n);
            });
        }
    });

    // 5. Final touches.
    let mut list: Vec<Host> = hosts.lock().unwrap().drain().map(|(_, h)| h).collect();
    for h in &mut list {
        if let Some(mac) = h.mac_address.as_deref().and_then(oui::parse_mac) {
            h.vendor = oui::vendor(&mac);
            h.private_mac = oui::is_locally_administered(&mac);
        }
        if h.is_self && h.netbios_name.is_none() {
            h.hostname = h.hostname.clone().or_else(sysinfo::System::host_name);
        }
        h.device_type = classify(h);
        h.display_name = display_name(h);
    }
    list.sort_by_key(|h| h.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0));

    if !cfg!(windows) {
        notes.push(
            "MAC addresses of other devices are only available where the operating system allows it (Android blocks this for apps), so some vendor names may be missing.".into(),
        );
    }
    if ranges.iter().any(|r| !nets.iter().any(|n| parse_range(r).ok().and_then(|v| v.first().copied()).map(|ip| net_contains(n, ip)).unwrap_or(false))) {
        notes.push("Some ranges are not on a directly connected network. Devices there are found by ping and TCP only, and their MAC addresses can't be read.".into());
    }
    notes.push("Devices that block ping and have no open ports, or that are asleep, may not appear. Running the scan again can find more.".into());

    let cancelled = CANCEL.load(Ordering::Relaxed);
    if cancelled {
        notes.insert(0, "The scan was cancelled before it finished, so this list is incomplete.".into());
    }
    let finished_at = chrono::Local::now();
    emit("Done", total, total, list.len());
    Ok(ScanResult {
        started: started_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        finished: finished_at.format("%Y-%m-%dT%H:%M:%S").to_string(),
        duration_seconds: (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        ranges,
        addresses_scanned: total,
        hosts: list,
        notes,
        cancelled,
    })
}

struct RunGuard;
impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

#[tauri::command]
pub async fn scan_network(app: AppHandle, ranges: Vec<String>) -> Result<ScanResult, String> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err("A scan is already running.".into());
    }
    CANCEL.store(false, Ordering::SeqCst);
    // Android drops multicast packets (mDNS, SSDP) unless an app holds a multicast lock.
    #[cfg(target_os = "android")]
    crate::mobile::call(&app, "acquireMulticast", serde_json::json!({}));
    let app2 = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let _guard = RunGuard;
        run(&|p: &str, d, t, f| emit_event(&app2, p, d, t, f), ranges)
    })
    .await
    .map_err(|e| format!("The scan stopped unexpectedly: {e}"));
    #[cfg(target_os = "android")]
    crate::mobile::call(&app, "releaseMulticast", serde_json::json!({}));
    let _ = &app;
    result?
}

#[tauri::command]
pub fn cancel_scan() {
    CANCEL.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse() {
        assert_eq!(parse_range("192.168.1.0/24").unwrap().len(), 254);
        assert_eq!(parse_range("192.168.1.10-20").unwrap().len(), 11);
        assert_eq!(parse_range("10.0.0.5").unwrap().len(), 1);
        assert!(parse_range("10.0.0.0/8").is_err());
        assert!(parse_range("10.0.0.0/20").is_ok());
    }
}

/// Live scan of this machine's networks. Run with:
/// `cargo test --release live_scan -- --ignored --nocapture`
#[cfg(test)]
mod live {
    #[test]
    #[ignore]
    fn live_scan() {
        let t = std::time::Instant::now();
        let r = super::run(&|p: &str, d, t, f| if d == t { eprintln!("{p}: {d}/{t}, found {f}") }, vec![]).unwrap();
        eprintln!("ranges {:?} in {:.1}s", r.ranges, t.elapsed().as_secs_f64());
        for h in &r.hosts {
            eprintln!(
                "{:<15} {:<34} {:<32} {:<17} {:<28} ports={:?} by={:?}",
                h.ip,
                h.display_name.chars().take(34).collect::<String>(),
                h.device_type,
                h.mac_address.clone().unwrap_or_default(),
                h.vendor.clone().unwrap_or_default().chars().take(28).collect::<String>(),
                h.open_ports.iter().map(|p| p.port).collect::<Vec<_>>(),
                h.found_by
            );
        }
        for n in &r.notes {
            eprintln!("note: {n}");
        }
        let a = crate::attached::collect();
        eprintln!("\nvolumes {} drives {} printers {} monitors {} devices {} (peripherals {})",
            a.volumes.len(), a.drives.len(), a.printers.len(), a.monitors.len(), a.devices.len(),
            a.devices.iter().filter(|d| d.is_peripheral).count());
        for d in a.devices.iter().filter(|d| d.is_peripheral) {
            eprintln!("  [{}] {} ({}) {:?}", d.category, d.name, d.connection, d.vendor_id);
        }
        for v in &a.volumes { eprintln!("  vol {} {} {:?} {:?}", v.name, v.kind, v.label, v.network_path); }
        for d in &a.drives { eprintln!("  drive {} {:?} ext={} {:?}", d.model, d.interface, d.is_external, d.drive_letters); }
        for u in &a.usb_devices { eprintln!("  usb {} [{:?}] {}:{} fns={:?}", u.name, u.vendor_name, u.vendor_id, u.product_id, u.functions); }
        for p in &a.printers { eprintln!("  printer {} port={:?} net={}", p.name, p.port, p.is_network); }
        for m in &a.monitors { eprintln!("  monitor {} {:?}", m.name, m.manufacturer); }
        for n in &a.notes { eprintln!("  note: {n}"); }
    }
}
