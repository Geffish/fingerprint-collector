//! Service discovery: SSDP / UPnP and mDNS / Bonjour. These find devices that
//! announce themselves (routers, TVs, speakers, printers, phones, smart-home
//! gear) and supply friendly names and model numbers.

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::probe;

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpnpInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    pub device_type: Option<String>,
    pub serial_number: Option<String>,
    pub server: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MdnsInfo {
    pub hostname: Option<String>,
    pub services: BTreeSet<String>,
    pub instance_names: BTreeSet<String>,
    pub model: Option<String>,
    pub friendly_name: Option<String>,
    pub details: BTreeSet<String>,
}

// ----------------------------------------------------------------- SSDP ---

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    let v = xml[start..end].trim();
    (!v.is_empty()).then(|| {
        v.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&apos;", "'")
            .replace("&quot;", "\"")
    })
}

/// Multicast M-SEARCH from each local address, then fetch each device description.
pub fn ssdp(local_addrs: &[Ipv4Addr], listen: Duration, cancel: &AtomicBool) -> HashMap<Ipv4Addr, UpnpInfo> {
    let mut found: HashMap<Ipv4Addr, UpnpInfo> = HashMap::new();
    let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    let mut sockets = Vec::new();
    for addr in local_addrs {
        if let Ok(s) = UdpSocket::bind(SocketAddr::new((*addr).into(), 0)) {
            let _ = s.set_multicast_ttl_v4(2);
            let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
            for st in ["ssdp:all", "upnp:rootdevice"] {
                let msg = format!(
                    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
                );
                let _ = s.send_to(msg.as_bytes(), target);
            }
            sockets.push(s);
        }
    }

    let start = Instant::now();
    let mut buf = [0u8; 4096];
    while start.elapsed() < listen && !cancel.load(Ordering::Relaxed) {
        for s in &sockets {
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                let SocketAddr::V4(from) = from else { continue };
                let text = String::from_utf8_lossy(&buf[..n]);
                let entry = found.entry(*from.ip()).or_default();
                for line in text.lines() {
                    let Some((k, v)) = line.split_once(':') else { continue };
                    let v = v.trim().to_string();
                    match k.trim().to_ascii_uppercase().as_str() {
                        "LOCATION" => {
                            // Prefer the root device description.
                            if entry.location.is_none() || text.contains("upnp:rootdevice") {
                                entry.location = Some(v);
                            }
                        }
                        "SERVER" if entry.server.is_none() => entry.server = Some(v),
                        _ => {}
                    }
                }
            }
        }
    }

    // Fetch descriptions in parallel.
    std::thread::scope(|scope| {
        let handles: Vec<_> = found
            .iter()
            .filter_map(|(ip, info)| info.location.clone().map(|loc| (*ip, loc)))
            .map(|(ip, loc)| scope.spawn(move || (ip, probe::http_get(&loc, Duration::from_secs(3)))))
            .collect();
        for h in handles {
            if let Ok((ip, Some(xml))) = h.join() {
                if let Some(info) = found.get_mut(&ip) {
                    info.friendly_name = xml_tag(&xml, "friendlyName");
                    info.manufacturer = xml_tag(&xml, "manufacturer");
                    info.model_name = xml_tag(&xml, "modelName");
                    info.model_number = xml_tag(&xml, "modelNumber");
                    info.model_description = xml_tag(&xml, "modelDescription");
                    info.device_type = xml_tag(&xml, "deviceType");
                    info.serial_number = xml_tag(&xml, "serialNumber");
                }
            }
        }
    });
    found
}

// ----------------------------------------------------------------- mDNS ---

const SERVICE_TYPES: &[&str] = &[
    "_http._tcp",
    "_https._tcp",
    "_workstation._tcp",
    "_device-info._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_ssh._tcp",
    "_sftp-ssh._tcp",
    "_rfb._tcp",
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_scanner._tcp",
    "_uscan._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_homekit._tcp",
    "_hap._tcp",
    "_googlecast._tcp",
    "_androidtvremote2._tcp",
    "_amzn-wplay._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_matter._tcp",
    "_matterc._udp",
    "_hue._tcp",
    "_esphomelib._tcp",
    "_miio._udp",
    "_nvstream._tcp",
    "_daap._tcp",
    "_adisk._tcp",
    "_rdlink._tcp",
    "_mqtt._tcp",
];

fn friendly_service(ty: &str) -> String {
    let t = ty.trim_end_matches(".local.").trim_end_matches('.');
    let name = match t {
        "_http._tcp" => "Web server",
        "_https._tcp" => "Secure web server",
        "_workstation._tcp" => "Workstation",
        "_device-info._tcp" => "Device info",
        "_smb._tcp" => "SMB file sharing",
        "_afpovertcp._tcp" => "Apple file sharing",
        "_ssh._tcp" | "_sftp-ssh._tcp" => "SSH",
        "_rfb._tcp" => "Screen sharing (VNC)",
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => "Printer",
        "_scanner._tcp" | "_uscan._tcp" => "Scanner",
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => "AirPlay audio",
        "_companion-link._tcp" => "Apple companion link",
        "_homekit._tcp" | "_hap._tcp" => "HomeKit accessory",
        "_googlecast._tcp" => "Google Cast",
        "_androidtvremote2._tcp" => "Android TV",
        "_amzn-wplay._tcp" => "Amazon Fire TV",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_sonos._tcp" => "Sonos",
        "_matter._tcp" | "_matterc._udp" => "Matter smart-home device",
        "_hue._tcp" => "Philips Hue bridge",
        "_esphomelib._tcp" => "ESPHome device",
        "_miio._udp" => "Xiaomi smart device",
        "_nvstream._tcp" => "NVIDIA GameStream",
        "_daap._tcp" => "iTunes library sharing",
        "_adisk._tcp" => "Time Machine disk",
        "_rdlink._tcp" => "Remote Desktop link",
        "_mqtt._tcp" => "MQTT broker",
        other => return other.trim_start_matches('_').replace("._tcp", "").replace("._udp", ""),
    };
    name.to_string()
}

pub fn mdns(listen: Duration, cancel: &AtomicBool) -> HashMap<Ipv4Addr, MdnsInfo> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let mut found: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    let Ok(daemon) = ServiceDaemon::new() else {
        return found;
    };

    let mut types: BTreeSet<String> = SERVICE_TYPES.iter().map(|t| format!("{t}.local.")).collect();
    let mut receivers = Vec::new();
    let meta = daemon.browse("_services._dns-sd._udp.local.").ok();
    for t in &types {
        if let Ok(rx) = daemon.browse(t) {
            receivers.push(rx);
        }
    }

    let start = Instant::now();
    while start.elapsed() < listen && !cancel.load(Ordering::Relaxed) {
        // New service types announced by devices.
        if let Some(meta) = &meta {
            while let Ok(ev) = meta.try_recv() {
                if let ServiceEvent::ServiceFound(_, fullname) = ev {
                    // fullname looks like "_foo._tcp.local."
                    if fullname.starts_with('_') && types.insert(fullname.clone()) {
                        if let Ok(rx) = daemon.browse(&fullname) {
                            receivers.push(rx);
                        }
                    }
                }
            }
        }
        for rx in &receivers {
            while let Ok(ev) = rx.try_recv() {
                let ServiceEvent::ServiceResolved(svc) = ev else { continue };
                let service = friendly_service(&svc.ty_domain);
                let instance = svc
                    .fullname
                    .strip_suffix(&format!(".{}", svc.ty_domain))
                    .unwrap_or(&svc.fullname)
                    .replace("\\032", " ");
                // Sub-typed services keep extra labels: keep only the instance part.
                let instance = instance.split("._").next().unwrap_or("").to_string();
                let host = svc.host.trim_end_matches('.').trim_end_matches(".local").to_string();
                let get = |k: &str| svc.txt_properties.get_property_val_str(k).map(|s| s.to_string());
                let model = get("md")
                    .or_else(|| get("model"))
                    .or_else(|| get("ty"))
                    .or_else(|| get("usb_MDL"))
                    .or_else(|| get("am"));
                let friendly = get("fn");
                for ip in svc.get_addresses_v4() {
                    let e = found.entry(ip).or_default();
                    if e.hostname.is_none() && !host.is_empty() {
                        e.hostname = Some(host.clone());
                    }
                    e.services.insert(service.clone());
                    if e.friendly_name.is_none() {
                        e.friendly_name = friendly.clone().filter(|f| looks_human(f));
                    }
                    if looks_human(&instance) {
                        e.instance_names.insert(instance.clone());
                    }
                    if e.model.is_none() {
                        e.model = model.clone().filter(|m| !m.is_empty());
                    }
                    if let Some(v) = get("usb_MFG") {
                        e.details.insert(format!("Manufacturer: {v}"));
                    }
                    if let Some(v) = get("rp").filter(|_| service == "Printer") {
                        e.details.insert(format!("Print queue: {v}"));
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Ok(rx) = daemon.shutdown() {
        let _ = rx.recv_timeout(Duration::from_millis(500));
    }
    found
}

/// Skip machine identifiers (hex IDs, UUIDs, bare numbers) as display names.
fn looks_human(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 2 {
        return false;
    }
    let hexish = t.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    // A long run of hex digits anywhere means an embedded device ID.
    let mut run = 0usize;
    let mut longest = 0usize;
    for c in t.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    !(hexish && t.len() >= 8) && longest < 16 && !t.chars().all(|c| c.is_ascii_digit())
}
