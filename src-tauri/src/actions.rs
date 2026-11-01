//! App services that sit beside the scanner: saved data, Wake-on-LAN, quick
//! actions, Wi-Fi details, PDF export and the desktop background mode.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// When set, closing the window hides it to the system tray instead of quitting.
pub static BACKGROUND: AtomicBool = AtomicBool::new(false);

// ----------------------------------------------------------- app info ---

#[derive(Serialize)]
pub struct AppInfo {
    os: String,
    version: String,
    desktop: bool,
    started_minimised: bool,
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    AppInfo {
        os: std::env::consts::OS.to_string(),
        version: app.package_info().version.to_string(),
        desktop: cfg!(desktop),
        started_minimised: std::env::args().any(|a| a == "--minimized"),
    }
}

#[tauri::command]
pub fn set_background_mode(enabled: bool) {
    BACKGROUND.store(enabled, Ordering::SeqCst);
}

// -------------------------------------------------------------- store ---

const STORES: &[&str] = &["devices", "scan-history", "settings"];

fn store_path(app: &AppHandle, name: &str) -> Result<std::path::PathBuf, String> {
    if !STORES.contains(&name) {
        return Err(format!("Unknown data store “{name}”."));
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Could not create {}: {e}", dir.display()))?;
    Ok(dir.join(format!("{name}.json")))
}

#[tauri::command]
pub fn store_load(app: AppHandle, name: String) -> Result<Option<serde_json::Value>, String> {
    let path = store_path(&app, &name)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(serde_json::from_str(&text).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Could not read {}: {e}", path.display())),
    }
}

#[tauri::command]
pub fn store_save(app: AppHandle, name: String, value: serde_json::Value) -> Result<(), String> {
    let path = store_path(&app, &name)?;
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, text).map_err(|e| format!("Could not write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("Could not save {}: {e}", path.display()))
}

// ------------------------------------------------------- Wake-on-LAN ---

/// Send a Wake-on-LAN magic packet to every connected IPv4 network.
#[tauri::command]
pub fn wake_on_lan(mac: String) -> Result<String, String> {
    let m = crate::oui::parse_mac(&mac).ok_or_else(|| format!("“{mac}” is not a MAC address."))?;
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&m);
    }

    let send = |bind: Ipv4Addr, to: Ipv4Addr| -> usize {
        let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(bind, 0)) else { return 0 };
        let _ = sock.set_broadcast(true);
        [9u16, 7].iter().filter(|port| sock.send_to(&packet, SocketAddrV4::new(to, **port)).is_ok()).count()
    };
    let mut sent = 0;
    for n in crate::interfaces::local_nets() {
        let mask = if n.prefix == 0 { 0 } else { u32::MAX << (32 - n.prefix as u32) };
        let broadcast = Ipv4Addr::from(u32::from(n.address) | !mask);
        sent += send(n.address, broadcast);
        sent += send(n.address, Ipv4Addr::BROADCAST);
    }
    if sent == 0 {
        sent += send(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
    }
    if sent == 0 {
        return Err("Could not send the wake-up packet on any network.".into());
    }
    Ok(crate::oui::format_mac(&m))
}

// ------------------------------------------------------ quick actions ---

fn valid_ip(ip: &str) -> Result<Ipv4Addr, String> {
    ip.trim().parse().map_err(|_| format!("“{ip}” is not an IPv4 address."))
}

#[cfg(windows)]
fn spawn_hidden(program: &str, arg: String) -> Result<(), String> {
    std::process::Command::new(program)
        .arg(arg)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start {program}: {e}"))
}

/// Open the device's shared folders in File Explorer.
#[tauri::command]
pub fn open_share(ip: String) -> Result<(), String> {
    let ip = valid_ip(&ip)?;
    #[cfg(windows)]
    return spawn_hidden("explorer.exe", format!(r"\\{ip}"));
    #[cfg(not(windows))]
    return Err(format!("Opening \\\\{ip} is only available on Windows."));
}

/// Start a Remote Desktop connection to the device.
#[tauri::command]
pub fn open_remote_desktop(ip: String) -> Result<(), String> {
    let ip = valid_ip(&ip)?;
    #[cfg(windows)]
    return spawn_hidden("mstsc.exe", format!("/v:{ip}"));
    #[cfg(not(windows))]
    return Err(format!("Remote Desktop to {ip} is only available on Windows."));
}

// --------------------------------------------------------------- Wi-Fi ---

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WifiInfo {
    pub interface: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub state: Option<String>,
    pub signal_percent: Option<u32>,
    pub rssi_dbm: Option<i32>,
    pub radio_type: Option<String>,
    pub band: Option<String>,
    pub channel: Option<String>,
    pub frequency_mhz: Option<u32>,
    pub rx_rate_mbps: Option<f64>,
    pub tx_rate_mbps: Option<f64>,
    pub authentication: Option<String>,
    pub cipher: Option<String>,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub note: Option<String>,
}

#[cfg(windows)]
fn wifi_windows() -> Result<Option<WifiInfo>, String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Could not run netsh: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(parse_netsh(&text))
}

/// Parse `netsh wlan show interfaces`. Returns the first connected adapter,
/// or the first adapter if none is connected.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_netsh(text: &str) -> Option<WifiInfo> {
    let mut adapters: Vec<WifiInfo> = Vec::new();
    let needs_location = text.to_ascii_lowercase().contains("location");
    for line in text.lines() {
        let Some((k, v)) = line.split_once(" : ").or_else(|| line.split_once(": ")) else { continue };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_string();
        if key == "name" {
            adapters.push(WifiInfo { interface: Some(val), ..Default::default() });
            continue;
        }
        let Some(w) = adapters.last_mut() else { continue };
        let num = |s: &str| s.trim_end_matches('%').trim().parse::<f64>().ok();
        match key.as_str() {
            "ssid" => w.ssid = Some(val),
            "bssid" | "ap bssid" => w.bssid = Some(val.to_ascii_uppercase()),
            "state" => w.state = Some(val),
            "radio type" => w.radio_type = Some(val),
            "band" => w.band = Some(val),
            "channel" => w.channel = Some(val),
            "receive rate (mbps)" => w.rx_rate_mbps = num(&val),
            "transmit rate (mbps)" => w.tx_rate_mbps = num(&val),
            "signal" => w.signal_percent = num(&val).map(|n| n as u32),
            "rssi" => w.rssi_dbm = val.parse().ok(),
            "authentication" => w.authentication = Some(val),
            "cipher" => w.cipher = Some(val),
            _ => {}
        }
    }
    let mut pick = adapters
        .iter()
        .position(|a| a.state.as_deref().map(|s| s.eq_ignore_ascii_case("connected")).unwrap_or(false))
        .map(|i| adapters.swap_remove(i))
        .or_else(|| adapters.into_iter().next())?;
    if pick.ssid.is_none() && needs_location {
        pick.note = Some("Windows hides the network name until location access is turned on for desktop apps (Settings → Privacy & security → Location).".into());
    }
    Some(pick)
}

#[tauri::command]
pub async fn get_wifi_info(app: AppHandle) -> Result<Option<WifiInfo>, String> {
    let _ = &app;
    #[cfg(windows)]
    return tauri::async_runtime::spawn_blocking(wifi_windows).await.map_err(|e| e.to_string())?;
    #[cfg(target_os = "android")]
    return crate::mobile::call_as::<Option<WifiInfo>>(&app, "wifiInfo", serde_json::json!({}));
    #[cfg(not(any(windows, target_os = "android")))]
    return Ok(None);
}

// ----------------------------------------------------------------- PDF ---

/// A Chromium-based browser that can print to PDF headlessly: Edge, then Chrome, then Brave.
#[cfg(windows)]
fn browser_path() -> Option<std::path::PathBuf> {
    const BROWSERS: &[&str] = &[
        r"Microsoft\Edge\Application\msedge.exe",
        r"Google\Chrome\Application\chrome.exe",
        r"BraveSoftware\Brave-Browser\Application\brave.exe",
    ];
    BROWSERS.iter().find_map(|rel| {
        ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"].iter().find_map(|var| {
            let p = std::path::Path::new(&std::env::var(var).ok()?).join(rel);
            p.exists().then_some(p)
        })
    })
}

/// Render the HTML report to PDF with a headless Chromium browser.
#[cfg(windows)]
fn pdf_windows(html: &str, path: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    let out = std::path::PathBuf::from(path);
    if !out.extension().map(|e| e.eq_ignore_ascii_case("pdf")).unwrap_or(false) {
        return Err("The file name must end in .pdf.".into());
    }
    let edge = browser_path().ok_or("Creating a PDF needs Microsoft Edge, Google Chrome or Brave, and none was found. Save the HTML report and print it to PDF instead.")?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let work = std::env::temp_dir().join(format!("fingerprint-collector-pdf-{stamp}"));
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let src = work.join("report.html");
    std::fs::write(&src, html).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&out);

    let url = format!("file:///{}", src.display().to_string().replace('\\', "/").replace(' ', "%20"));
    let mut child = std::process::Command::new(edge)
        .args([
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--no-pdf-header-footer",
        ])
        .arg(format!("--user-data-dir={}", work.join("profile").display()))
        .arg(format!("--print-to-pdf={}", out.display()))
        .arg(url)
        .creation_flags(0x0800_0000)
        .spawn()
        .map_err(|e| format!("Could not start the browser to create the PDF: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(90);
    let finished = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                break false;
            }
        }
    };
    // The browser can hold its profile for a moment after exiting.
    for _ in 0..10 {
        if std::fs::remove_dir_all(&work).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    match std::fs::metadata(&out) {
        Ok(m) if m.len() > 0 => Ok(out.display().to_string()),
        _ if !finished => Err("Creating the PDF took too long and was stopped.".into()),
        _ => Err("The browser did not create the PDF.".into()),
    }
}

/// Windows: write a PDF to `path`. Android: open the system print dialog,
/// which offers "Save as PDF".
#[tauri::command]
pub async fn export_pdf(app: AppHandle, html: String, path: Option<String>, name: String) -> Result<String, String> {
    let _ = (&app, &name, &path);
    #[cfg(windows)]
    {
        let path = path.ok_or("No file was chosen.")?;
        return tauri::async_runtime::spawn_blocking(move || pdf_windows(&html, &path)).await.map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "android")]
    {
        crate::mobile::call_as::<serde_json::Value>(&app, "printHtml", serde_json::json!({ "html": html, "name": name }))?;
        return Ok("the print dialog".into());
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        let _ = html;
        return Err("PDF export is not available on this system. Save the HTML report and print it to PDF.".into());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn netsh_parses() {
        let text = "There is 1 interface on the system:\r\n\r\n    Name                   : Wi-Fi\r\n    Description            : Intel(R) Wi-Fi 6\r\n    State                  : connected\r\n    SSID                   : Home\r\n    AP BSSID               : aa:bb:cc:dd:ee:ff\r\n    Band                   : 5 GHz\r\n    Channel                : 44\r\n    Radio type             : 802.11ax\r\n    Authentication         : WPA2-Personal\r\n    Receive rate (Mbps)    : 1201\r\n    Signal                 : 92%\r\n    Rssi                   : -48\r\n";
        let w = super::parse_netsh(text).unwrap();
        assert_eq!(w.ssid.as_deref(), Some("Home"));
        assert_eq!(w.bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(w.signal_percent, Some(92));
        assert_eq!(w.rssi_dbm, Some(-48));
        assert_eq!(w.rx_rate_mbps, Some(1201.0));
    }
}
