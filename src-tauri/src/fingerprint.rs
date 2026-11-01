//! This device's fingerprint and the CSV history of fingerprints.

use std::fs::{self, OpenOptions};
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sysinfo::System;
use tauri::{AppHandle, Manager};

const CSV_FILE_NAME: &str = "network_fingerprints.csv";

/// Column order matches the original Python script, so existing CSV files stay compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub computer_name: String,
    pub os: String,
    pub processor_architecture: String,
    pub processor_model: String,
    pub ip_address: String,
    pub mac_address: String,
    pub system_time: String,
}

fn or_na(value: Option<String>) -> String {
    match value {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => "N/A".to_string(),
    }
}

/// Primary local IP address: the address the OS would use for an outbound
/// connection. The target does not need to be reachable (UDP connect sends nothing).
/// Falls back to resolving the host name, which may return a loopback address.
pub fn primary_ip() -> Option<IpAddr> {
    let via_socket = UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("10.255.255.255:1").map(|_| s))
        .and_then(|s| s.local_addr());
    if let Ok(addr) = via_socket {
        if !addr.ip().is_unspecified() {
            return Some(addr.ip());
        }
    }
    let host = System::host_name().unwrap_or_default();
    (host.as_str(), 0)
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4())
        .map(|a| a.ip())
}

/// Primary MAC address as colon-separated upper-case hex.
fn get_mac_address() -> String {
    match mac_address::get_mac_address() {
        Ok(Some(mac)) => {
            let bytes = mac.bytes();
            if bytes.iter().all(|b| *b == 0) {
                "N/A (null MAC returned)".to_string()
            } else if bytes == [0x02, 0, 0, 0, 0, 0] {
                // Android 6+ hides the real hardware address from apps.
                "N/A (hidden by the operating system)".to_string()
            } else {
                crate::oui::format_mac(&bytes)
            }
        }
        Ok(None) => "N/A (no interface found)".to_string(),
        Err(e) => format!("N/A: {e}"),
    }
}

fn get_processor_model() -> String {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    or_na(sys.cpus().first().map(|c| c.brand().to_string()))
}

fn get_os() -> String {
    let long = System::long_os_version()
        .or_else(System::name)
        .unwrap_or_else(|| std::env::consts::OS.to_string());
    match System::kernel_version() {
        Some(k) if !k.is_empty() => format!("{long} ({k})"),
        _ => long,
    }
}

pub fn collect() -> Fingerprint {
    Fingerprint {
        computer_name: or_na(System::host_name()),
        os: get_os(),
        processor_architecture: or_na(Some(System::cpu_arch())),
        processor_model: get_processor_model(),
        ip_address: primary_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        mac_address: get_mac_address(),
        system_time: chrono::Local::now()
            .format("%Y-%m-%dT%H:%M:%S%.6f")
            .to_string(),
    }
}

fn csv_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Could not find the app data folder: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("Could not create {}: {e}", dir.display()))?;
    Ok(dir.join(CSV_FILE_NAME))
}

#[tauri::command]
pub fn collect_fingerprint() -> Fingerprint {
    collect()
}

/// Appends the fingerprint to the CSV file, writing a header row if the file is new.
/// Returns the absolute path of the CSV file.
#[tauri::command]
pub fn save_fingerprint(app: AppHandle, fingerprint: Fingerprint) -> Result<String, String> {
    let path = csv_path(&app)?;
    let is_new = fs::metadata(&path).map(|m| m.len() == 0).unwrap_or(true);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Could not write to CSV file {}: {e}", path.display()))?;
    let mut writer = csv::WriterBuilder::new().has_headers(is_new).from_writer(file);
    writer
        .serialize(&fingerprint)
        .and_then(|_| writer.flush().map_err(csv::Error::from))
        .map_err(|e| format!("Could not write to CSV file {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

/// All saved fingerprints, oldest first.
#[tauri::command]
pub fn load_history(app: AppHandle) -> Result<Vec<Fingerprint>, String> {
    let path = csv_path(&app)?;
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let mut reader = csv::Reader::from_path(&path)
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    Ok(reader.deserialize().filter_map(Result::ok).collect())
}

/// The raw CSV text, for exporting to a location the user chooses.
#[tauri::command]
pub fn history_csv(app: AppHandle) -> Result<String, String> {
    let path = csv_path(&app)?;
    if !path.is_file() {
        return Ok(String::new());
    }
    fs::read_to_string(&path).map_err(|e| format!("Could not read {}: {e}", path.display()))
}

#[tauri::command]
pub fn clear_history(app: AppHandle) -> Result<(), String> {
    let path = csv_path(&app)?;
    if path.is_file() {
        fs::remove_file(&path).map_err(|e| format!("Could not delete {}: {e}", path.display()))?;
    }
    Ok(())
}

#[tauri::command]
pub fn get_csv_path(app: AppHandle) -> Result<String, String> {
    csv_path(&app).map(|p| p.display().to_string())
}
