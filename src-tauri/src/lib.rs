//! Network Fingerprint Collector.
//!
//! - This device's fingerprint, logged to CSV (ported from the original Python app).
//! - Network interfaces and a scan of every device on the local network.
//! - Devices attached to this computer: drives, USB devices, peripherals, printers.

mod attached;
mod discovery;
mod fingerprint;
mod interfaces;
mod oui;
mod probe;
mod scan;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            fingerprint::collect_fingerprint,
            fingerprint::save_fingerprint,
            fingerprint::load_history,
            fingerprint::history_csv,
            fingerprint::clear_history,
            fingerprint::get_csv_path,
            interfaces::get_interfaces,
            interfaces::get_scan_ranges,
            scan::scan_network,
            scan::cancel_scan,
            attached::get_attached_devices,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Fingerprint Collector");
}
