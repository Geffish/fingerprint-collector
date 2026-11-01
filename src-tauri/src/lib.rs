//! Network Fingerprint Collector.
//!
//! - This device's fingerprint, logged to CSV (ported from the original Python app).
//! - Network interfaces and a scan of every device on the local network.
//! - Devices attached to this computer: drives, USB devices, peripherals, printers.
//! - Desktop: system tray, scheduled scans in the background, auto-update.

mod actions;
mod attached;
mod discovery;
mod fingerprint;
mod interfaces;
#[cfg(target_os = "android")]
mod mobile;
mod oui;
mod probe;
mod scan;

#[cfg(desktop)]
fn show_main(app: &tauri::AppHandle) {
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(desktop)]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::Emitter;

    let show = MenuItem::with_id(app, "show", "Open Fingerprint Collector", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan network now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&show, &scan, &sep, &quit])?;

    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Fingerprint Collector")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "scan" => {
                let _ = app.emit("tray-scan", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
            .plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                Some(vec!["--minimized"]),
            ))
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_process::init());
    }
    #[cfg(target_os = "android")]
    {
        builder = builder.plugin(mobile::init());
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(desktop)]
            {
                use tauri::Manager;
                setup_tray(app)?;
                // Started at sign-in: stay in the tray.
                if std::env::args().any(|a| a == "--minimized") {
                    actions::BACKGROUND.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.hide();
                    }
                }
            }
            let _ = app;
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if actions::BACKGROUND.load(std::sync::atomic::Ordering::SeqCst) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            let _ = (window, event);
        })
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
            actions::app_info,
            actions::set_background_mode,
            actions::store_load,
            actions::store_save,
            actions::wake_on_lan,
            actions::open_share,
            actions::open_remote_desktop,
            actions::get_wifi_info,
            actions::export_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Fingerprint Collector");
}
