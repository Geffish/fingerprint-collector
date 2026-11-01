//! Bridge to the Android helper written in Kotlin
//! (`gen/android/app/src/main/java/com/geffert/fingerprintcollector/NetInfoPlugin.kt`).
//! It supplies what Android only exposes through Java APIs: Wi-Fi details,
//! the multicast lock that mDNS and SSDP need, USB OTG devices, storage
//! volumes and the system print dialog.

use serde::de::DeserializeOwned;
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager, Wry};

pub struct NetInfo(PluginHandle<Wry>);

pub fn init() -> TauriPlugin<Wry> {
    Builder::<Wry>::new("netinfo")
        .setup(|app, api| {
            let handle = api.register_android_plugin("com.geffert.fingerprintcollector", "NetInfoPlugin")?;
            app.manage(NetInfo(handle));
            Ok(())
        })
        .build()
}

pub fn call_as<T: DeserializeOwned>(app: &AppHandle, command: &str, args: serde_json::Value) -> Result<T, String> {
    let helper = app.try_state::<NetInfo>().ok_or("The Android helper is not loaded.")?;
    helper.0.run_mobile_plugin::<T>(command, args).map_err(|e| e.to_string())
}

pub fn call(app: &AppHandle, command: &str, args: serde_json::Value) {
    let _ = call_as::<serde_json::Value>(app, command, args);
}
