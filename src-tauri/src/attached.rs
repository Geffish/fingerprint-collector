//! Devices attached to this computer: drives and volumes, USB devices,
//! peripherals, monitors, printers, Bluetooth, and every Plug and Play device.

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Volume {
    pub name: String,
    pub mount_point: String,
    pub label: Option<String>,
    pub kind: String,
    pub file_system: Option<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub removable: bool,
    pub network_path: Option<String>,
    pub physical_drive: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PhysicalDrive {
    pub model: String,
    pub interface: Option<String>,
    pub media_type: Option<String>,
    pub serial_number: Option<String>,
    pub size_bytes: Option<u64>,
    pub partitions: Option<u64>,
    pub status: Option<String>,
    pub is_external: bool,
    pub drive_letters: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Printer {
    pub name: String,
    pub driver: Option<String>,
    pub port: Option<String>,
    pub location: Option<String>,
    pub is_network: bool,
    pub is_shared: bool,
    pub is_default: bool,
    pub is_offline: bool,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Monitor {
    pub name: String,
    pub manufacturer: Option<String>,
    pub serial_number: Option<String>,
    pub year_of_manufacture: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Device {
    pub name: String,
    pub category: String,
    pub class: Option<String>,
    pub connection: String,
    pub manufacturer: Option<String>,
    pub status: Option<String>,
    pub device_id: Option<String>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    /// Shown in the default "peripherals" view; system plumbing is hidden.
    pub is_peripheral: bool,
}

/// One physical USB device, with the functions Windows created for it
/// (a headset shows up as audio, HID and control functions).
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsbDevice {
    pub name: String,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub vendor_id: String,
    pub product_id: String,
    pub serial_number: Option<String>,
    pub functions: Vec<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AttachedReport {
    pub collected: String,
    pub usb_devices: Vec<UsbDevice>,
    pub volumes: Vec<Volume>,
    pub drives: Vec<PhysicalDrive>,
    pub printers: Vec<Printer>,
    pub monitors: Vec<Monitor>,
    pub devices: Vec<Device>,
    pub notes: Vec<String>,
}

static USB_TEXT: &str = include_str!("../data/usb.txt");

fn usb_table() -> &'static std::collections::HashMap<&'static str, &'static str> {
    static T: std::sync::OnceLock<std::collections::HashMap<&'static str, &'static str>> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        USB_TEXT
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

/// (vendor name, product name) from the USB ID database.
pub fn usb_names(vid: &str, pid: &str) -> (Option<String>, Option<String>) {
    let t = usb_table();
    let v = vid.to_ascii_uppercase();
    let p = pid.to_ascii_uppercase();
    (
        t.get(v.as_str()).map(|s| s.to_string()),
        t.get(format!("{v}{p}").as_str()).map(|s| s.to_string()),
    )
}

/// Generic names Windows gives to sub-functions of a device.
fn is_generic_function(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "usb input device",
        "hid-compliant vendor-defined device",
        "hid-compliant system controller",
        "hid-compliant consumer control device",
        "hid-compliant device",
        "usb composite device",
        "generic usb hub",
        "usb root hub",
        "bluetooth peripheral device",
    ]
    .iter()
    .any(|g| n.starts_with(g))
}

/// Map a Windows PnP class to a friendly category and whether it is a peripheral.
fn categorise(class: &str, device_id: &str) -> (&'static str, bool) {
    let id = device_id.to_ascii_uppercase();
    match class.to_ascii_lowercase().as_str() {
        "keyboard" => ("Keyboards", true),
        "mouse" => ("Mice and pointing devices", true),
        "hidclass" => ("Human interface devices", id.starts_with("HID\\VID") || id.starts_with("USB\\") || id.contains("BTH")),
        "monitor" => ("Monitors", true),
        "display" => ("Display adapters", true),
        "camera" | "image" => ("Cameras and scanners", true),
        "media" => ("Sound, video and game controllers", true),
        "audioendpoint" => ("Audio inputs and outputs", true),
        "bluetooth" => ("Bluetooth", id.starts_with("BTHENUM") || id.starts_with("BTHLE") || id.starts_with("BTHLEDEVICE") || id.starts_with("USB\\")),
        "diskdrive" => ("Disk drives", true),
        "cdrom" => ("DVD / CD-ROM drives", true),
        "wpd" => ("Portable devices (phones, cameras, media players)", true),
        "printer" | "printqueue" => ("Printers", class.eq_ignore_ascii_case("printer")),
        "net" => ("Network adapters", !id.starts_with("SWD\\") && !id.starts_with("ROOT\\")),
        "ports" => ("Ports (COM and LPT)", true),
        "usb" => ("USB controllers and hubs", false),
        "usbdevice" => ("USB devices", true),
        "smartcardreader" | "smartcard" => ("Smart card readers", true),
        "biometric" => ("Biometric devices", true),
        "sensor" => ("Sensors", true),
        "battery" => ("Batteries", false),
        "modem" => ("Modems", true),
        "infrared" => ("Infrared devices", true),
        "xboxcomposite" | "xnacomposite" => ("Game controllers", true),
        "processor" => ("Processors", false),
        "memorytechnologydriver" | "sdhost" => ("Memory card readers", true),
        "securitydevices" => ("Security devices (TPM)", false),
        "firmware" => ("Firmware", false),
        "volume" | "volumesnapshot" => ("Storage volumes", false),
        "softwaredevice" | "softwarecomponent" => ("Software devices", false),
        "system" => ("System devices", false),
        "computer" => ("Computer", false),
        "hdc" | "scsiadapter" => ("Storage controllers", false),
        "extension" => ("Extensions", false),
        "printqueueinternal" => ("Printers", false),
        "" => ("Other devices", id.starts_with("USB\\")),
        _ => ("Other devices", id.starts_with("USB\\")),
    }
}

fn connection(device_id: &str) -> &'static str {
    let id = device_id.to_ascii_uppercase();
    if id.starts_with("USB") || id.contains("\\VID_") && id.starts_with("HID") {
        "USB"
    } else if id.starts_with("BTH") || id.contains("BTHLE") || id.contains("{00001124") {
        "Bluetooth"
    } else if id.starts_with("SWD\\PRINTENUM") || id.starts_with("SWD\\DAFUPNPPROVIDER") || id.starts_with("SWD\\DAFWSDPROVIDER") || id.starts_with("UMB\\") {
        "Network"
    } else if id.starts_with("DISPLAY\\") {
        "Display cable"
    } else if id.starts_with("PCI\\") {
        "PCI / internal"
    } else if id.starts_with("ACPI\\") || id.starts_with("ROOT\\") || id.starts_with("SWD\\") {
        "System"
    } else {
        "Internal"
    }
}

fn vid_pid(device_id: &str) -> (Option<String>, Option<String>) {
    let id = device_id.to_ascii_uppercase();
    let grab = |key: &str| {
        id.find(key).map(|i| id[i + key.len()..].chars().take(4).collect::<String>()).filter(|s| s.len() == 4)
    };
    (grab("VID_"), grab("PID_"))
}

// ----------------------------------------------------------------- Windows --

#[cfg(windows)]
mod win {
    use super::*;
    use std::collections::HashMap;
    use wmi::{Variant, WMIConnection};

    type Row = HashMap<String, Variant>;

    fn s(row: &Row, k: &str) -> Option<String> {
        match row.get(k)? {
            Variant::String(v) => Some(v.trim().to_string()).filter(|v| !v.is_empty()),
            Variant::Null | Variant::Empty => None,
            other => Some(format!("{other:?}")),
        }
    }

    fn u(row: &Row, k: &str) -> Option<u64> {
        match row.get(k)? {
            Variant::String(v) => v.trim().parse().ok(),
            Variant::UI1(v) => Some(*v as u64),
            Variant::UI2(v) => Some(*v as u64),
            Variant::UI4(v) => Some(*v as u64),
            Variant::UI8(v) => Some(*v),
            Variant::I1(v) => u64::try_from(*v).ok(),
            Variant::I2(v) => u64::try_from(*v).ok(),
            Variant::I4(v) => u64::try_from(*v).ok(),
            Variant::I8(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    fn b(row: &Row, k: &str) -> bool {
        matches!(row.get(k), Some(Variant::Bool(true)))
    }

    /// WmiMonitorID strings are arrays of UTF-16 code units, zero-padded.
    fn u16_array(row: &Row, k: &str) -> Option<String> {
        let Variant::Array(items) = row.get(k)? else { return None };
        let chars: String = items
            .iter()
            .filter_map(|v| match v {
                Variant::UI2(c) => Some(*c as u32),
                Variant::UI1(c) => Some(*c as u32),
                Variant::I4(c) => Some(*c as u32),
                Variant::UI4(c) => Some(*c),
                _ => None,
            })
            .take_while(|c| *c != 0)
            .filter_map(char::from_u32)
            .collect();
        Some(chars.trim().to_string()).filter(|s| !s.is_empty())
    }

    fn q(con: &WMIConnection, query: &str, notes: &mut Vec<String>) -> Vec<Row> {
        match con.raw_query::<Row>(query) {
            Ok(rows) => rows,
            Err(e) => {
                notes.push(format!("Could not read device information ({}): {e}", query.split_whitespace().last().unwrap_or("")));
                Vec::new()
            }
        }
    }

    fn printer_status(code: Option<u64>) -> Option<String> {
        Some(
            match code? {
                1 => "Other",
                2 => "Unknown",
                3 => "Idle",
                4 => "Printing",
                5 => "Warming up",
                6 => "Stopped printing",
                7 => "Offline",
                _ => return None,
            }
            .to_string(),
        )
    }

    pub fn collect(report: &mut AttachedReport) {
        let con = match WMIConnection::new() {
            Ok(c) => c,
            Err(e) => {
                report.notes.push(format!("Windows Management Instrumentation is unavailable: {e}"));
                return;
            }
        };
        let notes = &mut report.notes;

        // Volumes, including mapped network drives.
        for r in q(&con, "SELECT DeviceID, DriveType, FileSystem, FreeSpace, Size, VolumeName, ProviderName FROM Win32_LogicalDisk", notes) {
            let kind = match u(&r, "DriveType") {
                Some(2) => "Removable (USB / card)",
                Some(3) => "Local disk",
                Some(4) => "Network drive",
                Some(5) => "CD / DVD",
                Some(6) => "RAM disk",
                _ => "Unknown",
            };
            report.volumes.push(Volume {
                name: s(&r, "DeviceID").unwrap_or_default(),
                mount_point: s(&r, "DeviceID").map(|d| format!("{d}\\")).unwrap_or_default(),
                label: s(&r, "VolumeName"),
                kind: kind.to_string(),
                file_system: s(&r, "FileSystem"),
                total_bytes: u(&r, "Size"),
                free_bytes: u(&r, "FreeSpace"),
                removable: u(&r, "DriveType") == Some(2),
                network_path: s(&r, "ProviderName"),
                physical_drive: None,
            });
        }

        // Physical drives.
        // Drive letter → disk number, from the partition association
        // (Antecedent: ...Win32_DiskPartition.DeviceID="Disk #1, Partition #0",
        //  Dependent:  ...Win32_LogicalDisk.DeviceID="D:").
        let mut letter_disk: Vec<(String, u64)> = Vec::new();
        for a in q(&con, "SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition", notes) {
            let (Some(ante), Some(dep)) = (s(&a, "Antecedent"), s(&a, "Dependent")) else { continue };
            let disk = ante
                .split("Disk #")
                .nth(1)
                .and_then(|r| r.split(',').next())
                .and_then(|n| n.trim().parse::<u64>().ok());
            let letter = dep.rsplit("DeviceID=\"").next().map(|r| r.trim_end_matches('"').to_string());
            if let (Some(d), Some(l)) = (disk, letter) {
                letter_disk.push((l, d));
            }
        }

        for r in q(&con, "SELECT Index, Model, InterfaceType, MediaType, SerialNumber, Size, Partitions, Status, PNPDeviceID FROM Win32_DiskDrive", notes) {
            let pnp = s(&r, "PNPDeviceID").unwrap_or_default();
            let iface = s(&r, "InterfaceType");
            let media = s(&r, "MediaType");
            // USB-attached SCSI (UAS) drives report "SCSI", so also trust the media type.
            let external = iface.as_deref() == Some("USB")
                || pnp.to_ascii_uppercase().starts_with("USBSTOR")
                || media.as_deref().map(|m| m.to_ascii_lowercase().contains("external") || m.to_ascii_lowercase().contains("removable")).unwrap_or(false);
            let model = s(&r, "Model").unwrap_or_else(|| "Disk drive".into());

            let index = u(&r, "Index");
            let mut letters: Vec<String> = letter_disk
                .iter()
                .filter(|(_, d)| Some(*d) == index)
                .map(|(l, _)| l.clone())
                .collect();
            letters.sort();
            for v in report.volumes.iter_mut().filter(|v| letters.contains(&v.name)) {
                v.physical_drive = Some(model.clone());
                if external {
                    v.removable = true;
                    v.kind = "External drive".into();
                }
            }

            report.drives.push(PhysicalDrive {
                model,
                is_external: external,
                interface: iface,
                media_type: media,
                serial_number: s(&r, "SerialNumber"),
                size_bytes: u(&r, "Size"),
                partitions: u(&r, "Partitions"),
                status: s(&r, "Status"),
                drive_letters: letters,
            });
        }

        // Printers (local, USB and network).
        for r in q(&con, "SELECT Name, DriverName, PortName, Location, Network, Shared, Default, WorkOffline, PrinterStatus FROM Win32_Printer", notes) {
            report.printers.push(Printer {
                name: s(&r, "Name").unwrap_or_default(),
                driver: s(&r, "DriverName"),
                port: s(&r, "PortName"),
                location: s(&r, "Location"),
                is_network: b(&r, "Network"),
                is_shared: b(&r, "Shared"),
                is_default: b(&r, "Default"),
                is_offline: b(&r, "WorkOffline"),
                status: printer_status(u(&r, "PrinterStatus")),
            });
        }

        // Monitors with real model names (root\WMI).
        if let Ok(wmi_ns) = WMIConnection::with_namespace_path("ROOT\\WMI") {
            if let Ok(rows) = wmi_ns.raw_query::<Row>("SELECT ManufacturerName, UserFriendlyName, SerialNumberID, YearOfManufacture FROM WmiMonitorID") {
                for r in rows {
                    report.monitors.push(Monitor {
                        name: u16_array(&r, "UserFriendlyName").unwrap_or_else(|| "Monitor".into()),
                        manufacturer: u16_array(&r, "ManufacturerName"),
                        serial_number: u16_array(&r, "SerialNumberID").filter(|s| s != "0"),
                        year_of_manufacture: u(&r, "YearOfManufacture").filter(|y| *y > 1990),
                    });
                }
            }
        }

        // Every present Plug and Play device.
        for r in q(&con, "SELECT Name, PNPClass, Manufacturer, Status, DeviceID, Present FROM Win32_PnPEntity", notes) {
            if matches!(r.get("Present"), Some(Variant::Bool(false))) {
                continue;
            }
            let id = s(&r, "DeviceID").unwrap_or_default();
            let class = s(&r, "PNPClass");
            let (category, peripheral) = categorise(class.as_deref().unwrap_or(""), &id);
            let (vid, pid) = vid_pid(&id);
            let conn = connection(&id);
            let name = s(&r, "Name").unwrap_or_else(|| "Unknown device".into());
            // Root hubs, host controllers, virtual adapters, generic sub-functions and
            // Bluetooth profile/service entries are plumbing, not attached devices.
            let lname = name.to_ascii_lowercase();
            let uid = id.to_ascii_uppercase();
            let bt_service = conn == "Bluetooth"
                && !uid.contains("DEV_")
                && !matches!(category, "Sound, video and game controllers" | "Audio inputs and outputs" | "Keyboards" | "Mice and pointing devices");
            let plumbing = lname.contains("root hub")
                || lname.contains("host controller")
                || lname.contains("virtual")
                || lname.contains("wan miniport")
                || is_generic_function(&name)
                || bt_service
                || category == "System devices";
            report.devices.push(Device {
                name,
                category: category.to_string(),
                class,
                connection: conn.to_string(),
                manufacturer: s(&r, "Manufacturer").filter(|m| !m.starts_with('(')),
                status: s(&r, "Status"),
                device_id: Some(id),
                vendor_id: vid,
                product_id: pid,
                is_peripheral: (peripheral || conn == "USB" || conn == "Bluetooth") && !plumbing,
            });
        }
        report.devices.sort_by(|a, b| (&a.category, &a.name).cmp(&(&b.category, &b.name)));
        report.usb_devices = build_usb_devices(&report.devices);
    }
}

/// Physical USB devices: entries named `USB\VID_xxxx&PID_yyyy\<instance>` without an
/// interface number (`&MI_`), with their child functions gathered by VID/PID.
fn build_usb_devices(devices: &[Device]) -> Vec<UsbDevice> {
    let mut out: Vec<UsbDevice> = Vec::new();
    for d in devices {
        let Some(id) = d.device_id.as_deref() else { continue };
        let uid = id.to_ascii_uppercase();
        if !uid.starts_with("USB\\VID_") || uid.contains("&MI_") {
            continue;
        }
        let (Some(vid), Some(pid)) = (d.vendor_id.clone(), d.product_id.clone()) else { continue };
        let lname = d.name.to_ascii_lowercase();
        if lname.contains("hub") && d.category == "USB controllers and hubs" && !lname.contains("mass storage") {
            continue;
        }
        let key = format!("VID_{vid}&PID_{pid}");
        let mut functions: Vec<String> = devices
            .iter()
            .filter(|o| !std::ptr::eq(*o, d))
            .filter(|o| o.device_id.as_deref().map(|x| x.to_ascii_uppercase().contains(&key)).unwrap_or(false))
            .map(|o| o.name.clone())
            .filter(|n| !is_generic_function(n))
            .collect();
        functions.sort();
        functions.dedup();
        let (vendor_name, product_name) = usb_names(&vid, &pid);
        // Prefer a specific name: the device's own, a named function, or the USB ID database.
        // "HID Keyboard Device", "HID-compliant headset", "USB Mass Storage Device"
        // say what a thing is, not which product it is.
        let vague = |n: &str| {
            let l = n.to_ascii_lowercase();
            is_generic_function(n) || l.starts_with("hid ") || l.starts_with("hid-compliant") || l.contains("mass storage")
        };
        let name = if !vague(&d.name) {
            d.name.clone()
        } else if let Some(f) = functions.iter().find(|f| !vague(f)) {
            f.clone()
        } else if let Some(p) = product_name.clone() {
            p
        } else {
            let kind = functions.first().cloned().unwrap_or_else(|| d.name.clone());
            match &vendor_name {
                Some(v) => format!("{v} – {kind}"),
                None => kind,
            }
        };
        let serial = id.rsplit('\\').next().filter(|s| !s.contains('&') && s.len() > 4).map(|s| s.to_string());
        out.push(UsbDevice {
            name,
            vendor_name,
            product_name,
            vendor_id: vid,
            product_id: pid,
            serial_number: serial,
            functions,
            status: d.status.clone(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ------------------------------------------------------------ Linux/Android --

#[cfg(not(windows))]
fn collect_other(report: &mut AttachedReport) {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    for d in disks.list() {
        report.volumes.push(Volume {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().display().to_string(),
            label: None,
            kind: if d.is_removable() { "Removable".into() } else { format!("{:?}", d.kind()) },
            file_system: Some(d.file_system().to_string_lossy().to_string()),
            total_bytes: Some(d.total_space()),
            free_bytes: Some(d.available_space()),
            removable: d.is_removable(),
            network_path: None,
            physical_drive: None,
        });
    }

    // USB devices from sysfs (desktop Linux; Android blocks this for apps).
    let mut usb_read = false;
    if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
        for e in entries.flatten() {
            let p = e.path();
            let read = |f: &str| std::fs::read_to_string(p.join(f)).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            let Some(vid) = read("idVendor") else { continue };
            usb_read = true;
            let product = read("product");
            let is_hub = read("bDeviceClass").as_deref() == Some("09");
            report.devices.push(Device {
                name: product.unwrap_or_else(|| format!("USB device {vid}")),
                category: if is_hub { "USB controllers and hubs".into() } else { "USB devices".into() },
                class: read("bDeviceClass"),
                connection: "USB".into(),
                manufacturer: read("manufacturer"),
                status: None,
                device_id: Some(e.file_name().to_string_lossy().to_string()),
                vendor_id: Some(vid.to_uppercase()),
                product_id: read("idProduct").map(|s| s.to_uppercase()),
                is_peripheral: !is_hub,
            });
        }
    }
    if !usb_read {
        report.notes.push(
            "This operating system does not let apps list USB devices or peripherals. Storage volumes and network adapters are shown instead.".into(),
        );
    }
}

pub fn collect() -> AttachedReport {
    let mut report = AttachedReport {
        collected: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        ..Default::default()
    };
    #[cfg(windows)]
    win::collect(&mut report);
    #[cfg(not(windows))]
    collect_other(&mut report);
    report
}

#[tauri::command]
pub async fn get_attached_devices() -> Result<AttachedReport, String> {
    // WMI needs its own COM-initialised thread.
    tauri::async_runtime::spawn_blocking(collect)
        .await
        .map_err(|e| format!("Could not read attached devices: {e}"))
}
