//! MAC address formatting and vendor lookup (IEEE OUI / MA-M / MA-S registries).

use std::collections::HashMap;
use std::sync::OnceLock;

static OUI_TEXT: &str = include_str!("../data/oui.txt");

fn table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        OUI_TEXT
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

pub fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// True when the "locally administered" bit is set: the address was assigned by
/// software (phones' private Wi-Fi addresses, VMs, VPN adapters), not the maker.
pub fn is_locally_administered(bytes: &[u8]) -> bool {
    bytes.first().map(|b| b & 0x02 != 0).unwrap_or(false)
}

pub fn is_usable(bytes: &[u8]) -> bool {
    bytes.len() == 6 && !bytes.iter().all(|b| *b == 0) && !bytes.iter().all(|b| *b == 0xFF)
}

/// Vendor name for a MAC address, longest registered prefix first.
pub fn vendor(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 6 {
        return None;
    }
    if is_locally_administered(bytes) {
        return Some("Private / randomised address".to_string());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    let t = table();
    [9, 7, 6]
        .iter()
        .find_map(|n| t.get(&hex[..*n]))
        .map(|s| s.to_string())
}

pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<u8> = text
        .split(|c| c == ':' || c == '-')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    parts.try_into().ok()
}
