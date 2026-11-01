//! This device's network interfaces.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::oui;

#[derive(Debug, Clone, Serialize)]
pub struct NetInterface {
    pub name: String,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub kind: String,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway_ip: Option<String>,
    pub gateway_mac: Option<String>,
    pub dns_servers: Vec<String>,
    pub is_up: bool,
    pub is_default: bool,
    pub is_loopback: bool,
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u32>,
    pub dhcp: Option<bool>,
}

/// A local IPv4 network the scanner can sweep.
#[derive(Debug, Clone)]
pub struct LocalNet {
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub mac: Option<[u8; 6]>,
    pub is_default: bool,
}

pub fn raw() -> Vec<netdev::Interface> {
    netdev::get_interfaces()
}

pub fn list() -> Vec<NetInterface> {
    let mut out: Vec<NetInterface> = raw()
        .into_iter()
        .map(|i| {
            let mac = i.mac_addr.map(|m| m.octets()).filter(|m| oui::is_usable(m));
            let gw = i.gateway.as_ref();
            NetInterface {
                friendly_name: i.friendly_name.clone(),
                description: i.description.clone(),
                kind: i.if_type.name(),
                mac_address: mac.map(|m| oui::format_mac(&m)),
                vendor: mac.and_then(|m| oui::vendor(&m)),
                ipv4: i.ipv4.iter().map(|n| n.to_string()).collect(),
                ipv6: i.ipv6.iter().map(|n| n.to_string()).collect(),
                gateway_ip: gw.and_then(|g| g.ipv4.first()).map(|ip| ip.to_string()),
                gateway_mac: gw
                    .map(|g| g.mac_addr.octets())
                    .filter(|m| oui::is_usable(m))
                    .map(|m| oui::format_mac(&m)),
                dns_servers: i.dns_servers.iter().map(|d| d.to_string()).collect(),
                is_up: i.is_up(),
                is_default: i.default,
                is_loopback: i.is_loopback(),
                speed_mbps: i
                    .transmit_speed
                    .or(i.receive_speed)
                    .filter(|s| *s > 0 && *s < u64::MAX / 2)
                    .map(|s| s / 1_000_000),
                mtu: i.mtu,
                dhcp: i.dhcp_v4_enabled,
                name: i.name,
            }
        })
        .collect();
    // Default interface first, then active ones, then the rest.
    out.sort_by_key(|i| (!i.is_default, !(i.is_up && !i.ipv4.is_empty()), i.is_loopback));
    out
}

/// Active, non-loopback IPv4 networks.
pub fn local_nets() -> Vec<LocalNet> {
    let mut nets = Vec::new();
    for i in raw() {
        if i.is_loopback() || !i.is_up() {
            continue;
        }
        let gateway = i.gateway.as_ref().and_then(|g| g.ipv4.first().copied());
        let mac = i.mac_addr.map(|m| m.octets()).filter(|m| oui::is_usable(m));
        for n in &i.ipv4 {
            let addr = n.addr();
            if addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() {
                continue;
            }
            nets.push(LocalNet {
                interface: i
                    .friendly_name
                    .clone()
                    .or_else(|| i.description.clone())
                    .unwrap_or_else(|| i.name.clone()),
                address: addr,
                prefix: n.prefix_len(),
                gateway,
                mac,
                is_default: i.default,
            });
        }
    }
    nets.sort_by_key(|n| !n.is_default);
    nets
}

#[tauri::command]
pub fn get_interfaces() -> Vec<NetInterface> {
    list()
}

/// Suggested scan ranges: each active network, capped to the /24 around this
/// device when the real network is larger.
#[derive(Debug, Clone, Serialize)]
pub struct SuggestedRange {
    pub cidr: String,
    pub interface: String,
    pub hosts: u32,
    pub note: Option<String>,
    /// Virtual machine, VPN or container network: not ticked by default.
    pub is_virtual: bool,
}

fn looks_virtual(n: &LocalNet) -> bool {
    let name = n.interface.to_ascii_lowercase();
    let mac_vendor = n.mac.and_then(|m| oui::vendor(&m)).unwrap_or_default().to_ascii_lowercase();
    n.prefix >= 31
        || ["vethernet", "vmware", "virtualbox", "hyper-v", "wsl", "docker", "vpn", "tap", "tun", "wireguard", "nordlynx", "tailscale", "zerotier", "loopback"]
            .iter()
            .any(|k| name.contains(k))
        || ["vmware", "oracle", "parallels"].iter().any(|k| mac_vendor.contains(k))
        || n.mac.map(|m| m[..3] == [0x00, 0x15, 0x5D]).unwrap_or(false) // Hyper-V
}

pub fn suggested_ranges() -> Vec<SuggestedRange> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for n in local_nets() {
        let (prefix, note) = if n.prefix < 24 {
            (
                24,
                Some(format!(
                    "Network is /{}; limited to the /24 around this device. Enter a wider range to scan more.",
                    n.prefix
                )),
            )
        } else {
            (n.prefix, None)
        };
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
        let network = Ipv4Addr::from(u32::from(n.address) & mask);
        let cidr = format!("{network}/{prefix}");
        if !seen.insert(cidr.clone()) {
            continue;
        }
        let hosts = if prefix >= 31 { 1u32 << (32 - prefix as u32) } else { (1u32 << (32 - prefix as u32)) - 2 };
        let is_virtual = looks_virtual(&n) && !n.is_default;
        out.push(SuggestedRange { cidr, interface: n.interface, hosts, note, is_virtual });
    }
    out
}

#[tauri::command]
pub fn get_scan_ranges() -> Vec<SuggestedRange> {
    suggested_ranges()
}
