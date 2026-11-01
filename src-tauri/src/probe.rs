//! Low-level host probes: ARP, ICMP echo, TCP connect, NetBIOS, reverse DNS,
//! and the operating system's ARP / neighbour cache.

use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ ARP ---

/// Resolve a host's MAC address on the local link (Windows `SendARP`).
/// A reply means the host is up, even if it ignores ping and has no open ports.
#[cfg(windows)]
pub fn arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
    use windows::Win32::NetworkManagement::IpHelper::SendARP;
    let mut mac = [0u8; 8];
    let mut len: u32 = mac.len() as u32;
    let dest = u32::from_ne_bytes(ip.octets());
    let rc = unsafe { SendARP(dest, 0, mac.as_mut_ptr().cast(), &mut len) };
    if rc == 0 && len >= 6 {
        let m = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
        crate::oui::is_usable(&m).then_some(m)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn arp(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}

/// IPv4 → MAC entries from the OS neighbour cache.
#[cfg(windows)]
pub fn arp_table() -> Vec<(Ipv4Addr, [u8; 6])> {
    use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2};
    use windows::Win32::Networking::WinSock::{AF_INET, NlnsIncomplete, NlnsPermanent, NlnsUnreachable};

    let mut out = Vec::new();
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpNetTable2(AF_INET, &mut table) };
    if rc.0 != 0 || table.is_null() {
        return out;
    }
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for row in rows {
            if row.State == NlnsUnreachable || row.State == NlnsIncomplete || row.State == NlnsPermanent {
                continue;
            }
            if row.PhysicalAddressLength != 6 {
                continue;
            }
            let raw = row.Address.Ipv4.sin_addr.S_un.S_addr;
            let ip = Ipv4Addr::from(raw.to_ne_bytes());
            let p = row.PhysicalAddress;
            let mac = [p[0], p[1], p[2], p[3], p[4], p[5]];
            if crate::oui::is_usable(&mac) {
                out.push((ip, mac));
            }
        }
        FreeMibTable(table as *const _);
    }
    out
}

/// Linux exposes the cache in /proc/net/arp. Android 10+ blocks it for apps.
#[cfg(not(windows))]
pub fn arp_table() -> Vec<(Ipv4Addr, [u8; 6])> {
    let Ok(text) = std::fs::read_to_string("/proc/net/arp") else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 || cols[2] == "0x0" {
                return None;
            }
            let ip: Ipv4Addr = cols[0].parse().ok()?;
            let mac = crate::oui::parse_mac(cols[3])?;
            crate::oui::is_usable(&mac).then_some((ip, mac))
        })
        .collect()
}

// ----------------------------------------------------------------- ICMP ---

/// ICMP echo. Returns the round-trip time in milliseconds.
#[cfg(windows)]
pub struct Pinger(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Pinger {
    pub fn new() -> Option<Self> {
        use windows::Win32::NetworkManagement::IpHelper::IcmpCreateFile;
        unsafe { IcmpCreateFile().ok().map(Pinger) }
    }

    pub fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
        use windows::Win32::NetworkManagement::IpHelper::{IcmpSendEcho, ICMP_ECHO_REPLY};
        let payload = *b"fingerprint-collector";
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64];
        let n = unsafe {
            IcmpSendEcho(
                self.0,
                u32::from_ne_bytes(ip.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                None,
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout.as_millis() as u32,
            )
        };
        if n == 0 {
            return None;
        }
        let r = unsafe { &*(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
        // Status 0 = IP_SUCCESS, and the reply must come from the target itself.
        (r.Status == 0 && r.Address == u32::from_ne_bytes(ip.octets())).then_some(r.RoundTripTime as f64)
    }
}

#[cfg(windows)]
impl Drop for Pinger {
    fn drop(&mut self) {
        use windows::Win32::NetworkManagement::IpHelper::IcmpCloseHandle;
        unsafe {
            let _ = IcmpCloseHandle(self.0);
        }
    }
}

/// Linux / Android "ping sockets" (SOCK_DGRAM + IPPROTO_ICMP) need no root.
#[cfg(not(windows))]
pub struct Pinger;

#[cfg(not(windows))]
impl Pinger {
    pub fn new() -> Option<Self> {
        Some(Pinger)
    }

    pub fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        use std::mem::MaybeUninit;

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
        sock.set_read_timeout(Some(timeout)).ok()?;
        let seq: u16 = rand_u16();
        let mut pkt = vec![8u8, 0, 0, 0, 0, 0, (seq >> 8) as u8, seq as u8];
        pkt.extend_from_slice(b"fingerprint-collector");
        let ck = checksum(&pkt);
        pkt[2] = (ck >> 8) as u8;
        pkt[3] = ck as u8;
        let addr = SockAddr::from(SocketAddr::new(IpAddr::V4(ip), 0));
        let start = Instant::now();
        sock.send_to(&pkt, &addr).ok()?;
        let mut buf = [MaybeUninit::<u8>::uninit(); 512];
        while start.elapsed() < timeout {
            let (n, from) = sock.recv_from(&mut buf).ok()?;
            let data: Vec<u8> = buf[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
            let from_ip = from.as_socket_ipv4().map(|s| *s.ip());
            if from_ip == Some(ip) && data.first() == Some(&0) {
                return Some(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        None
    }
}

#[cfg(not(windows))]
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = (chunk[0] as u32) << 8 | *chunk.get(1).unwrap_or(&0) as u32;
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(not(windows))]
fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    (n ^ (n >> 16)) as u16
}

// ------------------------------------------------------------------ TCP ---

pub enum TcpResult {
    Open(f64),
    /// The host answered with a reset: it is up, the port is closed.
    Refused,
    NoAnswer,
}

pub fn tcp(ip: Ipv4Addr, port: u16, timeout: Duration) -> TcpResult {
    let start = Instant::now();
    match TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout) {
        Ok(_) => TcpResult::Open(start.elapsed().as_secs_f64() * 1000.0),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => TcpResult::Refused,
        Err(_) => TcpResult::NoAnswer,
    }
}

/// Well-known ports checked on every live host, with the service each suggests.
pub const PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (135, "Microsoft RPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB file sharing"),
    (515, "LPD printing"),
    (548, "AFP (Apple file sharing)"),
    (554, "RTSP (camera / media stream)"),
    (631, "IPP printing"),
    (1883, "MQTT (IoT)"),
    (1900, "UPnP"),
    (3389, "Remote Desktop"),
    (5000, "UPnP / NAS web"),
    (5001, "NAS web (HTTPS)"),
    (5353, "mDNS"),
    (5900, "VNC remote control"),
    (7000, "AirPlay"),
    (8008, "Chromecast HTTP"),
    (8009, "Chromecast"),
    (8080, "HTTP (alternate)"),
    (8443, "HTTPS (alternate)"),
    (8888, "HTTP (alternate)"),
    (9100, "Printer (raw / JetDirect)"),
    (32400, "Plex Media Server"),
    (49152, "UPnP device"),
    (62078, "Apple device sync"),
];

/// Quick liveness ports for networks where ARP is unavailable (Android).
pub const LIVENESS_PORTS: &[u16] = &[80, 443, 445, 22, 62078, 8080, 139, 554, 9100, 7000];

// -------------------------------------------------------------- NetBIOS ---

#[derive(Debug, Clone, Default)]
pub struct NetbiosInfo {
    pub name: Option<String>,
    pub group: Option<String>,
    pub mac: Option<[u8; 6]>,
}

/// NetBIOS node status query (UDP 137). Windows PCs and Samba servers answer
/// with their computer name and workgroup.
pub fn netbios(ip: Ipv4Addr, timeout: Duration) -> Option<NetbiosInfo> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut q = vec![0x4E, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
    // "*" padded to 16 bytes, first-level encoded.
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        q.push(b'A' + (b >> 4));
        q.push(b'A' + (b & 0x0F));
    }
    q.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    sock.send_to(&q, SocketAddr::new(IpAddr::V4(ip), 137)).ok()?;

    let mut buf = [0u8; 1024];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != IpAddr::V4(ip) || n < 57 {
        return None;
    }
    let data = &buf[..n];
    let count = data[56] as usize;
    let mut info = NetbiosInfo::default();
    let mut off = 57;
    for _ in 0..count {
        if off + 18 > n {
            break;
        }
        let raw_name = String::from_utf8_lossy(&data[off..off + 15]).trim_end().to_string();
        let suffix = data[off + 15];
        let flags = u16::from_be_bytes([data[off + 16], data[off + 17]]);
        let is_group = flags & 0x8000 != 0;
        if suffix == 0x00 && !is_group && info.name.is_none() {
            info.name = Some(raw_name);
        } else if suffix == 0x00 && is_group && info.group.is_none() {
            info.group = Some(raw_name);
        }
        off += 18;
    }
    if off + 6 <= n {
        let m = [data[off], data[off + 1], data[off + 2], data[off + 3], data[off + 4], data[off + 5]];
        if crate::oui::is_usable(&m) {
            info.mac = Some(m);
        }
    }
    (info.name.is_some() || info.group.is_some()).then_some(info)
}

// ---------------------------------------------------------- Reverse DNS ---

/// Reverse DNS with a hard time limit (the system resolver can stall for seconds).
pub fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    });
    let name = rx.recv_timeout(timeout).ok().flatten()?;
    let name = name.trim_end_matches('.').to_string();
    // The resolver echoes the address back when there is no name.
    (name.parse::<IpAddr>().is_err() && !name.is_empty()).then_some(name)
}

// ----------------------------------------------------------- HTTP (GET) ---

/// Minimal HTTP/1.0 GET for UPnP device descriptions (always plain HTTP on the LAN).
pub fn http_get(url: &str, timeout: Duration) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr: SocketAddr = if hostport.contains(':') {
        hostport.parse().ok()?
    } else {
        format!("{hostport}:80").parse().ok()?
    };
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    use std::io::Write;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {hostport}\r\nUser-Agent: FingerprintCollector/1.0\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut body = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut chunk = [0u8; 8192];
    while Instant::now() < deadline && body.len() < 512 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&body).to_string();
    text.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}
