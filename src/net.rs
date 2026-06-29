//! Internet Sharing detection and Wi‑Fi client discovery.
//!
//! All network I/O goes through native macOS shell commands — no extra crates.
//!
//! ## Discovery strategy
//!
//! ```text
//!   ┌─────────────────┐     live signal      ┌──────────────────┐
//!   │ arp -a          │ ───────────────────► │ connected = true │
//!   │ (on bridge100)  │                      │ label: ● now     │
//!   └─────────────────┘                      └──────────────────┘
//!
//!   ┌─────────────────┐     historical       ┌──────────────────┐
//!   │ /var/db/        │ ───────────────────► │ connected = false│
//!   │ dhcpd_leases    │   (names, old IPs)   │ label: past      │
//!   └─────────────────┘                      └──────────────────┘
//!
//!   Secondary liveness: bridge ARP, nettop byte counters (no per-host ping)
//! ```
//!
//! a standard /var/db/dhcpd_leases file looks like this:
//!
//! ```text
//! {
//!     ip_address=192.168.64.2
//!     hw_address=1,ee:df:e4:7b:50:4d
//!     identifier=1,ee:df:e4:7b:50:4d
//!     lease=0x6a02282f
//!     name=minint-1llret8
//! }
//! ```
//!
//! See the [crate-level guide](crate) for terminology and data-flow diagrams.

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

/// Path to macOS DHCP lease database written by `bootpd`.
const LEASES: &str = "/var/db/dhcpd_leases";

/// Result of checking whether Internet Sharing is active.
#[derive(Clone, Debug, Default)]
pub struct Sharing {
    /// `true` when a bridge interface with an IPv4 address exists.
    pub active: bool,
    /// BSD interface name, usually `bridge100`.
    pub interface: String,
    /// Gateway IP on the shared subnet, usually `192.168.2.1`.
    pub gateway: String,
    /// CIDR prefix length derived from netmask, usually `24`.
    pub prefix: u8,
}

/// One row in the client table.
#[derive(Clone, Debug)]
pub struct Client {
    /// IPv4 address on the shared subnet.
    pub ip: String,
    /// Hardware MAC address.
    pub mac: String,
    /// Hostname from DHCP lease, if reported by the client.
    pub name: String,
    /// On the sharing bridge right now (bridge ARP or active nettop flows).
    pub connected: bool,
    /// Whether this IP is in the PF block list.
    pub blocked: bool,
    /// Bytes received from this client (nettop delta, current refresh).
    pub bytes_in: u64,
    /// Bytes sent to this client (nettop delta, current refresh).
    pub bytes_out: u64,
}

/// Detect Internet Sharing by looking for a bridge interface with an IPv4 address.
///
/// Tries `bridge100` first, then any `bridge*` from `ifconfig -l`.
///
/// # Example output when sharing is off
///
/// ```text
/// Sharing { active: false, .. Default }
/// ```
pub fn detect_sharing() -> Sharing {
    let mut sharing = Sharing::default();
    if let Some((iface, gw, prefix)) = find_bridge() {
        sharing.active = true;
        sharing.interface = iface;
        sharing.gateway = gw;
        sharing.prefix = prefix;
    }
    sharing
}

/// Locate the Internet Sharing bridge and parse its gateway IP + prefix.
fn find_bridge() -> Option<(String, String, u8)> {
    if let Some(info) = parse_ifconfig("bridge100") {
        return Some(("bridge100".into(), info.0, info.1));
    }
    let list = cmd_output(&["ifconfig", "-l"]);
    for iface in list.split_whitespace().filter(|i| i.starts_with("bridge")) {
        if let Some(info) = parse_ifconfig(iface) {
            return Some((iface.to_string(), info.0, info.1));
        }
    }
    None
}

/// Parse `ifconfig <iface>` output for `inet` and `netmask` lines.
///
/// Returns `(gateway_ip, prefix_length)`.
fn parse_ifconfig(iface: &str) -> Option<(String, u8)> {
    let out = cmd_output(&["ifconfig", iface]);
    if out.contains("does not exist") {
        return None;
    }
    let mut ip = None;
    let mut mask = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let addr = rest.split_whitespace().next()?;
            ip = Some(addr.to_string());
        }
        if let Some(rest) = line.strip_prefix("netmask ") {
            let hex = rest.split_whitespace().next()?;
            if let Some(prefix) = netmask_to_prefix(hex) {
                mask = Some(prefix);
            }
        }
    }
    Some((ip?, mask.unwrap_or(24)))
}

/// Convert macOS hex netmask (e.g. `0xffffff00`) to CIDR prefix length.
fn netmask_to_prefix(hex: &str) -> Option<u8> {
    let hex = hex.strip_prefix("0x")?;
    let n = u32::from_str_radix(hex, 16).ok()?;
    Some(n.count_ones() as u8)
}

/// Build the full client list by merging bridge ARP, DHCP leases, and bandwidth data.
///
/// Returns empty vec when [`Sharing::active`] is false.
///
/// Sort order: connected clients first, then by IP ascending.
/// Build the full client list: DHCP leases first, then bridge ARP, then nettop bandwidth.
///
/// Order is intentional for speed — `/var/db/dhcpd_leases` is a single small file;
/// [`connected_on_bridge`] uses `arp -a -i bridge100` (scoped, not full `arp -a`).
/// Per-host `ping` was removed — it ran sequentially and blocked for ~1 s per lease.
pub fn discover_clients(sharing: &Sharing, blocked: &[String]) -> Vec<Client> {
    if !sharing.active {
        return vec![];
    }

    let mut map: HashMap<String, Client> = HashMap::new();

    if let Ok(text) = fs::read_to_string(LEASES) {
        for record in parse_leases(&text) {
            if !in_subnet(&record.ip, &sharing.gateway, sharing.prefix) {
                continue;
            }
            if record.ip == sharing.gateway {
                continue;
            }
            map.insert(
                record.ip.clone(),
                Client {
                    ip: record.ip,
                    mac: record.mac,
                    name: record.name,
                    connected: false,
                    blocked: false,
                    bytes_in: 0,
                    bytes_out: 0,
                },
            );
        }
    }

    let online = connected_on_bridge(&sharing.gateway, sharing.prefix, &sharing.interface);
    for (ip, mac) in &online {
        map.entry(ip.clone())
            .and_modify(|c| {
                c.connected = true;
                if c.mac.is_empty() {
                    c.mac = mac.clone();
                }
            })
            .or_insert_with(|| Client {
                ip: ip.clone(),
                mac: mac.clone(),
                name: String::new(),
                connected: true,
                blocked: false,
                bytes_in: 0,
                bytes_out: 0,
            });
    }

    let bandwidth = nettop_bandwidth(&sharing.gateway, sharing.prefix);
    let mut clients: Vec<Client> = map.into_values().collect();
    for c in &mut clients {
        if online.contains_key(&c.ip) {
            c.connected = true;
        } else if bandwidth.contains_key(&c.ip) {
            c.connected = true;
        }
        if let Some((in_b, out_b)) = bandwidth.get(&c.ip) {
            c.bytes_in = *in_b;
            c.bytes_out = *out_b;
        }
        c.blocked = blocked.iter().any(|b| b == &c.ip);
    }
    clients.sort_by(|a, b| b.connected.cmp(&a.connected).then_with(|| a.ip.cmp(&b.ip)));
    clients
}

/// Parse `arp -a -i <iface>` for complete MAC entries on the sharing bridge.
///
/// Uses interface-scoped ARP instead of full `arp -a` (which scans every interface
/// and can be slow when many stale entries exist on `en0`).
fn connected_on_bridge(gateway: &str, prefix: u8, iface: &str) -> HashMap<String, String> {
    let out = cmd_output(&["arp", "-a", "-i", iface]);
    let mut map = HashMap::new();
    for line in out.lines() {
        let Some(start) = line.find('(') else {
            continue;
        };
        let Some(end) = line[start + 1..].find(')') else {
            continue;
        };
        let ip = &line[start + 1..start + 1 + end];
        if ip == gateway || !in_subnet(ip, gateway, prefix) {
            continue;
        }
        let Some(at) = line.find(" at ") else {
            continue;
        };
        let mac = line[at + 4..].split_whitespace().next().unwrap_or("");
        if mac == "(incomplete)" || !mac.contains(':') {
            continue;
        }
        map.insert(ip.to_string(), mac.to_string());
    }
    map
}

/// One record parsed from `/var/db/dhcpd_leases`.
struct LeaseRecord {
    ip: String,
    mac: String,
    name: String,
}

/// Parse the brace-delimited lease file format written by `bootpd`.
///
/// ```text
/// {
///     ip_address=192.168.64.2
///     hw_address=1,ee:df:e4:7b:50:4d
///     identifier=1,ee:df:e4:7b:50:4d
///     lease=0x6a02282f
///     name=minint-1llret8
/// }
/// ```
fn parse_leases(text: &str) -> Vec<LeaseRecord> {
    let mut records = vec![];
    let mut ip = String::new();
    let mut mac = String::new();
    let mut name = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line == "{" {
            ip.clear();
            mac.clear();
            name.clear();
        } else if line == "}" {
            if !ip.is_empty() {
                records.push(LeaseRecord {
                    ip: ip.clone(),
                    mac: mac.clone(),
                    name: name.clone(),
                });
            }
        } else if let Some(v) = line.strip_prefix("ip_address=") {
            ip = v.to_string();
        } else if let Some(v) = line.strip_prefix("hw_address=") {
            mac = v.strip_prefix("1,").unwrap_or(v).to_string();
        } else if let Some(v) = line.strip_prefix("name=") {
            name = v.to_string();
        }
    }
    records
}

/// Return `true` if `ip` is in the same IPv4 subnet as `gateway`/`prefix`.
fn in_subnet(ip: &str, gateway: &str, prefix: u8) -> bool {
    let Ok(ip) = Ipv4Addr::from_str(ip) else {
        return false;
    };
    let Ok(gw) = Ipv4Addr::from_str(gateway) else {
        return false;
    };
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(gw) & mask)
}

/// Run `nettop` once and aggregate byte counters per client IP on the shared subnet.
///
/// Command: `nettop -L 1 -n -x -d -t external`
fn nettop_bandwidth(gateway: &str, prefix: u8) -> HashMap<String, (u64, u64)> {
    let out = cmd_output(&["nettop", "-L", "1", "-n", "-x", "-d", "-t", "external"]);
    let mut map: HashMap<String, (u64, u64)> = HashMap::new();
    for line in out.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 6 {
            continue;
        }
        let conn = cols[1];
        if !(conn.starts_with("tcp") || conn.starts_with("udp")) {
            continue;
        }
        let ip = extract_client_ip(conn, gateway, prefix);
        let Some(ip) = ip else { continue };
        let in_b = cols[4].parse::<u64>().unwrap_or(0);
        let out_b = cols[5].parse::<u64>().unwrap_or(0);
        let e = map.entry(ip).or_insert((0, 0));
        e.0 += in_b;
        e.1 += out_b;
    }
    map
}

/// Extract a client IP from a nettop connection field.
///
/// Example input: `tcp4 192.168.2.5:54321<->8.8.8.8:443`
fn extract_client_ip(conn: &str, gateway: &str, prefix: u8) -> Option<String> {
    let rest = conn.split_whitespace().nth(1)?;
    for part in rest.split("<->") {
        let addr = part.split(':').next()?;
        if in_subnet(addr, gateway, prefix) && addr != gateway {
            return Some(addr.to_string());
        }
    }
    None
}

/// Look up the hardware vendor for a MAC address using api.macvendors.com.
///
/// Uses the first three octets (OUI). Requires network access.
pub fn lookup_vendor(mac: &str) -> Result<String, String> {
    let oui: String = mac.split(':').take(3).collect::<Vec<_>>().join(":");
    if oui.len() < 8 {
        return Err("invalid MAC".into());
    }
    let url = format!("https://api.macvendors.com/{oui}");
    let out = Command::new("curl")
        .args(["-sf", &url])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("lookup failed".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Format a byte count for table display (`—`, `512`, `1.2K`, `3.4M`).
pub fn format_bytes(n: u64) -> String {
    const K: u64 = 1024;
    if n >= K * K {
        format!("{:.1}M", n as f64 / (K * K) as f64)
    } else if n >= K {
        format!("{:.1}K", n as f64 / K as f64)
    } else if n > 0 {
        format!("{n}")
    } else {
        "—".into()
    }
}

/// Run a command and return stdout as UTF-8 (empty string on failure).
fn cmd_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lease_record() {
        let text = r#"{
name=raspberrypi
ip_address=192.168.2.8
hw_address=1,e4:5f:01:68:25:58
}"#;
        let records = parse_leases(text);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, "192.168.2.8");
        assert_eq!(records[0].mac, "e4:5f:01:68:25:58");
        assert_eq!(records[0].name, "raspberrypi");
    }

    #[test]
    fn in_subnet_check() {
        assert!(in_subnet("192.168.2.5", "192.168.2.1", 24));
        assert!(!in_subnet("192.168.3.5", "192.168.2.1", 24));
    }

    #[test]
    fn extract_ip_from_nettop_conn() {
        let ip = extract_client_ip("tcp4 192.168.2.5:54321<->8.8.8.8:443", "192.168.2.1", 24);
        assert_eq!(ip.as_deref(), Some("192.168.2.5"));
    }
}
