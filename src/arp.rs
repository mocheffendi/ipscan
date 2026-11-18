use std::collections::HashMap;
use std::net::IpAddr;
use std::process::{Command, Output, Stdio};

use macaddr_ouidb::MacAddress;

/// Phones (notably Android) use locally administered, randomized Wi-Fi MACs.
/// Those addresses are not registered with IEEE, so no OUI vendor exists.
pub const RANDOMIZED_VENDOR: &str = "Randomized / private";

/// MAC address and vendor resolved from the OUI database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacInfo {
    pub mac: String,
    pub manufacturer: String,
}

/// Read the whole OS ARP table once and index it by IP address.
///
/// ARP only covers IPv4 neighbors on the local link. Using the system
/// `arp`/`ip` utilities avoids raw sockets and administrator privileges.
pub async fn table() -> HashMap<IpAddr, MacInfo> {
    tokio::task::spawn_blocking(table_blocking)
        .await
        .unwrap_or_default()
}

fn table_blocking() -> HashMap<IpAddr, MacInfo> {
    let Some(output) = run_arp_command() else {
        return HashMap::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut found = HashMap::new();

    for line in text.lines() {
        let Some((ip, mac_text)) = parse_line(line) else {
            continue;
        };
        let Some(mac) = parse_mac(mac_text) else {
            continue;
        };

        // Multicast/broadcast entries (mDNS, SSDP, etc.) are not hosts.
        if mac.is_multicast() || mac.is_zero() {
            continue;
        }

        let manufacturer = vendor_name(&mac);
        found.insert(
            ip,
            MacInfo {
                mac: mac.to_string(),
                manufacturer,
            },
        );
    }

    found
}

/// Vendor label for a MAC. Locally administered addresses are randomized
/// (Android private Wi-Fi addresses, virtual adapters) and have no OUI entry,
/// so report them explicitly instead of the misleading "Unknown".
fn vendor_name(mac: &MacAddress) -> String {
    if mac.is_local() {
        return RANDOMIZED_VENDOR.to_string();
    }
    mac.oui()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn run_arp_command() -> Option<Output> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let mut command = Command::new("arp");
        command.creation_flags(CREATE_NO_WINDOW);
        command
            .arg("-a")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command.output().ok()
    }

    #[cfg(not(windows))]
    {
        // Linux: `ip neigh` is preferred; `arp -an` is the portable fallback.
        if let Ok(output) = Command::new("ip")
            .args(["neigh", "show"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            if output.status.success() {
                return Some(output);
            }
        }

        Command::new("arp")
            .arg("-an")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()
    }
}

/// Parse one line from `ip neigh`, `arp -n`, `arp -an`, or `arp -a`.
fn parse_line(line: &str) -> Option<(IpAddr, &str)> {
    let fields: Vec<&str> = line.split_whitespace().collect();

    // Linux: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
    if let Some(pos) = fields.iter().position(|field| *field == "lladdr") {
        let ip = ip_from_token(fields.first()?)?;
        return Some((ip, *fields.get(pos + 1)?));
    }

    // macOS/BSD: ? (192.168.1.1) at 0:11:22:33:44:55 on en0
    if let Some(pos) = fields.iter().position(|field| *field == "at") {
        let ip = fields.iter().find_map(|field| ip_from_token(field))?;
        return Some((ip, *fields.get(pos + 1)?));
    }

    // Windows: 192.168.1.1  00-11-22-33-44-55  dynamic
    let ip = ip_from_token(fields.first()?)?;
    Some((ip, *fields.get(1)?))
}

fn ip_from_token(token: &str) -> Option<IpAddr> {
    token
        .trim_matches(|c| matches!(c, '(' | ')' | '[' | ']'))
        .parse()
        .ok()
}

/// Normalize colon, dash, Cisco, and short macOS MAC formats.
fn parse_mac(text: &str) -> Option<MacAddress> {
    let groups: Vec<&str> = text
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|group| !group.is_empty())
        .collect();

    let mut bytes = [0u8; 6];

    if groups.len() == 6 {
        for (index, group) in groups.iter().enumerate() {
            if group.len() > 2 {
                return None;
            }
            let padded = if group.len() == 1 {
                format!("0{group}")
            } else {
                (*group).to_string()
            };
            bytes[index] = u8::from_str_radix(&padded, 16).ok()?;
        }
        return Some(MacAddress::new(bytes));
    }

    // Cisco style, e.g. 001A.2B3C.4D5E.
    let digits: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if digits.len() != 12 {
        return None;
    }
    for index in 0..6 {
        bytes[index] = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(MacAddress::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_mac_formats() {
        assert_eq!(
            parse_mac("00-11-22-33-44-55").unwrap().to_string(),
            "00:11:22:33:44:55"
        );
        assert_eq!(
            parse_mac("0:11:22:33:44:55").unwrap().to_string(),
            "00:11:22:33:44:55"
        );
        assert_eq!(
            parse_mac("001A.2B3C.4D5E").unwrap().to_string(),
            "00:1a:2b:3c:4d:5e"
        );
    }

    #[test]
    fn parses_arp_table_lines() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert_eq!(
            parse_line("192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"),
            Some((ip, "00:11:22:33:44:55"))
        );
        assert_eq!(
            parse_line("? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]"),
            Some((ip, "0:11:22:33:44:55"))
        );
        assert_eq!(
            parse_line("  192.168.1.1           00-11-22-33-44-55     dynamic"),
            Some((ip, "00-11-22-33-44-55"))
        );
        assert_eq!(
            parse_line("Internet Address      Physical Address      Type"),
            None
        );
    }

    #[test]
    fn resolves_vendor_from_oui() {
        let mac = parse_mac("00:50:56:00:00:00").unwrap();
        let vendor = mac.oui().unwrap_or_default();
        assert!(!vendor.is_empty());
    }

    #[test]
    fn labels_randomized_android_style_mac() {
        // Locally administered bit set (second nibble of the first octet is
        // odd): typical of Android's private/randomized Wi-Fi addresses.
        let mac = parse_mac("4a-22-58-c1-91-71").unwrap();
        assert!(mac.is_local());
        assert_eq!(vendor_name(&mac), RANDOMIZED_VENDOR);
    }

    #[test]
    fn skips_multicast_addresses() {
        let mac = parse_mac("01-00-5e-00-00-fb").unwrap();
        assert!(mac.is_multicast());
    }
}
