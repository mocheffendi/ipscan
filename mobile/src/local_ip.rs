//! Best-effort detection of the device's current Wi-Fi/LAN IPv4 address.
//!
//! A UDP `connect` only asks the OS which interface it would route through —
//! it sends no packets — so this works on desktop and Android without an extra
//! dependency or network permission. The chosen interface is normally Wi-Fi.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Destinations used only to pick a route. No data is ever sent to them.
const ROUTE_PROBES: [Ipv4Addr; 4] = [
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(9, 9, 9, 9),
    Ipv4Addr::new(208, 67, 222, 222),
];

/// Return the IPv4 address of the interface used for the default route.
pub fn wifi_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;

    for probe in ROUTE_PROBES {
        if socket.connect((probe, 80)).is_err() {
            continue;
        }
        if let Ok(SocketAddr::V4(addr)) = socket.local_addr() {
            let ip = *addr.ip();
            if is_useful(ip) {
                return Some(ip);
            }
        }
    }
    None
}

/// Quick-fill value for the detected network. Home Wi-Fi is virtually always
/// /24, and the scanner needs a range to be useful.
pub fn wifi_network() -> Option<String> {
    wifi_ip().map(network_24)
}

fn network_24(ip: Ipv4Addr) -> String {
    let [a, b, c, _] = ip.octets();
    format!("{a}.{b}.{c}.0/24")
}

fn is_useful(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_slash_24_from_wifi_address() {
        assert_eq!(network_24(Ipv4Addr::new(192, 168, 1, 23)), "192.168.1.0/24");
        assert_eq!(network_24(Ipv4Addr::new(10, 42, 7, 9)), "10.42.7.0/24");
    }

    #[test]
    fn ignores_non_lan_addresses() {
        assert!(!is_useful(Ipv4Addr::LOCALHOST));
        assert!(!is_useful(Ipv4Addr::UNSPECIFIED));
        assert!(!is_useful(Ipv4Addr::new(169, 254, 1, 2)));
        assert!(!is_useful(Ipv4Addr::BROADCAST));
        assert!(is_useful(Ipv4Addr::new(192, 168, 1, 23)));
    }
}
