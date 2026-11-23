use anyhow::{bail, Context, Result};

/// nmap-style "top 100" TCP ports, a good default for host scanning.
pub const TOP_100: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

const WEB_PORTS: &[u16] = &[
    80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
];
const DB_PORTS: &[u16] = &[1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017];
const MAIL_PORTS: &[u16] = &[25, 110, 143, 465, 587, 993, 995];
const REMOTE_PORTS: &[u16] = &[22, 23, 3389, 5900, 5985, 5986];
const WINDOWS_PORTS: &[u16] = &[135, 139, 445, 3389, 5985, 5986, 5357];

/// Ports with a well-known service name. Used for labels and for
/// `--ports ssh` style lookups.
pub const SERVICES: &[(u16, &str)] = &[
    (7, "echo"),
    (9, "discard"),
    (13, "daytime"),
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (37, "time"),
    (53, "domain"),
    (67, "dhcp-server"),
    (68, "dhcp-client"),
    (69, "tftp"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (113, "ident"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmptrap"),
    (179, "bgp"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (514, "syslog"),
    (515, "printer"),
    (548, "afp"),
    (554, "rtsp"),
    (587, "submission"),
    (631, "ipp"),
    (636, "ldaps"),
    (873, "rsync"),
    (990, "ftps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1080, "socks"),
    (1194, "openvpn"),
    (1433, "mssql"),
    (1521, "oracle"),
    (1723, "pptp"),
    (1883, "mqtt"),
    (2049, "nfs"),
    (2082, "cpanel"),
    (2083, "cpanel-ssl"),
    (2222, "ssh-alt"),
    (3000, "http-alt"),
    (3128, "squid"),
    (3306, "mysql"),
    (3389, "ms-wbt"),
    (4444, "krb524"),
    (5000, "http-alt"),
    (5060, "sip"),
    (5222, "xmpp"),
    (5357, "wsd"),
    (5432, "postgresql"),
    (5601, "kibana"),
    (5672, "amqp"),
    (5900, "vnc"),
    (5984, "couchdb"),
    (5985, "winrm"),
    (5986, "winrm-ssl"),
    (6379, "redis"),
    (6443, "kubernetes"),
    (7001, "weblogic"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8080, "http-proxy"),
    (8081, "http-alt"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "http-alt"),
    (9090, "http-alt"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (11211, "memcached"),
    (27017, "mongodb"),
    (27018, "mongodb"),
    (50000, "db2"),
];

/// Parse a port specification into a sorted, deduplicated list.
///
/// Accepted tokens (comma separated): `80`, `1-1024`, `top100`, `all`,
/// `web`, `db`, `mail`, `remote`, `windows`, or a service name like `ssh`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for token in spec.split(',') {
        let token = token.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }

        // Fast paths for groups and the full range first.
        if token == "all" || token == "full" {
            ports.extend(1..=u16::MAX);
            continue;
        }
        if let Some(group) = named_group(&token) {
            ports.extend_from_slice(group);
            continue;
        }
        if let Ok(port) = token.parse::<u16>() {
            validate_port(port, &token)?;
            ports.push(port);
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .with_context(|| format!("invalid port range '{token}'"))?;
            let end: u16 = end
                .trim()
                .parse()
                .with_context(|| format!("invalid port range '{token}'"))?;
            validate_port(start, &token)?;
            validate_port(end, &token)?;
            if start > end {
                bail!("invalid port range '{token}': start is greater than end");
            }
            ports.extend(start..=end);
            continue;
        }
        if let Some(port) = port_by_service(&token) {
            ports.push(port);
            continue;
        }

        bail!("unknown port, range or group '{token}'");
    }

    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        bail!("no ports to scan");
    }
    Ok(ports)
}

pub fn service_name(port: u16) -> Option<&'static str> {
    SERVICES
        .iter()
        .find(|(candidate, _)| *candidate == port)
        .map(|(_, name)| *name)
}

pub fn port_by_service(name: &str) -> Option<u16> {
    SERVICES
        .iter()
        .find(|(_, service)| service.eq_ignore_ascii_case(name))
        .map(|(port, _)| *port)
}

fn validate_port(port: u16, input: &str) -> Result<()> {
    if port == 0 {
        bail!("port 0 is not a valid TCP port (input: '{input}')");
    }
    Ok(())
}

fn named_group(name: &str) -> Option<&'static [u16]> {
    match name {
        "top100" | "top" | "common" => Some(TOP_100),
        "web" | "http" => Some(WEB_PORTS),
        "db" | "database" => Some(DB_PORTS),
        "mail" => Some(MAIL_PORTS),
        "remote" => Some(REMOTE_PORTS),
        "windows" => Some(WINDOWS_PORTS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_list_has_100_entries() {
        assert_eq!(TOP_100.len(), 100);
    }

    #[test]
    fn parses_list_and_range() {
        assert_eq!(parse_ports("22,80,1-3").unwrap(), vec![1, 2, 3, 22, 80]);
    }

    #[test]
    fn parses_service_names_and_groups() {
        let ports = parse_ports("ssh,https,web").unwrap();
        assert!(ports.contains(&22));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
    }

    #[test]
    fn deduplicates_ports() {
        assert_eq!(parse_ports("80,80,79-81").unwrap(), vec![79, 80, 81]);
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("nope").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn full_range_is_complete() {
        let ports = parse_ports("all").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&65535));
    }
}
