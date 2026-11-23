use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::ports::service_name;
use crate::scanner::HostResult;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const UP: &str = "\x1b[1;32m";

pub fn print_table(hosts: &[HostResult], show_all: bool, color: bool) {
    let rows: Vec<&HostResult> = hosts
        .iter()
        .filter(|host| show_all || !host.open_ports.is_empty())
        .collect();

    if rows.is_empty() {
        println!("No open ports found on {} scanned host(s).", hosts.len());
        return;
    }

    let ip_width = rows
        .iter()
        .map(|host| host.ip.to_string().len())
        .max()
        .unwrap_or(10)
        .max("IP ADDRESS".len());
    let host_width = rows
        .iter()
        .map(|host| host.hostname.as_deref().unwrap_or("-").chars().count())
        .max()
        .unwrap_or(8)
        .max("HOSTNAME".len())
        .min(32);
    let port_width = rows
        .iter()
        .flat_map(|host| host.open_ports.iter())
        .map(|port| port.port.to_string().len())
        .max()
        .unwrap_or(0)
        .max(5)
        .max("no open ports".len());
    let mac_width = rows
        .iter()
        .map(|host| host.mac.as_deref().unwrap_or("-").chars().count())
        .max()
        .unwrap_or(1)
        .max("MAC ADDRESS".len());
    let manufacturer_width = rows
        .iter()
        .map(|host| {
            fit(host.manufacturer.as_deref().unwrap_or("-"), 28)
                .chars()
                .count()
        })
        .max()
        .unwrap_or(1)
        .max("MANUFACTURER".len());
    let service_width = rows
        .iter()
        .flat_map(|host| host.open_ports.iter())
        .map(|port| service_label(port.port).len())
        .max()
        .unwrap_or(0)
        .max("SERVICE".len());
    let has_banner = rows
        .iter()
        .flat_map(|host| host.open_ports.iter())
        .any(|port| port.banner.is_some());

    let mut out = String::new();
    out.push_str(&format!(
        "{}  {}  {}  {}  {}  {}  {}",
        cell("IP ADDRESS", ip_width, BOLD, color),
        cell("HOSTNAME", host_width, BOLD, color),
        cell("MAC ADDRESS", mac_width, BOLD, color),
        cell("MANUFACTURER", manufacturer_width, BOLD, color),
        cell("PORT", port_width, BOLD, color),
        cell("SERVICE", service_width, BOLD, color),
        cell_right("LATENCY", 8, BOLD, color),
    ));
    if has_banner {
        out.push_str("  ");
        out.push_str(&cell("BANNER", 6, BOLD, color));
    }
    out.push('\n');

    for host in rows {
        let ip = host.ip.to_string();
        let hostname = host.hostname.as_deref().unwrap_or("-");
        let mac = fit(host.mac.as_deref().unwrap_or("-"), mac_width);
        let manufacturer = fit(
            host.manufacturer.as_deref().unwrap_or("-"),
            manufacturer_width,
        );
        let ping_latency = host.ping_latency.map(format_latency).unwrap_or_default();

        if host.open_ports.is_empty() {
            out.push_str(&format!(
                "{}  {}  {}  {}  {}  {}  {}",
                cell(&ip, ip_width, DIM, color),
                cell(hostname, host_width, DIM, color),
                cell(&mac, mac_width, DIM, color),
                cell(&manufacturer, manufacturer_width, DIM, color),
                cell("no open ports", port_width, DIM, color),
                cell("", service_width, "", color),
                cell_right(
                    &ping_latency,
                    8,
                    if host.ping_latency.is_some() {
                        YELLOW
                    } else {
                        ""
                    },
                    color,
                ),
            ));
            if has_banner {
                out.push_str("  ");
                out.push_str(&cell("", 6, "", color));
            }
            out.push('\n');
            continue;
        }

        for (index, port) in host.open_ports.iter().enumerate() {
            let first = index == 0;
            let service = service_label(port.port);

            out.push_str(&cell(
                if first { &ip } else { "" },
                ip_width,
                if first { UP } else { "" },
                color && first,
            ));
            out.push_str("  ");
            out.push_str(&cell(
                if first { hostname } else { "" },
                host_width,
                "",
                color,
            ));
            out.push_str("  ");
            out.push_str(&cell(if first { &mac } else { "" }, mac_width, DIM, color));
            out.push_str("  ");
            out.push_str(&cell(
                if first { &manufacturer } else { "" },
                manufacturer_width,
                DIM,
                color,
            ));
            out.push_str("  ");
            out.push_str(&cell(&port.port.to_string(), port_width, GREEN, color));
            out.push_str("  ");
            out.push_str(&cell(&service, service_width, CYAN, color));
            out.push_str("  ");
            out.push_str(&cell_right(&format_latency(port.latency), 8, YELLOW, color));

            if has_banner {
                out.push_str("  ");
                out.push_str(&paint(
                    &fit(port.banner.as_deref().unwrap_or("-"), 80),
                    DIM,
                    color,
                ));
            }
            out.push('\n');
        }
    }

    print!("{}", out.trim_end_matches('\n'));
    println!();
}

pub fn print_summary(
    scanned: usize,
    port_count: usize,
    live: usize,
    open_ports: usize,
    elapsed: Duration,
) {
    eprintln!();
    eprintln!(
        "Scanned {scanned} host(s) x {port_count} port(s) in {:.2}s",
        elapsed.as_secs_f64()
    );
    eprintln!("{live} host(s) up, {open_ports} open port(s) found");
}

pub fn json_report(hosts: &[HostResult], elapsed: Duration) -> String {
    let scanned_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    let hosts: Vec<Value> = hosts
        .iter()
        .map(|host| {
            let ports: Vec<Value> = host
                .open_ports
                .iter()
                .map(|port| {
                    json!({
                        "port": port.port,
                        "service": service_name(port.port),
                        "latency_ms": round2(port.latency),
                        "banner": port.banner.as_deref(),
                    })
                })
                .collect();

            json!({
                "ip": host.ip.to_string(),
                "hostname": host.hostname.as_deref(),
                "mac": host.mac.as_deref(),
                "manufacturer": host.manufacturer.as_deref(),
                "ping_latency_ms": host.ping_latency.map(round2),
                "up": !host.open_ports.is_empty(),
                "open_ports": ports,
            })
        })
        .collect();

    let report = json!({
        "tool": "ipscan",
        "version": env!("CARGO_PKG_VERSION"),
        "scanned_at_unix": scanned_at,
        "duration_ms": elapsed.as_millis() as u64,
        "hosts": hosts,
    });

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

pub fn csv_report(hosts: &[HostResult]) -> String {
    let mut out = String::from(
        "ip,hostname,mac,manufacturer,ping_latency_ms,port,service,latency_ms,state,banner\n",
    );

    for host in hosts {
        let ip = csv_field(&host.ip.to_string());
        let hostname = csv_field(host.hostname.as_deref().unwrap_or(""));
        let mac = csv_field(host.mac.as_deref().unwrap_or(""));
        let manufacturer = csv_field(host.manufacturer.as_deref().unwrap_or(""));
        let ping_latency = host
            .ping_latency
            .map(|latency| format!("{:.2}", latency.as_secs_f64() * 1000.0))
            .unwrap_or_default();

        if host.open_ports.is_empty() {
            out.push_str(&format!(
                "{ip},{hostname},{mac},{manufacturer},{ping_latency},,,,no-open-ports,\n"
            ));
            continue;
        }

        for port in &host.open_ports {
            out.push_str(&format!(
                "{ip},{hostname},{mac},{manufacturer},{ping_latency},{},{},{:.2},open,{}\n",
                port.port,
                csv_field(service_name(port.port).unwrap_or("")),
                port.latency.as_secs_f64() * 1000.0,
                csv_field(port.banner.as_deref().unwrap_or("")),
            ));
        }
    }

    out
}

pub fn write_report(path: &Path, data: &str) -> io::Result<()> {
    if is_stdout(path) {
        let mut stdout = io::stdout().lock();
        stdout.write_all(data.as_bytes())?;
        if !data.ends_with('\n') {
            stdout.write_all(b"\n")?;
        }
        stdout.flush()
    } else {
        fs::write(path, data)
    }
}

pub fn is_stdout(path: &Path) -> bool {
    path == Path::new("-")
}

fn service_label(port: u16) -> String {
    service_name(port).unwrap_or("-").to_string()
}

pub fn format_latency(latency: Duration) -> String {
    let ms = latency.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{ms:.2}ms")
    } else if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{ms:.0}ms")
    }
}

fn round2(latency: Duration) -> f64 {
    (latency.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

fn paint(text: &str, code: &str, color: bool) -> String {
    if color && !code.is_empty() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

fn cell(text: &str, width: usize, code: &str, color: bool) -> String {
    let fitted = fit(text, width);
    let padding = width.saturating_sub(fitted.chars().count());
    paint(&format!("{fitted}{}", " ".repeat(padding)), code, color)
}

fn cell_right(text: &str, width: usize, code: &str, color: bool) -> String {
    let fitted = fit(text, width);
    let padding = width.saturating_sub(fitted.chars().count());
    paint(&format!("{}{fitted}", " ".repeat(padding)), code, color)
}

fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut truncated: String = text.chars().take(width - 1).collect();
    truncated.push('…');
    truncated
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn sample() -> Vec<HostResult> {
        vec![HostResult {
            ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            hostname: Some("router,lan".to_string()),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            manufacturer: Some("Example, Inc".to_string()),
            ping_latency: Some(Duration::from_millis(5)),
            open_ports: vec![crate::scanner::PortResult {
                port: 80,
                latency: Duration::from_micros(1500),
                banner: Some("HTTP/1.0 200 \"OK\"".to_string()),
            }],
        }]
    }

    #[test]
    fn json_contains_hosts_and_ports() {
        let report = json_report(&sample(), Duration::from_secs(2));
        let value: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(value["hosts"][0]["ip"], "10.0.0.1");
        assert_eq!(value["hosts"][0]["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(value["hosts"][0]["manufacturer"], "Example, Inc");
        assert_eq!(value["hosts"][0]["ping_latency_ms"], 5.0);
        assert_eq!(value["hosts"][0]["open_ports"][0]["port"], 80);
        assert_eq!(value["hosts"][0]["open_ports"][0]["service"], "http");
    }

    #[test]
    fn csv_escapes_special_characters() {
        let csv = csv_report(&sample());
        assert!(csv.contains("\"router,lan\""));
        assert!(csv.contains("\"HTTP/1.0 200 \"\"OK\"\"\""));
        assert!(csv.contains("aa:bb:cc:dd:ee:ff"));
        assert!(csv.contains("\"Example, Inc\""));
        assert!(csv.contains(",5.00,"));
        assert!(csv.contains(",1.50,open,"));
    }

    #[test]
    fn fits_long_text() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("ab", 4), "ab");
    }
}
