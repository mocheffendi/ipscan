use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use indicatif::ProgressBar;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{arp, ping};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// One open TCP port discovered on a host.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub latency: Duration,
    pub banner: Option<String>,
}

/// Scan result for one host.
#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub manufacturer: Option<String>,
    pub ping_latency: Option<Duration>,
    pub open_ports: Vec<PortResult>,
}

/// Messages streamed from the scanner to the GUI.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Host(HostResult),
}

#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    pub timeout: Duration,
    pub concurrency: usize,
    pub banners: bool,
    /// Measure ICMP reply time for hosts with no open ports.
    pub ping: bool,
}

/// Scan every host for every port, bounded by the configured concurrency.
///
/// Results are also streamed through `events` as each host completes, which
/// lets the GUI update while the scan is still running. Set `cancel` to stop
/// early; partial results are still returned.
///
/// Returns results sorted by IP address, with ports sorted numerically.
pub async fn scan(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    config: ScanConfig,
    progress: ProgressBar,
    cancel: Arc<AtomicBool>,
    events: Option<mpsc::Sender<ScanEvent>>,
) -> Vec<HostResult> {
    let ports = Arc::new(ports);
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let ping_semaphore = Arc::new(Semaphore::new(ping::DEFAULT_CONCURRENCY));

    // Hosts are processed in parallel, but a global semaphore caps the number
    // of sockets in flight so memory/ports stay under control on large ranges.
    let host_concurrency = config.concurrency.clamp(1, 128);
    let port_concurrency = config.concurrency.clamp(1, 32);

    let mut results: Vec<HostResult> = stream::iter(hosts.into_iter().map(|ip| {
        let ports = Arc::clone(&ports);
        let semaphore = Arc::clone(&semaphore);
        let ping_semaphore = Arc::clone(&ping_semaphore);
        let progress = progress.clone();
        let cancel = Arc::clone(&cancel);
        let events = events.clone();

        async move {
            let mut open_ports = Vec::new();

            if !cancel.load(Ordering::Relaxed) {
                let mut pending = stream::iter((0..ports.len()).map(|index| {
                    let port = ports[index];
                    let semaphore = Arc::clone(&semaphore);
                    let cancel = Arc::clone(&cancel);
                    async move {
                        if cancel.load(Ordering::Relaxed) {
                            return None;
                        }
                        probe(ip, port, config, semaphore, cancel).await
                    }
                }))
                .buffer_unordered(port_concurrency);

                while let Some(result) = pending.next().await {
                    if let Some(port) = result {
                        open_ports.push(port);
                    }
                }
            }

            // Ping hosts with no open ports as soon as their port scan finishes,
            // so the GUI can show reply time at any moment (even if the
            // "ping-only hosts" filter was off when the scan started).
            let mut ping_latency = None;
            if config.ping && open_ports.is_empty() && !cancel.load(Ordering::Relaxed) {
                let permit = ping_semaphore.acquire().await.ok();
                if permit.is_some() {
                    ping_latency = ping::check(ip, config.timeout).await;
                }
            }

            progress.inc(1);
            let result = HostResult {
                ip,
                hostname: None,
                mac: None,
                manufacturer: None,
                ping_latency,
                open_ports,
            };

            if let Some(events) = &events {
                let _ = events.send(ScanEvent::Host(result.clone()));
            }
            result
        }
    }))
    .buffer_unordered(host_concurrency)
    .collect()
    .await;

    for host in &mut results {
        host.open_ports.sort_by_key(|port| port.port);
    }
    results.sort_by_key(|host| host.ip);
    results
}

/// Reverse-DNS lookup for hosts that have at least one open port.
pub async fn resolve_hostnames(hosts: &mut [HostResult], progress: ProgressBar) {
    let jobs: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter(|(_, host)| !host.open_ports.is_empty())
        .map(|(index, host)| (index, host.ip))
        .collect();

    if jobs.is_empty() {
        return;
    }

    let names: Vec<(usize, Option<String>)> = stream::iter(jobs.into_iter().map(|(index, ip)| {
        let progress = progress.clone();
        async move {
            let name = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
                .await
                .ok()
                .flatten();
            progress.inc(1);
            (index, name)
        }
    }))
    .buffer_unordered(32)
    .collect()
    .await;

    for (index, name) in names {
        if let Some(name) = name {
            let name = name.trim_end_matches('.').to_string();
            if !name.is_empty() && name != hosts[index].ip.to_string() {
                hosts[index].hostname = Some(name);
            }
        }
    }
}

/// Resolve MAC addresses and OUI vendors for IPv4 neighbors.
///
/// This runs after the port scan so the ARP cache has already been populated
/// by the TCP connections (and by ICMP ping when that option is enabled).
pub async fn resolve_macs(hosts: &mut [HostResult], progress: ProgressBar) {
    if hosts.is_empty() {
        return;
    }

    // One `arp -a`/`ip neigh` call covers the whole subnet, so we do not spawn
    // a process per scanned address.
    let table = arp::table().await;

    for host in hosts.iter_mut() {
        if let Some(info) = table.get(&host.ip) {
            host.mac = Some(info.mac.clone());
            host.manufacturer = Some(info.manufacturer.clone());
        }
        progress.inc(1);
    }
}

async fn probe(
    ip: IpAddr,
    port: u16,
    config: ScanConfig,
    semaphore: Arc<Semaphore>,
    cancel: Arc<AtomicBool>,
) -> Option<PortResult> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }

    let permit = semaphore.acquire_owned().await.ok()?;
    if cancel.load(Ordering::Relaxed) {
        return None;
    }

    let address = SocketAddr::new(ip, port);
    let started = Instant::now();

    let stream = tokio::time::timeout(config.timeout, TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    let latency = started.elapsed();

    // Release the connection slot while reading a banner (only open ports get
    // here, so this cannot create a huge number of extra sockets).
    drop(permit);

    let banner = if config.banners {
        grab_banner(stream, port).await
    } else {
        None
    };

    Some(PortResult {
        port,
        latency,
        banner,
    })
}

const HTTP_REQUEST: &[u8] =
    b"HEAD / HTTP/1.0\r\nHost: ipscan.local\r\nUser-Agent: ipscan\r\nConnection: close\r\n\r\n";

async fn grab_banner(mut stream: TcpStream, port: u16) -> Option<String> {
    // Well-known plain-text HTTP ports must be prompted before they answer.
    let known_http = matches!(
        port,
        80 | 3000 | 5000 | 8000 | 8008 | 8080 | 8081 | 8888 | 9000
    );

    if known_http {
        let _ = stream.write_all(HTTP_REQUEST).await;
    }

    // Services such as SSH, FTP or SMTP greet immediately, so listen first.
    let passive_timeout = if known_http { 600 } else { 350 };
    if let Some(banner) = read_banner(&mut stream, passive_timeout).await {
        return Some(banner);
    }

    // Nothing greeted us: it may be an HTTP server on a custom port. Never
    // send plaintext to TLS ports, and do not probe the known HTTP ports twice.
    if known_http || is_tls_port(port) {
        return None;
    }

    let _ = stream.write_all(HTTP_REQUEST).await;
    read_banner(&mut stream, 600).await
}

async fn read_banner(stream: &mut TcpStream, timeout_ms: u64) -> Option<String> {
    let mut buffer = [0u8; 1024];
    let read =
        tokio::time::timeout(Duration::from_millis(timeout_ms), stream.read(&mut buffer)).await;

    match read {
        Ok(Ok(n)) if n > 0 => sanitize_banner(&buffer[..n]),
        _ => None,
    }
}

fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 990 | 993 | 995 | 2083 | 5061 | 5986 | 8443
    )
}

fn sanitize_banner(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let cleaned: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.chars().take(120).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    fn config() -> ScanConfig {
        ScanConfig {
            timeout: Duration::from_millis(500),
            concurrency: 16,
            banners: false,
            ping: false,
        }
    }

    #[tokio::test]
    async fn detects_an_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let semaphore = Arc::new(Semaphore::new(4));
        let result = probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            config(),
            semaphore,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert!(result.is_some());
        assert_eq!(result.unwrap().port, port);
    }

    #[tokio::test]
    async fn ignores_a_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let semaphore = Arc::new(Semaphore::new(4));
        let result = probe(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            config(),
            semaphore,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn records_ping_latency_for_a_host_without_open_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut scan_config = config();
        scan_config.ping = true;
        let results = scan(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            vec![closed_port],
            scan_config,
            ProgressBar::hidden(),
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .await;

        assert!(results[0].open_ports.is_empty());
        assert!(results[0].ping_latency.is_some());
    }

    #[tokio::test]
    async fn streams_results_and_can_be_cancelled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let (sender, receiver) = mpsc::channel();
        let results = scan(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            vec![port],
            config(),
            ProgressBar::hidden(),
            Arc::new(AtomicBool::new(false)),
            Some(sender),
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].open_ports.len(), 1);

        let event = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let ScanEvent::Host(host) = event;
        assert_eq!(host.ip, results[0].ip);
        assert_eq!(host.open_ports.len(), 1);

        let cancelled = scan(
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            vec![port],
            config(),
            ProgressBar::hidden(),
            Arc::new(AtomicBool::new(true)),
            None,
        )
        .await;
        assert_eq!(cancelled.len(), 1);
        assert!(cancelled[0].open_ports.is_empty());
    }

    #[test]
    fn sanitizes_banners() {
        assert_eq!(
            sanitize_banner(b"SSH-2.0-OpenSSH_9.6\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        assert_eq!(sanitize_banner(b"  \r\n"), None);
    }
}
