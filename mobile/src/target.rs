use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use anyhow::{bail, Context, Result};

/// Upper bound for a single scan, so a typo such as `10.0.0.0/8` cannot
/// allocate millions of addresses (or run for days by accident).
pub const MAX_TARGETS: u128 = 1_048_576;

/// Expand every target expression into a deduplicated list of IP addresses.
///
/// Accepted forms:
/// * `192.168.1.10` / `fe80::1` — a single address
/// * `192.168.1.0/24` / `2001:db8::/126` — a CIDR block
/// * `192.168.1.1-50` / `192.168.1.1-192.168.1.9` — an inclusive range
/// * `192.168.1.*` — a wildcard over the last IPv4 octet (1-254)
/// * `example.com` / `localhost` — a hostname, resolved through the OS
pub fn parse_targets(args: &[String]) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for raw in args {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let expanded =
                expand_target(part).with_context(|| format!("invalid target '{part}'"))?;

            for addr in expanded {
                if !seen.insert(addr) {
                    continue;
                }
                if targets.len() as u128 >= MAX_TARGETS {
                    bail!("target list exceeds the maximum of {MAX_TARGETS} addresses");
                }
                targets.push(addr);
            }
        }
    }

    Ok(targets)
}

fn expand_target(target: &str) -> Result<Vec<IpAddr>> {
    // Parse a literal address first: IPv6 literals also contain ':' but no '-',
    // and hostnames may contain '-' (my-host.local), so order matters here.
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if target.contains('/') {
        return parse_cidr(target);
    }
    if target.contains('*') {
        return parse_wildcard(target);
    }
    if let Some((start, end)) = target.split_once('-') {
        let start = start.trim();
        let end = end.trim();
        // Treat this as a range only when the left side looks like an IP.
        // Otherwise it is a hostname such as "my-host.local".
        if start.parse::<IpAddr>().is_ok() || start.split('.').count() == 4 {
            if end.is_empty() {
                bail!("range is missing its end address");
            }
            return parse_range(start, end);
        }
    }
    resolve_hostname(target)
}

fn parse_cidr(target: &str) -> Result<Vec<IpAddr>> {
    let (addr, prefix) = target
        .split_once('/')
        .context("expected ADDRESS/PREFIX, e.g. 192.168.1.0/24")?;
    let addr: IpAddr = addr.trim().parse().context("invalid IP address")?;
    let prefix: u8 = prefix.trim().parse().context("invalid prefix length")?;

    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                bail!("IPv4 prefix length must be between 0 and 32");
            }
            let count = 1u128 << (32 - prefix);
            ensure_limit(count)?;
            let network = u128::from(u32::from(v4) & ipv4_mask(prefix));
            Ok((0..count)
                .map(|i| IpAddr::V4(Ipv4Addr::from((network + i) as u32)))
                .collect())
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                bail!("IPv6 prefix length must be between 0 and 128");
            }
            let count = 1u128 << (128 - prefix);
            ensure_limit(count)?;
            let network = u128::from(v6) & ipv6_mask(prefix);
            Ok((0..count)
                .map(|i| IpAddr::V6(Ipv6Addr::from(network + i)))
                .collect())
        }
    }
}

fn parse_wildcard(target: &str) -> Result<Vec<IpAddr>> {
    let octets: Vec<&str> = target.split('.').collect();
    if octets.len() != 4 || octets[3] != "*" || octets[..3].contains(&"*") {
        bail!("wildcards are only supported for the last octet, e.g. 192.168.1.*");
    }

    let prefix = format!("{}.0", octets[..3].join("."));
    let base: Ipv4Addr = prefix
        .parse()
        .with_context(|| format!("invalid IPv4 wildcard '{target}'"))?;
    let network = u32::from(base);

    Ok((1..=254u32)
        .map(|i| IpAddr::V4(Ipv4Addr::from(network | i)))
        .collect())
}

fn parse_range(start: &str, end: &str) -> Result<Vec<IpAddr>> {
    let start: IpAddr = start.parse().context("invalid range start address")?;

    match start {
        IpAddr::V4(start_v4) => {
            let end_v4 = match end.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => v4,
                Ok(IpAddr::V6(_)) => bail!("range mixes IPv4 and IPv6"),
                Err(_) => {
                    // Short form: 192.168.1.10-20
                    let last: u32 = end
                        .parse()
                        .with_context(|| format!("invalid range end '{end}'"))?;
                    if last > 255 {
                        bail!("range end octet must be between 0 and 255");
                    }
                    let base = u32::from(start_v4) & !0xff;
                    Ipv4Addr::from(base | last)
                }
            };

            if u32::from(end_v4) < u32::from(start_v4) {
                bail!("range start is greater than range end");
            }
            let count = u128::from(u32::from(end_v4) - u32::from(start_v4)) + 1;
            ensure_limit(count)?;

            Ok((0..count)
                .map(|i| IpAddr::V4(Ipv4Addr::from(u32::from(start_v4) + i as u32)))
                .collect())
        }
        IpAddr::V6(start_v6) => {
            let end_v6: Ipv6Addr = end.parse().context("IPv6 ranges need a full end address")?;
            if u128::from(end_v6) < u128::from(start_v6) {
                bail!("range start is greater than range end");
            }
            let count = u128::from(end_v6) - u128::from(start_v6) + 1;
            ensure_limit(count)?;

            Ok((0..count)
                .map(|i| IpAddr::V6(Ipv6Addr::from(u128::from(start_v6) + i)))
                .collect())
        }
    }
}

fn resolve_hostname(host: &str) -> Result<Vec<IpAddr>> {
    let resolved: Vec<IpAddr> = (host, 0)
        .to_socket_addrs()
        .with_context(|| format!("could not resolve hostname '{host}'"))?
        .map(|addr| addr.ip())
        .collect();

    if resolved.is_empty() {
        bail!("hostname '{host}' did not resolve to any address");
    }

    let mut seen = HashSet::new();
    Ok(resolved
        .into_iter()
        .filter(|addr| seen.insert(*addr))
        .collect())
}

fn ensure_limit(count: u128) -> Result<()> {
    if count > MAX_TARGETS {
        bail!("target expands to {count} addresses; the limit is {MAX_TARGETS}");
    }
    Ok(())
}

fn ipv4_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn ipv6_mask(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(targets: &[&str]) -> Result<Vec<IpAddr>> {
        let owned: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
        parse_targets(&owned)
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn parses_single_ip() {
        assert_eq!(parse(&["192.168.1.3"]).unwrap(), vec![ip("192.168.1.3")]);
    }

    #[test]
    fn parses_cidr_block() {
        let addrs = parse(&["192.168.1.0/30"]).unwrap();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], ip("192.168.1.0"));
        assert_eq!(addrs[3], ip("192.168.1.3"));
    }

    #[test]
    fn parses_ipv6_cidr() {
        let addrs = parse(&["2001:db8::/126"]).unwrap();
        assert_eq!(addrs.len(), 4);
    }

    #[test]
    fn parses_short_range() {
        let addrs = parse(&["10.0.0.10-12"]).unwrap();
        assert_eq!(
            addrs,
            vec![ip("10.0.0.10"), ip("10.0.0.11"), ip("10.0.0.12"),]
        );
    }

    #[test]
    fn parses_full_range() {
        let addrs = parse(&["10.0.0.1-10.0.0.2"]).unwrap();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn parses_wildcard_without_network_and_broadcast() {
        let addrs = parse(&["192.168.5.*"]).unwrap();
        assert_eq!(addrs.len(), 254);
        assert_eq!(addrs[0], ip("192.168.5.1"));
        assert_eq!(addrs[253], ip("192.168.5.254"));
    }

    #[test]
    fn deduplicates_targets() {
        let addrs = parse(&["10.0.0.1", "10.0.0.1,10.0.0.2"]).unwrap();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse(&["10.0.0.9-1"]).is_err());
    }

    #[test]
    fn rejects_oversized_block() {
        assert!(parse(&["10.0.0.0/8"]).is_err());
    }

    #[test]
    fn rejects_bad_wildcard() {
        assert!(parse(&["10.*.0.1"]).is_err());
    }
}
