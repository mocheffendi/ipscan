use std::net::IpAddr;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Reasonable default for parallel ping checks from a single host.
pub const DEFAULT_CONCURRENCY: usize = 32;

/// Check ICMP reachability and return the round-trip reply time.
///
/// Using the system command keeps this cross-platform and avoids raw sockets,
/// so it works on Windows/Linux/macOS without administrator/root privileges.
/// A process is spawned per address, so callers should bound concurrency.
pub async fn check(ip: IpAddr, timeout: Duration) -> Option<Duration> {
    tokio::task::spawn_blocking(move || check_blocking(ip, timeout))
        .await
        .ok()
        .flatten()
}

fn check_blocking(ip: IpAddr, timeout: Duration) -> Option<Duration> {
    let started = Instant::now();
    let output = run_ping(ip, timeout)?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    // Parsed RTT is more accurate than process wall time; fall back to the
    // latter only if the platform formats the reply unexpectedly.
    Some(parse_latency(&text).unwrap_or_else(|| started.elapsed()))
}

fn run_ping(ip: IpAddr, timeout: Duration) -> Option<Output> {
    let mut command = Command::new("ping");

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Avoid flashing a console window when called from the GUI.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let millis = timeout.as_millis().min(u128::from(u32::MAX));
        command.creation_flags(CREATE_NO_WINDOW);
        command.args(["-n", "1", "-w", &millis.to_string()]);
    }

    #[cfg(target_os = "linux")]
    {
        // Linux `-W` is in whole seconds.
        let seconds = timeout.as_secs().max(1);
        command.args(["-c", "1", "-n", "-W", &seconds.to_string()]);
    }

    #[cfg(target_os = "macos")]
    {
        // macOS `-W` is in milliseconds.
        let millis = timeout.as_millis().max(1);
        command.args(["-c", "1", "-n", "-W", &millis.to_string()]);
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        command.args(["-c", "1"]);
    }

    command
        .arg(ip.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    command.output().ok()
}

/// Extract `time=0.123 ms`, `time=12ms`, or `time<1ms` from ping output.
fn parse_latency(output: &str) -> Option<Duration> {
    for line in output.lines() {
        let lowered = line.to_ascii_lowercase();
        let Some(pos) = lowered.find("time") else {
            continue;
        };
        let rest = line[pos + 4..].trim_start_matches(['=', ':', ' ', '\t']);

        if let Some(value) = rest.strip_prefix('<') {
            let number = take_number(value);
            if !number.is_empty() {
                let millis: f64 = number.parse().ok()?;
                // `<1ms` means anywhere between 0 and 1 ms; use the midpoint.
                return Some(Duration::from_secs_f64(millis / 2000.0));
            }
        }

        let number = take_number(rest);
        if number.is_empty() {
            continue;
        }
        let millis: f64 = number.parse().ok()?;
        let tail = rest[number.len()..].trim_start();
        if tail.starts_with("ms") {
            return Some(Duration::from_secs_f64(millis / 1000.0));
        }
    }
    None
}

fn take_number(text: &str) -> &str {
    let mut end = 0;
    let mut seen_digit = false;
    let mut seen_dot = false;

    for (index, character) in text.char_indices() {
        if character.is_ascii_digit() {
            seen_digit = true;
            end = index + character.len_utf8();
        } else if character == '.' && !seen_dot {
            seen_dot = true;
            end = index + 1;
        } else {
            break;
        }
    }

    if seen_digit {
        &text[..end]
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_reply_times() {
        assert_eq!(
            parse_latency("64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.036 ms"),
            Some(Duration::from_micros(36))
        );
        assert_eq!(
            parse_latency("Reply from 192.168.1.1: bytes=32 time=12ms TTL=64"),
            Some(Duration::from_millis(12))
        );
        assert_eq!(
            parse_latency("Reply from 127.0.0.1: bytes=32 time<1ms TTL=128"),
            Some(Duration::from_micros(500))
        );
        assert_eq!(parse_latency("Request timed out."), None);
    }

    #[tokio::test]
    async fn loopback_is_reachable_with_reply_time() {
        let latency = check("127.0.0.1".parse().unwrap(), Duration::from_millis(1000))
            .await
            .expect("loopback should answer ping");
        assert!(latency < Duration::from_secs(1));
    }
}
