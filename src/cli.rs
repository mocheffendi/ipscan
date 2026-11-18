use std::path::PathBuf;

use clap::Parser;

const EXAMPLES: &str = "\
EXAMPLES:
  ipscan                     open the desktop GUI
  ipscan --gui               open the desktop GUI explicitly
  ipscan 192.168.1.0/24
  ipscan 192.168.1.1-254 -p 22,80,443
  ipscan 10.0.0.1-10.0.0.50 --ports 1-1024 --timeout 500
  ipscan 192.168.1.* --ports web
  ipscan example.com -p top100 --banners
  ipscan 192.168.1.0/24 --json scan.json --csv scan.csv
  ipscan 192.168.1.0/24 --ping
  ipscan 192.168.1.0/24 --no-mac
  ipscan 192.168.1.0/24 -q --all";

/// Fast, cross-platform TCP IP range and port scanner.
#[derive(Parser, Debug)]
#[command(
    name = "ipscan",
    version,
    about = "Modern cross-platform IP and TCP port scanner (GUI + CLI)",
    long_about = "ipscan is a fast TCP connect scanner with a modern desktop GUI and a full CLI.\n\
                  Run it without arguments (or with --gui) to open the desktop app, or pass\n\
                  targets to scan directly from the terminal.\n\n\
                  It needs no administrator rights, works on Windows, Linux and macOS, and can\n\
                  scan single addresses, CIDR blocks, ranges, wildcards and hostnames.",
    after_help = EXAMPLES
)]
pub struct Cli {
    /// Target(s): IP, CIDR block, range (10.0.0.1-50 or 10.0.0.1-10.0.0.9),
    /// wildcard (192.168.1.*) or hostname. Comma-separated values are accepted.
    #[arg(required = true, value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Ports to scan: 80, 1-1024, 22,80,443, or a group (top100, all, web, db,
    /// mail, remote, windows) or a service name (ssh, https, ...)
    #[arg(short, long, default_value = "top100", value_name = "PORTS")]
    pub ports: String,

    /// Timeout per connection attempt, in milliseconds
    #[arg(short = 't', long, default_value_t = 1000, value_name = "MS")]
    pub timeout: u64,

    /// Maximum number of concurrent connection attempts
    #[arg(short = 'c', long, default_value_t = 512, value_name = "N")]
    pub concurrency: usize,

    /// Also list hosts with no open ports
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Include hosts with no open ports only when they answer ICMP ping
    #[arg(long)]
    pub ping: bool,

    /// Try to read service banners from open ports
    #[arg(long)]
    pub banners: bool,

    /// Skip reverse-DNS lookups
    #[arg(long)]
    pub no_resolve: bool,

    /// Skip MAC/vendor resolution (ARP)
    #[arg(long)]
    pub no_mac: bool,

    /// Write results as JSON to FILE ("-" for stdout)
    #[arg(long, value_name = "FILE")]
    pub json: Option<PathBuf>,

    /// Write results as CSV to FILE ("-" for stdout)
    #[arg(long, value_name = "FILE")]
    pub csv: Option<PathBuf>,

    /// Disable ANSI colors
    #[arg(long)]
    pub no_color: bool,

    /// Hide the progress bar
    #[arg(short = 'q', long)]
    pub quiet: bool,
}
