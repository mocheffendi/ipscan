// Windows: no black console window when the .exe is launched from Explorer.
// CLI mode reattaches to the parent terminal below (see `console`).
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;
use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

mod arp;
mod cli;
mod gui;
mod output;
mod ping;
mod ports;
mod scanner;
mod target;

use cli::Cli;
use scanner::ScanConfig;

/// A GUI-subsystem binary has no stdio by default. When this same executable
/// is used as a CLI from cmd/PowerShell, attach to the launching terminal and
/// reopen CONIN$/CONOUT$ so clap, progress bars and result tables still print.
#[cfg(target_os = "windows")]
mod console {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn GetStdHandle(which: u32) -> isize;
        fn SetStdHandle(which: u32, handle: isize) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const u8,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: isize,
        ) -> isize;
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn valid(handle: isize) -> bool {
        handle != 0 && handle != -1
    }

    pub fn attach_parent_console() {
        unsafe {
            if valid(GetStdHandle(STD_OUTPUT_HANDLE)) {
                return;
            }
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                return;
            }

            let out_name = wide("CONOUT$");
            let out = CreateFileW(
                out_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if valid(out) {
                SetStdHandle(STD_OUTPUT_HANDLE, out);
                SetStdHandle(STD_ERROR_HANDLE, out);
            }

            let in_name = wide("CONIN$");
            let input = CreateFileW(
                in_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if valid(input) {
                SetStdHandle(STD_INPUT_HANDLE, input);
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    let help_requested = args.iter().skip(1).any(|arg| {
        matches!(
            arg.to_string_lossy().as_ref(),
            "--help" | "-h" | "--version" | "-V"
        )
    });
    let gui_requested = !help_requested
        && (args.len() == 1
            || args
                .iter()
                .skip(1)
                .any(|arg| arg.to_string_lossy() == "--gui"));

    if gui_requested {
        return match gui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error:#}");
                eprintln!(
                    "Tip: run `ipscan <TARGET>` for CLI mode, or `ipscan --help` for options."
                );
                ExitCode::FAILURE
            }
        };
    }

    #[cfg(target_os = "windows")]
    console::attach_parent_console();

    let cli = Cli::parse_from(
        args.iter()
            .filter(|arg| arg.to_string_lossy() != "--gui")
            .cloned(),
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let ports = ports::parse_ports(&cli.ports)?;
    let hosts = target::parse_targets(&cli.targets)?;
    if hosts.is_empty() {
        bail!("no targets to scan");
    }

    let stdout_paths = [&cli.json, &cli.csv]
        .into_iter()
        .flatten()
        .filter(|path| output::is_stdout(path))
        .count();
    if stdout_paths > 1 {
        bail!("only one of --json/- and --csv/- can write to stdout");
    }

    let color =
        !cli.no_color && io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    eprintln!(
        "Scanning {} host(s) x {} port(s) (timeout {} ms, concurrency {})",
        hosts.len(),
        ports.len(),
        cli.timeout.max(1),
        cli.concurrency.max(1)
    );

    let config = ScanConfig {
        timeout: Duration::from_millis(cli.timeout.max(1)),
        concurrency: cli.concurrency.max(1),
        banners: cli.banners,
        ping: cli.ping,
    };

    let started = Instant::now();
    let progress = progress_bar(hosts.len() as u64, cli.quiet, "scanning");
    let mut results = scanner::scan(
        hosts,
        ports.clone(),
        config,
        progress.clone(),
        Arc::new(AtomicBool::new(false)),
        None,
    )
    .await;
    progress.finish_and_clear();

    if !cli.no_resolve {
        let live = results
            .iter()
            .filter(|host| !host.open_ports.is_empty())
            .count();
        if live > 0 {
            let dns_progress = progress_bar(live as u64, cli.quiet, "resolving names");
            scanner::resolve_hostnames(&mut results, dns_progress.clone()).await;
            dns_progress.finish_and_clear();
        }
    }

    let scanned_total = results.len();

    if cli.ping {
        let checked = results
            .iter()
            .filter(|host| host.open_ports.is_empty())
            .count();
        let responded = results
            .iter()
            .filter(|host| host.ping_latency.is_some())
            .count();
        results.retain(|host| !host.open_ports.is_empty() || host.ping_latency.is_some());

        if !cli.quiet {
            eprintln!("Ping check: {responded}/{checked} host(s) without open ports responded");
        }
    }

    if !cli.no_mac {
        let arp_progress = progress_bar(results.len() as u64, cli.quiet, "resolving mac");
        scanner::resolve_macs(&mut results, arp_progress.clone()).await;
        arp_progress.finish_and_clear();
    }

    let elapsed = started.elapsed();

    if let Some(path) = &cli.json {
        output::write_report(path, &output::json_report(&results, elapsed))?;
    }
    if let Some(path) = &cli.csv {
        output::write_report(path, &output::csv_report(&results))?;
    }
    if stdout_paths == 0 {
        output::print_table(&results, cli.all || cli.ping, color);
    }

    let live = results
        .iter()
        .filter(|host| !host.open_ports.is_empty())
        .count();
    let open = results.iter().map(|host| host.open_ports.len()).sum();

    output::print_summary(scanned_total, ports.len(), live, open, elapsed);
    Ok(())
}

fn progress_bar(length: u64, quiet: bool, verb: &str) -> ProgressBar {
    if quiet || !io::stderr().is_terminal() || length == 0 {
        return ProgressBar::hidden();
    }

    let bar = ProgressBar::new(length);
    let style = ProgressStyle::with_template(
        "{spinner:.cyan} {msg:>15} [{bar:32.cyan/blue}] {pos}/{len} ({eta})",
    )
    .expect("valid progress template")
    .progress_chars("=>-");
    bar.set_style(style);
    bar.set_message(verb.to_string());
    bar.enable_steady_tick(Duration::from_millis(120));
    bar
}
