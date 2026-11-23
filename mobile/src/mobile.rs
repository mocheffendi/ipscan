//! Portrait-first UI for the standalone Android app.
//!
//! This is a separate crate from the desktop scanner: it has its own palette,
//! its own widget sizes and a single vertical flow (stats, progress, config,
//! live results) that scrolls with a finger drag. Everything is reachable by
//! tap — no hover-only controls and no desktop shortcuts.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use eframe::egui;
use egui::{Align, Color32, CornerRadius, FontId, Layout, Margin, RichText, Stroke, TextStyle, Ui};

use crate::helpers::{format_elapsed, host_matches, host_visible, progress_bar};
use crate::local_ip;
use crate::scanner::{self, HostResult, ScanConfig, ScanEvent};
use crate::{arp, output, ports, target};

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

// Palette from mobile/stitch.html (dark theme).
pub(crate) const BG: Color32 = Color32::from_rgb(7, 12, 21);
pub(crate) const CARD: Color32 = Color32::from_rgb(18, 29, 52);
pub(crate) const CHIP_BG: Color32 = Color32::from_rgb(9, 17, 34);
pub(crate) const INPUT: Color32 = Color32::from_rgb(8, 14, 28);
pub(crate) const BORDER: Color32 = Color32::from_rgb(30, 45, 74);
pub(crate) const TEXT: Color32 = Color32::from_rgb(241, 245, 249);
pub(crate) const MUTED: Color32 = Color32::from_rgb(116, 131, 157);
pub(crate) const ACCENT: Color32 = Color32::from_rgb(0, 229, 255);
pub(crate) const ACCENT_DARK: Color32 = Color32::from_rgb(0, 131, 143);
pub(crate) const SUCCESS: Color32 = Color32::from_rgb(52, 211, 153);
pub(crate) const WARNING: Color32 = Color32::from_rgb(251, 191, 36);
pub(crate) const DANGER: Color32 = Color32::from_rgb(248, 113, 113);

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Idle,
    Scanning,
    Done,
    Cancelled,
}

/// The two portrait-screen sections, like the segmented control in the design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Setup,
    Results,
}

/// Which setting the single slider in PERFORMANCE controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SliderField {
    Timeout,
    Concurrency,
}

enum UiEvent {
    Host(HostResult),
    Hostname(IpAddr, String),
    Mac {
        ip: IpAddr,
        mac: String,
        manufacturer: String,
    },
    Finished {
        elapsed: Duration,
        cancelled: bool,
    },
    Failed(String),
}

/// One host card in the results list.
struct MobileRow {
    ip: IpAddr,
    latency: Option<String>,
    subtitle: String,
    ports: Vec<String>,
    details: Vec<String>,
}

pub struct MobileApp {
    tab: Tab,
    targets: String,
    ports: String,
    timeout_ms: u64,
    concurrency: usize,
    slider_field: SliderField,
    banners: bool,
    resolve_mac: bool,
    resolve_hostnames: bool,
    show_pingable: bool,
    cheatsheet_open: bool,

    state: ScanState,
    stopping: bool,
    results: BTreeMap<IpAddr, HostResult>,
    /// The ARP watcher can resolve a MAC before its host finishes scanning.
    /// Keep those details until the matching IP row arrives.
    mac_cache: BTreeMap<IpAddr, (String, String)>,
    total: usize,
    scanned: usize,
    live_hosts: usize,
    open_ports: usize,
    port_count: usize,
    started: Option<Instant>,
    final_elapsed: Option<Duration>,
    receiver: Option<Receiver<UiEvent>>,
    cancel: Option<Arc<AtomicBool>>,

    error: Option<String>,
    status: String,
    filter: String,
    expanded: Option<IpAddr>,
}

impl MobileApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let (targets, status) = detected_targets();
        Self {
            tab: Tab::Setup,
            targets,
            ports: "top100".to_string(),
            timeout_ms: 1000,
            concurrency: 512,
            slider_field: SliderField::Concurrency,
            banners: false,
            resolve_mac: true,
            resolve_hostnames: true,
            show_pingable: false,
            cheatsheet_open: false,
            filter: String::new(),

            state: ScanState::Idle,
            stopping: false,
            results: Default::default(),
            mac_cache: Default::default(),
            total: 0,
            scanned: 0,
            live_hosts: 0,
            open_ports: 0,
            port_count: 0,
            started: None,
            final_elapsed: None,
            receiver: None,
            cancel: None,

            error: None,
            status,
            expanded: None,
        }
    }

    /// The round reset button in the bottom dock.
    fn reset_defaults(&mut self) {
        let (targets, status) = detected_targets();
        self.tab = Tab::Setup;
        self.targets = targets;
        self.ports = "top100".to_string();
        self.timeout_ms = 1000;
        self.concurrency = 512;
        self.slider_field = SliderField::Concurrency;
        self.banners = false;
        self.resolve_mac = true;
        self.resolve_hostnames = true;
        self.show_pingable = false;
        self.filter.clear();
        self.cheatsheet_open = false;
        self.error = None;
        self.status = status;
    }

    /// Re-detect the current Wi-Fi network and fill it into TARGETS.
    fn fill_wifi_network(&mut self) {
        match local_ip::wifi_network() {
            Some(network) => {
                self.targets = network.clone();
                self.error = None;
                self.status = format!("Wi-Fi network detected: {network}");
            }
            None => {
                self.status = "No Wi-Fi address detected — choose a target manually.".to_string();
            }
        }
    }

    /// One slider for both settings: tap Timeout or Concurrency to pick which
    /// value it edits. Kept in the same place in PERFORMANCE.
    fn value_slider(&mut self) -> egui::Slider<'_> {
        let field = self.slider_field;
        // Concurrency stays linear so 512 sits at ~25% of the 1..2048 track.
        // The timeout range is much wider, so it keeps a logarithmic scale.
        let (range, suffix, logarithmic) = match field {
            SliderField::Timeout => (50.0..=60_000.0, " ms", true),
            SliderField::Concurrency => (1.0..=2_048.0, "", false),
        };

        egui::Slider::from_get_set(range, move |value| {
            if let Some(value) = value {
                let value = value.round() as u64;
                match field {
                    SliderField::Timeout => {
                        self.timeout_ms = value.clamp(50, 60_000);
                    }
                    SliderField::Concurrency => {
                        self.concurrency = (value as usize).clamp(1, 2_048);
                    }
                }
            }
            match field {
                SliderField::Timeout => self.timeout_ms as f64,
                SliderField::Concurrency => self.concurrency as f64,
            }
        })
        .integer()
        .logarithmic(logarithmic)
        .suffix(suffix)
    }

    fn is_scanning(&self) -> bool {
        self.state == ScanState::Scanning
    }

    fn elapsed(&self) -> Duration {
        self.final_elapsed
            .or_else(|| self.started.map(|started| started.elapsed()))
            .unwrap_or_default()
    }

    fn scan_fraction(&self) -> f32 {
        if self.is_scanning() || self.state == ScanState::Cancelled {
            if self.total == 0 {
                0.0
            } else {
                (self.scanned as f32 / self.total as f32).clamp(0.0, 1.0)
            }
        } else if self.state == ScanState::Done {
            1.0
        } else {
            0.0
        }
    }

    fn start_scan(&mut self) {
        let hosts = match target::parse_targets(std::slice::from_ref(&self.targets)) {
            Ok(hosts) if hosts.is_empty() => {
                self.error = Some("Enter at least one target.".to_string());
                return;
            }
            Ok(hosts) => hosts,
            Err(error) => {
                self.error = Some(format!("{error:#}"));
                return;
            }
        };
        let ports = match ports::parse_ports(&self.ports) {
            Ok(ports) => ports,
            Err(error) => {
                self.error = Some(format!("{error:#}"));
                return;
            }
        };

        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let config = ScanConfig {
            timeout: Duration::from_millis(self.timeout_ms.max(1)),
            concurrency: self.concurrency.max(1),
            banners: self.banners,
            ping: true,
        };
        let resolve_mac = self.resolve_mac;
        let resolve_hostnames = self.resolve_hostnames;
        let total = hosts.len();
        // The background ARP watcher needs the target list too.
        let arp_hosts = hosts.clone();
        let port_count = ports.len();
        let cancel_for_worker = Arc::clone(&cancel);
        let started = Instant::now();

        self.error = None;
        self.results.clear();
        self.mac_cache.clear();
        self.expanded = None;
        self.state = ScanState::Scanning;
        self.stopping = false;
        self.scanned = 0;
        self.live_hosts = 0;
        self.open_ports = 0;
        self.total = total;
        self.port_count = port_count;
        self.final_elapsed = None;
        self.started = Some(started);
        self.receiver = Some(receiver);
        self.cancel = Some(cancel);
        self.status = format!("Scanning {total} host(s) on {port_count} port(s)...");

        let spawn = std::thread::Builder::new()
            .name("ipscan-worker".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = sender.send(UiEvent::Failed(format!(
                            "could not start the scan runtime: {error}"
                        )));
                        return;
                    }
                };

                // The scanner streams events; a tiny bridge forwards host rows
                // to the UI channel so they appear while the scan is running.
                let (host_sender, host_receiver) = mpsc::channel::<ScanEvent>();
                let bridge_sender = sender.clone();
                let bridge = std::thread::Builder::new()
                    .name("ipscan-events".to_string())
                    .spawn(move || {
                        for event in host_receiver {
                            let ScanEvent::Host(host) = event;
                            if bridge_sender.send(UiEvent::Host(host)).is_err() {
                                break;
                            }
                        }
                    });

                // The OS ARP cache is populated by the TCP connections while
                // the scan runs. Poll it in the background so MAC address and
                // vendor appear next to each IP as soon as it is known.
                let mac_watcher = if resolve_mac {
                    let mac_sender = sender.clone();
                    let mac_cancel = Arc::clone(&cancel_for_worker);
                    Some(runtime.spawn(async move {
                        let mut sent = std::collections::HashSet::new();
                        loop {
                            if mac_cancel.load(Ordering::Relaxed) {
                                break;
                            }
                            let table = arp::table().await;
                            for ip in &arp_hosts {
                                if sent.contains(ip) {
                                    continue;
                                }
                                if let Some(info) = table.get(ip) {
                                    if mac_sender
                                        .send(UiEvent::Mac {
                                            ip: *ip,
                                            mac: info.mac.clone(),
                                            manufacturer: info.manufacturer.clone(),
                                        })
                                        .is_err()
                                    {
                                        return;
                                    }
                                    sent.insert(*ip);
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }))
                } else {
                    None
                };

                runtime.block_on(async move {
                    let mut results = scanner::scan(
                        hosts,
                        ports,
                        config,
                        indicatif::ProgressBar::hidden(),
                        Arc::clone(&cancel_for_worker),
                        Some(host_sender),
                    )
                    .await;

                    if let Some(watcher) = &mac_watcher {
                        watcher.abort();
                    }

                    // Ensure all host events are queued before DNS names.
                    if let Ok(bridge) = bridge {
                        let _ = bridge.join();
                    }

                    if resolve_hostnames {
                        scanner::resolve_hostnames(&mut results, indicatif::ProgressBar::hidden())
                            .await;
                        for host in &results {
                            if let Some(hostname) = &host.hostname {
                                let _ = sender.send(UiEvent::Hostname(host.ip, hostname.clone()));
                            }
                        }
                    }

                    let cancelled = cancel_for_worker.load(Ordering::Relaxed);

                    if resolve_mac && !cancelled {
                        scanner::resolve_macs(&mut results, indicatif::ProgressBar::hidden()).await;
                        for host in &results {
                            if let (Some(mac), Some(manufacturer)) = (&host.mac, &host.manufacturer)
                            {
                                let _ = sender.send(UiEvent::Mac {
                                    ip: host.ip,
                                    mac: mac.clone(),
                                    manufacturer: manufacturer.clone(),
                                });
                            }
                        }
                    }

                    let _ = sender.send(UiEvent::Finished {
                        elapsed: started.elapsed(),
                        cancelled,
                    });
                });
            });

        if spawn.is_err() {
            self.state = ScanState::Idle;
            self.started = None;
            self.receiver = None;
            self.cancel = None;
            self.error = Some("Could not start the background scan thread.".to_string());
        }
    }

    fn request_stop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
            self.stopping = true;
            self.status = "Stopping scan, keeping partial results...".to_string();
        }
    }

    fn poll_events(&mut self) {
        let mut events = Vec::new();
        let mut disconnected = false;

        if let Some(receiver) = &self.receiver {
            loop {
                match receiver.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        for event in events {
            self.apply_event(event);
        }

        if disconnected && self.is_scanning() {
            self.state = ScanState::Done;
            self.final_elapsed = Some(self.elapsed());
            self.stopping = false;
            self.cancel = None;
            self.status = "Scan finished.".to_string();
        }
        if disconnected {
            self.receiver = None;
        }
    }

    fn apply_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::Host(host) => {
                self.scanned += 1;
                if !host.open_ports.is_empty() {
                    self.live_hosts += 1;
                    self.open_ports += host.open_ports.len();
                }
                let mut host = host;
                if let Some((mac, manufacturer)) = self.mac_cache.remove(&host.ip) {
                    host.mac = Some(mac);
                    host.manufacturer = Some(manufacturer);
                }
                self.results.insert(host.ip, host);
            }
            UiEvent::Hostname(ip, hostname) => {
                if let Some(host) = self.results.get_mut(&ip) {
                    host.hostname = Some(hostname);
                }
            }
            UiEvent::Mac {
                ip,
                mac,
                manufacturer,
            } => {
                if let Some(host) = self.results.get_mut(&ip) {
                    host.mac = Some(mac);
                    host.manufacturer = Some(manufacturer);
                } else {
                    // ARP can resolve this neighbor before its port scan ends.
                    self.mac_cache.insert(ip, (mac, manufacturer));
                }
            }
            UiEvent::Finished { elapsed, cancelled } => {
                self.final_elapsed = Some(elapsed);
                self.state = if cancelled {
                    ScanState::Cancelled
                } else {
                    ScanState::Done
                };
                self.stopping = false;
                self.receiver = None;
                self.cancel = None;
                let open = self.open_ports;
                self.status = if cancelled {
                    format!("Scan stopped. {open} open port(s) found so far.")
                } else {
                    format!(
                        "Scan complete in {}. {open} open port(s) found.",
                        format_elapsed(elapsed)
                    )
                };
            }
            UiEvent::Failed(message) => {
                self.state = ScanState::Idle;
                self.stopping = false;
                self.cancel = None;
                self.receiver = None;
                self.error = Some(message);
                self.status = "Scan failed to start.".to_string();
            }
        }
    }

    /// Hosts shown as cards in the Results tab.
    fn build_rows(&self) -> Vec<MobileRow> {
        let needle = self.filter.trim().to_lowercase();
        self.results
            .values()
            .filter(|host| host_visible(host, self.show_pingable))
            .filter(|host| host_matches(host, &needle))
            .map(|host| {
                let ports = host
                    .open_ports
                    .iter()
                    .map(|port| match ports::service_name(port.port) {
                        Some(service) => format!("{}/tcp {service}", port.port),
                        None => format!("{}/tcp", port.port),
                    })
                    .collect();

                let mut subtitle = Vec::new();
                if let Some(hostname) = &host.hostname {
                    subtitle.push(hostname.clone());
                }
                if let Some(manufacturer) = &host.manufacturer {
                    subtitle.push(manufacturer.clone());
                } else if let Some(mac) = &host.mac {
                    if mac == arp::RANDOMIZED_VENDOR {
                        subtitle.push("private Wi-Fi address".to_string());
                    } else {
                        subtitle.push(mac.clone());
                    }
                }

                let mut details = Vec::new();
                if let Some(mac) = &host.mac {
                    details.push(format!("MAC: {mac}"));
                }
                if let Some(latency) = host.ping_latency {
                    details.push(format!("ICMP reply: {}", output::format_latency(latency)));
                }
                for port in &host.open_ports {
                    match (&port.banner, ports::service_name(port.port)) {
                        (Some(banner), _) => {
                            details.push(format!("Port {}: {}", port.port, banner))
                        }
                        (None, Some(service)) => details.push(format!(
                            "Port {} ({}): {}",
                            port.port,
                            service,
                            output::format_latency(port.latency)
                        )),
                        (None, None) => details.push(format!(
                            "Port {}: {}",
                            port.port,
                            output::format_latency(port.latency)
                        )),
                    }
                }

                MobileRow {
                    ip: host.ip,
                    latency: host.ping_latency.map(output::format_latency),
                    subtitle: subtitle.join(" · "),
                    ports,
                    details,
                }
            })
            .collect()
    }

    fn export_json(&self) -> String {
        let hosts: Vec<HostResult> = self.results.values().cloned().collect();
        if hosts.is_empty() {
            return "Nothing to export yet.".to_string();
        }
        let name = format!("ipscan-report-{}.json", unix_seconds());
        match std::fs::write(&name, output::json_report(&hosts, self.elapsed())) {
            Ok(()) => format!("Saved {name}"),
            Err(error) => format!("Could not save {name}: {error}"),
        }
    }

    fn export_csv(&self) -> String {
        let hosts: Vec<HostResult> = self.results.values().cloned().collect();
        if hosts.is_empty() {
            return "Nothing to export yet.".to_string();
        }
        let name = format!("ipscan-report-{}.csv", unix_seconds());
        match std::fs::write(&name, output::csv_report(&hosts)) {
            Ok(()) => format!("Saved {name}"),
            Err(error) => format!("Could not save {name}: {error}"),
        }
    }
}

/// Auto-fill value and matching status message at startup / on reset.
fn detected_targets() -> (String, String) {
    match local_ip::wifi_network() {
        Some(network) => (
            network.clone(),
            format!("Wi-Fi network detected: {network}"),
        ),
        None => (
            "192.168.1.0/24".to_string(),
            "Configure targets & ports, then tap Start".to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Start the portrait GUI (used by the Android entry point).
pub fn run() -> Result<()> {
    run_native()
}

/// Android entry: called by `android-activity`'s glue before `run_native`.
#[cfg(target_os = "android")]
pub fn run_android(app: winit::platform::android::activity::AndroidApp) -> Result<()> {
    ANDROID_APP.with(|slot| *slot.borrow_mut() = Some(app));
    run_native()
}

#[cfg(target_os = "android")]
thread_local! {
    static ANDROID_APP: std::cell::RefCell<
        Option<winit::platform::android::activity::AndroidApp>,
    > = const { std::cell::RefCell::new(None) };
}

fn run_native() -> Result<()> {
    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("ipscan mobile — TCP port scanner"),
        ..Default::default()
    };
    #[cfg(target_os = "android")]
    {
        options.android_app = ANDROID_APP.with(|slot| slot.borrow().clone());
    }

    eframe::run_native(
        "ipscan",
        options,
        Box::new(move |cc| Ok(Box::new(MobileApp::new(cc)))),
    )
    .map_err(|error| anyhow::anyhow!("could not start the mobile GUI: {error}"))
}

// ---------------------------------------------------------------------------
// Android safe area (status bar, navigation bar, display cutouts)
// ---------------------------------------------------------------------------

/// Returns `(top, bottom, left, right)` in egui points. The NativeActivity
/// surface covers the whole display, so system bars would otherwise overlap
/// the header and the scan button. `content_rect()` is the inset-free area
/// reported by Android and updates when the keyboard or orientation changes.
#[cfg(target_os = "android")]
fn safe_area(ctx: &egui::Context) -> (f32, f32, f32, f32) {
    ANDROID_APP.with(|slot| {
        let borrowed = slot.borrow();
        let Some(app) = borrowed.as_ref() else {
            return (0.0, 0.0, 0.0, 0.0);
        };
        let rect = app.content_rect();
        if rect.right <= rect.left || rect.bottom <= rect.top {
            return (0.0, 0.0, 0.0, 0.0);
        }
        let ppu = ctx.pixels_per_point().max(0.1);
        let width = ctx.screen_rect().width() * ppu;
        let height = ctx.screen_rect().height() * ppu;
        (
            (rect.top.max(0) as f32 / ppu).clamp(0.0, 200.0),
            ((height - rect.bottom.max(0) as f32).max(0.0) / ppu).clamp(0.0, 300.0),
            (rect.left.max(0) as f32 / ppu).clamp(0.0, 200.0),
            ((width - rect.right.max(0) as f32).max(0.0) / ppu).clamp(0.0, 200.0),
        )
    })
}

#[cfg(not(target_os = "android"))]
fn safe_area(_ctx: &egui::Context) -> (f32, f32, f32, f32) {
    (0.0, 0.0, 0.0, 0.0)
}

/// egui stores margins as `i8`, so round the point-based safe area here.
fn margin_px(left: f32, right: f32, top: f32, bottom: f32) -> Margin {
    Margin {
        left: left.round().clamp(0.0, 127.0) as i8,
        right: right.round().clamp(0.0, 127.0) as i8,
        top: top.round().clamp(0.0, 127.0) as i8,
        bottom: bottom.round().clamp(0.0, 127.0) as i8,
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

impl eframe::App for MobileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        let (safe_top, safe_bottom, safe_left, safe_right) = safe_area(ctx);
        let mut start = false;
        header(self, ctx, safe_top, safe_left, safe_right);
        central(self, ctx, &mut start, safe_left, safe_right);
        dock(self, ctx, &mut start, safe_bottom, safe_left, safe_right);

        // The soft keyboard's "Done" acts like the Start button.
        let enter_pressed = ctx.input(|input| input.key_pressed(egui::Key::Enter));
        if start || (enter_pressed && !self.is_scanning()) {
            self.start_scan();
        }

        if self.is_scanning() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }
}

// ---------------------------------------------------------------------------
// Fixed chrome: header (brand, tabs) and bottom action dock
// ---------------------------------------------------------------------------

fn header(
    app: &mut MobileApp,
    ctx: &egui::Context,
    safe_top: f32,
    safe_left: f32,
    safe_right: f32,
) {
    egui::TopBottomPanel::top("header")
        .frame(
            egui::Frame::NONE
                .fill(BG)
                .stroke(Stroke::new(1.0_f32, BORDER))
                .inner_margin(margin_px(
                    14.0 + safe_left,
                    14.0 + safe_right,
                    9.0 + safe_top,
                    9.0,
                )),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                radar_icon(ui, 32.0, app.is_scanning());
                ui.add_space(9.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("ipscan").size(16.0).strong().color(TEXT));
                        version_badge(ui);
                    });
                    ui.label(
                        RichText::new("Modern TCP port scanner")
                            .size(10.5)
                            .color(MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    status_pill(ui, app.state, app.stopping);
                });
            });
            ui.add_space(8.0);
            tabs(app, ui);
        });
}

fn tabs(app: &mut MobileApp, ui: &mut Ui) {
    let count = app
        .results
        .values()
        .filter(|host| host_visible(host, app.show_pingable))
        .count();
    let setup_selected = app.tab == Tab::Setup;
    let results_selected = app.tab == Tab::Results;
    // 8 pt of frame margin + 4 pt gap between the two buttons.
    let width = (ui.available_width() - 16.0) / 2.0;

    let mut setup_clicked = false;
    let mut results_clicked = false;
    egui::Frame::NONE
        .fill(CHIP_BG)
        .corner_radius(CornerRadius::same(10))
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(Margin::symmetric(4, 3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                setup_clicked = tab_button(ui, "Scan Setup", setup_selected, width);
                ui.add_space(4.0);
                results_clicked =
                    tab_button(ui, &format!("Results   {count}"), results_selected, width);
            });
        });
    if setup_clicked {
        app.tab = Tab::Setup;
    }
    if results_clicked {
        app.tab = Tab::Results;
    }
}

fn tab_button(ui: &mut Ui, label: &str, selected: bool, width: f32) -> bool {
    let color = if selected { TEXT } else { MUTED };
    ui.add(
        egui::Button::new(RichText::new(label).size(12.0).strong().color(color))
            .fill(if selected { CARD } else { Color32::TRANSPARENT })
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(8))
            .min_size(egui::vec2(width, 30.0)),
    )
    .clicked()
}

fn dock(
    app: &mut MobileApp,
    ctx: &egui::Context,
    start: &mut bool,
    safe_bottom: f32,
    safe_left: f32,
    safe_right: f32,
) {
    egui::TopBottomPanel::bottom("dock")
        .exact_height(90.0 + safe_bottom)
        .frame(
            egui::Frame::NONE
                .fill(BG)
                .stroke(Stroke::new(1.0_f32, BORDER))
                .inner_margin(margin_px(
                    12.0 + safe_left,
                    12.0 + safe_right,
                    7.0,
                    7.0 + safe_bottom,
                )),
        )
        .show(ctx, |ui| {
            let color = if app.error.is_some() {
                DANGER
            } else if app.is_scanning() {
                ACCENT
            } else {
                MUTED
            };
            ui.label(RichText::new(&app.status).size(10.5).color(color));
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                let scanning = app.is_scanning();
                let (label, fill) = if scanning {
                    ("Stop scan", DANGER)
                } else {
                    ("Start scan", ACCENT)
                };
                let width = (ui.available_width() - 52.0).max(120.0);
                let button = egui::Button::new(
                    RichText::new(label)
                        .size(15.0)
                        .strong()
                        .color(Color32::from_rgb(4, 16, 24)),
                )
                .fill(fill)
                .corner_radius(CornerRadius::same(12))
                .min_size(egui::vec2(width, 46.0));
                if ui.add(button).clicked() {
                    if scanning {
                        app.request_stop();
                    } else {
                        *start = true;
                    }
                }

                let reset = egui::Button::new(RichText::new("↻").size(20.0).color(TEXT))
                    .fill(CARD)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .corner_radius(CornerRadius::same(12))
                    .min_size(egui::vec2(44.0, 46.0));
                if ui.add(reset).clicked() {
                    app.reset_defaults();
                }
            });
        });
}

// ---------------------------------------------------------------------------
// Scrollable content
// ---------------------------------------------------------------------------

fn central(
    app: &mut MobileApp,
    ctx: &egui::Context,
    start: &mut bool,
    safe_left: f32,
    safe_right: f32,
) {
    egui::CentralPanel::default()
        .frame(egui::Frame::NONE.fill(BG).inner_margin(margin_px(
            12.0 + safe_left,
            12.0 + safe_right,
            12.0,
            12.0,
        )))
        .show(ctx, |ui| {
            // One scroll area for the whole portrait page — drag to scroll.
            egui::ScrollArea::vertical()
                .id_salt("mobile_main")
                .drag_to_scroll(true)
                .show(ui, |ui| {
                    metrics(app, ui);
                    ui.add_space(12.0);
                    match app.tab {
                        Tab::Setup => setup_card(app, ui),
                        Tab::Results => results_tab(app, ui),
                    }
                    // Keep the last control (target cheatsheet / host cards)
                    // well clear of the fixed bottom dock at maximum scroll.
                    ui.add_space(96.0);
                });
        });

    // Tab buttons need mutable access; handle them after the panels are drawn
    // using the responses recorded in `header` (see `tab_click` below).
    let _ = start;
}

fn metrics(app: &MobileApp, ui: &mut Ui) {
    let ping_only = app
        .results
        .values()
        .filter(|host| host.open_ports.is_empty() && host.ping_latency.is_some())
        .count();

    ui.columns(2, |columns| {
        stat_card(
            &mut columns[0],
            "HOSTS SCANNED",
            &format!("{} / {}", app.scanned, app.total),
            TEXT,
        );
        stat_card(
            &mut columns[1],
            "LIVE HOSTS",
            &app.live_hosts.to_string(),
            SUCCESS,
        );
    });
    ui.add_space(7.0);
    ui.columns(2, |columns| {
        stat_card(
            &mut columns[0],
            "PING-ONLY",
            &ping_only.to_string(),
            WARNING,
        );
        stat_card(
            &mut columns[1],
            "OPEN PORTS",
            &app.open_ports.to_string(),
            ACCENT,
        );
    });
    ui.add_space(8.0);
    progress_card(app, ui);
}

fn stat_card(ui: &mut Ui, label: &str, value: &str, color: Color32) {
    card_frame()
        .inner_margin(Margin::symmetric(11, 10))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(9.5).strong().color(MUTED));
            ui.add_space(1.0);
            ui.label(RichText::new(value).size(19.0).strong().color(color));
        });
}

fn progress_card(app: &MobileApp, ui: &mut Ui) {
    let fraction = app.scan_fraction();
    let title = match app.state {
        ScanState::Idle => "Ready to scan",
        ScanState::Scanning if app.stopping => "Stopping scan",
        ScanState::Scanning => "Scanning network",
        ScanState::Done => "Scan complete",
        ScanState::Cancelled => "Scan stopped",
    };
    let subtitle = match app.state {
        ScanState::Idle => "Configure targets & ports, then tap Start".to_string(),
        ScanState::Scanning if app.stopping => "Waiting for active connections...".to_string(),
        ScanState::Scanning => format!(
            "{} of {} hosts · {} ports/host",
            app.scanned, app.total, app.port_count
        ),
        ScanState::Done => format!(
            "{} hosts · {} live · {} open ports",
            app.total, app.live_hosts, app.open_ports
        ),
        ScanState::Cancelled => format!("Partial results · {}/{} hosts", app.scanned, app.total),
    };

    card_frame()
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(12.5).strong().color(TEXT));
                    ui.label(RichText::new(subtitle).size(10.5).color(MUTED));
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    ui.label(
                        RichText::new(format_elapsed(app.elapsed()))
                            .size(9.5)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{:.0}%", fraction * 100.0))
                            .size(18.0)
                            .strong()
                            .color(ACCENT),
                    );
                });
            });
            ui.add_space(8.0);
            progress_bar(ui, fraction, app.is_scanning());
        });
}

fn setup_card(app: &mut MobileApp, ui: &mut Ui) {
    card_frame()
        .inner_margin(Margin::symmetric(13, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("SCAN SETUP").size(10.5).strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new("TCP Connect").size(10.0).color(ACCENT));
                });
            });
            ui.separator();

            // TARGETS with quick-fill chips.
            ui.horizontal(|ui| {
                ui.label(RichText::new("TARGETS").size(11.5).strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(chip_button("Wi-Fi /24")).clicked() {
                        app.fill_wifi_network();
                    }
                    if ui.add(chip_button("private /24")).clicked() {
                        app.targets = "192.168.1.0/24".to_string();
                    }
                    if ui.add(chip_button("localhost")).clicked() {
                        app.targets = "127.0.0.1".to_string();
                    }
                    ui.label(RichText::new("Quick fill:").size(9.5).color(MUTED));
                });
            });
            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.targets)
                    .hint_text("e.g. 192.168.1.0/24, 10.0.0.1")
                    .font(TextStyle::Monospace)
                    .min_size(egui::vec2(ui.available_width(), 38.0)),
            );

            ui.add_space(10.0);
            ui.label(RichText::new("PORTS").size(11.5).strong().color(TEXT));
            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.ports)
                    .hint_text("top100, 80,443, 1-1024")
                    .font(TextStyle::Monospace)
                    .min_size(egui::vec2(ui.available_width(), 38.0)),
            );
            ui.label(
                RichText::new("Ranges (1-1024), groups (web, db, mail), or a comma list.")
                    .size(10.0)
                    .color(MUTED),
            );

            // Performance.
            ui.add_space(10.0);
            ui.separator();
            ui.label(RichText::new("PERFORMANCE").size(9.5).strong().color(MUTED));
            ui.add_space(4.0);
            ui.columns(2, |columns| {
                if mini_stat(
                    &mut columns[0],
                    "Timeout",
                    &format!("{} ms", app.timeout_ms),
                    TEXT,
                    app.slider_field == SliderField::Timeout,
                ) {
                    app.slider_field = SliderField::Timeout;
                }
                if mini_stat(
                    &mut columns[1],
                    "Concurrency",
                    &app.concurrency.to_string(),
                    ACCENT,
                    app.slider_field == SliderField::Concurrency,
                ) {
                    app.slider_field = SliderField::Concurrency;
                }
            });
            ui.add_space(5.0);
            ui.label(
                RichText::new(match app.slider_field {
                    SliderField::Timeout => "Slider: timeout (50 ms - 60 s)",
                    SliderField::Concurrency => "Slider: concurrency (1 - 2048)",
                })
                .size(9.5)
                .color(MUTED),
            );
            // Full-width slider; the value is already shown in the card above.
            full_width_slider(ui, app.value_slider().show_value(false));
            ui.horizontal(|ui| {
                let (low, high) = match app.slider_field {
                    SliderField::Timeout => ("50 ms", "60 s"),
                    SliderField::Concurrency => ("1", "2048"),
                };
                ui.label(RichText::new(low).size(9.0).color(MUTED));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(high).size(9.0).color(MUTED));
                });
            });

            // Probe options.
            ui.add_space(8.0);
            ui.separator();
            ui.checkbox(&mut app.resolve_hostnames, "Resolve hostnames");
            ui.checkbox(&mut app.resolve_mac, "Resolve MAC / vendor (ARP)");
            ui.checkbox(&mut app.banners, "Grab service banners");

            // Target cheatsheet accordion.
            ui.add_space(8.0);
            let caption = if app.cheatsheet_open {
                "TARGET CHEATSHEET  ▴"
            } else {
                "TARGET CHEATSHEET  ▾"
            };
            if ui.add(chip_button(caption)).clicked() {
                app.cheatsheet_open = !app.cheatsheet_open;
            }
            if app.cheatsheet_open {
                for (example, meaning) in [
                    ("192.168.1.0/24", "CIDR subnet"),
                    ("10.0.0.1-50", "Short range"),
                    ("192.168.1.*", "Wildcard"),
                    ("example.com", "Hostname domain"),
                ] {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(example).size(10.5).monospace().color(ACCENT));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new(meaning).size(10.0).color(MUTED));
                        });
                    });
                }
            }
        });
}

/// egui sizes sliders from `spacing.slider_width`; stretch it to the card width.
fn full_width_slider(ui: &mut Ui, slider: egui::Slider<'_>) -> egui::Response {
    let width = ui.available_width().max(60.0);
    let previous = ui.spacing().slider_width;
    ui.spacing_mut().slider_width = width;
    let response = ui.add(slider);
    ui.spacing_mut().slider_width = previous;
    response
}

/// Tappable stat: selects which value the shared slider controls.
fn mini_stat(ui: &mut Ui, label: &str, value: &str, color: Color32, selected: bool) -> bool {
    egui::Frame::NONE
        .fill(if selected {
            Color32::from_rgb(9, 59, 70)
        } else {
            CHIP_BG
        })
        .corner_radius(CornerRadius::same(10))
        .stroke(Stroke::new(
            1.0_f32,
            if selected { ACCENT_DARK } else { BORDER },
        ))
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            let mut clicked = ui
                .add(
                    egui::Button::new(RichText::new(label).size(10.0).color(if selected {
                        ACCENT
                    } else {
                        MUTED
                    }))
                    .frame(false),
                )
                .clicked();
            clicked |= ui
                .add(
                    egui::Button::new(RichText::new(value).size(13.0).strong().color(color))
                        .frame(false),
                )
                .clicked();
            clicked
        })
        .inner
}

fn results_tab(app: &mut MobileApp, ui: &mut Ui) {
    card_frame()
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.filter)
                    .hint_text("Filter IP, host, port, service...")
                    .min_size(egui::vec2(ui.available_width(), 34.0)),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(&mut app.show_pingable, "Show ping-only hosts");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(chip_button("CSV")).clicked() {
                        app.status = app.export_csv();
                    }
                    if ui.add(chip_button("JSON")).clicked() {
                        app.status = app.export_json();
                    }
                });
            });
        });
    ui.add_space(10.0);

    let rows = app.build_rows();
    card_frame()
        .inner_margin(Margin::symmetric(12, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if rows.is_empty() {
                empty_state(app, ui);
                return;
            }
            for row in rows {
                host_card(app, ui, row);
                ui.add_space(7.0);
            }
        });
}

fn empty_state(app: &MobileApp, ui: &mut Ui) {
    let filtered = !app.filter.trim().is_empty();
    ui.add_space(8.0);
    ui.vertical_centered(|ui| {
        radar_icon(ui, 100.0, app.is_scanning());
        ui.add_space(10.0);
        let title = if filtered {
            "No hosts match the filter"
        } else if app.is_scanning() {
            "Scanning for open ports..."
        } else {
            "No results yet"
        };
        let subtitle = if filtered {
            "Try a different IP, hostname, port or service name."
        } else if app.is_scanning() {
            "Results appear here as each host finishes."
        } else {
            "Enter your target CIDR or host range and press Start scan to begin."
        };
        ui.label(RichText::new(title).size(13.0).strong().color(TEXT));
        ui.label(RichText::new(subtitle).size(10.5).color(MUTED));
    });
    ui.add_space(8.0);
}

fn host_card(app: &mut MobileApp, ui: &mut Ui, row: MobileRow) {
    let expanded = app.expanded == Some(row.ip);
    let ip = row.ip;

    egui::Frame::NONE
        .fill(CHIP_BG)
        .corner_radius(CornerRadius::same(12))
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(Margin::symmetric(11, 9))
        .show(ui, |ui| {
            let title = if let Some(latency) = &row.latency {
                format!("●  {ip}     {latency}")
            } else {
                format!("●  {ip}")
            };
            if ui
                .add(
                    egui::Button::new(RichText::new(title).size(12.0).strong().color(TEXT))
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE)
                        .corner_radius(CornerRadius::same(0))
                        .min_size(egui::vec2(ui.available_width(), 22.0)),
                )
                .clicked()
            {
                app.expanded = if expanded { None } else { Some(ip) };
            }
            if !row.subtitle.is_empty() {
                ui.label(RichText::new(&row.subtitle).size(10.0).color(MUTED));
            }
            if !row.ports.is_empty() {
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    for port in &row.ports {
                        port_chip(ui, port);
                    }
                });
            }
            if expanded {
                ui.add_space(5.0);
                for detail in &row.details {
                    ui.label(RichText::new(detail).size(10.0).color(MUTED));
                }
            }
        });
}

// ---------------------------------------------------------------------------
// Small drawing helpers
// ---------------------------------------------------------------------------

fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(CARD)
        .corner_radius(CornerRadius::same(14))
        .stroke(Stroke::new(1.0_f32, BORDER))
}

fn chip_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(10.0).monospace().color(ACCENT))
        .fill(CHIP_BG)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(7))
        .min_size(egui::vec2(74.0, 24.0))
}

fn port_chip(ui: &mut Ui, text: &str) {
    egui::Frame::NONE
        .fill(Color32::from_rgba_unmultiplied(0, 229, 255, 34))
        .corner_radius(CornerRadius::same(6))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(0, 229, 255, 90),
        ))
        .inner_margin(Margin::symmetric(6, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(9.5).monospace().color(ACCENT));
        });
}

fn version_badge(ui: &mut Ui) {
    egui::Frame::NONE
        .fill(CARD)
        .corner_radius(CornerRadius::same(5))
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(Margin::symmetric(5, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .size(9.0)
                    .monospace()
                    .color(MUTED),
            );
        });
}

fn status_pill(ui: &mut Ui, state: ScanState, stopping: bool) {
    let (label, color) = match (state, stopping) {
        (ScanState::Scanning, true) => ("STOPPING", WARNING),
        (ScanState::Scanning, false) => ("SCANNING", ACCENT),
        (ScanState::Done, _) => ("COMPLETED", SUCCESS),
        (ScanState::Cancelled, _) => ("CANCELLED", WARNING),
        (ScanState::Idle, _) => ("READY", SUCCESS),
    };
    egui::Frame::NONE
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            24,
        ))
        .corner_radius(CornerRadius::same(20))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 70),
        ))
        .inner_margin(Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 3.5, color);
                ui.label(RichText::new(label).size(10.0).strong().color(color));
            });
        });
}

/// The radar mark from the design: three rings, a sweep line and a glowing tip.
fn radar_icon(ui: &mut Ui, size: f32, animated: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let center = rect.center();
    let radius = size * 0.5 - 2.0;
    let painter = ui.painter();

    for fraction in [1.0_f32, 0.72, 0.44] {
        painter.circle_stroke(
            center,
            radius * fraction,
            Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(0, 229, 255, 70)),
        );
    }
    painter.circle_filled(center, 2.5, ACCENT);

    let angle = if animated {
        ui.input(|input| input.time * 1.6) as f32
    } else {
        -0.6
    };
    let tip = center + egui::vec2(angle.cos() * radius, angle.sin() * radius);
    painter.line_segment([center, tip], Stroke::new(1.5_f32, ACCENT));
    painter.circle_filled(tip, 2.5, ACCENT);
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = CARD;
    visuals.extreme_bg_color = INPUT;
    visuals.faint_bg_color = CHIP_BG;
    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(0, 229, 255, 70);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.noninteractive.bg_fill = CARD;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);
    visuals.widgets.inactive.bg_fill = CHIP_BG;
    visuals.widgets.inactive.weak_bg_fill = CHIP_BG;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(26, 45, 75);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_DARK);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0, 70, 85);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, ACCENT);
    for widgets in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.noninteractive,
    ] {
        widgets.corner_radius = CornerRadius::same(8);
    }

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(9.0, 5.0);
    style.spacing.interact_size.y = 38.0;
    style.spacing.scroll.bar_width = 6.0;
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(18.0)),
        (TextStyle::Body, FontId::proportional(12.5)),
        (TextStyle::Monospace, FontId::monospace(11.5)),
        (TextStyle::Button, FontId::proportional(12.5)),
        (TextStyle::Small, FontId::proportional(10.5)),
    ]
    .into();
    style.animation_time = 0.12;
    ctx.set_style(style);
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
