use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use eframe::egui;
use egui::{Align, Color32, CornerRadius, FontId, Layout, Margin, RichText, Stroke, TextStyle, Ui};
use egui_extras::{Column, TableBuilder};

use crate::arp;
use crate::local_ip;
use crate::scanner::{self, HostResult, PortResult, ScanConfig, ScanEvent};
use crate::{output, ports, target};

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

const BG: Color32 = Color32::from_rgb(7, 11, 18);
const HEADER_BG: Color32 = Color32::from_rgb(9, 16, 28);
const SURFACE: Color32 = Color32::from_rgb(14, 22, 38);
const SURFACE_ALT: Color32 = Color32::from_rgb(18, 29, 48);
const INPUT: Color32 = Color32::from_rgb(9, 17, 30);
const BORDER: Color32 = Color32::from_rgb(30, 43, 64);
const TEXT: Color32 = Color32::from_rgb(230, 237, 247);
const MUTED: Color32 = Color32::from_rgb(139, 155, 180);
const ACCENT: Color32 = Color32::from_rgb(34, 211, 238);
const ACCENT_DARK: Color32 = Color32::from_rgb(8, 51, 68);
const ACCENT_SOFT: Color32 = Color32::from_rgb(14, 58, 69);
const SUCCESS: Color32 = Color32::from_rgb(52, 211, 153);
const WARNING: Color32 = Color32::from_rgb(251, 191, 36);
const DANGER: Color32 = Color32::from_rgb(248, 113, 113);

const HEADER_HEIGHT: f32 = 82.0;
const FOOTER_HEIGHT: f32 = 30.0;
const SIDEBAR_WIDTH: f32 = 346.0;

/// Sum of the results table's initial column widths, inter-column spacing,
/// the banner minimum and the vertical scrollbar. Below this the table gets a
/// horizontal scrollbar instead of pushing the whole window out of shape.
const TABLE_MIN_WIDTH: f32 = 810.0;

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

#[derive(Default)]
struct UiAction {
    start: bool,
    stop: bool,
}

/// Which setting the single slider in the performance card controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SliderField {
    Timeout,
    Concurrency,
}

struct ResultRow<'a> {
    host: &'a HostResult,
    port: Option<&'a PortResult>,
    first: bool,
}

pub fn run() -> Result<()> {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
        .map_err(|error| anyhow::anyhow!("could not load application icon: {error}"))?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ipscan — TCP Port Scanner")
            .with_icon(icon.clone())
            .with_app_id("ipscan")
            .with_inner_size([1220.0, 800.0])
            .with_min_inner_size([1000.0, 660.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ipscan",
        options,
        Box::new(move |cc| Ok(Box::new(IpScanApp::new(cc, icon)))),
    )
    .map_err(|error| anyhow::anyhow!("could not start the GUI: {error}"))
}

struct IpScanApp {
    targets: String,
    ports: String,
    timeout_ms: u64,
    concurrency: usize,
    slider_field: SliderField,
    resolve: bool,
    banners: bool,
    resolve_mac: bool,
    show_pingable: bool,
    filter: String,

    // Live scan state
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
    /// The same PNG used for the window icon, drawn in the in-app header.
    icon_texture: egui::TextureHandle,
}

impl IpScanApp {
    fn new(cc: &eframe::CreationContext<'_>, icon: egui::IconData) -> Self {
        configure_style(&cc.egui_ctx);

        let (pixels, size) = header_icon_pixels(&icon);
        let icon_texture = cc.egui_ctx.load_texture(
            "app-icon",
            egui::ColorImage::from_rgba_unmultiplied([size, size], &pixels),
            egui::TextureOptions::LINEAR,
        );

        let wifi = local_ip::wifi_network();
        let status = match &wifi {
            Some(network) => format!("Wi-Fi network detected: {network}. Ready to scan."),
            None => "No Wi-Fi address detected — choose a target below.".to_string(),
        };

        Self {
            targets: wifi.unwrap_or_default(),
            ports: "top100".to_string(),
            timeout_ms: 1000,
            concurrency: 512,
            slider_field: SliderField::Concurrency,
            resolve: true,
            banners: false,
            resolve_mac: true,
            show_pingable: false,
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
            icon_texture,
        }
    }

    /// Re-detect the current Wi-Fi network and fill it into TARGETS.
    fn fill_wifi_network(&mut self) {
        match local_ip::wifi_network() {
            Some(network) => {
                self.targets = network.clone();
                self.error = None;
                self.status = format!("Wi-Fi network detected: {network}. Ready to scan.");
            }
            None => {
                self.status = "No Wi-Fi address detected — choose a target manually.".to_string();
            }
        }
    }

    /// One slider for both settings: click Timeout or Concurrency to pick which
    /// value it edits. Kept in the same place in the performance card.
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
            // Always collect ICMP reply time; the checkbox only filters rows.
            ping: true,
        };
        let resolve = self.resolve;
        let resolve_mac = self.resolve_mac;
        let total = hosts.len();
        // The background ARP watcher needs the target list too.
        let arp_hosts = hosts.clone();
        let port_count = ports.len();
        let cancel_for_worker = Arc::clone(&cancel);
        let started = Instant::now();

        self.error = None;
        self.results.clear();
        self.mac_cache.clear();
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
                // vendor appear next to each IP as soon as it is known, instead
                // of only after the whole scan (and DNS) has finished.
                let mac_watcher = if resolve_mac {
                    let mac_sender = sender.clone();
                    let mac_cancel = Arc::clone(&cancel_for_worker);
                    Some(runtime.spawn(async move {
                        let mut sent = HashSet::new();
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

                    // Live watching is done; one final ARP read below catches
                    // anything that only showed up at the very end.
                    if let Some(watcher) = &mac_watcher {
                        watcher.abort();
                    }

                    // Ensure all host events are queued before DNS names/finish.
                    if let Ok(bridge) = bridge {
                        let _ = bridge.join();
                    }

                    if resolve {
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

        if disconnected {
            if self.is_scanning() {
                self.state = ScanState::Done;
                self.final_elapsed = Some(self.elapsed());
                self.stopping = false;
                self.cancel = None;
                self.status = "Scan finished.".to_string();
            }
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
                let summary = if cancelled {
                    format!("Scan stopped. {open} open port(s) found so far.")
                } else {
                    format!(
                        "Scan complete in {}. {open} open port(s) found.",
                        format_elapsed(elapsed)
                    )
                };
                self.status = summary;
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

    /// Hosts that the table currently shows. With the ping option enabled,
    /// hosts without open ports must have answered ICMP echo.
    fn visible_hosts(&self) -> Vec<HostResult> {
        self.results
            .values()
            .filter(|host| host_visible(host, self.show_pingable))
            .cloned()
            .collect()
    }

    fn export_json(&self) -> String {
        let hosts = self.visible_hosts();
        if hosts.is_empty() {
            return "Nothing to export yet.".to_string();
        }
        let data = output::json_report(&hosts, self.elapsed());
        let name = format!("ipscan-report-{}.json", unix_seconds());
        match std::fs::write(&name, data) {
            Ok(()) => format!("Saved {name}"),
            Err(error) => format!("Could not save {name}: {error}"),
        }
    }

    fn export_csv(&self) -> String {
        let hosts = self.visible_hosts();
        if hosts.is_empty() {
            return "Nothing to export yet.".to_string();
        }
        let name = format!("ipscan-report-{}.csv", unix_seconds());
        match std::fs::write(&name, output::csv_report(&hosts)) {
            Ok(()) => format!("Saved {name}"),
            Err(error) => format!("Could not save {name}: {error}"),
        }
    }

    fn header(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header")
            .exact_height(HEADER_HEIGHT)
            .frame(
                egui::Frame::NONE
                    .fill(HEADER_BG)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .inner_margin(Margin::symmetric(22, 14)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(
                        egui::Image::from_texture(&self.icon_texture)
                            .fit_to_exact_size(egui::vec2(38.0, 38.0))
                            .corner_radius(CornerRadius::same(9)),
                    );
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("ipscan").size(22.0).strong().color(TEXT));
                        ui.label(
                            RichText::new("Modern TCP port scanner")
                                .size(11.5)
                                .color(MUTED),
                        );
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        status_pill(ui, self.state, self.stopping);
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                                .size(11.0)
                                .monospace()
                                .color(MUTED),
                        );
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new("TCP connect · cross-platform")
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                });
            });
    }

    fn footer(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("footer")
            .exact_height(FOOTER_HEIGHT)
            .frame(
                egui::Frame::NONE
                    .fill(HEADER_BG)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .inner_margin(Margin::symmetric(16, 4)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    let color = if self.error.is_some() {
                        DANGER
                    } else if self.is_scanning() {
                        ACCENT
                    } else {
                        MUTED
                    };
                    ui.label(RichText::new(&self.status).size(11.0).color(color));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.is_scanning() {
                            ui.add(egui::Spinner::new().size(11.0).color(ACCENT));
                            ui.label(RichText::new("live updates").size(10.5).color(MUTED));
                        } else {
                            ui.label(
                                RichText::new(format!(
                                    "{} host(s) stored · {} open port(s)",
                                    self.results.len(),
                                    self.open_ports
                                ))
                                .size(10.5)
                                .color(MUTED),
                            );
                        }
                    });
                });
            });
    }

    fn sidebar(&mut self, ctx: &egui::Context) -> UiAction {
        let mut action = UiAction::default();

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(SIDEBAR_WIDTH)
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(Margin::symmetric(16, 16)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        section_label(ui, "SCAN SETUP");
                        ui.add_space(8.0);
                        self.config_card(ui, &mut action);
                        ui.add_space(12.0);
                        self.tips_card(ui);
                    });
            });

        action
    }

    fn config_card(&mut self, ui: &mut Ui, action: &mut UiAction) {
        egui::Frame::NONE
            .fill(SURFACE)
            .corner_radius(CornerRadius::same(14))
            .stroke(Stroke::new(1.0_f32, BORDER))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                field_label(ui, "TARGETS");
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.targets)
                        .hint_text("192.168.1.0/24, 10.0.0.1-50, example.com")
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(TextStyle::Monospace),
                );
                ui.add_space(5.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Quick fill:").size(10.5).color(MUTED));
                    if ui
                        .link(RichText::new("Wi-Fi /24").size(11.0))
                        .on_hover_text("Detect the current Wi-Fi address and fill its /24 network")
                        .clicked()
                    {
                        self.fill_wifi_network();
                    }
                    if ui.link(RichText::new("localhost").size(11.0)).clicked() {
                        self.targets = "127.0.0.1".to_string();
                    }
                    if ui.link(RichText::new("private /24").size(11.0)).clicked() {
                        self.targets = "192.168.1.0/24".to_string();
                    }
                });

                ui.add_space(12.0);
                field_label(ui, "PORTS");
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.ports)
                        .hint_text("top100, 1-1024, 22,80,443, web")
                        .desired_width(f32::INFINITY)
                        .font(TextStyle::Monospace),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Ranges, groups (web, db, mail, remote) and service names work too.",
                    )
                    .size(10.5)
                    .color(MUTED),
                );

                ui.add_space(14.0);
                field_label(ui, "PERFORMANCE");
                ui.add_space(6.0);
                // Same tappable stat cards as the mobile app.
                ui.columns(2, |columns| {
                    if mini_stat(
                        &mut columns[0],
                        "Timeout",
                        &format!("{} ms", self.timeout_ms),
                        TEXT,
                        self.slider_field == SliderField::Timeout,
                    ) {
                        self.slider_field = SliderField::Timeout;
                    }
                    if mini_stat(
                        &mut columns[1],
                        "Concurrency",
                        &self.concurrency.to_string(),
                        ACCENT,
                        self.slider_field == SliderField::Concurrency,
                    ) {
                        self.slider_field = SliderField::Concurrency;
                    }
                });
                ui.add_space(6.0);
                ui.label(
                    RichText::new(match self.slider_field {
                        SliderField::Timeout => "Slider: connect timeout (50 ms - 60 s)",
                        SliderField::Concurrency => "Slider: concurrency (1 - 2048)",
                    })
                    .size(10.0)
                    .color(MUTED),
                );
                ui.add_space(2.0);
                // One full-width slider for both settings; values live in the cards.
                full_width_slider(ui, self.value_slider().show_value(false));

                ui.add_space(10.0);
                ui.checkbox(&mut self.resolve, "Resolve hostnames")
                    .on_hover_text("Reverse-DNS lookup for hosts with open ports");
                ui.checkbox(&mut self.resolve_mac, "Resolve MAC / vendor (ARP)")
                    .on_hover_text(
                        "Read the OS ARP cache for local IPv4 neighbors and resolve the OUI vendor",
                    );
                ui.checkbox(&mut self.banners, "Grab service banners")
                    .on_hover_text(
                        "Read the first line of service responses (may send a small HTTP probe)",
                    );

                ui.add_space(14.0);

                let scanning = self.is_scanning();
                let (label, fill, hover) = if scanning {
                    ("Stop scan", DANGER, Color32::from_rgb(255, 145, 145))
                } else {
                    ("Start scan", ACCENT, Color32::from_rgb(103, 232, 249))
                };

                let button = egui::Button::new(
                    RichText::new(label)
                        .size(14.5)
                        .strong()
                        .color(Color32::from_rgb(4, 12, 20)),
                )
                .fill(fill)
                .stroke(Stroke::NONE)
                .corner_radius(CornerRadius::same(9))
                .min_size(egui::vec2(ui.available_width(), 40.0));

                let response = ui.add(button);
                if response.clicked() {
                    if scanning {
                        action.stop = true;
                    } else {
                        action.start = true;
                    }
                }
                if response.hovered() {
                    ui.painter().rect_stroke(
                        response.rect,
                        CornerRadius::same(9),
                        Stroke::new(1.5_f32, hover),
                        egui::StrokeKind::Inside,
                    );
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if scanning {
                        ui.add(egui::Spinner::new().size(12.0).color(ACCENT));
                        ui.label(
                            RichText::new(if self.stopping {
                                "Stopping..."
                            } else {
                                "Press Esc to stop"
                            })
                            .size(10.5)
                            .color(MUTED),
                        );
                    } else {
                        ui.label(RichText::new("Ctrl+Enter to start").size(10.5).color(MUTED));
                    }
                });

                if let Some(error) = &self.error {
                    ui.add_space(8.0);
                    ui.label(RichText::new(error).size(11.0).color(DANGER));
                }
            });
    }

    fn tips_card(&self, ui: &mut Ui) {
        egui::Frame::NONE
            .fill(HEADER_BG)
            .corner_radius(CornerRadius::same(12))
            .stroke(Stroke::new(1.0_f32, BORDER))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new("TARGET CHEATSHEET")
                        .size(10.0)
                        .strong()
                        .color(MUTED),
                );
                ui.add_space(6.0);
                for (syntax, meaning) in [
                    ("192.168.1.0/24", "CIDR block"),
                    ("10.0.0.1-50", "short range"),
                    ("192.168.1.*", "wildcard (1-254)"),
                    ("example.com", "hostname"),
                ] {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(syntax).size(10.5).monospace().color(ACCENT));
                        ui.label(RichText::new(meaning).size(10.5).color(MUTED));
                    });
                }
            });
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG).inner_margin(Margin::same(18)))
            .show(ctx, |ui| {
                self.stats_row(ui);
                ui.add_space(12.0);
                self.progress_card(ui);
                ui.add_space(12.0);
                self.filter_row(ui);
                ui.add_space(10.0);
                self.results_card(ui);
            });
    }

    fn stats_row(&self, ui: &mut Ui) {
        let progress = self.scan_fraction();
        let ping_only = self
            .results
            .values()
            .filter(|host| host.open_ports.is_empty() && host.ping_latency.is_some())
            .count();
        ui.columns(5, |columns| {
            stat_card(
                &mut columns[0],
                "HOSTS SCANNED",
                &format!("{} / {}", self.scanned, self.total),
                if self.total > 0 && self.scanned >= self.total {
                    SUCCESS
                } else {
                    TEXT
                },
                progress,
            );
            stat_card(
                &mut columns[1],
                "LIVE HOSTS",
                &self.live_hosts.to_string(),
                SUCCESS,
                progress,
            );
            stat_card(
                &mut columns[2],
                "PING-ONLY HOSTS",
                &ping_only.to_string(),
                WARNING,
                progress,
            );
            stat_card(
                &mut columns[3],
                "OPEN PORTS",
                &self.open_ports.to_string(),
                ACCENT,
                progress,
            );
            stat_card(
                &mut columns[4],
                "ELAPSED",
                &format_elapsed(self.elapsed()),
                WARNING,
                progress,
            );
        });
    }

    fn progress_card(&self, ui: &mut Ui) {
        let fraction = self.scan_fraction();
        let (title, subtitle) = match self.state {
            ScanState::Idle => (
                "Ready to scan".to_string(),
                "Configure your targets and ports, then press Start scan.".to_string(),
            ),
            ScanState::Scanning if self.stopping => (
                "Stopping scan".to_string(),
                "Waiting for active connections to finish...".to_string(),
            ),
            ScanState::Scanning => (
                "Scanning network".to_string(),
                format!(
                    "{} of {} hosts scanned · {} ports per host",
                    self.scanned, self.total, self.port_count
                ),
            ),
            ScanState::Done => (
                "Scan complete".to_string(),
                format!(
                    "{} hosts scanned · {} live · {} open ports",
                    self.total, self.live_hosts, self.open_ports
                ),
            ),
            ScanState::Cancelled => (
                "Scan stopped".to_string(),
                format!(
                    "Partial results kept · {} of {} hosts scanned",
                    self.scanned, self.total
                ),
            ),
        };

        egui::Frame::NONE
            .fill(SURFACE)
            .corner_radius(CornerRadius::same(14))
            .stroke(Stroke::new(1.0_f32, BORDER))
            .inner_margin(Margin::symmetric(18, 14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(title).size(15.0).strong().color(TEXT));
                        ui.add_space(1.0);
                        ui.label(RichText::new(subtitle).size(11.0).color(MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{:.0}%", fraction * 100.0))
                                .size(22.0)
                                .strong()
                                .color(if self.is_scanning() { ACCENT } else { TEXT }),
                        );
                    });
                });
                ui.add_space(8.0);
                progress_bar(ui, fraction, self.is_scanning());
            });
    }

    fn filter_row(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.add_sized(
                [270.0, 32.0],
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter IP, host, port, service..."),
            );
            ui.add_space(4.0);
            ui.checkbox(&mut self.show_pingable, "Show ping-only hosts")
                .on_hover_text(
                    "Include hosts with no open ports, but only if they respond to ICMP ping",
                );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(ghost_button("Export CSV")).clicked() {
                    self.status = self.export_csv();
                }
                ui.add_space(6.0);
                if ui.add(ghost_button("Export JSON")).clicked() {
                    self.status = self.export_json();
                }
            });
        });
    }

    fn results_card(&mut self, ui: &mut Ui) {
        let needle = self.filter.trim().to_lowercase();
        let mut filtered: Vec<&HostResult> = self
            .results
            .values()
            .filter(|host| host_visible(host, self.show_pingable))
            .filter(|host| host_matches(host, &needle))
            .collect();

        // BTreeMap already yields IP order; sorting keeps it explicit and stable.
        filtered.sort_by_key(|host| host.ip);

        let open_shown: usize = filtered.iter().map(|host| host.open_ports.len()).sum();
        let mut rows: Vec<ResultRow<'_>> = Vec::with_capacity(
            filtered
                .iter()
                .map(|host| host.open_ports.len().max(1))
                .sum(),
        );
        for host in &filtered {
            if host.open_ports.is_empty() {
                rows.push(ResultRow {
                    host,
                    port: None,
                    first: true,
                });
            } else {
                for (index, port) in host.open_ports.iter().enumerate() {
                    rows.push(ResultRow {
                        host,
                        port: Some(port),
                        first: index == 0,
                    });
                }
            }
        }

        let available = ui.available_height();
        egui::Frame::NONE
            .fill(SURFACE)
            .corner_radius(CornerRadius::same(14))
            .stroke(Stroke::new(1.0_f32, BORDER))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                // Leave room for the frame's inner margin so the card fills the
                // remaining space without overflowing the central panel.
                ui.set_min_height((available - 30.0).max(150.0));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("RESULTS").size(10.0).strong().color(MUTED));
                    ui.label(
                        RichText::new(format!(
                            "{} host(s) · {} open port(s)",
                            filtered.len(),
                            open_shown
                        ))
                        .size(10.5)
                        .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.is_scanning() {
                            ui.add(egui::Spinner::new().size(11.0).color(ACCENT));
                            ui.label(RichText::new("streaming live").size(10.5).color(ACCENT));
                        }
                    });
                });
                ui.add_space(6.0);

                if rows.is_empty() {
                    empty_state(ui, self.is_scanning(), !needle.is_empty());
                    return;
                }

                // Reserve space for the 26 px header and the horizontal
                // scrollbar that appears when the table is wider than the card.
                let table_height = (ui.available_height() - 34.0).max(120.0);
                results_table(ui, &rows, table_height);
            });
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
}

impl eframe::App for IpScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        let start_shortcut =
            ctx.input(|input| input.modifiers.command && input.key_pressed(egui::Key::Enter));
        let stop_shortcut = ctx.input(|input| input.key_pressed(egui::Key::Escape));

        self.header(ctx);
        self.footer(ctx);
        let action = self.sidebar(ctx);
        self.central(ctx);

        if action.stop || (stop_shortcut && self.is_scanning()) {
            self.request_stop();
        }
        if (action.start || start_shortcut) && !self.is_scanning() {
            self.start_scan();
        }

        if self.is_scanning() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [
            BG.r() as f32 / 255.0,
            BG.g() as f32 / 255.0,
            BG.b() as f32 / 255.0,
            1.0,
        ]
    }
}

// ---------------------------------------------------------------------------
// Styling helpers
// ---------------------------------------------------------------------------

/// Box-filter the 1024 px source down to a small header texture. Without this
/// (or mipmaps) minifying a large icon to 38 px looks noisy and aliased.
fn header_icon_pixels(icon: &egui::IconData) -> (Vec<u8>, usize) {
    const SIZE: usize = 64;
    let width = icon.width as usize;
    let height = icon.height as usize;
    let scale = (width / SIZE).max(1);
    let mut out = vec![0u8; SIZE * SIZE * 4];

    for y in 0..SIZE {
        for x in 0..SIZE {
            let mut r = 0u32;
            let mut g = 0u32;
            let mut b = 0u32;
            let mut a = 0u32;
            for dy in 0..scale {
                for dx in 0..scale {
                    let sx = x * scale + dx;
                    let sy = y * scale + dy;
                    if sx >= width || sy >= height {
                        continue;
                    }
                    let i = (sy * width + sx) * 4;
                    let alpha = icon.rgba[i + 3] as u32;
                    r += icon.rgba[i] as u32 * alpha;
                    g += icon.rgba[i + 1] as u32 * alpha;
                    b += icon.rgba[i + 2] as u32 * alpha;
                    a += alpha;
                }
            }
            if a == 0 {
                continue;
            }
            let o = (y * SIZE + x) * 4;
            out[o] = (r / a) as u8;
            out[o + 1] = (g / a) as u8;
            out[o + 2] = (b / a) as u8;
            out[o + 3] = (a / (scale * scale) as u32).min(255) as u8;
        }
    }
    (out, SIZE)
}

fn configure_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = INPUT;
    visuals.faint_bg_color = Color32::from_rgb(10, 18, 31);
    visuals.override_text_color = Some(TEXT);
    visuals.hyperlink_color = ACCENT;
    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(34, 211, 238, 70);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);
    visuals.widgets.inactive.bg_fill = SURFACE_ALT;
    visuals.widgets.inactive.weak_bg_fill = SURFACE_ALT;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(26, 41, 66);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(26, 41, 66);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(51, 78, 112));
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    visuals.widgets.active.bg_fill = ACCENT_DARK;
    visuals.widgets.active.weak_bg_fill = ACCENT_DARK;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, ACCENT);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(8);

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 28.0;
    style.spacing.scroll.bar_width = 8.0;
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(24.0)),
        (TextStyle::Body, FontId::proportional(13.5)),
        (TextStyle::Monospace, FontId::monospace(12.5)),
        (TextStyle::Button, FontId::proportional(13.0)),
        (TextStyle::Small, FontId::proportional(10.5)),
    ]
    .into();
    style.animation_time = 0.14;
    ctx.set_style(style);
}

fn status_pill(ui: &mut Ui, state: ScanState, stopping: bool) {
    let (label, color) = match (state, stopping) {
        (ScanState::Scanning, true) => ("STOPPING", WARNING),
        (ScanState::Scanning, false) => ("SCANNING", ACCENT),
        (ScanState::Done, _) => ("COMPLETED", SUCCESS),
        (ScanState::Cancelled, _) => ("CANCELLED", WARNING),
        (ScanState::Idle, _) => ("READY", MUTED),
    };

    egui::Frame::NONE
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            24,
        ))
        .corner_radius(CornerRadius::same(20))
        .inner_margin(Margin::symmetric(11, 5))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 3.5, color);
                ui.label(RichText::new(label).size(10.5).strong().color(color));
            });
        });
}

fn section_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(10.0).strong().color(MUTED));
}

fn field_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(10.0).strong().color(MUTED));
}

/// Tappable stat card, identical in spirit to the mobile PERFORMANCE cards.
/// Clicking one selects which value the shared slider edits.
fn mini_stat(ui: &mut Ui, label: &str, value: &str, color: Color32, selected: bool) -> bool {
    egui::Frame::NONE
        .fill(if selected { ACCENT_SOFT } else { SURFACE_ALT })
        .corner_radius(CornerRadius::same(10))
        .stroke(Stroke::new(
            1.0_f32,
            if selected { ACCENT_DARK } else { BORDER },
        ))
        .inner_margin(Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut clicked = ui
                .add(
                    egui::Button::new(RichText::new(label).size(10.5).color(if selected {
                        ACCENT
                    } else {
                        MUTED
                    }))
                    .frame(false),
                )
                .clicked();
            clicked |= ui
                .add(
                    egui::Button::new(
                        RichText::new(value)
                            .size(14.0)
                            .strong()
                            .monospace()
                            .color(color),
                    )
                    .frame(false),
                )
                .clicked();
            clicked
        })
        .inner
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

fn stat_card(ui: &mut Ui, label: &str, value: &str, color: Color32, active: f32) {
    egui::Frame::NONE
        .fill(SURFACE)
        .corner_radius(CornerRadius::same(13))
        .stroke(Stroke::new(1.0_f32, BORDER))
        .inner_margin(Margin::symmetric(16, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(label).size(9.5).strong().color(MUTED));
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(value).size(23.0).strong().color(color));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if active > 0.0 && active < 1.0 {
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(26.0, 5.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, CornerRadius::same(3), INPUT);
                        let mut filled = rect;
                        filled.set_width(rect.width() * active);
                        ui.painter()
                            .rect_filled(filled, CornerRadius::same(3), ACCENT);
                    }
                });
            });
        });
}

fn progress_bar(ui: &mut Ui, fraction: f32, animated: bool) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 9.0), egui::Sense::hover());
    let corner = CornerRadius::same(5);
    let painter = ui.painter();
    painter.rect_filled(rect, corner, INPUT);

    let fraction = fraction.clamp(0.0, 1.0);
    if fraction > 0.0 {
        let mut filled = rect;
        filled.set_width((rect.width() * fraction).max(4.0));
        painter.rect_filled(filled, corner, ACCENT);

        if animated {
            let glow = Color32::from_rgba_unmultiplied(34, 211, 238, 40);
            let mut glow_rect = filled;
            glow_rect.set_height(filled.height() + 4.0);
            glow_rect = glow_rect.translate(egui::vec2(0.0, -2.0));
            painter.rect_filled(glow_rect, CornerRadius::same(6), glow);
        }
    }
}

fn ghost_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).size(11.5).color(TEXT))
        .fill(SURFACE_ALT)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(8))
        .min_size(egui::vec2(96.0, 30.0))
}

/// URL opened when a port cell is clicked. TLS ports use https, everything
/// else http; IPv6 literals need brackets in a URL.
fn browser_url(ip: IpAddr, port: u16) -> String {
    let scheme = if matches!(port, 443 | 7443 | 8443 | 9443) {
        "https"
    } else {
        "http"
    };
    let host = match ip {
        IpAddr::V6(_) => format!("[{ip}]"),
        IpAddr::V4(_) => ip.to_string(),
    };
    format!("{scheme}://{host}:{port}/")
}

/// eframe only handles `Context::open_url` in the web backend, so launch the
/// system browser directly for the native GUI.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let spawned = std::process::Command::new("explorer.exe").arg(url).spawn();
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(url).spawn();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let spawned = std::process::Command::new("xdg-open").arg(url).spawn();

    if let Err(error) = spawned {
        eprintln!("could not open browser for {url}: {error}");
    }
}

fn results_table(ui: &mut Ui, rows: &[ResultRow<'_>], height: f32) {
    // Keep the table at a readable minimum width. If the window (and therefore
    // the card) gets narrower, the surrounding scroll area takes over with a
    // horizontal scrollbar instead of overflowing and jamming the layout.
    let table_width = ui.available_width().max(TABLE_MIN_WIDTH);
    egui::ScrollArea::horizontal()
        .id_salt("results_table_hscroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(table_width);

            let table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::exact(22.0))
                .column(Column::initial(116.0).at_least(110.0).clip(true))
                .column(Column::initial(92.0).at_least(84.0).clip(true))
                .column(Column::initial(116.0).at_least(110.0).clip(true))
                .column(Column::initial(110.0).at_least(100.0).clip(true))
                .column(Column::initial(48.0).at_least(44.0).clip(true))
                .column(Column::initial(76.0).at_least(70.0).clip(true))
                .column(Column::initial(58.0).at_least(54.0).clip(true))
                .column(Column::remainder().at_least(100.0).clip(true))
                .min_scrolled_height(0.0)
                .max_scroll_height(height);

            table
                .header(26.0, |mut header| {
                    header.col(|_ui| {});
                    for title in [
                        "IP ADDRESS",
                        "HOSTNAME",
                        "MAC ADDRESS",
                        "MANUFACTURER",
                        "PORT",
                        "SERVICE",
                        "LATENCY",
                        "BANNER",
                    ] {
                        header.col(|ui| {
                            ui.label(RichText::new(title).size(9.5).strong().color(MUTED));
                        });
                    }
                })
                .body(|body| {
                    body.rows(29.0, rows.len(), |mut row| {
                        let result = &rows[row.index()];

                        row.col(|ui| {
                            if result.first {
                                let color = if result.host.open_ports.is_empty() {
                                    MUTED
                                } else {
                                    SUCCESS
                                };
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(14.0, 14.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(rect.center(), 3.5, color);
                            }
                        });

                        row.col(|ui| {
                            if result.first {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(result.host.ip.to_string())
                                            .size(12.5)
                                            .monospace()
                                            .color(TEXT),
                                    )
                                    .truncate(),
                                );
                            }
                        });

                        row.col(|ui| {
                            if result.first {
                                let hostname = result.host.hostname.as_deref().unwrap_or("—");
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(hostname).size(12.0).color(MUTED),
                                    )
                                    .truncate(),
                                );
                            }
                        });

                        row.col(|ui| {
                            if !result.first {
                                return;
                            }
                            match &result.host.mac {
                                Some(mac) => {
                                    ui.label(RichText::new(mac).size(11.5).monospace().color(TEXT));
                                }
                                None => {
                                    ui.label(RichText::new("—").size(12.0).color(MUTED));
                                }
                            }
                        });

                        row.col(|ui| {
                    if !result.first {
                        return;
                    }
                    match &result.host.manufacturer {
                        Some(vendor) => {
                            let tip = if vendor == arp::RANDOMIZED_VENDOR {
                                "Locally administered MAC (e.g. Android private Wi-Fi address). \
                                 Randomized per network, so it has no IEEE vendor OUI."
                            } else {
                                vendor.as_str()
                            };
                            ui.add(
                                egui::Label::new(RichText::new(vendor).size(11.5).color(MUTED))
                                    .truncate(),
                            )
                            .on_hover_text(tip);
                        }
                        None => {
                            ui.label(RichText::new("—").size(12.0).color(MUTED));
                        }
                    }
                });

                        row.col(|ui| match result.port {
                            Some(port) => {
                                let url = browser_url(result.host.ip, port.port);
                                let response = ui.link(
                                    RichText::new(port.port.to_string())
                                        .size(12.5)
                                        .monospace()
                                        .color(ACCENT),
                                );
                                if response.clicked() {
                                    open_in_browser(&url);
                                }
                                response.on_hover_text(format!("Open {url} in browser"));
                            }
                            None => {
                                ui.label(RichText::new("—").size(12.0).color(MUTED));
                            }
                        });

                        row.col(|ui| match result.port {
                            Some(port) => match ports::service_name(port.port) {
                                Some(service) => {
                                    egui::Frame::NONE
                                        .fill(ACCENT_SOFT)
                                        .corner_radius(CornerRadius::same(5))
                                        .inner_margin(Margin::symmetric(7, 2))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(service).size(10.5).color(ACCENT),
                                            );
                                        });
                                }
                                None => {
                                    ui.label(RichText::new("unknown").size(11.0).color(MUTED));
                                }
                            },
                            None => {
                                ui.label(RichText::new("—").size(12.0).color(MUTED));
                            }
                        });

                        row.col(|ui| match result.port {
                            Some(port) => {
                                ui.label(
                                    RichText::new(output::format_latency(port.latency))
                                        .size(11.5)
                                        .monospace()
                                        .color(latency_color(port.latency)),
                                );
                            }
                            None => match result.host.ping_latency {
                                Some(latency) => {
                                    ui.label(
                                        RichText::new(output::format_latency(latency))
                                            .size(11.5)
                                            .monospace()
                                            .color(latency_color(latency)),
                                    )
                                    .on_hover_text("ICMP ping reply time");
                                }
                                None => {
                                    ui.label(RichText::new("—").size(12.0).color(MUTED));
                                }
                            },
                        });

                        row.col(|ui| match result.port {
                            Some(port) => match &port.banner {
                                Some(banner) => {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(banner)
                                                .size(11.0)
                                                .monospace()
                                                .color(MUTED),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(banner);
                                }
                                None => {
                                    ui.label(RichText::new("—").size(12.0).color(MUTED));
                                }
                            },
                            None => {
                                ui.label(
                                    RichText::new("no open ports")
                                        .size(11.0)
                                        .italics()
                                        .color(MUTED),
                                );
                            }
                        });
                    });
                });
        });
}

fn empty_state(ui: &mut Ui, scanning: bool, filtered: bool) {
    let height = (ui.available_height() - 8.0).max(150.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), height),
        Layout::top_down(Align::Center),
        |ui| {
            ui.add_space((height * 0.12).min(50.0));
            radar_icon(ui, scanning);
            ui.add_space(10.0);
            let (title, subtitle) = if filtered {
                (
                    "No hosts match the filter",
                    "Try a different IP, hostname, port or service name.",
                )
            } else if scanning {
                (
                    "Scanning for open ports...",
                    "Results appear here as each host finishes.",
                )
            } else {
                (
                    "No results yet",
                    "Enter a target and press Start scan to begin.",
                )
            };
            ui.label(RichText::new(title).size(15.0).strong().color(TEXT));
            ui.add_space(2.0);
            ui.label(RichText::new(subtitle).size(11.5).color(MUTED));
        },
    );
}

fn radar_icon(ui: &mut Ui, animated: bool) {
    let size = 86.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let center = rect.center();
    let radius = size * 0.42;
    let painter = ui.painter();

    for ring in 1..=3 {
        painter.circle_stroke(
            center,
            radius * (ring as f32 / 3.0),
            Stroke::new(1.0_f32, BORDER),
        );
    }

    let angle = if animated {
        (ui.input(|input| input.time) * 1.6) as f32 % std::f32::consts::TAU
    } else {
        -0.65
    };
    let tip = center + egui::vec2(angle.cos(), angle.sin()) * radius;

    painter.line_segment([center, tip], Stroke::new(2.0_f32, ACCENT));
    painter.circle_filled(tip, 3.0, ACCENT);
    painter.circle_filled(center, 2.0, MUTED);
}

/// A host is shown when it has open ports, or when the ping option is on and
/// it answered ICMP echo. Hosts without open ports are hidden by default.
fn host_visible(host: &HostResult, show_pingable: bool) -> bool {
    !host.open_ports.is_empty() || (show_pingable && host.ping_latency.is_some())
}

fn host_matches(host: &HostResult, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let ip = host.ip.to_string().to_lowercase();
    if ip.contains(needle) {
        return true;
    }
    if let Some(hostname) = &host.hostname {
        if hostname.to_lowercase().contains(needle) {
            return true;
        }
    }
    if host
        .mac
        .as_deref()
        .is_some_and(|mac| mac.to_lowercase().contains(needle))
    {
        return true;
    }
    if host
        .manufacturer
        .as_deref()
        .is_some_and(|vendor| vendor.to_lowercase().contains(needle))
    {
        return true;
    }
    host.open_ports.iter().any(|port| {
        port.port.to_string().contains(needle)
            || ports::service_name(port.port).is_some_and(|service| service.contains(needle))
            || port
                .banner
                .as_deref()
                .is_some_and(|banner| banner.to_lowercase().contains(needle))
    })
}

fn latency_color(latency: Duration) -> Color32 {
    if latency < Duration::from_millis(10) {
        SUCCESS
    } else if latency < Duration::from_millis(100) {
        WARNING
    } else {
        DANGER
    }
}

fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        let total = seconds as u64;
        format!("{}m {:02}s", total / 60, total % 60)
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_host() -> HostResult {
        HostResult {
            ip: "192.168.1.1".parse().unwrap(),
            hostname: Some("router.lan".to_string()),
            mac: Some("00:11:22:33:44:55".to_string()),
            manufacturer: Some("Example Vendor".to_string()),
            ping_latency: None,
            open_ports: vec![PortResult {
                port: 80,
                latency: Duration::from_millis(12),
                banner: Some("HTTP/1.0 200 OK".to_string()),
            }],
        }
    }

    #[test]
    fn builds_browser_url_from_ip_and_port() {
        assert_eq!(
            browser_url("192.168.1.5".parse().unwrap(), 80),
            "http://192.168.1.5:80/"
        );
        assert_eq!(
            browser_url("192.168.1.5".parse().unwrap(), 443),
            "https://192.168.1.5:443/"
        );
        assert_eq!(
            browser_url("2001:db8::1".parse().unwrap(), 8080),
            "http://[2001:db8::1]:8080/"
        );
    }

    #[test]
    fn filters_hosts_by_ip_hostname_port_service_and_banner() {
        let host = sample_host();
        assert!(host_matches(&host, "192.168"));
        assert!(host_matches(&host, "router"));
        assert!(host_matches(&host, "80"));
        assert!(host_matches(&host, "http"));
        assert!(host_matches(&host, "200 ok"));
        assert!(host_matches(&host, "00:11:22"));
        assert!(host_matches(&host, "example vendor"));
        assert!(!host_matches(&host, "postgres"));
    }

    #[test]
    fn ping_option_only_shows_reachable_no_port_hosts() {
        let live = sample_host();
        let no_ports = |ip: &str| HostResult {
            ip: ip.parse().unwrap(),
            hostname: None,
            mac: None,
            manufacturer: None,
            ping_latency: None,
            open_ports: vec![],
        };
        let mut reachable = no_ports("127.0.0.1");
        reachable.ping_latency = Some(Duration::from_millis(2));
        let silent = no_ports("192.0.2.1");

        assert!(host_visible(&live, false));
        assert!(!host_visible(&reachable, false));
        assert!(!host_visible(&silent, true));
        assert!(host_visible(&reachable, true));
    }

    #[test]
    fn formats_elapsed_time() {
        assert_eq!(format_elapsed(Duration::from_millis(1500)), "1.5s");
        assert_eq!(format_elapsed(Duration::from_secs(65)), "1m 05s");
    }
}
