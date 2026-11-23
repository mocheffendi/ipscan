//! Small UI helpers shared inside the mobile crate.
//!
//! These used to live in the desktop GUI module. The mobile app is standalone,
//! so it owns its copies — the desktop source stays exactly as it was.

use std::time::Duration;

use eframe::egui;
use egui::{CornerRadius, Ui};

use crate::mobile::{ACCENT, INPUT};
use crate::{ports, scanner::HostResult};

pub(crate) fn progress_bar(ui: &mut Ui, fraction: f32, animated: bool) {
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
            let glow = egui::Color32::from_rgba_unmultiplied(0, 229, 255, 40);
            let mut glow_rect = filled;
            glow_rect.set_height(filled.height() + 4.0);
            glow_rect = glow_rect.translate(egui::vec2(0.0, -2.0));
            painter.rect_filled(glow_rect, CornerRadius::same(6), glow);
        }
    }
}

/// A host is shown when it has open ports, or when the ping option is on and
/// it answered ICMP echo. Hosts without open ports are hidden by default.
pub(crate) fn host_visible(host: &HostResult, show_pingable: bool) -> bool {
    !host.open_ports.is_empty() || (show_pingable && host.ping_latency.is_some())
}

pub(crate) fn host_matches(host: &HostResult, needle: &str) -> bool {
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

pub(crate) fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        let total = seconds as u64;
        format!("{}m {:02}s", total / 60, total % 60)
    }
}
