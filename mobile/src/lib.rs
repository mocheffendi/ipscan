//! ipscan mobile — a standalone, portrait-first Android port.
//!
//! This crate is intentionally independent of the desktop `ipscan` crate:
//! the desktop app stays at 0.5.1 for Windows/macOS/Linux, while this crate
//! carries the touch UI, the Android manifest and the APK build script.
//!
//! The scan engine, target/port parsers and ARP/DNS helpers are compiled into
//! this crate as modules, so both apps share the same logic without sharing
//! a single source tree. On Android, `android_main` is the APK entry point.

pub mod arp;
mod helpers;
mod local_ip;
pub mod mobile;
pub mod output;
pub mod ping;
pub mod ports;
pub mod scanner;
pub mod target;

/// Android entry point. NativeActivity calls this after loading `libipscan.so`;
/// it must only return when the user leaves the app.
#[cfg(target_os = "android")]
#[no_mangle]
pub fn android_main(app: winit::platform::android::activity::AndroidApp) {
    let _ = mobile::run_android(app);
}
