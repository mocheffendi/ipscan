# ipscan mobile (Android)

Standalone, portrait-first Android build of ipscan. This is its own Cargo
package (`mobile/Cargo.toml`) with its own UI, manifest, resources and build
script. The desktop app in the repository root stays at **0.5.1** for
Windows/macOS/Linux and is not modified by this crate.

## Layout

```
mobile/
├── Cargo.toml            # package: ipscan-mobile 0.5.1; lib: ipscan (cdylib)
├── AndroidManifest.xml   # NativeActivity, INTERNET permission
├── res/                  # launcher icons
├── android-build.sh      # cargo -> aapt -> zipalign -> apksigner
├── stitch.html           # portrait UI design reference
└── src/
    ├── lib.rs            # module root + android_main()
    ├── mobile.rs         # portrait UI: cards, stats, config, live results
    ├── helpers.rs        # mobile copies of a few egui helpers
    ├── local_ip.rs       # Wi-Fi address detection + /24 quick fill
    ├── scanner.rs        # scan engine (compiled into this crate)
    ├── target.rs         # target parsing
    ├── ports.rs          # port parsing / service names
    ├── arp.rs            # ARP + vendor lookup
    ├── output.rs         # JSON / CSV reports
    └── ping.rs           # ICMP reachability
```

The portrait UI follows `mobile/stitch.html`: sticky header with radar mark,
version badge and status pill; segmented **Scan Setup / Results** tabs; a
2×2 metric grid and progress card; a bottom action dock with a large
Start/Stop button and reset. The Setup tab auto-fills the detected Wi-Fi `/24`
network, has quick-fill chips (including *Wi-Fi /24* to re-detect), tappable
Timeout/Concurrency stats that select which value the shared slider edits
(concurrency up to 2048), probe toggles and a target cheatsheet; the Results tab
has a filter bar, JSON/CSV export and tappable host cards with port chips.

The page scrolls with a finger drag (egui `ScrollArea` with
`drag_to_scroll`), so config and results stay reachable on small screens and
while the on-screen keyboard is open. Touch targets are sized for a phone
(46 pt scan button, ~2.7 px/pt on a 1080x2400 display).

Android safe area is read from `AndroidApp::content_rect()` every frame and
applied to the header, central panel and bottom dock, keeping content clear of
the status bar, gesture navigation bar and display cutouts. A trailing spacer
in the scroll view keeps the last control (target cheatsheet) above the dock.

## Build

Requires the Rust toolchain, Android SDK + NDK, and a JDK for `apksigner`.

```bash
export JAVA_HOME=/path/to/jdk
export PATH="$JAVA_HOME/bin:$PATH"
./mobile/android-build.sh
```

Output: `mobile/build/out/ipscan.apk`. The debug keystore is kept at
`mobile/ipscan-debug.keystore` (ignored by git) so rebuilding and updating the
app does not change its signature.

## Install

```bash
adb install -r mobile/build/out/ipscan.apk
```

On Xiaomi devices you may need to approve "Install via USB" in the developer
options, or use `adb install -r --user 0 ...`.

Launch with:

```bash
adb shell am start -n org.ipscan.ipscan/android.app.NativeActivity
```
