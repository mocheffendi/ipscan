#!/usr/bin/env bash
# Build the standalone Android crate into mobile/build/out/ipscan.apk.
#
# This is a separate Cargo package (mobile/Cargo.toml) from the 0.5.1 desktop
# app, so nothing here touches the Windows/macOS/Linux source tree.
#
# Steps:
#   1. cargo build --release --target aarch64-linux-android (produces libipscan.so)
#   2. package it with aapt (+ AndroidManifest.xml, resources)
#   3. zipalign the APK
#   4. sign with apksigner (requires java; a debug keystore is generated on
#      first run and kept outside build/ so updates keep the same signature)
#
# Prerequisites: Rust toolchain, Android SDK + NDK. The script finds them at
# $ANDROID_HOME (default $HOME/Android/Sdk) or $ANDROID_NDK_HOME.
# Output: mobile/build/out/ipscan.apk
#
# Install on a device or emulator:
#   adb install -r mobile/build/out/ipscan.apk

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"

if [ ! -d "$SDK" ]; then
    echo "error: Android SDK not found at $SDK (set ANDROID_HOME)" >&2
    exit 1
fi

NDK="${ANDROID_NDK_HOME:-$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)}"
if [ -z "${NDK:-}" ] || [ ! -d "$NDK" ]; then
    echo "error: no NDK found in $SDK/ndk (set ANDROID_NDK_HOME)" >&2
    exit 1
fi

TOOLS="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
API_JAR="$(ls -d "$SDK"/platforms/* | sort -V | tail -1)/android.jar"

PREBUILT_DIR="$(ls "$NDK/toolchains/llvm/prebuilt")"
LINKER="$NDK/toolchains/llvm/prebuilt/$PREBUILT_DIR/bin/aarch64-linux-android24-clang++"
if [ ! -x "$LINKER" ]; then
    echo "error: NDK linker not found: $LINKER" >&2
    exit 1
fi

cd "$ROOT"

echo "==> cargo build --release --target aarch64-linux-android"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$LINKER"
cargo build --release --target aarch64-linux-android

STAGE="$ROOT/build"
OUT="$STAGE/out"
rm -rf "$STAGE"
mkdir -p "$STAGE/lib/arm64-v8a" "$OUT"
cp target/aarch64-linux-android/release/libipscan.so "$STAGE/lib/arm64-v8a/libipscan.so"

echo "==> aapt package (manifest, resources, lib/arm64-v8a/libipscan.so)"
cd "$STAGE"
"$TOOLS/aapt" package -f -M ../AndroidManifest.xml -S ../res -I "$API_JAR" -F out/ipscan.apk
"$TOOLS/aapt" add -v out/ipscan.apk lib/arm64-v8a/libipscan.so

echo "==> zipalign -p 4"
"$TOOLS/zipalign" -v -p 4 out/ipscan.apk out/ipscan-aligned.apk
mv -f out/ipscan-aligned.apk out/ipscan.apk

echo "==> apksigner sign + verify"
if ! command -v java >/dev/null 2>&1; then
    echo "error: java not in PATH — install a JDK (e.g. Adoptium Temurin) to run apksigner" >&2
    exit 1
fi
KEYSTORE="$ROOT/ipscan-debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    echo "    generating debug keystore: $KEYSTORE"
    keytool -genkeypair -noprompt -keystore "$KEYSTORE" -alias ipscan -keyalg RSA -keysize 2048 \
        -validity 10000 -storepass "android-debug" -keypass "android-debug" \
        -dname "CN=ipscan,O=ipscan"
fi
"$TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-pass "pass:android-debug" --ks-key-alias ipscan out/ipscan.apk
"$TOOLS/apksigner" verify out/ipscan.apk

echo "==> apksigner verify --verbose (signatures)"
"$TOOLS/apksigner" verify --verbose out/ipscan.apk | head -20

echo "==> Done: $OUT/ipscan.apk"
echo "    Install: adb install -r $OUT/ipscan.apk"
