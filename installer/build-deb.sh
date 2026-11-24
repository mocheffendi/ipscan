#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb package from the release binary.
#
# This follows the same idea as build.ps1 for Windows: the package version is
# read from the root Cargo.toml, so there is a single source of truth. The
# static assets (desktop entry, icon) come from the root/ staging tree, while
# DEBIAN/control is generated here with the current version and host arch.
#
# Prerequisites: Rust toolchain and dpkg-deb (from the dpkg package).
# Output: installer/out/ipscan_<version>_<arch>.deb
#
# From the repository root:
#   bash installer/build-deb.sh
# Install with:
#   sudo apt install ./installer/out/ipscan_<version>_<arch>.deb

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
OUT="$ROOT/installer/out"

VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/Cargo.toml" | head -1)"
if [ -z "$VERSION" ]; then
    echo "error: cannot read package version from $ROOT/Cargo.toml" >&2
    exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "error: dpkg-deb not found — install the dpkg package" >&2
    exit 1
fi

if command -v dpkg >/dev/null 2>&1; then
    ARCH="$(dpkg --print-architecture)"
else
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7*) ARCH="armhf" ;;
        *)
            echo "error: unsupported architecture $(uname -m)" >&2
            exit 1
            ;;
    esac
fi

echo "==> cargo build --release ($VERSION, $ARCH)"
cargo build --release --manifest-path "$ROOT/Cargo.toml"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/icons/hicolor/128x128/apps" \
         "$STAGE/usr/share/doc/ipscan" \
         "$STAGE/usr/share/metainfo"

cp "$ROOT/target/release/ipscan" "$STAGE/usr/bin/ipscan"
cp "$ROOT/root/usr/share/applications/ipscan.desktop" \
   "$STAGE/usr/share/applications/ipscan.desktop"
cp "$ROOT/root/usr/share/icons/hicolor/128x128/apps/ipscan.png" \
   "$STAGE/usr/share/icons/hicolor/128x128/apps/ipscan.png"
cp "$ROOT/org.ipscan.ipscan.metainfo.xml" \
   "$STAGE/usr/share/metainfo/org.ipscan.ipscan.metainfo.xml"
cp "$ROOT/LICENSE" "$STAGE/usr/share/doc/ipscan/copyright"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: ipscan
Version: $VERSION
Architecture: $ARCH
Maintainer: ipscan <ipscan@localhost>
Section: utils
Priority: optional
Depends: libc6, libgcc-s1, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, libegl1, libgl1, libxrender1
Description: Fast, cross-platform TCP IP range and port scanner
 Fast, cross-platform TCP IP range and port scanner — GUI desktop modern
 (egui) dan mode CLI (clap). Scanner TCP port dengan TCP connect, tanpa root.
EOF

find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE/usr/share" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/usr/bin/ipscan"
chmod 0644 "$STAGE/DEBIAN/control"

mkdir -p "$OUT"
DEB="$OUT/ipscan_${VERSION}_${ARCH}.deb"
echo "==> dpkg-deb --build -> $DEB"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB"

echo "==> dpkg-deb --info"
dpkg-deb --info "$DEB"

echo "==> Done: $DEB"
echo "    Install: sudo apt install $DEB"
