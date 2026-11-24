# Installer

Skrip untuk membuat paket installer Windows dan Linux dari binary release yang sama:

| File | Tool | Keterangan |
| --- | --- | --- |
| `ipscan-<versi>-setup.exe` | Inno Setup 6 | Wizard modern, shortcut Start Menu, opsi desktop icon, uninstaller |
| `ipscan-<versi>.msi` | WiX Toolset v6 | Paket MSI standar (bisa di-deploy lewat GPO), shortcut Start Menu + Desktop |
| `ipscan_<versi>_<arsitektur>.deb` | `dpkg-deb` | Paket Debian/Ubuntu: binary, desktop entry, ikon, metainfo, dan LICENSE |

Keduanya meng-copy `target/release/ipscan.exe` dan `LICENSE` ke `Program Files\ipscan`,
membuat shortcut, serta mendaftarkan uninstaller. Versi diambil otomatis dari `Cargo.toml`.

## Prasyarat

```powershell
winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements

dotnet tool install --global wix --version 6.0.2
wix extension add -g WixToolset.UI.wixext/6.0.2
wix extension add -g WixToolset.Util.wixext/6.0.2
```

## Build semua

Dari root repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\build.ps1
```

Hasil ada di `installer/out/`.

## Build manual

```powershell
# Pastikan cargo build --release sudah dijalankan.
$version = '0.5.1'  # samakan dengan Cargo.toml

& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" installer\ipscan.iss /dAppVersion=$version

wix build installer\ipscan.wxs -d Version=$version `
    -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext `
    -pdbtype none -o installer\out\ipscan-$version.msi
```

GUID di `ipscan.iss` (`AppId`) dan `ipscan.wxs` (`UpgradeCode`, GUID komponen)
**jangan diubah** antar-rilis, agar upgrade dan uninstall tetap dikenali Windows.

## Paket Debian (.deb)

`build-deb.sh` membuat paket `.deb` untuk Debian/Ubuntu dari `target/release/ipscan`.
Versi dibaca otomatis dari `Cargo.toml`, arsitektur dari `dpkg --print-architecture`,
dan aset statis (desktop entry, ikon, metainfo) diambil dari `root/`. Script ini
memakai staging directory sementara, jadi tidak mengubah tree `root/`.

Prasyarat:

```bash
sudo apt install dpkg    # menyediakan dpkg-deb
# Toolchain GUI seperti pada build manual: build-essential pkg-config \
#   libx11-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev
```

Build dari root repo:

```bash
bash installer/build-deb.sh
# hasil: installer/out/ipscan_<versi>_<arsitektur>.deb
```

Pasang paketnya:

```bash
sudo apt install ./installer/out/ipscan_0.5.1_amd64.deb
# alternatif: sudo dpkg -i <file.deb> && sudo apt -f install
```

Paket berisi `/usr/bin/ipscan`, desktop entry, ikon hicolor 128x128, berkas
AppStream di `/usr/share/metainfo/`, dan `LICENSE` sebagai
`/usr/share/doc/ipscan/copyright`.
