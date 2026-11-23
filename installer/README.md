# Installer Windows

Skrip untuk membuat dua paket installer dari binary release yang sama:

| File | Tool | Keterangan |
| --- | --- | --- |
| `ipscan-<versi>-setup.exe` | Inno Setup 6 | Wizard modern, shortcut Start Menu, opsi desktop icon, uninstaller |
| `ipscan-<versi>.msi` | WiX Toolset v6 | Paket MSI standar (bisa di-deploy lewat GPO), shortcut Start Menu + Desktop |

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
