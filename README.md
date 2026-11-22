<p align="center">
  <img src="assets/icon.png" alt="ipscan logo" width="180">
</p>

# ipscan

Scanner IP dan port TCP modern untuk Windows, Linux, dan macOS — ditulis dengan Rust,
[Tokio](https://tokio.rs), dan [egui](https://www.egui.rs). Tersedia sebagai **aplikasi
desktop native** dan **CLI**. Tidak memerlukan hak administrator karena memakai
*TCP connect scan* (bukan raw socket/SYN scan).

## Fitur

- **GUI desktop modern**: tema gelap, progres live, kartu statistik, tabel hasil, filter
- **CLI lengkap** untuk otomasi dan pemakaian dari terminal
- **Target fleksibel**: IP tunggal, CIDR, range, wildcard, dan hostname
- **Port fleksibel**: daftar, range, grup (`top100`, `all`, `web`, ...), atau nama service (`ssh`, `https`)
- **Paralel & cepat**: ratusan koneksi bersamaan, timeout dan concurrency bisa diatur
- **Reverse DNS** otomatis untuk host yang hidup
- **MAC & manufacturer** dari ARP cache tetangga lokal + database OUI (~40 ribu vendor)
- **Banner grabbing** opsional untuk mengenali service
- **Klik port di tabel hasil** untuk langsung membuka `http://<ip>:<port>/` di browser
  default (`https://` untuk port TLS umum seperti 443/8443)
- **Ekspor JSON dan CSV**, baik dari GUI maupun CLI
- **Installer Windows**: paket `setup.exe` (Inno Setup) dan `.msi` (WiX Toolset)
- Satu binary portabel, tanpa runtime tambahan (tidak butuh Node.js atau browser)

## Build

Prasyarat: Rust 1.81+ dan toolchain C/C++ standar untuk GUI (`MSVC Build Tools` di
Windows, `Xcode Command Line Tools` di macOS, dan paket X11/Wayland/OpenGL di Linux).

```bash
cargo build --release
# hasil: target/release/ipscan (Linux/macOS) atau target\release\ipscan.exe (Windows)
```

Linux (Debian/Ubuntu) biasanya membutuhkan:

```bash
sudo apt install build-essential pkg-config libx11-dev libxkbcommon-dev \
  libwayland-dev libgl1-mesa-dev
```

Atau pasang ke `PATH`:

```bash
cargo install --path .
```

## Installer Windows

Selain binary portabel, tersedia dua skrip di [`installer/`](installer/) untuk menghasilkan
paket installer dari binary release yang sama:

- `ipscan-<versi>-setup.exe` — wizard modern dari **Inno Setup 6**, dengan shortcut Start
  Menu, opsi shortcut Desktop, dan uninstaller.
- `ipscan-<versi>.msi` — paket **WiX Toolset v6** untuk deployment standar/GPO.

Keduanya meng-copy `ipscan.exe` dan `LICENSE` ke `Program Files\ipscan` dan mendaftarkan
uninstaller. Versi diambil otomatis dari `Cargo.toml`.

```powershell
# Prasyarat (sekali):
winget install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
dotnet tool install --global wix --version 6.0.2
wix extension add -g WixToolset.UI.wixext/6.0.2
wix extension add -g WixToolset.Util.wixext/6.0.2

# Build keduanya (hasil di installer/out/):
powershell -ExecutionPolicy Bypass -File .\installer\build.ps1
```

Detail dan perintah build manual ada di [`installer/README.md`](installer/README.md).

## Mode GUI

Jalankan tanpa argumen, atau dengan `--gui`:

```bash
ipscan
ipscan --gui
```

Di Windows, `ipscan.exe` juga bisa langsung di-double-click. Jendela GUI menyediakan:

- Input target dan port dengan validasi langsung
- Pengaturan timeout, concurrency, reverse DNS, MAC/vendor, dan banner grabbing
- Progress bar dan statistik live (host dipindai, host hidup, **ping-only hosts**, port
  terbuka, waktu)
- Tabel hasil dengan kolom **MAC ADDRESS** dan **MANUFACTURER**, bisa di-resize/difilter
  dan tetap responsive dengan scrollbar horizontal saat jendela diperkecil. MAC/vendor
  muncul live begitu host terdeteksi tanpa menunggu scan 100%. Nomor **PORT** adalah link:
  klik untuk membuka alamat tersebut di browser default. Reply time ICMP selalu dikumpulkan
  saat scan, jadi opsi **Show ping-only hosts** bisa dicentang kapan saja (termasuk setelah
  hasil muncul). Kolom **LATENCY** menampilkan reply time ping untuk host tanpa port terbuka
- Tombol **Export JSON/CSV** (disimpan di direktori kerja dengan nama
  `ipscan-report-<timestamp>.json/csv`)
- `Ctrl+Enter` untuk mulai scan, `Esc` untuk berhenti (hasil parsial tetap disimpan)

## Mode CLI

```text
ipscan [OPTIONS] <TARGET>...
```

Contoh:

```bash
# Scan host di satu subnet dengan 100 port terpopuler
ipscan 192.168.1.0/24

# Range singkat + beberapa port
ipscan 192.168.1.1-254 -p 22,80,443

# Range penuh, timeout lebih agresif
ipscan 10.0.0.1-10.0.0.50 --ports 1-1024 --timeout 500

# Wildcard dan grup port
ipscan 192.168.1.* --ports web

# Hostname + banner grabbing
ipscan example.com -p top100 --banners

# Ekspor hasil
ipscan 192.168.1.0/24 --json hasil.json --csv hasil.csv

# Host tanpa port terbuka hanya ditampilkan jika merespons ping
ipscan 192.168.1.0/24 --ping

# Diam (tanpa progress bar), tampilkan juga host tanpa port terbuka
ipscan 192.168.1.0/24 -q --all
```

### Format target

| Format | Contoh |
| --- | --- |
| IP tunggal | `192.168.1.10`, `2001:db8::1` |
| CIDR | `192.168.1.0/24`, `2001:db8::/126` |
| Range singkat | `192.168.1.10-50` |
| Range penuh | `192.168.1.10-192.168.1.50` |
| Wildcard oktet terakhir | `192.168.1.*` (1-254) |
| Hostname | `example.com`, `localhost` |

Beberapa target dapat digabung dengan koma: `192.168.1.0/24,10.0.0.5,example.com`.
CIDR dipindai secara penuh, termasuk alamat network dan broadcast.

### Format port

| Format | Contoh |
| --- | --- |
| Daftar | `22,80,443` |
| Range | `1-1024` |
| Grup | `top100`, `all`, `web`, `db`, `mail`, `remote`, `windows` |
| Nama service | `ssh`, `https`, `mysql`, `rdp` |

Default: `top100`.

## Opsi

| Opsi | Keterangan | Default |
| --- | --- | --- |
| `-p, --ports <PORTS>` | Port yang dipindai | `top100` |
| `-t, --timeout <MS>` | Timeout per koneksi (milidetik) | `1000` |
| `-c, --concurrency <N>` | Jumlah koneksi bersamaan | `512` |
| `-a, --all` | Tampilkan juga host tanpa port terbuka | mati |
| `--ping` | Host tanpa port terbuka hanya ditampilkan jika merespons ping (latency = reply time) | mati |
| `--banners` | Coba baca banner service | mati |
| `--no-resolve` | Lewati reverse DNS | mati |
| `--no-mac` | Lewati resolusi MAC/vendor (ARP) | mati |
| `--json <FILE>` | Simpan hasil JSON (`-` = stdout) | - |
| `--csv <FILE>` | Simpan hasil CSV (`-` = stdout) | - |
| `--no-color` | Matikan warna ANSI | mati |
| `-q, --quiet` | Sembunyikan progress bar | mati |

## Contoh output

```text
IP ADDRESS    HOSTNAME     MAC ADDRESS        MANUFACTURER       PORT  SERVICE        LATENCY  BANNER
192.168.1.1   router.lan   00:11:22:33:44:55  Cisco Systems      80    http             1.2ms  HTTP/1.0 200 OK
                                                                443   https            0.8ms  -
192.168.1.20  nas.local    aa:bb:cc:dd:ee:ff  Synology           445   microsoft-ds     2.1ms  -
                                                                5000  http-alt        12.4ms  HTTP/1.0 200 OK

Scanned 254 host(s) x 100 port(s) in 9.31s
2 host(s) up, 4 open port(s) found
```

Contoh JSON:

```json
{
  "tool": "ipscan",
  "version": "0.3.0",
  "scanned_at_unix": 1780000000,
  "duration_ms": 9310,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.lan",
      "mac": "00:11:22:33:44:55",
      "manufacturer": "Cisco Systems",
      "up": true,
      "open_ports": [
        {
          "port": 80,
          "service": "http",
          "latency_ms": 1.2,
          "banner": "HTTP/1.0 200 OK"
        }
      ]
    }
  ]
}
```

## Keterbatasan

- Pemindaian port hanya memakai **TCP connect** (bukan SYN scan atau UDP scan).
- Host dianggap **up** jika minimal satu port yang dipindai terbuka. Opsi `--ping`
  (GUI: **Show ping-only hosts**) menambahkan host tanpa port terbuka yang merespons
  ICMP echo. Di GUI, reply time ping selalu diukur untuk setiap host tanpa port terbuka
  saat scan berjalan, terlepas dari status checkbox; checkbox hanya mengubah filter
  tampilan. Pengecekan memakai utilitas `ping` bawaan sistem dan satu proses per alamat
  dengan konkurensi maksimal 32, jadi paling cocok untuk subnet kecil. Reply time diambil
  dari baris `time=` output `ping` dan ditampilkan di kolom **LATENCY**.
- Host yang memblokir ICMP tetapi punya port terbuka tetap ditampilkan lewat hasil TCP.
- MAC/vendor hanya tersedia untuk **IPv4 di subnet lokal** yang sudah masuk ARP cache
  (biasanya terisi otomatis oleh koneksi TCP/ICMP scanner). Alamat remote dan IPv6 tidak
  punya entri ARP. Seluruh tabel ARP dibaca sekali saja memakai `arp`/`ip` bawaan sistem;
  bisa dimatikan dengan `--no-mac` (GUI: **Resolve MAC / vendor (ARP)**).
- CIDR dibatasi maksimal **1.048.576 alamat** per pemanggilan untuk mencegah kesalahan
  input menghabiskan memori.
- Banner tidak selalu tersedia; banyak service baru mengirim banner setelah menerima
  data. Untuk port non-TLS yang tidak menyapa lebih dulu, `--banners` mengirim probe
  `HTTP HEAD` ringan. Port TLS tidak dikirimi data plaintext.
- Pindai hanya jaringan yang Anda miliki atau punya izin untuk diuji.

## Riwayat versi

### 0.3.0

- Menambahkan skrip installer Windows: `setup.exe` (Inno Setup 6) dan `.msi` (WiX Toolset v6)
  lewat `installer/build.ps1`; keduanya memasang shortcut dan uninstaller
- Versi rilis kini satu sumber di `Cargo.toml` dan otomatis dipakai installer serta metadata

### 0.2.0

- Klik nomor **PORT** di tabel hasil untuk membuka `http://<ip>:<port>/` di browser default
  (`https://` untuk port TLS umum seperti 443/7443/8443/9443; IPv6 memakai tanda kurung)
- Tabel hasil tetap responsive saat jendela diperkecil, dengan scrollbar horizontal
- MAC address dan manufacturer ditampilkan live saat host muncul, tidak menunggu scan 100%
- MAC locally administered (misalnya alamat Wi-Fi privat Android) diberi label
  `Randomized / private` dan bukan `Unknown`
- Icon window, header, dan file `.exe` memakai `assets/icon.png`
- `.exe` Windows tidak lagi memunculkan jendela command prompt saat dijalankan dari Explorer;
  mode CLI dari terminal tetap menampilkan output seperti biasa

### 0.1.0

- Rilis awal: GUI dan CLI, TCP connect scan, target dan port fleksibel, reverse DNS,
  MAC/OUI, banner grabbing, serta ekspor JSON/CSV

## Lisensi

MIT — lihat [LICENSE](LICENSE).
