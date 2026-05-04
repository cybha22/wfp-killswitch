# Advanced VPN Kill Switch untuk Windows

Kill switch VPN level OS yang dibangun dengan Go, menggunakan Windows Filtering Platform (WFP) untuk proteksi jaringan fail-closed. Dirancang lebih kuat dari kill switch bawaan ProtonVPN.

## Apa yang Dilakukan

Program ini memastikan **tidak ada traffic jaringan yang keluar dari PC** kecuali melalui tunnel VPN. Jika VPN putus karena alasan apapun (crash, reconnect, sleep/wake, adapter reset), semua traffic langsung diblokir sampai VPN kembali aktif.

Berbeda dengan kill switch level aplikasi yang bisa gagal diam-diam, ini beroperasi di level kernel yang sama dengan Windows Firewall — pendekatan yang sama digunakan oleh Tailscale, WireGuard, dan Mullvad.

## Fitur Utama

- **Enforcement native WFP** — Menggunakan Windows Filtering Platform API langsung (bukan command `netsh`)
- **Deteksi event-driven** — Deteksi putus VPN tanpa delay via `NotifyAddrChange` (bukan polling)
- **Fail-closed by design** — State default adalah BLOCK ALL; traffic VPN di-permit secara eksplisit
- **Auto-detect parameter VPN** — IP server dan DNS terdeteksi otomatis dari route table
- **Handle pergantian server** — Ganti server ProtonVPN otomatis trigger refresh rules
- **Windows Service** — Berjalan sebagai NT service dengan startup otomatis dan recovery saat crash
- **Proteksi DNS leak** — Blokir plain DNS, DNS-over-TLS, dan enforce NRPT policy
- **Blokir IPv6** — Blokir total traffic IPv6 untuk mencegah bypass tunnel
- **Filter per-proses** — Hanya executable ProtonVPN yang bisa bypass firewall
- **Proteksi boot-time** — Filter WFP persisten yang bertahan setelah reboot (dalam pengembangan)

## Cara Kerja

```
1. Service start (otomatis saat boot)
2. Buka WFP session, daftarkan sublayer dengan prioritas tinggi
3. Pasang rules BLOCK ALL sebagai baseline
4. Deteksi VPN interface, server IP, DNS dari route table
5. Jika VPN UP: tambah rules PERMIT untuk interface VPN + proses ProtonVPN
6. Jika VPN DOWN: hapus rules PERMIT, BLOCK ALL tetap aktif
7. Monitor perubahan jaringan via Windows event notifications
8. Saat VPN reconnect/ganti server: re-detect IP, update rules
```

## Persyaratan

- Windows 10 atau lebih baru
- Go 1.24+ (untuk build)
- Hak Administrator (untuk akses WFP dan instalasi service)
- ProtonVPN terinstall dan terkonfigurasi

## Build

```powershell
go build -ldflags="-s -w -H windowsgui" -o killswitch.exe ./cmd/killswitch/
```

Untuk build debug (dengan output console):

```powershell
go build -o killswitch.exe ./cmd/killswitch/
```

## Penggunaan

Semua command memerlukan PowerShell atau Command Prompt yang di-elevate (Administrator).

```powershell
# Install sebagai Windows service (auto-start saat boot)
.\killswitch.exe install

# Start service
.\killswitch.exe start

# Cek status
.\killswitch.exe status

# Stop service
.\killswitch.exe stop

# Uninstall service dan hapus semua filter WFP
.\killswitch.exe uninstall

# Jalankan di foreground untuk debugging (Ctrl+C untuk stop)
.\killswitch.exe debug
```

## Konfigurasi

File konfigurasi: `configs/config.yaml`

```yaml
vpn:
  adapter_name: "ProtonVPN"
  adapter_description: "WireGuard Tunnel"
  auto_detect: true
  process_paths:
    - "C:\\Program Files\\Proton\\VPN\\v4.3.14\\ProtonVPN.Client.exe"
    - "C:\\Program Files\\Proton\\VPN\\v4.3.14\\ProtonVPNService.exe"
    - "C:\\Program Files\\Proton\\VPN\\v4.3.14\\ProtonVPN.WireGuardService.exe"

firewall:
  mode: "strict"
  block_ipv6: true
  dns_leak_protection: true
  boot_time_protection: true
  allow_lan: false
  allow_dhcp: true
  allow_loopback: true
```

Ketika `auto_detect: true` (default), program otomatis mendeteksi IP server VPN dari route table dan DNS server dari interface VPN. Tidak perlu konfigurasi IP manual.

## Arsitektur

```
cmd/killswitch/         Entry point (CLI + mode service)
internal/firewall/      WFP session, rules, sublayers
internal/monitor/       Monitoring jaringan event-driven
internal/dns/           Pencegahan DNS leak (WFP + NRPT)
internal/policy/        State machine (LOCKED/UNLOCKED)
internal/service/       Integrasi Windows Service
internal/config/        Konfigurasi YAML
internal/logger/        Structured logging (zap)
pkg/winapi/             Binding Windows API
```

## Hierarki Rules WFP

| Prioritas | Rule | Tujuan |
|-----------|------|--------|
| 1000 | Permit interface VPN | Izinkan semua traffic di tunnel WireGuard |
| 900 | Permit proses ProtonVPN | Izinkan app VPN membuat koneksi |
| 800 | Permit DHCP | Izinkan assignment alamat jaringan |
| 600 | Permit loopback | Izinkan komunikasi localhost |
| 500 | Permit IP server VPN | Izinkan pembentukan tunnel awal |
| 100 | Block semuanya | Rule deny catch-all |

## Catatan Penting

- **Test di VM dulu.** Salah konfigurasi bisa mengunci internet sepenuhnya.
- **Recovery darurat:** Jalankan `.\killswitch.exe uninstall` atau gunakan `scripts/uninstall.ps1` untuk menghapus semua filter.
- **Nonaktifkan kill switch bawaan ProtonVPN** untuk menghindari konflik (sublayer kita prioritas lebih tinggi, tapi lebih bersih jika dinonaktifkan).
- **Update `process_paths`** jika ProtonVPN update ke versi/direktori baru.
- Fitur `boot_time_protection` (filter persisten yang bertahan setelah reboot) belum sepenuhnya diimplementasi.

## Dependensi

- [tailscale/wf](https://github.com/tailscale/wf) — Library WFP untuk Go (digunakan Tailscale di production)
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) — System call Windows
- [go.uber.org/zap](https://github.com/uber-go/zap) — Structured logging
- [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) — Parsing konfigurasi

## Referensi

- [Tailscale: Programming the Windows Firewall with Go](https://tailscale.com/blog/windows-firewall)
- [WireGuard Windows Firewall Implementation](https://github.com/WireGuard/wireguard-windows/tree/master/tunnel/firewall)
- [Mullvad Firewall Integration](https://mullvad-mullvadvpn-app.mintlify.app/security/firewall)
- [Microsoft WFP Documentation](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

## Lisensi

MIT
