# Advanced PROTON VPN Kill Switch for Windows

A production-grade, OS-level VPN kill switch built in Go that provides fail-closed network protection using the Windows Filtering Platform (WFP). Designed to be stronger than ProtonVPN's built-in kill switch.

## What It Does

This program ensures that **zero network traffic leaves your machine** unless it goes through your VPN tunnel. If the VPN drops for any reason (crash, reconnect, sleep/wake, adapter reset), all traffic is immediately blocked until the VPN is back up.

Unlike application-level kill switches that can fail silently, this operates at the same kernel level as the Windows Firewall itself — the same approach used by Tailscale, WireGuard, and Mullvad.

## Key Features

- **WFP-native enforcement** — Uses Windows Filtering Platform API directly (not `netsh` commands)
- **Event-driven detection** — Zero-latency VPN drop detection via `NotifyAddrChange` (not polling)
- **Fail-closed by design** — Default state is BLOCK ALL; VPN traffic is explicitly permitted
- **Auto-detect VPN parameters** — Server IPs and DNS detected from route table automatically
- **Handles server changes** — Switching ProtonVPN servers triggers automatic rule refresh
- **Windows Service** — Runs as NT service with automatic startup and crash recovery
- **DNS leak protection** — Blocks plain DNS, DNS-over-TLS, and enforces NRPT policy
- **IPv6 block** — Complete IPv6 traffic block to prevent tunnel bypass
- **Per-process filtering** — Only ProtonVPN executables can bypass the firewall
- **Boot-time protection** — Persistent WFP filters survive reboot (planned)

## How It Works

```
1. Service starts (automatically on boot)
2. Opens WFP session, registers sublayer with high priority
3. Installs BLOCK ALL rules as baseline
4. Detects VPN interface, server IPs, DNS from route table
5. If VPN is UP: adds PERMIT rules for VPN interface + ProtonVPN processes
6. If VPN goes DOWN: removes PERMIT rules, BLOCK ALL remains active
7. Monitors network changes via Windows event notifications
8. On VPN reconnect/server change: re-detects IPs, updates rules
```

## Requirements

- Windows 10 or later
- Go 1.24+ (for building)
- Administrator privileges (for WFP access and service installation)
- ProtonVPN installed and configured

## Building

```powershell
go build -ldflags="-s -w -H windowsgui" -o killswitch.exe ./cmd/killswitch/
```

For debug builds (with console output):

```powershell
go build -o killswitch.exe ./cmd/killswitch/
```

## Usage

All commands require an elevated (Administrator) PowerShell or Command Prompt.

```powershell
# Install as Windows service (auto-starts on boot)
.\killswitch.exe install

# Start the service
.\killswitch.exe start

# Check status
.\killswitch.exe status

# Stop the service
.\killswitch.exe stop

# Uninstall service and remove all WFP filters
.\killswitch.exe uninstall

# Run in foreground for debugging (Ctrl+C to stop)
.\killswitch.exe debug
```

## Windows Service Behavior

Once installed, the kill switch runs as a Windows Service called `AdvancedKillSwitch`:

| Event | What Happens |
|-------|-------------|
| PC shutdown and restart | Service auto-starts on boot, blocks traffic until VPN connects |
| VPN disconnects | All traffic blocked immediately |
| VPN reconnects | Traffic restored automatically |
| VPN switches server | New server IP auto-detected, rules updated |
| Service crash | Windows auto-restarts it (0s delay recovery) |
| `.\killswitch.exe stop` | Service stops, all WFP rules removed, internet restored |
| `.\killswitch.exe uninstall` | Service removed permanently, all filters cleaned |

The service depends on BFE (Base Filtering Engine) and starts automatically after Windows boot. You can also manage it via `services.msc` (look for "Advanced VPN Kill Switch").

To check logs:
```powershell
Get-Content "C:\ProgramData\AdvancedKillSwitch\logs\killswitch.log" -Tail 30
```

## Configuration

Configuration file: `configs/config.yaml`

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

When `auto_detect: true` (default), the program automatically detects VPN server IPs from the route table and DNS servers from the VPN interface. No manual IP configuration needed.

## Architecture

```
cmd/killswitch/         Entry point (CLI + service mode)
internal/firewall/      WFP session, rules, sublayers
internal/monitor/       Event-driven network monitoring
internal/dns/           DNS leak prevention (WFP + NRPT)
internal/policy/        State machine (LOCKED/UNLOCKED)
internal/service/       Windows Service integration
internal/config/        YAML configuration
internal/logger/        Structured logging (zap)
pkg/winapi/             Windows API bindings
```

## WFP Rule Hierarchy

| Priority | Rule | Purpose |
|----------|------|---------|
| 1000 | Permit VPN interface | Allow all traffic on WireGuard tunnel |
| 900 | Permit ProtonVPN processes | Allow VPN app to establish connection |
| 800 | Permit DHCP | Allow network address assignment |
| 600 | Permit loopback | Allow localhost communication |
| 500 | Permit VPN server IP | Allow initial tunnel establishment |
| 100 | Block everything | Catch-all deny rule |

## Demo Log

Real output from `.\killswitch.exe debug` showing the kill switch in action:

```
PS> .\killswitch.exe debug

14:05:05  info  running in interactive/debug mode
14:05:05  info  initializing WFP firewall controller
14:05:05  info  auto-detecting VPN server IPs and DNS servers
14:05:05  info  detected VPN interface index: 27
14:05:05  info  detected VPN server IPs: [146.70.14.19]
14:05:06  info  detected VPN DNS servers: [10.2.0.1]
14:05:06  info  applying lockdown rules
14:05:06  info  firewall initialized in LOCKED state
14:05:06  info  DNS leak protection active
14:05:06  info  VPN state changed: DOWN -> UP
14:05:06  info  unlocking firewall for VPN LUID 14918723521478656
14:05:06  info  firewall state: UNLOCKED
14:05:06  info  kill switch active

# User disconnects ProtonVPN:
14:05:14  info  VPN state changed: UP -> RECONNECTING
14:05:16  info  VPN state changed: RECONNECTING -> DOWN
14:05:16  info  locking firewall - removing VPN permit rules
14:05:16  info  firewall state: LOCKED          <-- all traffic blocked

# User reconnects ProtonVPN (different server):
14:06:39  info  VPN state changed: DOWN -> UP
14:06:39  info  refreshed VPN server IPs: [169.150.196.155]   <-- new server auto-detected
14:06:39  info  refreshed VPN DNS servers: [10.2.0.1]
14:06:39  info  firewall state: UNLOCKED        <-- traffic restored
```

Key observations:
- VPN disconnect detected in under 2 seconds
- Server IP change (146.70.14.19 -> 169.150.196.155) auto-detected
- Traffic blocked during entire VPN-down window
- No manual configuration needed for server changes

## Important Notes

- **Test in a VM first.** Misconfiguration can lock you out of the internet entirely.
- **Emergency recovery:** Run `.\killswitch.exe uninstall` or use `scripts/uninstall.ps1` to remove all filters.
- **Disable ProtonVPN's built-in kill switch** to avoid conflicts (our sublayer has higher priority, but cleaner to disable).
- **Update `process_paths`** if ProtonVPN updates to a new version directory.
- The `boot_time_protection` feature (persistent filters surviving reboot) is not yet fully implemented.

## Dependencies

- [tailscale/wf](https://github.com/tailscale/wf) — Go WFP library (used by Tailscale in production)
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) — Windows system calls
- [go.uber.org/zap](https://github.com/uber-go/zap) — Structured logging
- [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) — Configuration parsing

## References

- [Tailscale: Programming the Windows Firewall with Go](https://tailscale.com/blog/windows-firewall)
- [WireGuard Windows Firewall Implementation](https://github.com/WireGuard/wireguard-windows/tree/master/tunnel/firewall)
- [Mullvad Firewall Integration](https://mullvad-mullvadvpn-app.mintlify.app/security/firewall)
- [Microsoft WFP Documentation](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

## License

MIT
