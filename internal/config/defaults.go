package config

import "time"

// Defaults returns a Config with sensible default values
// pre-configured for the current ProtonVPN installation.
func Defaults() *Config {
	return &Config{
		VPN: VPNConfig{
			AdapterName:        "ProtonVPN",
			AdapterDescription: "WireGuard Tunnel",
			AutoDetect:         true,
			ProcessPaths: []string{
				`C:\Program Files\Proton\VPN\v4.3.14\ProtonVPN.Client.exe`,
				`C:\Program Files\Proton\VPN\v4.3.14\ProtonVPNService.exe`,
				`C:\Program Files\Proton\VPN\v4.3.14\ProtonVPN.WireGuardService.exe`,
			},
		},
		Firewall: FirewallConfig{
			Mode:               "strict",
			BlockIPv6:          true,
			DNSLeakProtection:  true,
			BootTimeProtection: true,
			AllowLAN:           false,
			AllowDHCP:          true,
			AllowLoopback:      true,
		},
		Monitor: MonitorConfig{
			EventDriven:        true,
			BackupPollInterval: 5 * time.Second,
			VPNIPRange:         "10.0.0.0/8",
		},
		Service: ServiceConfig{
			Name:        "AdvancedKillSwitch",
			DisplayName: "Advanced VPN Kill Switch",
			Description: "OS-level VPN kill switch with WFP enforcement",
			AutoStart:   true,
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       `C:\ProgramData\AdvancedKillSwitch\logs\killswitch.log`,
			MaxSizeMB:  10,
			MaxBackups: 3,
		},
	}
}
