package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	VPN      VPNConfig      `yaml:"vpn"`
	Firewall FirewallConfig `yaml:"firewall"`
	Monitor  MonitorConfig  `yaml:"monitor"`
	Service  ServiceConfig  `yaml:"service"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type VPNConfig struct {
	AdapterName        string   `yaml:"adapter_name"`
	AdapterDescription string   `yaml:"adapter_description"`
	InterfaceIndex     int      `yaml:"interface_index"`
	ServerIPs          []string `yaml:"server_ips"`
	DNSServers         []string `yaml:"dns_servers"`
	ProcessPaths       []string `yaml:"process_paths"`
	AutoDetect         bool     `yaml:"auto_detect"`
}

// FirewallConfig controls WFP behavior.
type FirewallConfig struct {
	Mode               string `yaml:"mode"` // "strict" or "permissive"
	BlockIPv6          bool   `yaml:"block_ipv6"`
	DNSLeakProtection  bool   `yaml:"dns_leak_protection"`
	BootTimeProtection bool   `yaml:"boot_time_protection"`
	AllowLAN           bool   `yaml:"allow_lan"`
	AllowDHCP          bool   `yaml:"allow_dhcp"`
	AllowLoopback      bool   `yaml:"allow_loopback"`
}

// MonitorConfig controls network monitoring behavior.
type MonitorConfig struct {
	EventDriven        bool          `yaml:"event_driven"`
	BackupPollInterval time.Duration `yaml:"backup_poll_interval"`
	VPNIPRange         string        `yaml:"vpn_ip_range"`
}

// ServiceConfig controls Windows service properties.
type ServiceConfig struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
	AutoStart   bool   `yaml:"auto_start"`
}

// LoggingConfig controls logging behavior.
type LoggingConfig struct {
	Level      string `yaml:"level"` // "debug", "info", "warn", "error"
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// Load reads and parses the YAML config file.
// Falls back to defaults if file doesn't exist.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.VPN.AdapterName == "" {
		return fmt.Errorf("vpn.adapter_name is required")
	}
	if !c.VPN.AutoDetect {
		if len(c.VPN.ServerIPs) == 0 {
			return fmt.Errorf("vpn.server_ips required when auto_detect is false")
		}
		if len(c.VPN.DNSServers) == 0 {
			return fmt.Errorf("vpn.dns_servers required when auto_detect is false")
		}
	}
	if c.Firewall.Mode != "strict" && c.Firewall.Mode != "permissive" {
		return fmt.Errorf("firewall.mode must be 'strict' or 'permissive', got %q", c.Firewall.Mode)
	}
	return nil
}
