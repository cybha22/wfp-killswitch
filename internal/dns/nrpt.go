package dns

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const nrptBasePath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

func (g *Guard) setNRPT() error {
	g.log.Info("configuring NRPT to force VPN DNS")

	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		nrptBasePath+`\AdvancedKillSwitch`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		return fmt.Errorf("create NRPT key: %w", err)
	}
	defer key.Close()

	if err := key.SetStringValue("Name", "."); err != nil {
		return err
	}

	dnsServers := ""
	for i, s := range g.cfg.VPN.DNSServers {
		if i > 0 {
			dnsServers += ";"
		}
		dnsServers += s
	}
	if err := key.SetStringValue("GenericDNSServers", dnsServers); err != nil {
		return err
	}

	if err := key.SetDWordValue("ConfigOptions", 0x8); err != nil {
		return err
	}

	g.log.Infof("NRPT configured: all DNS -> %s", dnsServers)
	return nil
}

func (g *Guard) removeNRPT() {
	err := registry.DeleteKey(
		registry.LOCAL_MACHINE,
		nrptBasePath+`\AdvancedKillSwitch`,
	)
	if err != nil {
		g.log.Debugf("NRPT cleanup: %v", err)
	}
}
