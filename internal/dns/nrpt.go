package dns

import (
	"golang.org/x/sys/windows/registry"
)

const nrptBasePath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

func (g *Guard) setNRPT() error {
	g.log.Info("skipping NRPT - using WFP DNS rules only (NRPT breaks some browsers)")
	return nil
}

func (g *Guard) removeNRPT() {
	_ = registry.DeleteKey(
		registry.LOCAL_MACHINE,
		nrptBasePath+`\AdvancedKillSwitch`,
	)
}
