package firewall

import (
	"fmt"

	wf "github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Persistent filters use a SEPARATE non-dynamic WFP session.
// When the session is non-dynamic, rules survive BFE restarts and reboots.
// Architecture matches Mullvad's approach:
//   - Persistent sublayer at weight 0xFFFF (highest)
//   - Contains ONLY block-all rules
//   - Dynamic session's PERMIT rules (lower weight) allow VPN through
//   - If service crashes, persistent BLOCK remains = fail-closed

type PersistentManager struct {
	providerID windows.GUID
	sublayerID windows.GUID
	ruleIDs    []wf.RuleID
}

func NewPersistentManager() *PersistentManager {
	return &PersistentManager{
		providerID: mustGUID("d4e5f6a7-b8c9-0123-4567-89abcdef0123"),
		sublayerID: mustGUID("e5f6a7b8-c9d0-1234-5678-9abcdef01234"),
	}
}

func (pm *PersistentManager) Install() error {
	session, err := wf.New(&wf.Options{
		Name:    "AdvancedKillSwitch-Persistent",
		Dynamic: false,
	})
	if err != nil {
		return fmt.Errorf("open persistent WFP session: %w", err)
	}
	defer session.Close()

	_ = session.AddProvider(&wf.Provider{
		ID:   wf.ProviderID(pm.providerID),
		Name: "Advanced Kill Switch Persistent",
	})

	_ = session.AddSublayer(&wf.Sublayer{
		ID:     wf.SublayerID(pm.sublayerID),
		Name:   "Boot-time Block All",
		Weight: WeightPersistent,
	})

	layers := []wf.LayerID{
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthConnectV6,
		wf.LayerALEAuthRecvAcceptV4,
		wf.LayerALEAuthRecvAcceptV6,
	}

	for _, layer := range layers {
		guid, err := windows.GenerateGUID()
		if err != nil {
			continue
		}
		ruleID := wf.RuleID(guid)

		err = session.AddRule(&wf.Rule{
			ID:       ruleID,
			Name:     fmt.Sprintf("Persistent Block All - %s", layer),
			Layer:    layer,
			Sublayer: wf.SublayerID(pm.sublayerID),
			Weight:   100,
			Action:   wf.ActionBlock,
		})
		if err != nil {
			return fmt.Errorf("add persistent block rule: %w", err)
		}
		pm.ruleIDs = append(pm.ruleIDs, ruleID)
	}

	return nil
}

func (pm *PersistentManager) Remove() error {
	session, err := wf.New(&wf.Options{
		Name:    "AdvancedKillSwitch-Cleanup",
		Dynamic: false,
	})
	if err != nil {
		return fmt.Errorf("open cleanup WFP session: %w", err)
	}
	defer session.Close()

	for _, id := range pm.ruleIDs {
		_ = session.DeleteRule(id)
	}
	pm.ruleIDs = nil

	_ = session.DeleteSublayer(wf.SublayerID(pm.sublayerID))
	_ = session.DeleteProvider(wf.ProviderID(pm.providerID))

	return nil
}

func (pm *PersistentManager) IsInstalled() bool {
	return len(pm.ruleIDs) > 0
}
