package firewall

import (
	"fmt"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	wf "github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// WFP sublayer and provider GUIDs (generated once, reused).
var (
	providerGUID    = mustGUID("e8f5a3b1-7c2d-4e9f-b6a8-1d3f5c7e9b2a")
	killSwitchGUID  = mustGUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	dnsGuardGUID    = mustGUID("b2c3d4e5-f6a7-8901-bcde-f12345678901")
	persistentGUID  = mustGUID("c3d4e5f6-a7b8-9012-cdef-123456789012")
)

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString("{" + s + "}")
	if err != nil {
		panic(fmt.Sprintf("invalid GUID %q: %v", s, err))
	}
	return g
}

type WFPSession struct {
	cfg     *config.Config
	log     *logger.Logger
	session *wf.Session

	vpnPermitRuleIDs []wf.RuleID
	persistentMgr    *PersistentManager
}

// NewWFPSession opens a dynamic WFP session.
func NewWFPSession(cfg *config.Config, log *logger.Logger) (*WFPSession, error) {
	session, err := wf.New(&wf.Options{
		Name:    "AdvancedKillSwitch",
		Dynamic: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open WFP session: %w", err)
	}

	ws := &WFPSession{
		cfg:     cfg,
		log:     log,
		session: session,
	}

	// Register our provider
	if err := ws.registerProvider(); err != nil {
		session.Close()
		return nil, err
	}

	// Register sublayers
	if err := ws.registerSublayers(); err != nil {
		session.Close()
		return nil, err
	}

	return ws, nil
}

func (ws *WFPSession) registerProvider() error {
	return ws.session.AddProvider(&wf.Provider{
		ID:   wf.ProviderID(providerGUID),
		Name: "Advanced Kill Switch",
	})
}

func (ws *WFPSession) registerSublayers() error {
	// Kill Switch sublayer (dynamic rules)
	if err := ws.session.AddSublayer(&wf.Sublayer{
		ID:     wf.SublayerID(killSwitchGUID),
		Name:   "Kill Switch Rules",
		Weight: 0xFFFE,
	}); err != nil {
		return fmt.Errorf("add kill switch sublayer: %w", err)
	}

	// DNS Guard sublayer
	if err := ws.session.AddSublayer(&wf.Sublayer{
		ID:     wf.SublayerID(dnsGuardGUID),
		Name:   "DNS Guard Rules",
		Weight: 0xFFFD,
	}); err != nil {
		return fmt.Errorf("add DNS guard sublayer: %w", err)
	}

	return nil
}

// ApplyLockdown installs the base block-all rules.
func (ws *WFPSession) ApplyLockdown() error {
	ws.log.Info("applying lockdown rules")

	rules := BuildLockdownRules(ws.cfg, wf.SublayerID(killSwitchGUID))
	for _, rule := range rules {
		if err := ws.session.AddRule(rule); err != nil {
			return fmt.Errorf("add rule %q: %w", rule.Name, err)
		}
		ws.log.Debugf("added rule: %s (weight=%d, action=%v)", rule.Name, rule.Weight, rule.Action)
	}

	return nil
}

// ApplyVPNPermit adds rules to permit traffic on the VPN interface.
func (ws *WFPSession) ApplyVPNPermit(vpnLUID uint64) error {
	ws.log.Infof("applying VPN permit rules for LUID %d", vpnLUID)

	rules := BuildVPNPermitRules(vpnLUID, wf.SublayerID(killSwitchGUID))
	for _, rule := range rules {
		if err := ws.session.AddRule(rule); err != nil {
			return fmt.Errorf("add VPN permit rule %q: %w", rule.Name, err)
		}
		ws.vpnPermitRuleIDs = append(ws.vpnPermitRuleIDs, rule.ID)
		ws.log.Debugf("added VPN permit rule: %s", rule.Name)
	}

	return nil
}

// RemoveVPNPermit removes the VPN permit rules.
func (ws *WFPSession) RemoveVPNPermit() error {
	for _, id := range ws.vpnPermitRuleIDs {
		if err := ws.session.DeleteRule(id); err != nil {
			ws.log.Warnf("failed to delete VPN permit rule: %v", err)
		}
	}
	ws.vpnPermitRuleIDs = nil
	return nil
}

func (ws *WFPSession) InstallPersistentFilters() error {
	ws.log.Info("installing persistent boot-time filters")
	pm := NewPersistentManager()
	if err := pm.Install(); err != nil {
		return fmt.Errorf("persistent filters: %w", err)
	}
	ws.persistentMgr = pm
	ws.log.Info("persistent boot-time filters installed")
	return nil
}

func (ws *WFPSession) RemovePersistentFilters() error {
	if ws.persistentMgr == nil {
		return nil
	}
	ws.log.Info("removing persistent boot-time filters")
	return ws.persistentMgr.Remove()
}

func (ws *WFPSession) RawSession() *wf.Session {
	return ws.session
}

func (ws *WFPSession) Close() error {
	if ws.session != nil {
		return ws.session.Close()
	}
	return nil
}
