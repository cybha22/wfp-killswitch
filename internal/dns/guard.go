package dns

import (
	"net/netip"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	wf "github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

type Guard struct {
	cfg     *config.Config
	log     *logger.Logger
	session *wf.Session
	ruleIDs []wf.RuleID
}

func NewGuard(cfg *config.Config, log *logger.Logger, session *wf.Session) *Guard {
	return &Guard{
		cfg:     cfg,
		log:     log,
		session: session,
	}
}

func (g *Guard) Enable() error {
	if !g.cfg.Firewall.DNSLeakProtection {
		return nil
	}

	g.log.Info("enabling DNS leak protection")

	rules := g.buildDNSRules()
	for _, rule := range rules {
		if err := g.session.AddRule(rule); err != nil {
			return err
		}
		g.ruleIDs = append(g.ruleIDs, rule.ID)
	}

	if err := g.setNRPT(); err != nil {
		g.log.Warnf("NRPT setup failed: %v", err)
	}

	return nil
}

func (g *Guard) Disable() error {
	for _, id := range g.ruleIDs {
		_ = g.session.DeleteRule(id)
	}
	g.ruleIDs = nil

	g.removeNRPT()
	return nil
}

func (g *Guard) buildDNSRules() []*wf.Rule {
	var rules []*wf.Rule

	dnsGuardSublayer := wf.SublayerID(windows.GUID{
		Data1: 0xb2c3d4e5,
		Data2: 0xf6a7,
		Data3: 0x8901,
		Data4: [8]byte{0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x01},
	})

	for _, dnsServer := range g.cfg.VPN.DNSServers {
		addr, err := netip.ParseAddr(dnsServer)
		if err != nil {
			continue
		}

		guid, _ := windows.GenerateGUID()
		rules = append(rules, &wf.Rule{
			ID:       wf.RuleID(guid),
			Name:     "Allow DNS to VPN server",
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: dnsGuardSublayer,
			Weight:   900,
			Conditions: []*wf.Match{
				{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)},
				{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: addr},
			},
			Action: wf.ActionPermit,
		})
	}

	guid, _ := windows.GenerateGUID()
	rules = append(rules, &wf.Rule{
		ID:       wf.RuleID(guid),
		Name:     "Block all other DNS (UDP 53)",
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: dnsGuardSublayer,
		Weight:   100,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)},
		},
		Action: wf.ActionBlock,
	})

	guid2, _ := windows.GenerateGUID()
	rules = append(rules, &wf.Rule{
		ID:       wf.RuleID(guid2),
		Name:     "Block DNS-over-TLS (TCP 853)",
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: dnsGuardSublayer,
		Weight:   100,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(853)},
		},
		Action: wf.ActionBlock,
	})

	return rules
}
