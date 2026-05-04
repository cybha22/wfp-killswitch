package firewall

import (
	"fmt"
	"net/netip"

	"github.com/muhsh/advanced-killswitch/internal/config"
	wf "github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

func BuildLockdownRules(cfg *config.Config, sublayer wf.SublayerID) []*wf.Rule {
	var rules []*wf.Rule

	layers := []wf.LayerID{
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthRecvAcceptV4,
	}

	if cfg.Firewall.BlockIPv6 {
		v6Layers := []wf.LayerID{
			wf.LayerALEAuthConnectV6,
			wf.LayerALEAuthRecvAcceptV6,
		}
		for _, layer := range v6Layers {
			rules = append(rules, &wf.Rule{
				ID:       newRuleID(),
				Name:     fmt.Sprintf("Block IPv6 - %s", layer),
				Layer:    layer,
				Sublayer: sublayer,
				Weight:   50,
				Action:   wf.ActionBlock,
			})
		}
	}

	if cfg.Firewall.AllowLoopback {
		for _, layer := range layers {
			rules = append(rules, &wf.Rule{
				ID:       newRuleID(),
				Name:     fmt.Sprintf("Allow Loopback - %s", layer),
				Layer:    layer,
				Sublayer: sublayer,
				Weight:   600,
				Conditions: []*wf.Match{
					{
						Field: wf.FieldFlags,
						Op:    wf.MatchTypeFlagsAllSet,
						Value: uint32(0x00000001),
					},
				},
				Action: wf.ActionPermit,
			})
		}
	}

	if cfg.Firewall.AllowDHCP {
		rules = append(rules, buildDHCPRules(sublayer)...)
	}

	for _, serverIP := range cfg.VPN.ServerIPs {
		addr, err := netip.ParseAddr(serverIP)
		if err != nil {
			continue
		}
		rules = append(rules, &wf.Rule{
			ID:       newRuleID(),
			Name:     fmt.Sprintf("Allow VPN Server %s", serverIP),
			Layer:    wf.LayerALEAuthConnectV4,
			Sublayer: sublayer,
			Weight:   500,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPRemoteAddress,
					Op:    wf.MatchTypeEqual,
					Value: addr,
				},
			},
			Action: wf.ActionPermit,
		})
	}

	for _, procPath := range cfg.VPN.ProcessPaths {
		appID, err := wf.AppID(procPath)
		if err != nil {
			continue
		}
		for _, layer := range layers {
			rules = append(rules, &wf.Rule{
				ID:       newRuleID(),
				Name:     fmt.Sprintf("Allow ProtonVPN Process - %s", layer),
				Layer:    layer,
				Sublayer: sublayer,
				Weight:   900,
				Conditions: []*wf.Match{
					{
						Field: wf.FieldALEAppID,
						Op:    wf.MatchTypeEqual,
						Value: appID,
					},
				},
				Action: wf.ActionPermit,
			})
		}
	}

	// Permit WireGuard UDP (ProtonVPN uses WireGuard on various ports)
	// This ensures ProtonVPN can always establish tunnel even to new server IPs
	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow WireGuard UDP 51820",
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: sublayer,
		Weight:   490,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(51820)},
		},
		Action: wf.ActionPermit,
	})

	for _, layer := range layers {
		rules = append(rules, &wf.Rule{
			ID:       newRuleID(),
			Name:     fmt.Sprintf("Block All - %s", layer),
			Layer:    layer,
			Sublayer: sublayer,
			Weight:   100,
			Action:   wf.ActionBlock,
		})
	}

	return rules
}

func BuildVPNPermitRules(vpnLUID uint64, sublayer wf.SublayerID) []*wf.Rule {
	layers := []wf.LayerID{
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthRecvAcceptV4,
	}

	var rules []*wf.Rule

	for _, layer := range layers {
		rules = append(rules, &wf.Rule{
			ID:       newRuleID(),
			Name:     fmt.Sprintf("Permit All (VPN Active) - %s", layer),
			Layer:    layer,
			Sublayer: sublayer,
			Weight:   1000,
			Action:   wf.ActionPermit,
		})
	}

	return rules
}

func buildDHCPRules(sublayer wf.SublayerID) []*wf.Rule {
	var rules []*wf.Rule

	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow DHCPv4 Outbound",
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: sublayer,
		Weight:   800,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
			{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(68)},
			{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(67)},
		},
		Action: wf.ActionPermit,
	})

	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow DHCPv4 Inbound",
		Layer:    wf.LayerALEAuthRecvAcceptV4,
		Sublayer: sublayer,
		Weight:   800,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
			{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(68)},
		},
		Action: wf.ActionPermit,
	})

	return rules
}

func newRuleID() wf.RuleID {
	guid, err := windows.GenerateGUID()
	if err != nil {
		panic(fmt.Sprintf("generate GUID: %v", err))
	}
	return wf.RuleID(guid)
}
