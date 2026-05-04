package firewall

import (
	"fmt"
	"net/netip"

	"github.com/muhsh/advanced-killswitch/internal/config"
	wf "github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// BuildLockdownRules creates the base set of WFP rules for kill switch enforcement.
// These rules block all traffic except explicitly permitted exceptions.
func BuildLockdownRules(cfg *config.Config, sublayer wf.SublayerID) []*wf.Rule {
	var rules []*wf.Rule

	// Layers to apply rules on (both IPv4 and IPv6)
	layers := []wf.LayerID{
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthRecvAcceptV4,
	}

	if cfg.Firewall.BlockIPv6 {
		// Block IPv6 completely
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
	} else {
		layers = append(layers,
			wf.LayerALEAuthConnectV6,
			wf.LayerALEAuthRecvAcceptV6,
		)
	}

	// PERMIT: Loopback
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
						Value: uint32(0x00000001), // FWP_CONDITION_FLAG_IS_LOOPBACK
					},
				},
				Action: wf.ActionPermit,
			})
		}
	}

	// PERMIT: DHCP (UDP 67/68)
	if cfg.Firewall.AllowDHCP {
		rules = append(rules, buildDHCPRules(sublayer)...)
	}

	// PERMIT: VPN server IPs (needed for initial connection)
	for _, serverIP := range cfg.VPN.ServerIPs {
		addr, err := netip.ParseAddr(serverIP)
		if err != nil {
			continue
		}
		layer := wf.LayerALEAuthConnectV4
		if addr.Is6() {
			layer = wf.LayerALEAuthConnectV6
		}
		rules = append(rules, &wf.Rule{
			ID:       newRuleID(),
			Name:     fmt.Sprintf("Allow VPN Server %s", serverIP),
			Layer:    layer,
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

	// PERMIT: ProtonVPN processes (AppID-based)
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

	// BLOCK: Everything else (catch-all, lowest weight)
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

// BuildVPNPermitRules creates rules to permit traffic on the VPN interface.
func BuildVPNPermitRules(vpnLUID uint64, sublayer wf.SublayerID) []*wf.Rule {
	layers := []wf.LayerID{
		wf.LayerALEAuthConnectV4,
		wf.LayerALEAuthRecvAcceptV4,
		wf.LayerALEAuthConnectV6,
		wf.LayerALEAuthRecvAcceptV6,
	}

	var rules []*wf.Rule
	for _, layer := range layers {
		rules = append(rules, &wf.Rule{
			ID:       newRuleID(),
			Name:     fmt.Sprintf("Allow VPN Interface - %s", layer),
			Layer:    layer,
			Sublayer: sublayer,
			Weight:   1000,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldIPLocalInterface,
					Op:    wf.MatchTypeEqual,
					Value: vpnLUID,
				},
			},
			Action: wf.ActionPermit,
		})
	}

	return rules
}

func buildDHCPRules(sublayer wf.SublayerID) []*wf.Rule {
	var rules []*wf.Rule

	// DHCPv4: Allow UDP from port 68 to port 67
	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow DHCPv4 Outbound",
		Layer:    wf.LayerALEAuthConnectV4,
		Sublayer: sublayer,
		Weight:   800,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(68),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(67),
			},
		},
		Action: wf.ActionPermit,
	})

	// DHCPv4: Allow UDP from port 67 to port 68 (inbound)
	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow DHCPv4 Inbound",
		Layer:    wf.LayerALEAuthRecvAcceptV4,
		Sublayer: sublayer,
		Weight:   800,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(68),
			},
		},
		Action: wf.ActionPermit,
	})

	// DHCPv6: Allow UDP port 546/547
	rules = append(rules, &wf.Rule{
		ID:       newRuleID(),
		Name:     "Allow DHCPv6 Outbound",
		Layer:    wf.LayerALEAuthConnectV6,
		Sublayer: sublayer,
		Weight:   800,
		Conditions: []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(546),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(547),
			},
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
