package firewall

// Sublayer weight constants.
// Higher weight = higher priority in WFP evaluation.
const (
	// WeightPersistent is the highest weight for boot-time block-all filters.
	WeightPersistent uint16 = 0xFFFF

	// WeightKillSwitch is the weight for dynamic kill switch rules.
	WeightKillSwitch uint16 = 0xFFFE

	// WeightDNSGuard is the weight for DNS-specific filtering rules.
	WeightDNSGuard uint16 = 0xFFFD
)

// Rule weight constants within a sublayer.
// Higher weight = evaluated first within the sublayer.
const (
	// RuleWeightVPNInterface permits traffic on the VPN tunnel interface.
	RuleWeightVPNInterface uint64 = 1000

	// RuleWeightVPNProcess permits ProtonVPN processes to bypass the firewall.
	RuleWeightVPNProcess uint64 = 900

	// RuleWeightDHCP permits DHCP traffic for network connectivity.
	RuleWeightDHCP uint64 = 800

	// RuleWeightNDP permits Neighbor Discovery Protocol for IPv6.
	RuleWeightNDP uint64 = 700

	// RuleWeightLoopback permits loopback/localhost traffic.
	RuleWeightLoopback uint64 = 600

	// RuleWeightVPNServer permits traffic to VPN server IPs for initial connection.
	RuleWeightVPNServer uint64 = 500

	// RuleWeightBlockAll is the catch-all block rule.
	RuleWeightBlockAll uint64 = 100
)
