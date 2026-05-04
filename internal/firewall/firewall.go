package firewall

import (
	"fmt"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	"github.com/muhsh/advanced-killswitch/internal/monitor"
)

// State represents the current firewall enforcement state.
type State int

const (
	// StateLocked means all non-VPN traffic is blocked.
	StateLocked State = iota
	// StateUnlocked means VPN traffic is permitted.
	StateUnlocked
)

func (s State) String() string {
	switch s {
	case StateLocked:
		return "LOCKED"
	case StateUnlocked:
		return "UNLOCKED"
	default:
		return "UNKNOWN"
	}
}

// Controller manages WFP firewall rules for the kill switch.
type Controller struct {
	cfg   *config.Config
	log   *logger.Logger
	state State

	session *WFPSession
}

// NewController creates a new firewall controller.
func NewController(cfg *config.Config, log *logger.Logger) *Controller {
	return &Controller{
		cfg:   cfg,
		log:   log,
		state: StateLocked, // fail-closed: start locked
	}
}

func (c *Controller) Initialize() error {
	c.log.Info("initializing WFP firewall controller")

	if c.cfg.VPN.AutoDetect {
		c.log.Info("auto-detecting VPN server IPs and DNS servers")
		if err := c.autoDetectVPNParams(); err != nil {
			c.log.Warnf("auto-detect partial failure: %v", err)
		}
	}

	session, err := NewWFPSession(c.cfg, c.log)
	if err != nil {
		return err
	}
	c.session = session

	if c.cfg.Firewall.BootTimeProtection {
		if err := c.session.InstallPersistentFilters(); err != nil {
			c.log.Warnf("failed to install persistent filters: %v", err)
		}
	}

	if err := c.session.ApplyLockdown(); err != nil {
		return err
	}

	c.state = StateLocked
	c.log.Info("firewall initialized in LOCKED state")
	return nil
}

func (c *Controller) autoDetectVPNParams() error {
	adapterName := c.cfg.VPN.AdapterName

	ifaceIdx, err := monitor.DetectVPNInterfaceIndex(adapterName)
	if err != nil {
		return fmt.Errorf("detect interface index: %w", err)
	}
	c.cfg.VPN.InterfaceIndex = ifaceIdx
	c.log.Infof("detected VPN interface index: %d", ifaceIdx)

	serverIPs, err := monitor.DetectVPNServerIPs(ifaceIdx)
	if err == nil && len(serverIPs) > 0 {
		c.cfg.VPN.ServerIPs = make([]string, len(serverIPs))
		for i, ip := range serverIPs {
			c.cfg.VPN.ServerIPs[i] = ip.String()
		}
		c.log.Infof("detected VPN server IPs: %v", c.cfg.VPN.ServerIPs)
	}

	dnsServers, err := monitor.DetectVPNDNSServers(adapterName)
	if err == nil && len(dnsServers) > 0 {
		c.cfg.VPN.DNSServers = make([]string, len(dnsServers))
		for i, dns := range dnsServers {
			c.cfg.VPN.DNSServers[i] = dns.String()
		}
		c.log.Infof("detected VPN DNS servers: %v", c.cfg.VPN.DNSServers)
	}

	return nil
}

// Unlock permits VPN traffic while keeping everything else blocked.
func (c *Controller) Unlock(vpnLUID uint64) error {
	if c.state == StateUnlocked {
		return nil
	}

	c.log.Infof("unlocking firewall for VPN LUID %d", vpnLUID)

	if err := c.session.ApplyVPNPermit(vpnLUID); err != nil {
		return err
	}

	c.state = StateUnlocked
	c.log.Info("firewall state: UNLOCKED")
	return nil
}

// Lock removes VPN permit rules, falling back to block-all.
func (c *Controller) Lock() error {
	if c.state == StateLocked {
		return nil
	}

	c.log.Info("locking firewall - removing VPN permit rules")

	if err := c.session.RemoveVPNPermit(); err != nil {
		return err
	}

	c.state = StateLocked
	c.log.Info("firewall state: LOCKED")
	return nil
}

// State returns the current firewall state.
func (c *Controller) State() State {
	return c.state
}

// Shutdown closes the WFP session.
// If boot-time protection is enabled, persistent filters remain.
func (c *Controller) Shutdown(keepPersistent bool) error {
	c.log.Info("shutting down firewall controller")

	if c.session == nil {
		return nil
	}

	if !keepPersistent {
		if err := c.session.RemovePersistentFilters(); err != nil {
			c.log.Warnf("failed to remove persistent filters: %v", err)
		}
	}

	return c.session.Close()
}
