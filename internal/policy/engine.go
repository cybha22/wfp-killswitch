package policy

import (
	"sync"
	"time"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/dns"
	"github.com/muhsh/advanced-killswitch/internal/firewall"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	"github.com/muhsh/advanced-killswitch/internal/monitor"
)

type Engine struct {
	cfg *config.Config
	log *logger.Logger
	fw  *firewall.Controller

	mu             sync.RWMutex
	state          KillSwitchState
	lastTransition time.Time
	debounceTimer  *time.Timer
}

func NewEngine(cfg *config.Config, log *logger.Logger, fw *firewall.Controller) *Engine {
	return &Engine{
		cfg:            cfg,
		log:            log,
		fw:             fw,
		state:          StateInitializing,
		lastTransition: time.Now(),
	}
}

func (e *Engine) HandleVPNStateChange(vpnState monitor.VPNState) {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch vpnState {
	case monitor.VPNStateUp:
		e.transitionToUnlocked()
	case monitor.VPNStateDown:
		e.transitionToLocked()
	case monitor.VPNStateReconnecting:
		e.handleReconnecting()
	}
}

func (e *Engine) transitionToUnlocked() {
	if e.state == StateUnlocked {
		return
	}

	if e.debounceTimer != nil {
		e.debounceTimer.Stop()
		e.debounceTimer = nil
	}

	vpnIface := monitor.DetectVPNInterface(e.cfg.VPN.AdapterName)
	if vpnIface == nil {
		e.log.Warn("VPN interface not found during unlock attempt")
		return
	}

	if e.cfg.VPN.AutoDetect {
		e.refreshVPNParams(vpnIface.Index)
	}

	luid, err := monitor.DetectVPNInterfaceLUID(vpnIface.Index)
	if err != nil {
		e.log.Errorf("failed to get VPN LUID: %v", err)
		luid = uint64(vpnIface.Index)
	}

	if err := e.fw.Unlock(luid); err != nil {
		e.log.Errorf("failed to unlock firewall: %v", err)
		e.state = StateError
		return
	}

	e.state = StateUnlocked
	e.lastTransition = time.Now()
	e.log.Info("policy engine: UNLOCKED")
}

func (e *Engine) refreshVPNParams(ifaceIndex int) {
	serverIPs, err := monitor.DetectVPNServerIPs(ifaceIndex)
	if err == nil && len(serverIPs) > 0 {
		newIPs := make([]string, len(serverIPs))
		for i, ip := range serverIPs {
			newIPs[i] = ip.String()
		}
		e.cfg.VPN.ServerIPs = newIPs
		e.log.Infof("refreshed VPN server IPs: %v", newIPs)
	}

	dnsServers, err := monitor.DetectVPNDNSServers(e.cfg.VPN.AdapterName)
	if err == nil && len(dnsServers) > 0 {
		newDNS := make([]string, len(dnsServers))
		for i, dns := range dnsServers {
			newDNS[i] = dns.String()
		}
		e.cfg.VPN.DNSServers = newDNS
		e.log.Infof("refreshed VPN DNS servers: %v", newDNS)
	}
}

func (e *Engine) transitionToLocked() {
	if e.state == StateLocked {
		return
	}

	if err := e.fw.Lock(); err != nil {
		e.log.Errorf("failed to lock firewall: %v", err)
		e.state = StateError
		return
	}

	if err := dns.FlushDNSCache(); err != nil {
		e.log.Debugf("DNS cache flush: %v", err)
	}

	e.state = StateLocked
	e.lastTransition = time.Now()
	e.log.Info("policy engine: LOCKED")
}

func (e *Engine) handleReconnecting() {
	if e.debounceTimer != nil {
		return
	}

	e.debounceTimer = time.AfterFunc(2*time.Second, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.debounceTimer = nil

		if e.state == StateUnlocked || e.state == StateLocked {
			return
		}
		e.transitionToLocked()
	})
}

func (e *Engine) State() KillSwitchState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state
}
