package monitor

import (
	"context"
	"sync"
	"time"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/logger"
)

type VPNState int

const (
	VPNStateDown VPNState = iota
	VPNStateUp
	VPNStateReconnecting
)

func (s VPNState) String() string {
	switch s {
	case VPNStateDown:
		return "DOWN"
	case VPNStateUp:
		return "UP"
	case VPNStateReconnecting:
		return "RECONNECTING"
	default:
		return "UNKNOWN"
	}
}

type StateChangeCallback func(newState VPNState)

type Monitor struct {
	cfg      *config.Config
	log      *logger.Logger
	callback StateChangeCallback

	mu       sync.RWMutex
	state    VPNState
	cancelFn context.CancelFunc
}

func New(cfg *config.Config, log *logger.Logger, cb StateChangeCallback) *Monitor {
	return &Monitor{
		cfg:      cfg,
		log:      log,
		callback: cb,
		state:    VPNStateDown,
	}
}

func (m *Monitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	if m.cfg.Monitor.EventDriven {
		go m.runEventLoop(ctx)
	}

	go m.runBackupPoll(ctx)
	go m.runProcessWatch(ctx)

	m.log.Info("network monitor started")
	return nil
}

func (m *Monitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.log.Info("network monitor stopped")
}

func (m *Monitor) CurrentState() VPNState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Monitor) setState(newState VPNState) {
	m.mu.Lock()
	oldState := m.state
	m.state = newState
	m.mu.Unlock()

	if oldState != newState {
		m.log.Infof("VPN state changed: %s -> %s", oldState, newState)
		if m.callback != nil {
			m.callback(newState)
		}
	}
}

func (m *Monitor) runBackupPoll(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.Monitor.BackupPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkVPNStatus()
		}
	}
}

func (m *Monitor) checkVPNStatus() {
	iface := DetectVPNInterface(m.cfg.VPN.AdapterName)
	if iface == nil {
		m.setState(VPNStateDown)
		return
	}

	if !iface.IsUp {
		m.setState(VPNStateDown)
		return
	}

	if !HasValidVPNIP(iface, m.cfg.Monitor.VPNIPRange) {
		m.setState(VPNStateReconnecting)
		return
	}

	m.setState(VPNStateUp)
}
