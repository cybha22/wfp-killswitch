package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/dns"
	"github.com/muhsh/advanced-killswitch/internal/firewall"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	"github.com/muhsh/advanced-killswitch/internal/monitor"
	"github.com/muhsh/advanced-killswitch/internal/policy"
	"golang.org/x/sys/windows/svc"
)

type Service struct {
	cfg         *config.Config
	log         *logger.Logger
	isDebugMode bool
}

func New(cfg *config.Config, log *logger.Logger) *Service {
	return &Service{cfg: cfg, log: log}
}

func (s *Service) Run() error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect service mode: %w", err)
	}

	if !isService {
		return s.RunInteractive()
	}

	return svc.Run(s.cfg.Service.Name, &svcHandler{svc: s})
}

func (s *Service) RunInteractive() error {
	s.log.Info("running in interactive/debug mode")
	s.isDebugMode = true
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		s.log.Info("received shutdown signal")
		cancel()
	}()

	return s.runCore(ctx)
}

func (s *Service) runCore(ctx context.Context) error {
	fw := firewall.NewController(s.cfg, s.log)
	if err := fw.Initialize(); err != nil {
		return fmt.Errorf("firewall init: %w", err)
	}

	var dnsGuard *dns.Guard
	if s.cfg.Firewall.DNSLeakProtection && fw.Session() != nil {
		dnsGuard = dns.NewGuard(s.cfg, s.log, fw.Session().RawSession())
		if err := dnsGuard.Enable(); err != nil {
			s.log.Warnf("DNS guard enable failed: %v", err)
		} else {
			s.log.Info("DNS leak protection active")
		}
	}

	engine := policy.NewEngine(s.cfg, s.log, fw)

	mon := monitor.New(s.cfg, s.log, engine.HandleVPNStateChange)
	if err := mon.Start(ctx); err != nil {
		return fmt.Errorf("monitor start: %w", err)
	}

	s.log.Info("kill switch active")
	<-ctx.Done()

	s.log.Info("shutting down...")
	mon.Stop()

	if dnsGuard != nil {
		if err := dnsGuard.Disable(); err != nil {
			s.log.Warnf("DNS guard disable failed: %v", err)
		}
	}

	keepPersistent := s.cfg.Firewall.BootTimeProtection && !s.isDebugMode
	if err := fw.Shutdown(keepPersistent); err != nil {
		s.log.Errorf("firewall shutdown error: %v", err)
	}

	return nil
}

type svcHandler struct {
	svc *Service
}

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- h.svc.runCore(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				h.svc.log.Errorf("service error: %v", err)
				return true, 1
			}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-errCh
				return false, 0

			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		}
	}
}
