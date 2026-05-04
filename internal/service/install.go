package service

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func (s *Service) Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	existingSvc, err := m.OpenService(s.cfg.Service.Name)
	if err == nil {
		existingSvc.Close()
		return fmt.Errorf("service %q already exists", s.cfg.Service.Name)
	}

	var startType uint32 = mgr.StartManual
	if s.cfg.Service.AutoStart {
		startType = mgr.StartAutomatic
	}

	svcObj, err := m.CreateService(
		s.cfg.Service.Name,
		exePath,
		mgr.Config{
			DisplayName:  s.cfg.Service.DisplayName,
			Description:  s.cfg.Service.Description,
			StartType:    startType,
			Dependencies: []string{"BFE"},
		},
		"run",
	)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer svcObj.Close()

	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 0},
		{Type: mgr.ServiceRestart, Delay: 0},
	}
	if err := svcObj.SetRecoveryActions(recoveryActions, 86400); err != nil {
		s.log.Warnf("failed to set recovery actions: %v", err)
	}

	return nil
}

func (s *Service) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	svcObj, err := m.OpenService(s.cfg.Service.Name)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer svcObj.Close()

	status, err := svcObj.Query()
	if err == nil && status.State != svc.Stopped {
		_, _ = svcObj.Control(svc.Stop)
		time.Sleep(2 * time.Second)
	}

	if err := svcObj.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	// TODO: Remove persistent WFP filters here
	s.log.Info("service uninstalled, persistent filters should be removed")

	return nil
}

func (s *Service) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	svcObj, err := m.OpenService(s.cfg.Service.Name)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer svcObj.Close()

	return svcObj.Start()
}

func (s *Service) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	svcObj, err := m.OpenService(s.cfg.Service.Name)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer svcObj.Close()

	_, err = svcObj.Control(svc.Stop)
	return err
}

func (s *Service) Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	svcObj, err := m.OpenService(s.cfg.Service.Name)
	if err != nil {
		return "NOT INSTALLED", nil
	}
	defer svcObj.Close()

	status, err := svcObj.Query()
	if err != nil {
		return "", fmt.Errorf("query service: %w", err)
	}

	switch status.State {
	case svc.Stopped:
		return "STOPPED", nil
	case svc.Running:
		return "RUNNING", nil
	case svc.StartPending:
		return "START_PENDING", nil
	case svc.StopPending:
		return "STOP_PENDING", nil
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status.State), nil
	}
}
