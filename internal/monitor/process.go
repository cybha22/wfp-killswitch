package monitor

import (
	"context"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (m *Monitor) runProcessWatch(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !m.isAnyVPNProcessRunning() {
				m.log.Warn("no ProtonVPN processes detected")
				m.setState(VPNStateDown)
			}
		}
	}
}

func (m *Monitor) isAnyVPNProcessRunning() bool {
	for _, procPath := range m.cfg.VPN.ProcessPaths {
		procName := strings.ToLower(filepath.Base(procPath))
		if isProcessRunning(procName) {
			return true
		}
	}
	return false
}

func isProcessRunning(name string) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		exeName := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if exeName == name {
			return true
		}
		err = windows.Process32Next(snapshot, &entry)
	}

	return false
}
