package firewall

// PersistentFilterManager handles boot-time WFP filters that survive
// service restarts and system reboots.
//
// Architecture (same as Mullvad):
//   - Uses a SEPARATE non-dynamic WFP session
//   - Filters have FWPM_FILTER_FLAG_PERSISTENT flag
//   - Filters have FWPM_FILTER_FLAG_BOOTTIME flag
//   - Sublayer weight is 0xFFFF (highest possible)
//   - Contains ONLY block-all rules
//   - When the dynamic session starts, its PERMIT rules (lower weight)
//     allow VPN traffic through while persistent BLOCK remains as fallback
//
// Lifecycle:
//   Install/Start: Create persistent block-all filters
//   Running:       Dynamic session adds PERMIT rules for VPN
//   Stop:          Dynamic session closes (PERMIT removed), persistent BLOCK remains
//   Uninstall:     Remove persistent filters (internet restored)
//
// TODO: Implement using raw fwpuclnt.dll syscalls since tailscale/wf
// may not expose persistent filter flags directly.
// Reference: WireGuard's tunnel/firewall/blocker.go for raw WFP API usage.

// PersistentManager manages boot-time persistent WFP filters.
type PersistentManager struct {
	installed bool
}

// NewPersistentManager creates a new persistent filter manager.
func NewPersistentManager() *PersistentManager {
	return &PersistentManager{}
}

// Install creates persistent boot-time block-all filters.
func (pm *PersistentManager) Install() error {
	// TODO: Open non-dynamic WFP session
	// TODO: Create provider with persistent flag
	// TODO: Create sublayer with weight 0xFFFF
	// TODO: Add block-all rules with FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME
	// TODO: Close session (filters persist)
	pm.installed = true
	return nil
}

// Remove deletes all persistent filters.
func (pm *PersistentManager) Remove() error {
	// TODO: Open non-dynamic WFP session
	// TODO: Enumerate and delete our persistent filters by provider GUID
	// TODO: Close session
	pm.installed = false
	return nil
}

// IsInstalled returns whether persistent filters are currently active.
func (pm *PersistentManager) IsInstalled() bool {
	return pm.installed
}
