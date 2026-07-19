package filesecurity

import (
	"errors"
	"sync"
)

var (
	managementRootsMu sync.RWMutex
	managementRoots   *ManagedRoots
)

// InstallManagementFileRoots installs the startup-pinned root set used by the
// privileged management file handlers. It does not close a previously
// installed set; ownership and lifetime remain with the application or test.
func InstallManagementFileRoots(roots *ManagedRoots) error {
	if roots == nil {
		return errors.New("management file roots are nil")
	}
	managementRootsMu.Lock()
	managementRoots = roots
	managementRootsMu.Unlock()
	return nil
}

// ManagementFileRoots returns the installed fail-closed root set.
func ManagementFileRoots() (*ManagedRoots, error) {
	managementRootsMu.RLock()
	roots := managementRoots
	managementRootsMu.RUnlock()
	if roots == nil {
		return nil, errors.New("management file roots are not initialized")
	}
	return roots, nil
}
