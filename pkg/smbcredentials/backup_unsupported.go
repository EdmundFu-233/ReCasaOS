//go:build !linux

package smbcredentials

// BackupKeyring, RestoreKeyring, and RemoveBackup are Linux-only because the
// backup contract depends on descriptor-relative Linux syscalls.
func BackupKeyring(_ *Keyring) (BackupResult, error) {
	return BackupResult{}, ErrSourceProvisionUnsupported
}

// RestoreKeyring is Linux-only because the backup contract depends on
// descriptor-relative Linux syscalls.
func RestoreKeyring() (*Keyring, error) {
	return nil, ErrSourceProvisionUnsupported
}

// RemoveBackup is Linux-only because the backup contract depends on
// descriptor-relative Linux syscalls.
func RemoveBackup() (bool, error) {
	return false, ErrSourceProvisionUnsupported
}
