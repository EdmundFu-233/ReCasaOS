//go:build !linux

package smbcredentials

// ProvisionSystemKeyringSource is Linux-only because its create-only
// publication contract depends on descriptor-relative Linux syscalls.
func ProvisionSystemKeyringSource() (ProvisionResult, error) {
	return ProvisionResult{}, ErrSourceProvisionUnsupported
}
