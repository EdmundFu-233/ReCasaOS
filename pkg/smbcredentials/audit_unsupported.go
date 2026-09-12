//go:build !linux

package smbcredentials

// CheckSystemKeyringSourceStructure is Linux-only because its fixed-path
// structural snapshot depends on descriptor-relative Linux metadata and
// no-follow semantics.
func CheckSystemKeyringSourceStructure() error {
	return ErrSourceAuditUnsupported
}
