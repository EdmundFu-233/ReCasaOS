package smbcredentials

import "errors"

var (
	// ErrSourceKeyringMissing means the fixed source object was absent when a
	// read-only structural snapshot stably confirmed the safe namespace empty.
	// It does not by itself authorize provisioning or retry.
	ErrSourceKeyringMissing = errors.New("ReCasaOS SMB source keyring is missing")
	// ErrSourceAuditUnsupported means the fixed-path source audit cannot
	// provide its Linux descriptor-relative contract on this platform.
	ErrSourceAuditUnsupported = errors.New(
		"ReCasaOS SMB source keyring audit is unsupported",
	)
)
