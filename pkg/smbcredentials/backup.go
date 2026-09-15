package smbcredentials

import "errors"

var ErrBackupExists = errors.New("ReCasaOS SMB keyring backup already exists")

// BackupResult reports a completed keyring backup. CleanupRequired is a hard
// HOLD: a staging object was left behind and the operator must remove it and
// retry before trusting any backup.
type BackupResult struct {
	Created           bool
	CleanupRequired   bool
	DurabilityUnknown bool
}
