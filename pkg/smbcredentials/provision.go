package smbcredentials

import "errors"

const (
	// SourceKeyringPath is the only source path accepted by the production
	// provisioner. The source is intended for a future systemd LoadCredential=
	// boundary; provisioning it does not make it a runtime credential.
	SourceKeyringPath = "/etc/recasaos/" + CredentialName
)

var (
	// ErrSourceKeyringExists means the fixed destination is occupied by an
	// unvalidated object. It is a hard HOLD, never idempotent success.
	ErrSourceKeyringExists = errors.New(
		"ReCasaOS SMB source keyring destination is occupied and unvalidated",
	)
	ErrUnsafeSourceKeyring        = errors.New("unsafe ReCasaOS SMB source keyring boundary")
	ErrSourceProvisionUnsupported = errors.New(
		"ReCasaOS SMB source keyring provisioning is unsupported",
	)
	ErrSourceCleanupRequired = errors.New(
		"ReCasaOS SMB source keyring namespace recovery is required",
	)
)

// ProvisionResult separates namespace publication from durability and cleanup.
// A caller must never generate another key when Created is true, even when an
// error is returned. DurabilityUnknown and CleanupRequired are fail-closed HOLD
// states which require operator recovery before any retry. CleanupRequired
// also covers a namespace which could not be inspected well enough to prove
// that no staging object remains. An
// ErrSourceKeyringExists result is also a hard HOLD: the existing object was
// deliberately neither opened nor validated and must not be accepted as an
// already-provisioned keyring.
type ProvisionResult struct {
	Created           bool
	DurabilityUnknown bool
	CleanupRequired   bool
}
