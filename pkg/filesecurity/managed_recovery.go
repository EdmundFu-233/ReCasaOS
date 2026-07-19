package filesecurity

// ManagedTransferObservedState describes only the transaction shape that the
// inventory could prove at observation time. It deliberately does not claim a
// recovery role: without a durable ledger, an "entry" may be unpublished
// staging or an exchanged old target.
type ManagedTransferObservedState string

const (
	managedTransferTransactionPrefix          = ".recasaos-transfer-"
	managedTransferTransactionRandomHexLength = 32

	ManagedTransferObservedEmptyUnclassified        ManagedTransferObservedState = "empty_unclassified"
	ManagedTransferObservedEntryPresentUnclassified ManagedTransferObservedState = "entry_present_unclassified"
	ManagedTransferObservedUnverified               ManagedTransferObservedState = "unverified"
)

const ManagedTransferRecoveryRoleUnknown = "unknown"

// Stable, non-sensitive finding codes keep raw syscall errors and host details
// out of the authenticated inventory response.
const (
	ManagedTransferFindingCandidateOpenFailed      = "candidate_open_failed"
	ManagedTransferFindingCandidateMetadataUnsafe  = "candidate_metadata_unsafe"
	ManagedTransferFindingCandidateIdentityChanged = "candidate_identity_changed"
	ManagedTransferFindingParentIdentityChanged    = "parent_identity_changed"
	ManagedTransferFindingContentsUnexpected       = "contents_unexpected"
	ManagedTransferFindingEntryOpenFailed          = "entry_open_failed"
	ManagedTransferFindingEntryMetadataUnsafe      = "entry_metadata_unsafe"
	ManagedTransferFindingEntryMountChanged        = "entry_mount_changed"
	ManagedTransferFindingEntryIdentityChanged     = "entry_identity_changed"
	ManagedTransferFindingDirectoryReadFailed      = "directory_read_failed"
	ManagedTransferFindingEntryLimitExceeded       = "entry_limit_exceeded"
	ManagedTransferFindingCandidateLimitExceeded   = "candidate_limit_exceeded"
	ManagedTransferFindingConcurrentMutation       = "concurrent_mutation"
)

// ManagedTransferObservedIdentity is descriptor-derived metadata for an
// observed transaction or its single "entry" child. It is evidence for manual
// review, not authorization to delete the object.
type ManagedTransferObservedIdentity struct {
	MountID string `json:"mount_id"`
	Device  string `json:"device"`
	Inode   string `json:"inode"`
	Mode    uint32 `json:"mode"`
	Links   string `json:"links"`
	Size    string `json:"size"`
	Type    string `json:"type"`
}

// ManagedTransferInventoryItem reports one exact-format transaction name.
// RecoveryRole remains "unknown" until Issue #17 adds a crash-safe ledger.
type ManagedTransferInventoryItem struct {
	Name          string                           `json:"name"`
	ObservedState ManagedTransferObservedState     `json:"observed_state"`
	RecoveryRole  string                           `json:"recovery_role"`
	Finding       string                           `json:"finding,omitempty"`
	Identity      *ManagedTransferObservedIdentity `json:"identity,omitempty"`
	EntryIdentity *ManagedTransferObservedIdentity `json:"entry_identity,omitempty"`
}

// ManagedTransferInventoryResult is a bounded snapshot of one explicitly
// requested parent directory. Complete is false whenever a read failed or a
// response bound omitted candidates; Truncated distinguishes bound exhaustion
// from an observation error.
type ManagedTransferInventoryResult struct {
	Parent         string                         `json:"parent"`
	Items          []ManagedTransferInventoryItem `json:"items"`
	Complete       bool                           `json:"complete"`
	Truncated      bool                           `json:"truncated"`
	Scanned        int                            `json:"scanned"`
	CandidateCount int                            `json:"candidate_count"`
	Findings       []string                       `json:"findings,omitempty"`
}
