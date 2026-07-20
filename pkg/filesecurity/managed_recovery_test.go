package filesecurity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManagedTransferObservedIdentityJSONPreservesLargeValuesAsStrings(t *testing.T) {
	result := ManagedTransferInventoryResult{
		Parent:    "/DATA/destination",
		Complete:  false,
		Truncated: true,
		Findings: []string{
			ManagedTransferFindingCandidateLimitExceeded,
			ManagedTransferFindingConcurrentMutation,
		},
		Items: []ManagedTransferInventoryItem{{
			Name:          ".recasaos-transfer-0123456789abcdef0123456789abcdef",
			ObservedState: ManagedTransferObservedUnverified,
			RecoveryRole:  ManagedTransferRecoveryRoleUnknown,
			Finding:       ManagedTransferFindingContentsUnexpected,
			Identity: &ManagedTransferObservedIdentity{
				MountID: "0020000000000001",
				Device:  "0020000000000002",
				Inode:   "0020000000000003",
				Mode:    0o40700,
				Links:   "9007199254740996",
				Size:    "9007199254740997",
				Type:    "directory",
			},
		}},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{
		`"mount_id":"0020000000000001"`,
		`"device":"0020000000000002"`,
		`"inode":"0020000000000003"`,
		`"links":"9007199254740996"`,
		`"size":"9007199254740997"`,
		`"recovery_role":"unknown"`,
		`"finding":"contents_unexpected"`,
		`"findings":["candidate_limit_exceeded","concurrent_mutation"]`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("JSON lost exact identity %s: %s", expected, text)
		}
	}
	if strings.Contains(text, "safe_to_delete") {
		t.Fatalf("inventory exposed a deletion authorization: %s", text)
	}
}
