//go:build linux

package samba

import (
	"os"
	"testing"
	"time"
)

func TestRealProbeSandboxDropsIdentityAndAppliesLimitsBeforeReady(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to verify the production root-to-nobody exec boundary")
	}
	restoreProbeTestCommand(t, "identity", 2*time.Second)
	shares, err := GetSambaSharesList("nas.local", "445", "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 1 || shares[0] != "Media" {
		t.Fatalf("identity helper shares = %#v", shares)
	}
}
