//go:build linux

package service

import (
	"strings"
	"testing"
)

func TestSambaMountOptionsRequireMessageSigning(t *testing.T) {
	options := sambaMountOptions("alice", "secret", "445")
	for _, required := range []string{"sec=ntlmsspi", "sign"} {
		if !strings.Contains(","+options+",", ","+required+",") {
			t.Fatalf("mount options %q do not require %q", options, required)
		}
	}
}
