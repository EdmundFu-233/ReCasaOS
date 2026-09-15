//go:build !linux

package smbcredentials

import (
	"errors"
	"testing"
)

func TestSourceKeyringProvisioningIsUnavailableOffLinux(t *testing.T) {
	result, err := ProvisionSystemKeyringSource()
	if result != (ProvisionResult{}) || !errors.Is(err, ErrSourceProvisionUnsupported) {
		t.Fatalf("ProvisionSystemKeyringSource() result=%+v err=%v", result, err)
	}
}
