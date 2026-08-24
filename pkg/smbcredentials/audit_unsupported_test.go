//go:build !linux

package smbcredentials

import (
	"errors"
	"testing"
)

func TestSourceKeyringAuditIsUnavailableOffLinux(t *testing.T) {
	if err := CheckSystemKeyringSourceStructure(); !errors.Is(err, ErrSourceAuditUnsupported) {
		t.Fatalf("CheckSystemKeyringSourceStructure() error = %v", err)
	}
}
