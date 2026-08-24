//go:build !linux

package smbcredentials

import (
	"errors"
	"testing"
)

func TestSystemdCredentialLoaderIsUnavailableOffLinux(t *testing.T) {
	t.Setenv(systemdCredentialsDirectoryEnvironment, "/configured-but-unsupported")
	if keyring, err := LoadSystemdKeyring(); keyring != nil || err == nil || errors.Is(err, ErrSystemdCredentialNotProvided) {
		if keyring != nil {
			keyring.Destroy()
		}
		t.Fatalf("LoadSystemdKeyring() keyring=%v err=%v", keyring, err)
	}
	if keyring, err := LoadKeyringDirectory("/tmp/not-used"); keyring != nil || err == nil {
		if keyring != nil {
			keyring.Destroy()
		}
		t.Fatalf("LoadKeyringDirectory() keyring=%v err=%v", keyring, err)
	}
}
