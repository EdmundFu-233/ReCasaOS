//go:build !linux

package smbcredentials

import "testing"

func TestSystemdCredentialLoaderIsUnavailableOffLinux(t *testing.T) {
	if keyring, err := LoadSystemdKeyring(); keyring != nil || err == nil {
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
