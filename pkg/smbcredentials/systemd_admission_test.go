package smbcredentials

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSystemdKeyringClassifiesOnlyUnsetEnvironmentAsNotProvided(t *testing.T) {
	t.Setenv(systemdCredentialsDirectoryEnvironment, "configured-then-removed")
	if err := os.Unsetenv(systemdCredentialsDirectoryEnvironment); err != nil {
		t.Fatal(err)
	}
	keyring, err := LoadSystemdKeyring()
	if keyring != nil {
		keyring.Destroy()
	}
	if keyring != nil || err != ErrSystemdCredentialNotProvided {
		t.Fatalf("unconfigured admission keyring=%v err=%v", keyring, err)
	}
}

func TestLoadSystemdKeyringTreatsEmptyEnvironmentAsConfiguredFailure(t *testing.T) {
	t.Setenv(systemdCredentialsDirectoryEnvironment, "")
	keyring, err := LoadSystemdKeyring()
	if keyring != nil {
		keyring.Destroy()
	}
	if keyring != nil || err == nil || errors.Is(err, ErrSystemdCredentialNotProvided) {
		t.Fatalf("empty configured admission keyring=%v err=%v", keyring, err)
	}
}

func TestLoadSystemdKeyringTreatsMissingConfiguredDirectoryAsFailure(t *testing.T) {
	t.Setenv(systemdCredentialsDirectoryEnvironment, filepath.Join(t.TempDir(), "missing"))
	keyring, err := LoadSystemdKeyring()
	if keyring != nil {
		keyring.Destroy()
	}
	if keyring != nil || err == nil || errors.Is(err, ErrSystemdCredentialNotProvided) {
		t.Fatalf("missing configured admission keyring=%v err=%v", keyring, err)
	}
}
