//go:build !linux

package smbcredentials

import (
	"errors"
	"os"
)

// LoadSystemdKeyring returns exactly ErrSystemdCredentialNotProvided when the
// process environment has no CREDENTIALS_DIRECTORY entry. A configured entry
// is a hard error because systemd credential loading requires Linux.
func LoadSystemdKeyring() (*Keyring, error) {
	if _, configured := os.LookupEnv(systemdCredentialsDirectoryEnvironment); !configured {
		return nil, ErrSystemdCredentialNotProvided
	}
	return nil, errors.New("ReCasaOS SMB systemd credentials require Linux")
}

// LoadKeyringDirectory is unavailable off Linux because its validation relies
// on Linux descriptor-relative filesystem semantics.
func LoadKeyringDirectory(string) (*Keyring, error) {
	return nil, errors.New("ReCasaOS SMB systemd credentials require Linux")
}
