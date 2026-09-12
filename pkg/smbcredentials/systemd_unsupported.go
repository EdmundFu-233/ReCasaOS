//go:build !linux

package smbcredentials

import "errors"

func LoadSystemdKeyring() (*Keyring, error) {
	return nil, errors.New("ReCasaOS SMB systemd credentials require Linux")
}

func LoadKeyringDirectory(string) (*Keyring, error) {
	return nil, errors.New("ReCasaOS SMB systemd credentials require Linux")
}
