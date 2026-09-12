//go:build !linux

package sambasecurity

import "errors"

func LoadKeyring(string) (*Keyring, error) {
	return nil, errors.New("Samba credential keyrings require Linux")
}
