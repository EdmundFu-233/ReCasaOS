package main

import (
	"errors"
	"os"

	"github.com/IceWhaleTech/CasaOS/pkg/samba"
	"github.com/IceWhaleTech/CasaOS/pkg/smbcredentials"
)

// isInternalSambaProbeInvocation identifies the private Samba probe child
// invocation. It is platform-neutral so the exact argument contract can be
// asserted by every contributor platform's test run.
func isInternalSambaProbeInvocation() bool {
	return len(os.Args) == 2 && os.Args[1] == samba.InternalProbeArgument
}

// admitStartupSMBCredential validates the optional systemd credential payload
// before the Linux runtime starts any storage work. It stays platform-neutral
// so the startup admission contract can be compiled and tested on every
// contributor platform, including the Darwin compile-only CI job.
func admitStartupSMBCredential(load func() (*smbcredentials.Keyring, error)) (bool, error) {
	if load == nil {
		return false, errors.New("ReCasaOS SMB systemd credential loader is unavailable")
	}
	keyring, err := load()
	if keyring != nil {
		defer keyring.Destroy()
	}
	if keyring == nil && err == smbcredentials.ErrSystemdCredentialNotProvided {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if keyring == nil {
		return false, errors.New("ReCasaOS SMB systemd credential loader returned no keyring")
	}
	return true, nil
}
