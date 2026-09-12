package smbcredentials

import "errors"

const systemdCredentialsDirectoryEnvironment = "CREDENTIALS_DIRECTORY"

// ErrSystemdCredentialNotProvided is returned only when the process
// environment has no CREDENTIALS_DIRECTORY entry.
var ErrSystemdCredentialNotProvided = errors.New("ReCasaOS SMB systemd credential was not provided")
