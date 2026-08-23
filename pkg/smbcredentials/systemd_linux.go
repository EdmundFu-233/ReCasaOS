//go:build linux

package smbcredentials

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maxKeyringBytes = len(keyringMagic) + 1 + 1 + keyIDSize + maxKeys*(keyIDSize+keySize)

// LoadSystemdKeyring reads the fixed credential name only from the directory
// supplied by systemd. It never accepts key bytes from argv or the environment.
func LoadSystemdKeyring() (*Keyring, error) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		return nil, errors.New("ReCasaOS SMB systemd credential directory is unavailable")
	}
	return LoadKeyringDirectory(directory)
}

// LoadKeyringDirectory validates and reads an already-established runtime
// credential directory. It does not prove source-file, ancestor-path, or PID 1
// provenance. The production service should use LoadSystemdKeyring.
func LoadKeyringDirectory(directory string) (*Keyring, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == string(filepath.Separator) {
		return nil, errors.New("invalid ReCasaOS SMB credential directory")
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open ReCasaOS SMB credential directory")
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&0o077 != 0 || directoryStat.Mode&0o500 != 0o500 || hasSpecialModeBits(directoryStat.Mode) {
		return nil, errors.New("unsafe ReCasaOS SMB credential directory")
	}
	credentialFD, err := unix.Openat(directoryFD, CredentialName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("open ReCasaOS SMB systemd credential")
	}
	credential := os.NewFile(uintptr(credentialFD), CredentialName)
	if credential == nil {
		_ = unix.Close(credentialFD)
		return nil, errors.New("open ReCasaOS SMB systemd credential")
	}
	defer credential.Close()
	var credentialStat unix.Stat_t
	if err := unix.Fstat(credentialFD, &credentialStat); err != nil || credentialStat.Mode&unix.S_IFMT != unix.S_IFREG || credentialStat.Nlink != 1 || credentialStat.Uid != uint32(os.Geteuid()) || credentialStat.Mode&0o777 != 0o400 || hasSpecialModeBits(credentialStat.Mode) {
		return nil, errors.New("unsafe ReCasaOS SMB systemd credential")
	}
	data, err := io.ReadAll(io.LimitReader(credential, int64(maxKeyringBytes+1)))
	if err != nil || len(data) > maxKeyringBytes {
		clear(data)
		return nil, errors.New("read ReCasaOS SMB systemd credential")
	}
	keyring, parseErr := ParseKeyring(data)
	clear(data)
	if parseErr != nil {
		return nil, fmt.Errorf("parse ReCasaOS SMB systemd credential: %w", parseErr)
	}
	return keyring, nil
}

func hasSpecialModeBits(mode uint32) bool {
	return mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0
}
