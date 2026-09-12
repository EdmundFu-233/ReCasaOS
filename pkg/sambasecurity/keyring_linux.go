//go:build linux

package sambasecurity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LoadKeyring reads a pinned, single-link regular file owned by the effective
// service identity. CasaOS runs as root, so the packaged deployment requires a
// root-owned mode-0400 or mode-0600 keyring. Symlinks and replacement races fail
// closed.
func LoadKeyring(path string) (*Keyring, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("Samba credential keyring path must be a clean absolute non-root path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open Samba credential keyring: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open Samba credential keyring")
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()

	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, fmt.Errorf("inspect Samba credential keyring: %w", err)
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 ||
		opened.Uid != uint32(os.Geteuid()) || opened.Gid != uint32(os.Getegid()) ||
		opened.Mode&0o777 != 0o400 && opened.Mode&0o777 != 0o600 ||
		opened.Size <= 0 || opened.Size > maximumKeyring {
		return nil, errors.New("Samba credential keyring must be an owned single-link regular file with mode 0400 or 0600")
	}

	data, err := io.ReadAll(io.LimitReader(file, maximumKeyring+1))
	if err != nil || len(data) > maximumKeyring {
		clear(data)
		return nil, errors.New("read bounded Samba credential keyring")
	}
	var finalOpened, finalPath unix.Stat_t
	if err := unix.Fstat(fd, &finalOpened); err != nil {
		clear(data)
		return nil, fmt.Errorf("reinspect Samba credential keyring: %w", err)
	}
	if err := unix.Lstat(path, &finalPath); err != nil {
		clear(data)
		return nil, fmt.Errorf("reinspect Samba credential keyring path: %w", err)
	}
	if finalOpened.Dev != opened.Dev || finalOpened.Ino != opened.Ino ||
		finalOpened.Size != opened.Size || finalOpened.Mode != opened.Mode ||
		finalOpened.Uid != opened.Uid || finalOpened.Gid != opened.Gid ||
		finalPath.Dev != opened.Dev || finalPath.Ino != opened.Ino ||
		finalPath.Mode&unix.S_IFMT != unix.S_IFREG || finalPath.Nlink != 1 {
		clear(data)
		return nil, errors.New("Samba credential keyring changed while loading")
	}
	if err := file.Close(); err != nil {
		clear(data)
		return nil, fmt.Errorf("close Samba credential keyring: %w", err)
	}
	closed = true
	keyring, err := ParseKeyring(data)
	clear(data)
	return keyring, err
}
