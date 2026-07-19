//go:build linux

package filesecurity

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func commitNoReplaceAtomic(staging, destination string) (bool, error) {
	err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
	if err != nil {
		if errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			return true, errors.New("filesystem does not support atomic no-replace publication")
		}
		return true, err
	}

	parent, err := os.Open(filepath.Dir(destination))
	if err != nil {
		// The rename has already committed. A durability sync failure must not
		// be reported as an uncommitted upload and trigger a destructive retry.
		return true, nil
	}
	_ = parent.Sync()
	_ = parent.Close()
	return true, nil
}
