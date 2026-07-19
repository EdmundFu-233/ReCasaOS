//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// MountID returns the kernel mount identity for an already opened managed
// descriptor. Callers can pair it with a mutation lease to bind mountinfo
// validation to the exact directory inode used before or after mount changes.
func (m *ManagedRoots) MountID(opened *os.File) (uint64, error) {
	if m == nil || opened == nil {
		return 0, ErrUnsafePath
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, fs.ErrClosed
	}
	return managedMountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
}

// IsMountPoint reports whether absolutePath is a mount boundary below one of
// the pinned management roots. Both the parent and target are inspected with
// descriptor-relative statx calls, so a pathname swap cannot redirect the
// comparison outside the authorized root.
func (m *ManagedRoots) IsMountPoint(absolutePath string) (bool, error) {
	if m == nil {
		return false, ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return false, fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return false, err
	}
	parentFD, _, err := openManagedParent(root, location)
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)

	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return false, err
	}
	target, err := openManagedAt(root, location, unix.O_PATH, 0)
	if err != nil {
		return false, err
	}
	defer target.Close()
	if err := validateManagedOpenedFile(target, true); err != nil {
		return false, err
	}
	targetMountID, err := managedMountIDAt(int(target.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return false, err
	}
	return targetMountID != parentMountID, nil
}

// RemoveEmptyDirectory removes exactly one empty, non-mounted directory. It
// never recurses and refuses to remove a mount boundary.
func (m *ManagedRoots) RemoveEmptyDirectory(absolutePath string) error {
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	parentLocation, err := m.matchLocked(filepath.Dir(location.Canonical))
	if err != nil {
		return err
	}
	if err := m.validateManagedDestinationFD(root, parentFD, parentLocation); err != nil {
		return err
	}

	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	targetMountID, err := managedMountIDAt(parentFD, base, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if targetMountID != parentMountID {
		return fmt.Errorf("%w: refusing to remove a mount boundary", ErrUnsafePath)
	}
	if err := unix.Unlinkat(parentFD, base, unix.AT_REMOVEDIR); err != nil {
		if errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("%w: managed mount path is not a directory", ErrUnsafePath)
		}
		return err
	}
	return m.syncManagedDirectory(parentFD, "sync removed empty directory parent", true)
}
