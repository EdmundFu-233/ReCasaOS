//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

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
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return false, err
	}
	defer unix.Close(parentFD)

	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return false, err
	}
	targetFD, err := unix.Openat2(parentFD, base, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return false, classifyManagedResolutionError(err)
	}
	defer unix.Close(targetFD)
	targetMountID, err := managedMountIDAt(targetFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return false, err
	}
	return targetMountID != parentMountID, nil
}

// RemoveEmptyDirectory removes exactly one empty, non-mounted directory. It
// never recurses and refuses to remove a mount boundary.
func (m *ManagedRoots) RemoveEmptyDirectory(absolutePath string) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)

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
	return nil
}
