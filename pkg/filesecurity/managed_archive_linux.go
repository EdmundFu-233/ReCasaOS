//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	managedArchiveChildDescriptorName       = "<managed-archive-child>"
	maxManagedArchiveTraversalEntries int64 = 100_000
	maxManagedArchiveTraversalDepth         = 128
)

type managedArchiveTraversalState struct {
	entries int64
}

// managedArchiveReader intentionally has no Fd or Close method. The callback
// cannot take ownership of, seek, or inspect the underlying descriptor.
type managedArchiveReader struct {
	read func([]byte) (int, error)
}

func (reader managedArchiveReader) Read(buffer []byte) (int, error) {
	return reader.read(buffer)
}

// WalkManagedArchive opens the selected path once through its startup-pinned
// management root, then walks every child relative to the still-open parent
// descriptor. It never reconstructs a child absolute path after enumeration.
// Existing mount crossings remain supported for /mnt and /media, but each
// child's name-side mount identity must match the descriptor opened from that
// name. Symlinks, magic links, special files, hard-linked regular files, name
// replacements, and mount replacements fail closed.
//
// The visitor runs without a ManagedRoots lock. This is intentional: archive
// output and reads from FUSE or network storage can block, while the already
// opened descriptor remains a complete capability even if ManagedRoots closes.
func (m *ManagedRoots) WalkManagedArchive(absolutePath string, visitor ManagedArchiveVisitor) (resultErr error) {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	if visitor == nil {
		return errors.New("managed archive visitor is nil")
	}

	opened, err := m.open(absolutePath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, opened.Close())
	}()
	if err := validateManagedOpenedFile(opened, true); err != nil {
		return err
	}
	// Snapshot the deterministic test seam before traversal. Production code
	// cannot access this unexported field, and no lock is held across callbacks.
	m.mu.RLock()
	afterChildSnapshot := m.archiveAfterChildSnapshot
	mountIDAt := m.archiveMountIDAt
	m.mu.RUnlock()
	if mountIDAt == nil {
		mountIDAt = managedMountIDAt
	}
	mountID, err := mountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}

	state := &managedArchiveTraversalState{}
	return walkManagedArchiveDescriptor(opened, "", mountID, 0, state, visitor, afterChildSnapshot, mountIDAt)
}

func walkManagedArchiveDescriptor(opened *os.File, relative string, expectedMountID uint64, depth int, state *managedArchiveTraversalState, visitor ManagedArchiveVisitor, afterChildSnapshot func(string) error, mountIDAt func(int, string, int) (uint64, error)) error {
	if opened == nil || state == nil {
		return ErrUnsafePath
	}
	if depth > maxManagedArchiveTraversalDepth {
		return errors.New("managed archive exceeds depth limit")
	}
	if state.entries >= maxManagedArchiveTraversalEntries {
		return errors.New("managed archive exceeds entry limit")
	}
	state.entries++

	var descriptorStat unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &descriptorStat); err != nil {
		return err
	}
	if err := validateManagedArchiveStat(&descriptorStat); err != nil {
		return err
	}
	descriptorMountID, err := mountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if descriptorMountID != expectedMountID {
		return fmt.Errorf("%w: managed archive descriptor mount identity changed", ErrUnsafePath)
	}
	info, err := opened.Stat()
	if err != nil {
		return err
	}

	switch descriptorStat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		reader := managedArchiveReader{read: opened.Read}
		return visitor(relative, depth, info, reader)
	case unix.S_IFDIR:
		if err := visitor(relative, depth, info, nil); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: managed archive entry is not an allowed file type", ErrUnsafePath)
	}

	for {
		names, readErr := opened.Readdirnames(256)
		for _, name := range names {
			child, childMountID, err := openManagedArchiveChild(int(opened.Fd()), name, afterChildSnapshot, mountIDAt)
			if err != nil {
				return err
			}
			childRelative := name
			if relative != "" {
				childRelative = filepath.Join(relative, name)
			}
			if err := walkAndCloseManagedArchiveChild(child, childRelative, childMountID, depth+1, state, visitor, afterChildSnapshot, mountIDAt); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func walkAndCloseManagedArchiveChild(child *os.File, relative string, expectedMountID uint64, depth int, state *managedArchiveTraversalState, visitor ManagedArchiveVisitor, afterChildSnapshot func(string) error, mountIDAt func(int, string, int) (uint64, error)) (resultErr error) {
	if child == nil {
		return ErrUnsafePath
	}
	defer func() {
		resultErr = errors.Join(resultErr, child.Close())
	}()
	return walkManagedArchiveDescriptor(child, relative, expectedMountID, depth, state, visitor, afterChildSnapshot, mountIDAt)
}

func openManagedArchiveChild(parentFD int, name string, afterSnapshot func(string) error, mountIDAt func(int, string, int) (uint64, error)) (*os.File, uint64, error) {
	if err := ValidatePathComponent(name); err != nil {
		return nil, 0, err
	}
	var expected unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, 0, err
	}
	if err := validateManagedArchiveStat(&expected); err != nil {
		return nil, 0, err
	}
	expectedNameMountID, err := mountIDAt(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return nil, 0, err
	}
	if afterSnapshot != nil {
		if err := afterSnapshot(name); err != nil {
			return nil, 0, err
		}
	}

	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, 0, classifyManagedResolutionError(err)
	}
	opened := os.NewFile(uintptr(fd), managedArchiveChildDescriptorName)
	if opened == nil {
		unix.Close(fd)
		return nil, 0, errors.New("open managed archive child")
	}
	closeWithError := func(openErr error) (*os.File, uint64, error) {
		return nil, 0, errors.Join(openErr, opened.Close())
	}

	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return closeWithError(err)
	}
	if err := validateManagedArchiveStat(&actual); err != nil {
		return closeWithError(err)
	}
	if !sameManagedTransferStat(&expected, &actual) {
		return closeWithError(fmt.Errorf("%w: managed archive child changed while opening", ErrUnsafePath))
	}
	actualMountID, err := mountIDAt(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return closeWithError(err)
	}
	if actualMountID != expectedNameMountID {
		return closeWithError(fmt.Errorf("%w: managed archive child mount changed while opening", ErrUnsafePath))
	}
	var nameAfter unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &nameAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return closeWithError(err)
	}
	if !sameManagedTransferStat(&actual, &nameAfter) {
		return closeWithError(fmt.Errorf("%w: managed archive child name changed while opening", ErrUnsafePath))
	}
	nameMountIDAfter, err := mountIDAt(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return closeWithError(err)
	}
	if nameMountIDAfter != actualMountID {
		return closeWithError(fmt.Errorf("%w: managed archive child name mount changed while opening", ErrUnsafePath))
	}
	return opened, actualMountID, nil
}

func validateManagedArchiveStat(stat *unix.Stat_t) error {
	if stat == nil {
		return ErrUnsafePath
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if stat.Nlink != 1 {
			return fmt.Errorf("%w: managed archive regular file has multiple hard links", ErrUnsafePath)
		}
		return nil
	case unix.S_IFDIR:
		return nil
	default:
		return fmt.Errorf("%w: managed archive entry is not an allowed file type", ErrUnsafePath)
	}
}
