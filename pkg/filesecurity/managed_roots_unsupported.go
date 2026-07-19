//go:build !linux

package filesecurity

import (
	"io/fs"
	"os"
)

// ManagedRoots deliberately has no pathname-based fallback. ReCasaOS's
// privileged management file API is supported only where Linux openat2 can
// enforce its confinement policy.
type ManagedRoots struct{}

func RemoveManagementTree(string) error { return ErrManagedRootsUnsupported }

func OpenManagementFileRoots([]string) (*ManagedRoots, error) {
	return nil, ErrManagedRootsUnsupported
}

func OpenManagementFileRootsFromEnvironment() (*ManagedRoots, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) Close() error { return nil }

func (m *ManagedRoots) Match(string) (ManagedLocation, error) {
	return ManagedLocation{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) MatchChild(string, string) (ManagedLocation, error) {
	return ManagedLocation{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) OpenRegular(string) (*os.File, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) OpenPath(string) (*os.File, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) OpenDirectory(string) (*os.File, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) ChmodDirectory(string, fs.FileMode) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) Stat(string) (os.FileInfo, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CreateExclusive(string, fs.FileMode) (*os.File, error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) RewriteRegular(string, []byte) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) MkdirAll(string, fs.FileMode) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) Remove(string) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) RemoveAll(string) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) RenameNoReplace(string, string) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) DirectoryCount(string) (int, error) {
	return 0, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) TreeSize(string) (int64, error) {
	return 0, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CommitNoReplace(string, string) error {
	return ErrManagedRootsUnsupported
}
