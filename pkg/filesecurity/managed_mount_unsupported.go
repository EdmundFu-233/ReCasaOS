//go:build !linux

package filesecurity

import "os"

func (m *ManagedRoots) MountID(*os.File) (uint64, error) {
	return 0, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) AvailableBytes(string) (uint64, error) {
	return 0, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) IsMountPoint(string) (bool, error) {
	return false, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) RemoveEmptyDirectory(string) error {
	return ErrManagedRootsUnsupported
}
