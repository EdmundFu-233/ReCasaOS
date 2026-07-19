//go:build !linux

package filesecurity

func (m *ManagedRoots) IsMountPoint(string) (bool, error) {
	return false, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) RemoveEmptyDirectory(string) error {
	return ErrManagedRootsUnsupported
}
