//go:build !linux

package filesecurity

// WalkManagedArchive has no pathname-based fallback. Managed archive traversal
// is available only where Linux openat2 can enforce descriptor confinement.
func (m *ManagedRoots) WalkManagedArchive(string, ManagedArchiveVisitor) error {
	return ErrManagedRootsUnsupported
}
