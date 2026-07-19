//go:build !linux

package filesecurity

import (
	"io/fs"
)

type ManagedWritableFile struct{}

func (f *ManagedWritableFile) Write([]byte) (int, error) { return 0, ErrManagedRootsUnsupported }
func (f *ManagedWritableFile) Sync() error               { return ErrManagedRootsUnsupported }
func (f *ManagedWritableFile) Close() error              { return ErrManagedRootsUnsupported }
func (f *ManagedWritableFile) Abort() error              { return nil }
func (f *ManagedWritableFile) PublishedIdentity() (ManagedFileIdentity, error) {
	return ManagedFileIdentity{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) AcquireMutation() (func(), error) {
	return nil, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CreateExclusive(string, fs.FileMode) (*ManagedWritableFile, error) {
	return nil, ErrManagedRootsUnsupported
}
