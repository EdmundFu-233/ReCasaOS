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

func (m *ManagedRoots) RemoveAllBatch([]string) (ManagedBatchMutationResult, error) {
	return ManagedBatchMutationResult{}, ErrManagedRootsUnsupported
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

func (m *ManagedRoots) CommitNoReplaceWithIdentity(string, string) (ManagedFileIdentity, error) {
	return ManagedFileIdentity{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CommitNoReplaceWithExpectedIdentity(string, string, ManagedFileIdentity) (ManagedFileIdentity, error) {
	return ManagedFileIdentity{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CommitNoReplaceWithExpectedIdentityAndDigest(string, string, ManagedFileIdentity, [32]byte) (ManagedFileIdentity, error) {
	return ManagedFileIdentity{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) VerifyRegularIdentity(string, ManagedFileIdentity) error {
	return ErrManagedRootsUnsupported
}

func (m *ManagedRoots) CopyInto(string, string, ManagedConflictStyle) (ManagedTransferResult, error) {
	return ManagedTransferResult{}, ErrManagedRootsUnsupported
}

func (m *ManagedRoots) MoveInto(string, string, ManagedConflictStyle) (ManagedTransferResult, error) {
	return ManagedTransferResult{}, ErrManagedRootsUnsupported
}
