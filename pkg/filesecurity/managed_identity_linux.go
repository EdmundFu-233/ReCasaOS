//go:build linux

package filesecurity

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func managedFileIdentityFromStat(stat *unix.Stat_t) ManagedFileIdentity {
	if stat == nil {
		return ManagedFileIdentity{}
	}
	return ManagedFileIdentity{
		Device:              uint64(stat.Dev),
		Inode:               stat.Ino,
		Mode:                stat.Mode,
		Links:               uint64(stat.Nlink),
		Size:                stat.Size,
		ModifiedSeconds:     int64(stat.Mtim.Sec),
		ModifiedNanoseconds: int64(stat.Mtim.Nsec),
		ChangedSeconds:      int64(stat.Ctim.Sec),
		ChangedNanoseconds:  int64(stat.Ctim.Nsec),
	}
}

func captureManagedPublishedIdentity(parentFD int, name string) (ManagedFileIdentity, error) {
	publishedFD, err := unix.Openat(parentFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ManagedFileIdentity{}, err
	}
	defer unix.Close(publishedFD)
	var publishedStat unix.Stat_t
	if err := unix.Fstat(publishedFD, &publishedStat); err != nil {
		return ManagedFileIdentity{}, err
	}
	if publishedStat.Mode&unix.S_IFMT != unix.S_IFREG || publishedStat.Nlink != 1 {
		return ManagedFileIdentity{}, fmt.Errorf("%w: committed upload target is not a single-link regular file", ErrUnsafePath)
	}
	if err := verifyManagedNameIdentity(parentFD, name, &publishedStat); err != nil {
		return ManagedFileIdentity{}, err
	}
	return managedFileIdentityFromStat(&publishedStat), nil
}

// VerifyRegularIdentity performs only descriptor and no-follow name stat
// checks under the mutation lease. It deliberately never reads file contents,
// keeping completed-upload replay verification O(1) even for very large files.
func (m *ManagedRoots) VerifyRegularIdentity(absolutePath string, expected ManagedFileIdentity) error {
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()

	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	opened, err := openManagedAt(root, location, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	defer opened.Close()
	var descriptorStat unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &descriptorStat); err != nil {
		return err
	}
	if descriptorStat.Mode&unix.S_IFMT != unix.S_IFREG || descriptorStat.Nlink != 1 {
		return fmt.Errorf("%w: completed upload target is not a single-link regular file", ErrUnsafePath)
	}
	if managedFileIdentityFromStat(&descriptorStat) != expected {
		return fmt.Errorf("%w: completed upload target identity changed", ErrUnsafePath)
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
	if err := verifyManagedNameIdentity(parentFD, base, &descriptorStat); err != nil {
		return fmt.Errorf("%w: completed upload target name identity changed", ErrUnsafePath)
	}
	return nil
}
