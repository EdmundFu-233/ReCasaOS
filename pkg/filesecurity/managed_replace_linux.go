//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxReplaceBaseBytes = 255
	maxReplaceDataBytes = 16 << 20
)

var (
	// ErrReplacePathUnsafe reports a destination that cannot be published
	// without pathname trust: non-absolute, unclean, overlong, or carrying
	// an unsafe final component.
	ErrReplacePathUnsafe = errors.New("refusing unsafe atomic replace destination")
	// ErrReplaceDataUnsafe reports payload or permission arguments outside
	// the publishable bounds.
	ErrReplaceDataUnsafe = errors.New("refusing unsafe atomic replace payload")
)

// ReplaceRegularFile atomically publishes data at absolutePath, replacing
// any existing destination. Unlike a CreateTemp-plus-Rename pair, every
// step after the initial split is descriptor-relative: the parent directory
// is pinned with O_PATH|O_DIRECTORY|O_NOFOLLOW, staging uses O_TMPFILE (or
// an O_EXCL fallback where the filesystem refuses it), and publication is
// a same-dirfd rename. An ancestor swap by an unprivileged actor between
// the split and the pin remains outside the trusted-host boundary; parents
// under operator-controlled directories are the expected case.
//
// Callers needing create-only semantics must use ManagedRoots.CreateExclusive
// instead: this helper intentionally replaces.
func ReplaceRegularFile(absolutePath string, data []byte, permission fs.FileMode) error {
	_, err := ReplaceRegularFileWithCommit(absolutePath, data, permission)
	return err
}

// ReplaceRegularFileWithCommit is ReplaceRegularFile with an explicit commit
// report. published becomes true once the destination name has been atomically
// replaced; a failure of the final parent-directory durability sync is then
// returned together with published == true so callers can keep committed
// in-memory state aligned with the new file. Every path that returns
// published == false leaves the destination untouched.
func ReplaceRegularFileWithCommit(absolutePath string, data []byte, permission fs.FileMode) (bool, error) {
	directoryPath, base, err := splitReplaceDestination(absolutePath)
	if err != nil {
		return false, err
	}
	if len(data) > maxReplaceDataBytes {
		return false, ErrReplaceDataUnsafe
	}
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return false, ErrReplaceDataUnsafe
	}
	parentFD, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("%w: pin replace parent: %v", ErrReplacePathUnsafe, err)
	}
	defer unix.Close(parentFD)
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return false, fmt.Errorf("%w: inspect replace parent: %v", ErrReplacePathUnsafe, err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, fmt.Errorf("%w: replace parent is not a directory", ErrReplacePathUnsafe)
	}

	staged, cleanup, err := stageReplaceTemporary(parentFD, permission)
	if err != nil {
		return false, err
	}
	published := false
	defer func() {
		if !published {
			cleanup()
		}
	}()
	if err := writeReplaceFull(staged.fd, data); err != nil {
		return false, err
	}
	if err := unix.Fchmod(staged.fd, uint32(permission.Perm())); err != nil {
		return false, fmt.Errorf("chmod replace staging: %w", err)
	}
	if err := unix.Fsync(staged.fd); err != nil {
		return false, fmt.Errorf("sync replace staging: %w", err)
	}
	if err := verifyReplaceStaging(staged.fd); err != nil {
		return false, err
	}
	if err := staged.publish(parentFD, base); err != nil {
		return false, err
	}
	published = true
	if err := unix.Fsync(parentFD); err != nil {
		return true, fmt.Errorf("sync replace parent: %w", err)
	}
	return true, nil
}

func splitReplaceDestination(absolutePath string) (string, string, error) {
	if absolutePath == "" || !filepath.IsAbs(absolutePath) || filepath.Clean(absolutePath) != absolutePath {
		return "", "", ErrReplacePathUnsafe
	}
	if strings.ContainsRune(absolutePath, 0) {
		return "", "", ErrReplacePathUnsafe
	}
	base := filepath.Base(absolutePath)
	if base == "." || base == ".." || base == "/" || len(base) == 0 || len(base) > maxReplaceBaseBytes {
		return "", "", ErrReplacePathUnsafe
	}
	if strings.ContainsAny(base, "/\x00") {
		return "", "", ErrReplacePathUnsafe
	}
	return filepath.Dir(absolutePath), base, nil
}

type replaceStaging struct {
	fd        int
	name      string
	anonymous bool
	closed    bool
}

func (staged *replaceStaging) closeStaging() {
	if staged == nil || staged.closed {
		return
	}
	unix.Close(staged.fd)
	staged.closed = true
}

func stageReplaceTemporary(parentFD int, permission fs.FileMode) (*replaceStaging, func(), error) {
	noop := func() {}
	fd, err := unix.Openat(parentFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, uint32(permission.Perm()))
	if err == nil {
		staged := &replaceStaging{fd: fd, anonymous: true}
		return staged, func() { staged.closeStaging() }, nil
	}
	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EINVAL) {
		return nil, noop, fmt.Errorf("stage replace temporary: %w", err)
	}
	name, err := replaceTemporaryName()
	if err != nil {
		return nil, noop, err
	}
	fd, err = unix.Openat(parentFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(permission.Perm()))
	if err != nil {
		return nil, noop, fmt.Errorf("stage replace named temporary: %w", err)
	}
	staged := &replaceStaging{fd: fd, name: name}
	return staged, func() {
		_ = unix.Unlinkat(parentFD, name, 0)
		staged.closeStaging()
	}, nil
}

func replaceTemporaryName() (string, error) {
	var random [16]byte
	if _, err := unix.Getrandom(random[:], 0); err != nil {
		return "", fmt.Errorf("seed replace temporary name: %w", err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	name := make([]byte, 0, 32)
	name = append(name, ".recasaos-replace-"...)
	for _, b := range random {
		name = append(name, alphabet[int(b)%len(alphabet)])
	}
	return string(name), nil
}

func writeReplaceFull(fd int, data []byte) error {
	for written := 0; written < len(data); {
		count, err := unix.Write(fd, data[written:])
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("write replace staging: %w", err)
		}
		if count == 0 {
			return fmt.Errorf("short write to replace staging: %w", ErrReplaceDataUnsafe)
		}
		written += count
	}
	return nil
}

func verifyReplaceStaging(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect replace staging: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: replace staging is not a regular file", ErrReplacePathUnsafe)
	}
	if stat.Nlink != 1 && stat.Nlink != 0 {
		return fmt.Errorf("%w: replace staging is linked", ErrReplacePathUnsafe)
	}
	return nil
}

func (staged *replaceStaging) publish(parentFD int, base string) error {
	name := staged.name
	if staged.anonymous {
		// linkat cannot overwrite, so even anonymous staging lands on a
		// temporary name first; the final step is always one same-dirfd
		// atomic rename.
		linked, err := replaceTemporaryName()
		if err != nil {
			staged.closeStaging()
			return err
		}
		procPath := fmt.Sprintf("/proc/self/fd/%d", staged.fd)
		if err := unix.Linkat(unix.AT_FDCWD, procPath, parentFD, linked, unix.AT_SYMLINK_FOLLOW); err != nil {
			staged.closeStaging()
			return fmt.Errorf("publish replace staging: %w", err)
		}
		staged.closeStaging()
		name = linked
	}
	if err := unix.Renameat2(parentFD, name, parentFD, base, 0); err != nil {
		if staged.anonymous {
			_ = unix.Unlinkat(parentFD, name, 0)
		} else {
			staged.closeStaging()
		}
		return fmt.Errorf("publish replace staging: %w", err)
	}
	staged.closeStaging()
	return nil
}
