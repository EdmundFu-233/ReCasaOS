//go:build linux

package publicfiles

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const resolveUnderRoot = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

var (
	errPinnedObjectNotRegular         = errors.New("pinned object is not a single-link regular file")
	errPinnedIdentityChanged          = errors.New("pinned regular file identity changed during reopen")
	errPublicRootFilesystemNotAllowed = errors.New("public file root filesystem is not allowlisted")
)

type pinnedRegularReopener func(int) (int, error)

type pinnedRegularValidationError struct {
	err error
}

func (e *pinnedRegularValidationError) Error() string {
	return e.err.Error()
}

func (e *pinnedRegularValidationError) Unwrap() error {
	return e.err
}

type rootFilesystemIdentity struct {
	mountID uint64
	magic   int64
}

type rootFilesystemInspector func(int) (rootFilesystemIdentity, error)

type secureRoot struct {
	file           *os.File
	mountID        uint64
	filesystemType uint32
	mu             sync.RWMutex
	closed         bool
}

func openSecureRoot(absolutePath string) (*secureRoot, error) {
	return openSecureRootWith(absolutePath, inspectPublicRootFilesystem)
}

func openSecureRootWith(absolutePath string, inspect rootFilesystemInspector) (*secureRoot, error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer unix.Close(rootFD)

	relative := strings.TrimPrefix(absolutePath, "/")
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnsupported
		}
		return nil, errors.New("cannot securely open configured directory")
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return nil, errors.New("configured root is not a directory")
	}
	if inspect == nil {
		unix.Close(fd)
		return nil, errors.New("configured root filesystem inspector is unavailable")
	}
	identity, err := inspect(fd)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("cannot verify configured root filesystem: %w", err)
	}
	if identity.mountID == 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: kernel reported an invalid mount identifier", ErrUnsupported)
	}
	if _, allowed := publicRootFilesystemName(identity.magic); !allowed {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: filesystem type %#x; supported local filesystems are ext2/3/4, XFS, Btrfs, tmpfs, and F2FS", errPublicRootFilesystemNotAllowed, uint32(identity.magic))
	}
	root := &secureRoot{
		file:           os.NewFile(uintptr(fd), "public-file-root"),
		mountID:        identity.mountID,
		filesystemType: uint32(identity.magic),
	}

	// Probe both the exact openat2 policy and directory-read permission through
	// the already-pinned root descriptor. Reopening absolutePath here would
	// reintroduce a pathname-replacement race. There is intentionally no weaker
	// fallback for unreadable roots, older kernels, or rejecting seccomp
	// profiles.
	probe, err := root.open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		root.close()
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnsupported
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("configured root is not readable by the service user: %w", err)
		}
		return nil, errors.New("openat2 policy probe failed")
	}
	unix.Close(probe)
	return root, nil
}

func inspectPublicRootFilesystem(fd int) (rootFilesystemIdentity, error) {
	var identity rootFilesystemIdentity
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return identity, fmt.Errorf("inspect filesystem type from pinned root: %w", err)
	}
	identity.magic = int64(filesystem.Type)
	mountID, err := publicRootMountID(fd)
	if err != nil {
		return rootFilesystemIdentity{}, err
	}
	identity.mountID = mountID
	return identity, nil
}

func publicRootMountID(fd int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_DONT_SYNC, unix.STATX_TYPE|unix.STATX_MNT_ID, &stat); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return 0, fmt.Errorf("%w: statx mount identifiers: %v", ErrUnsupported, err)
		}
		return 0, fmt.Errorf("inspect mount identity from pinned root: %w", err)
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, fmt.Errorf("%w: kernel did not report a statx mount identifier", ErrUnsupported)
	}
	return stat.Mnt_id, nil
}

func publicRootFilesystemName(magic int64) (string, bool) {
	normalized := uint32(magic)
	if magic != int64(normalized) && magic != int64(int32(normalized)) {
		return "", false
	}
	switch normalized {
	case uint32(unix.EXT4_SUPER_MAGIC): // Shared by ext2, ext3, and ext4.
		return "ext2/3/4", true
	case uint32(unix.XFS_SUPER_MAGIC):
		return "XFS", true
	case uint32(unix.BTRFS_SUPER_MAGIC):
		return "Btrfs", true
	case uint32(unix.TMPFS_MAGIC):
		return "tmpfs", true
	case uint32(unix.F2FS_SUPER_MAGIC):
		return "F2FS", true
	default:
		return "", false
	}
}

func readVerifierFileSecure(absolutePath string) ([sha256.Size]byte, error) {
	return readVerifierFileSecureWith(absolutePath, reopenPinnedRegular)
}

func readVerifierFileSecureWith(absolutePath string, reopen pinnedRegularReopener) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, ErrUnsupported
	}
	defer unix.Close(rootFD)

	relative := strings.TrimPrefix(absolutePath, "/")
	if err := validateVerifierParentDirectory(rootFD, path.Dir(relative)); err != nil {
		return zero, err
	}

	fd, stat, err := openPinnedRegularValidated(func() (int, error) {
		return unix.Openat2(rootFD, relative, &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
	}, validateVerifierFileStat, reopen)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return zero, ErrUnsupported
		}
		if errors.Is(err, errPinnedObjectNotRegular) || errors.Is(err, errPinnedIdentityChanged) {
			return zero, errors.New("verifier file must be a stable single-link regular file")
		}
		var validationErr *pinnedRegularValidationError
		if errors.As(err, &validationErr) {
			return zero, validationErr.err
		}
		return zero, errors.New("cannot securely open verifier file")
	}
	file := os.NewFile(uintptr(fd), "public-file-verifier")
	defer file.Close()

	encoded, err := io.ReadAll(io.LimitReader(file, int64(publicVerifierFileMaxBytes+1)))
	if err != nil {
		return zero, errors.New("cannot read verifier file")
	}
	verifier, err := parsePublicVerifier(encoded)
	for index := range encoded {
		encoded[index] = 0
	}
	if err != nil {
		return zero, err
	}

	var afterRead unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &afterRead); err != nil {
		return zero, errors.New("cannot revalidate verifier file after reading")
	}
	if !sameStableRegularFile(&stat, &afterRead) ||
		stat.Size != afterRead.Size ||
		stat.Mtim != afterRead.Mtim ||
		stat.Ctim != afterRead.Ctim {
		return zero, errors.New("verifier file changed while it was being read")
	}
	if err := validateVerifierFileStat(&afterRead); err != nil {
		return zero, err
	}
	if err := revalidateVerifierPath(rootFD, relative, &afterRead); err != nil {
		return zero, err
	}
	return verifier, nil
}

func validateVerifierParentDirectory(rootFD int, relativeParent string) error {
	fd, err := unix.Openat2(rootFD, relativeParent, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return ErrUnsupported
		}
		return errors.New("cannot securely open verifier parent directory")
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("verifier parent must be a directory")
	}
	effectiveUID := uint32(os.Geteuid())
	if stat.Uid != 0 && stat.Uid != effectiveUID {
		return errors.New("verifier parent directory must be owned by root or the service user")
	}
	if stat.Mode&0o022 != 0 {
		return errors.New("verifier parent directory must not be writable by group or other users")
	}
	return nil
}

func validateVerifierFileStat(stat *unix.Stat_t) error {
	if !isSingleLinkRegular(stat) {
		return errors.New("verifier file must be a stable single-link regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("verifier file must be owned by the service user")
	}
	permissions := stat.Mode & 0o7777
	if permissions != 0o400 && permissions != 0o600 {
		return errors.New("verifier file permissions must be exactly 0400 or 0600")
	}
	return nil
}

func sameStableRegularFile(first, second *unix.Stat_t) bool {
	return isSingleLinkRegular(first) &&
		isSingleLinkRegular(second) &&
		first.Dev == second.Dev &&
		first.Ino == second.Ino
}

func revalidateVerifierPath(rootFD int, relative string, expected *unix.Stat_t) error {
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return errors.New("verifier path changed while it was being read")
	}
	defer unix.Close(fd)

	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil ||
		!sameStableRegularFile(expected, &current) ||
		expected.Size != current.Size ||
		expected.Mtim != current.Mtim ||
		expected.Ctim != current.Ctim ||
		validateVerifierFileStat(&current) != nil {
		return errors.New("verifier path changed while it was being read")
	}
	return nil
}

func (r *secureRoot) close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *secureRoot) open(relative string, flags int) (int, error) {
	if r == nil {
		return -1, unix.EBADF
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.file == nil {
		return -1, unix.EBADF
	}
	fd, err := unix.Openat2(int(r.file.Fd()), relative, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: resolveUnderRoot,
	})
	if err != nil {
		return -1, err
	}
	mountID, err := publicRootMountID(fd)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	if mountID != r.mountID {
		unix.Close(fd)
		return -1, unix.EXDEV
	}
	return fd, nil
}

func (r *secureRoot) list(relative string, maxEntries int) ([]Entry, error) {
	openPath := relative
	if openPath == "" {
		openPath = "."
	}
	fd, err := r.open(openPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "public-file-directory")
	defer directory.Close()

	names, err := directory.Readdirnames(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxEntries {
		return nil, errEntryLimit
	}

	entries := make([]Entry, 0, len(names))
	for _, name := range names {
		if !isSafeVisibleName(name) || strings.HasPrefix(name, ".") || strings.Contains(name, "/") {
			continue
		}
		childPath := name
		if relative != "" {
			childPath = path.Join(relative, name)
		}
		childFD, openErr := r.open(childPath, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW)
		if openErr != nil {
			if isHiddenFilesystemError(openErr) {
				continue
			}
			return nil, openErr
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(childFD, &stat)
		unix.Close(childFD)
		if statErr != nil {
			continue
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			entries = append(entries, Entry{Name: name, Type: "directory"})
		case unix.S_IFREG:
			// Multiple links make it impossible to prove that another name for
			// the inode does not exist outside the public root.
			if stat.Nlink == 1 {
				entries = append(entries, Entry{Name: name, Type: "file", Size: stat.Size})
			}
		}
	}
	return entries, nil
}

func (r *secureRoot) openRegular(relative string) (*os.File, fileInfo, error) {
	return r.openRegularWith(relative, reopenPinnedRegular)
}

func (r *secureRoot) openRegularWith(relative string, reopen pinnedRegularReopener) (*os.File, fileInfo, error) {
	fd, _, err := openPinnedRegular(func() (int, error) {
		return r.open(relative, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	}, reopen)
	if err != nil {
		if errors.Is(err, errPinnedObjectNotRegular) || errors.Is(err, errPinnedIdentityChanged) {
			return nil, nil, unix.EPERM
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), "public-file")
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, unix.EPERM
	}
	return file, info, nil
}

// openPinnedRegular first fixes the name to an O_PATH descriptor, validates
// that descriptor without invoking the target's data-open operation, and only
// then reopens that exact descriptor for reading. The procfd path is generated
// exclusively from a live descriptor; callers must never substitute a
// user-controlled pathname or fall back to opening the original pathname.
func openPinnedRegular(pin func() (int, error), reopen pinnedRegularReopener) (int, unix.Stat_t, error) {
	return openPinnedRegularValidated(pin, nil, reopen)
}

func openPinnedRegularValidated(
	pin func() (int, error),
	validate func(*unix.Stat_t) error,
	reopen pinnedRegularReopener,
) (int, unix.Stat_t, error) {
	var zero unix.Stat_t
	pinnedFD, err := pin()
	if err != nil {
		return -1, zero, err
	}
	defer unix.Close(pinnedFD)

	var before unix.Stat_t
	if err := unix.Fstat(pinnedFD, &before); err != nil {
		return -1, zero, fmt.Errorf("inspect pinned file: %w", err)
	}
	if !isSingleLinkRegular(&before) {
		return -1, zero, errPinnedObjectNotRegular
	}
	if validate != nil {
		if err := validate(&before); err != nil {
			return -1, zero, &pinnedRegularValidationError{err: err}
		}
	}
	if reopen == nil {
		return -1, zero, errors.New("pinned regular file reopener is unavailable")
	}

	dataFD, err := reopen(pinnedFD)
	if err != nil {
		return -1, zero, fmt.Errorf("reopen pinned regular file: %w", err)
	}
	closeData := true
	defer func() {
		if closeData {
			_ = unix.Close(dataFD)
		}
	}()

	var after unix.Stat_t
	if err := unix.Fstat(dataFD, &after); err != nil {
		return -1, zero, fmt.Errorf("inspect reopened regular file: %w", err)
	}
	if !isSingleLinkRegular(&after) {
		return -1, zero, errPinnedObjectNotRegular
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return -1, zero, errPinnedIdentityChanged
	}
	if validate != nil {
		if err := validate(&after); err != nil {
			return -1, zero, &pinnedRegularValidationError{err: err}
		}
	}

	closeData = false
	return dataFD, after, nil
}

func reopenPinnedRegular(pinnedFD int) (int, error) {
	return unix.Open(
		fmt.Sprintf("/proc/self/fd/%d", pinnedFD),
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
}

func isSingleLinkRegular(stat *unix.Stat_t) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
}

func isHiddenFilesystemError(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENOTDIR) ||
		errors.Is(err, unix.ELOOP) ||
		errors.Is(err, unix.EXDEV) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM)
}
