//go:build linux

package publicfiles

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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

func readTokenFileSecure(absolutePath string) ([]byte, error) {
	return readTokenFileSecureWith(absolutePath, reopenPinnedRegular)
}

func readTokenFileSecureWith(absolutePath string, reopen pinnedRegularReopener) ([]byte, error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer unix.Close(rootFD)

	fd, stat, err := openPinnedRegular(func() (int, error) {
		return unix.Openat2(rootFD, strings.TrimPrefix(absolutePath, "/"), &unix.OpenHow{
			Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		})
	}, reopen)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnsupported
		}
		if errors.Is(err, errPinnedObjectNotRegular) || errors.Is(err, errPinnedIdentityChanged) {
			return nil, errors.New("token file must be a stable single-link regular file")
		}
		return nil, errors.New("cannot securely open token file")
	}
	file := os.NewFile(uintptr(fd), "public-file-token")
	defer file.Close()

	if stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("token file must be owned by the service user")
	}
	if stat.Mode&0o177 != 0 {
		return nil, errors.New("token file must be non-executable and inaccessible by group or other users")
	}

	token, err := io.ReadAll(io.LimitReader(file, maxBearerTokenBytes+2))
	if err != nil {
		return nil, errors.New("cannot read token file")
	}
	token = bytes.TrimSuffix(token, []byte("\n"))
	token = bytes.TrimSuffix(token, []byte("\r"))
	if len(token) > maxBearerTokenBytes || !decodesToStrongToken(token) {
		return nil, fmt.Errorf("token must be base64 or hex encoding of at least 32 random bytes (maximum %d encoded bytes)", maxBearerTokenBytes)
	}
	distinct := make(map[byte]struct{}, 32)
	for _, value := range token {
		if value < 0x21 || value > 0x7e {
			return nil, errors.New("token must use visible ASCII without whitespace")
		}
		distinct[value] = struct{}{}
	}
	if len(distinct) < 12 {
		return nil, errors.New("token does not appear to contain enough randomness")
	}
	return token, nil
}

func decodesToStrongToken(token []byte) bool {
	value := string(token)
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) >= 32 {
		return true
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) >= 32 {
			return true
		}
	}
	return false
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
