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

	"golang.org/x/sys/unix"
)

const resolveUnderRoot = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV

type secureRoot struct {
	file *os.File
}

func openSecureRoot(absolutePath string) (*secureRoot, error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer unix.Close(rootFD)

	relative := strings.TrimPrefix(absolutePath, "/")
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
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
	root := &secureRoot{file: os.NewFile(uintptr(fd), "public-file-root")}

	// Probe the exact openat2 policy at startup. There is intentionally no
	// fallback for older kernels or seccomp profiles that reject it.
	probe, err := root.open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		root.close()
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnsupported
		}
		return nil, errors.New("openat2 policy probe failed")
	}
	unix.Close(probe)
	return root, nil
}

func readTokenFileSecure(absolutePath string) ([]byte, error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsupported
	}
	defer unix.Close(rootFD)

	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(absolutePath, "/"), &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, ErrUnsupported
		}
		return nil, errors.New("cannot securely open token file")
	}
	file := os.NewFile(uintptr(fd), "public-file-token")
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, errors.New("cannot inspect token file")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return nil, errors.New("token file must be a single-link regular file")
	}
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
	return r.file.Close()
}

func (r *secureRoot) open(relative string, flags int) (int, error) {
	return unix.Openat2(int(r.file.Fd()), relative, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: resolveUnderRoot,
	})
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
	fd, err := r.open(relative, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK)
	if err != nil {
		return nil, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		unix.Close(fd)
		return nil, nil, unix.EPERM
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

func isHiddenFilesystemError(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENOTDIR) ||
		errors.Is(err, unix.ELOOP) ||
		errors.Is(err, unix.EXDEV) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM)
}
