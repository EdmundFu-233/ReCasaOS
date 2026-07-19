//go:build linux

package filesecurity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const managedResolvePolicy = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

const (
	maxManagedTreeEntries int64 = 100_000
	maxManagedRemoveDepth       = 128
)

type managedRoot struct {
	path string
	file *os.File
}

// ManagedRoots pins each explicitly authorized management root to a directory
// descriptor. Client paths are resolved beneath those descriptors with
// openat2, so validation and use cannot be separated by a symlink swap.
//
// Mount crossings are intentionally allowed. CasaOS exposes removable and
// network filesystems below /mnt and /media; RESOLVE_NO_XDEV would break that
// core private-management use case. Symlinks and magic links remain forbidden.
type ManagedRoots struct {
	mu     sync.RWMutex
	roots  []managedRoot
	closed bool
}

func RemoveManagementTree(path string) error {
	roots, err := ManagementFileRoots()
	if err != nil {
		return err
	}
	return roots.RemoveAll(path)
}

// OpenManagementFileRoots validates and pins configured roots. Every root must
// already exist as a real directory; callers should fail startup when explicit
// configuration is invalid instead of silently widening or changing policy.
func OpenManagementFileRoots(paths []string) (*ManagedRoots, error) {
	cleaned, err := normalizeManagementFileRoots(paths)
	if err != nil {
		return nil, err
	}

	filesystemRootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pin filesystem root: %w", err)
	}
	defer unix.Close(filesystemRootFD)

	result := &ManagedRoots{roots: make([]managedRoot, 0, len(cleaned))}
	for _, root := range cleaned {
		fd, openErr := unix.Openat2(filesystemRootFD, strings.TrimPrefix(root, string(filepath.Separator)), &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: managedResolvePolicy,
		})
		if openErr != nil {
			_ = result.Close()
			if errors.Is(openErr, unix.ENOSYS) || errors.Is(openErr, unix.EINVAL) {
				return nil, fmt.Errorf("%w: %v", ErrManagedRootsUnsupported, openErr)
			}
			return nil, fmt.Errorf("pin management root %q: %w", root, classifyManagedResolutionError(openErr))
		}
		if _, mountErr := managedMountIDAt(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); mountErr != nil {
			unix.Close(fd)
			_ = result.Close()
			return nil, fmt.Errorf("verify management root %q mount boundary support: %w", root, mountErr)
		}
		pinned := os.NewFile(uintptr(fd), root)
		if pinned == nil {
			unix.Close(fd)
			_ = result.Close()
			return nil, fmt.Errorf("pin management root %q", root)
		}
		result.roots = append(result.roots, managedRoot{path: root, file: pinned})
	}
	return result, nil
}

// OpenManagementFileRootsFromEnvironment loads the explicit comma-separated
// setting, or the conservative CasaOS defaults when it is unset.
func OpenManagementFileRootsFromEnvironment() (*ManagedRoots, error) {
	paths, err := ParseManagementFileRoots(os.Getenv(ManagementFileRootsEnv))
	if err != nil {
		return nil, err
	}
	return OpenManagementFileRoots(paths)
}

func normalizeManagementFileRoots(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no roots configured", ErrInvalidManagedRoot)
	}
	seen := make(map[string]struct{}, len(paths))
	cleaned := make([]string, 0, len(paths))
	for _, candidate := range paths {
		root, err := canonicalAbsoluteManagedPath(candidate)
		if err != nil || root == string(filepath.Separator) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidManagedRoot, candidate)
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		cleaned = append(cleaned, root)
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if len(cleaned[i]) == len(cleaned[j]) {
			return cleaned[i] < cleaned[j]
		}
		return len(cleaned[i]) > len(cleaned[j])
	})
	return cleaned, nil
}

// Close releases the pinned root descriptors. It waits for in-flight
// operations holding a read lock and is idempotent.
func (m *ManagedRoots) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var result error
	for i := range m.roots {
		if err := m.roots[i].file.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Match returns the lexical mapping used by descriptor-relative operations.
func (m *ManagedRoots) Match(absolutePath string) (ManagedLocation, error) {
	if m == nil {
		return ManagedLocation{}, ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ManagedLocation{}, fs.ErrClosed
	}
	return m.matchLocked(absolutePath)
}

// MatchChild maps a validated child beneath an authorized management base.
func (m *ManagedRoots) MatchChild(base, relative string) (ManagedLocation, error) {
	if m == nil {
		return ManagedLocation{}, ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ManagedLocation{}, fs.ErrClosed
	}
	paths := make([]string, len(m.roots))
	for i := range m.roots {
		paths[i] = m.roots[i].path
	}
	return MatchManagementChild(paths, base, relative)
}

// OpenRegular opens an existing regular file without following symbolic or
// magic links in any component.
func (m *ManagedRoots) OpenRegular(absolutePath string) (*os.File, error) {
	opened, err := m.open(absolutePath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	if err := validateManagedOpenedFile(opened, false); err != nil {
		_ = opened.Close()
		return nil, err
	}
	return opened, nil
}

// OpenPath opens an existing file or directory through the managed root. The
// returned descriptor's Stat result, rather than a prior pathname lookup, must
// be used to decide how to process it.
func (m *ManagedRoots) OpenPath(absolutePath string) (*os.File, error) {
	opened, err := m.open(absolutePath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	if err := validateManagedOpenedFile(opened, true); err != nil {
		_ = opened.Close()
		return nil, err
	}
	return opened, nil
}

// OpenDirectory opens an existing directory beneath a configured root.
func (m *ManagedRoots) OpenDirectory(absolutePath string) (*os.File, error) {
	return m.open(absolutePath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}

// ChmodDirectory changes only a directory that was resolved beneath a pinned
// management root. Keeping the descriptor open across validation and chmod
// prevents a pathname swap from redirecting the permission change.
func (m *ManagedRoots) ChmodDirectory(absolutePath string, permission fs.FileMode) error {
	if permission&^fs.ModePerm != 0 {
		return fmt.Errorf("invalid managed directory permissions")
	}
	directory, err := m.OpenDirectory(absolutePath)
	if err != nil {
		return err
	}
	chmodErr := directory.Chmod(permission.Perm())
	closeErr := directory.Close()
	return errors.Join(chmodErr, closeErr)
}

// Stat inspects an existing path through a pinned root without following
// symbolic or magic links.
func (m *ManagedRoots) Stat(absolutePath string) (os.FileInfo, error) {
	opened, err := m.open(absolutePath, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	if err := validateManagedOpenedFile(opened, true); err != nil {
		return nil, err
	}
	return opened.Stat()
}

// CreateExclusive creates a new regular file without replacing an existing
// path. Its parent must already exist beneath an authorized root.
func (m *ManagedRoots) CreateExclusive(absolutePath string, permission fs.FileMode) (*os.File, error) {
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return nil, fmt.Errorf("invalid managed file permissions")
	}
	opened, err := m.open(absolutePath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NONBLOCK|unix.O_NOCTTY, permission.Perm())
	if err != nil {
		return nil, err
	}
	if err := validateManagedOpenedFile(opened, false); err != nil {
		_ = opened.Close()
		return nil, err
	}
	return opened, nil
}

// RewriteRegular replaces an existing regular file with a completely written,
// destination-local inode. The rename is relative to the already pinned parent
// descriptor, so clients never observe a truncated or partially written file.
func (m *ManagedRoots) RewriteRegular(absolutePath string, data []byte) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	existing, err := openManagedAt(root, location, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	var existingStat unix.Stat_t
	if err := unix.Fstat(int(existing.Fd()), &existingStat); err != nil {
		_ = existing.Close()
		return err
	}
	if err := validateManagedOpenedFile(existing, false); err != nil {
		_ = existing.Close()
		return err
	}
	_ = existing.Close()

	parentFD, destinationBase, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	temporary, temporaryName, err := createManagedTemporary(parentFD, ".recasaos-rewrite-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = unix.Unlinkat(parentFD, temporaryName, 0)
		}
	}()

	if err := unix.Fchown(int(temporary.Fd()), int(existingStat.Uid), int(existingStat.Gid)); err != nil {
		return err
	}
	if err := temporary.Chmod(fs.FileMode(existingStat.Mode & 0o777)); err != nil {
		return err
	}
	written, err := temporary.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporaryName, parentFD, destinationBase); err != nil {
		return err
	}
	committed = true
	_ = unix.Fsync(parentFD)
	return nil
}

// MkdirAll creates missing directories one component at a time relative to
// pinned directory descriptors. Existing components are reopened with the
// same no-symlink openat2 policy before they are used as parents.
func (m *ManagedRoots) MkdirAll(absolutePath string, permission fs.FileMode) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return fmt.Errorf("invalid managed directory permissions")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	if location.Relative == "." {
		return nil
	}

	currentFD, err := unix.FcntlInt(root.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() {
		if currentFD >= 0 {
			_ = unix.Close(currentFD)
		}
	}()

	for _, component := range strings.Split(location.Relative, string(filepath.Separator)) {
		nextFD, openErr := openManagedDirectoryAt(currentFD, component)
		if errors.Is(openErr, unix.ENOENT) {
			mkdirErr := unix.Mkdirat(currentFD, component, uint32(permission.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return classifyManagedResolutionError(mkdirErr)
			}
			nextFD, openErr = openManagedDirectoryAt(currentFD, component)
		}
		if openErr != nil {
			return classifyManagedResolutionError(openErr)
		}
		oldFD := currentFD
		currentFD = -1
		if err := unix.Close(oldFD); err != nil {
			unix.Close(nextFD)
			return err
		}
		currentFD = nextFD
	}
	return nil
}

// Remove removes one non-directory entry relative to its pinned parent.
func (m *ManagedRoots) Remove(absolutePath string) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	targetMountID, err := managedMountIDAt(parentFD, base, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if targetMountID != parentMountID {
		return fmt.Errorf("%w: refusing to remove a mount boundary", ErrUnsafePath)
	}
	if err := unix.Unlinkat(parentFD, base, 0); err != nil {
		return err
	}
	return nil
}

// RemoveAll recursively removes an entry without following links. The
// configured root itself can never be removed.
func (m *ManagedRoots) RemoveAll(absolutePath string) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	budget := int64(0)
	return removeManagedEntryAt(parentFD, base, parentMountID, 0, &budget)
}

// RenameNoReplace moves a managed entry between pinned parent descriptors and
// never replaces the destination. Cross-filesystem moves fail with EXDEV, as
// the legacy os.Rename behavior did.
func (m *ManagedRoots) RenameNoReplace(oldPath, newPath string) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	oldRoot, oldLocation, err := m.resolveLocked(oldPath)
	if err != nil {
		return err
	}
	newRoot, newLocation, err := m.resolveLocked(newPath)
	if err != nil {
		return err
	}
	opened, err := openManagedAt(oldRoot, oldLocation, unix.O_PATH, 0)
	if err != nil {
		return err
	}
	if err := validateManagedOpenedFile(opened, true); err != nil {
		_ = opened.Close()
		return err
	}
	_ = opened.Close()

	oldParentFD, oldBase, err := openManagedParent(oldRoot, oldLocation)
	if err != nil {
		return err
	}
	defer unix.Close(oldParentFD)
	newParentFD, newBase, err := openManagedParent(newRoot, newLocation)
	if err != nil {
		return err
	}
	defer unix.Close(newParentFD)
	if err := unix.Renameat2(oldParentFD, oldBase, newParentFD, newBase, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	_ = unix.Fsync(oldParentFD)
	if newParentFD != oldParentFD {
		_ = unix.Fsync(newParentFD)
	}
	return nil
}

// DirectoryCount counts immediate regular-file and directory entries while
// excluding links and special files that the management API cannot open.
func (m *ManagedRoots) DirectoryCount(absolutePath string) (int, error) {
	directory, err := m.OpenDirectory(absolutePath)
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	count := 0
	seen := int64(0)
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			seen++
			if seen > maxManagedTreeEntries {
				return 0, errors.New("managed directory exceeds entry limit")
			}
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return 0, err
			}
			if info.IsDir() || info.Mode().IsRegular() {
				count++
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, readErr
		}
	}
	return count, nil
}

// TreeSize sums regular files beneath a managed path with a finite traversal
// budget. Links and special files are not followed or counted.
func (m *ManagedRoots) TreeSize(absolutePath string) (int64, error) {
	var entries int64
	return m.treeSize(absolutePath, 0, &entries)
}

func (m *ManagedRoots) treeSize(absolutePath string, depth int, entries *int64) (int64, error) {
	if depth > maxManagedRemoveDepth {
		return 0, errors.New("managed tree exceeds depth limit")
	}
	if *entries >= maxManagedTreeEntries {
		return 0, errors.New("managed tree exceeds entry limit")
	}
	*entries = *entries + 1
	opened, err := m.OpenPath(absolutePath)
	if err != nil {
		return 0, err
	}
	info, err := opened.Stat()
	if err != nil {
		_ = opened.Close()
		return 0, err
	}
	if info.Mode().IsRegular() {
		_ = opened.Close()
		return info.Size(), nil
	}
	var total int64
	for {
		children, readErr := opened.ReadDir(256)
		for _, child := range children {
			if child.Type()&os.ModeSymlink != 0 {
				continue
			}
			childSize, err := m.treeSize(filepath.Join(absolutePath, child.Name()), depth+1, entries)
			if err != nil {
				_ = opened.Close()
				return 0, err
			}
			if childSize > int64(^uint64(0)>>1)-total {
				_ = opened.Close()
				return 0, errors.New("managed tree size overflow")
			}
			total += childSize
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = opened.Close()
			return 0, readErr
		}
	}
	return total, opened.Close()
}

// CommitNoReplace copies a completed staging file into a hidden file created
// relative to the destination parent, then publishes it atomically with
// renameat2(RENAME_NOREPLACE). Both source and destination are opened beneath
// pinned management roots; cross-filesystem uploads remain supported.
func (m *ManagedRoots) CommitNoReplace(stagingPath, destinationPath string) error {
	if m == nil {
		return ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fs.ErrClosed
	}
	stagingRoot, stagingLocation, err := m.resolveLocked(stagingPath)
	if err != nil {
		return err
	}
	destinationRoot, destinationLocation, err := m.resolveLocked(destinationPath)
	if err != nil {
		return err
	}

	source, err := openManagedAt(stagingRoot, stagingLocation, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := validateManagedOpenedFile(source, false); err != nil {
		return err
	}
	stagingInfo, err := source.Stat()
	if err != nil {
		return err
	}
	if stagingInfo.Size() < 0 || stagingInfo.Size() > MaxUploadTotalSize {
		return fmt.Errorf("upload staging file exceeds %d bytes", MaxUploadTotalSize)
	}

	parentFD, destinationBase, err := openManagedParent(destinationRoot, destinationLocation)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)

	temporary, temporaryName, err := createManagedTemporary(parentFD, ".recasaos-upload-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = unix.Unlinkat(parentFD, temporaryName, 0)
		}
	}()

	written, err := io.Copy(temporary, io.LimitReader(source, stagingInfo.Size()+1))
	if err != nil {
		return fmt.Errorf("copy upload to target filesystem: %w", err)
	}
	if written != stagingInfo.Size() {
		return fmt.Errorf("upload staging file changed while being committed")
	}
	if err := temporary.Chmod(stagingInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("set target-local upload permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync target-local upload staging file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close target-local upload staging file: %w", err)
	}
	if err := unix.Renameat2(parentFD, temporaryName, parentFD, destinationBase, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish upload without replacing destination: %w", err)
	}
	committed = true
	_ = unix.Fsync(parentFD)
	return nil
}

func (m *ManagedRoots) open(absolutePath string, flags int, permission fs.FileMode) (*os.File, error) {
	if m == nil {
		return nil, ErrManagedPathOutsideRoots
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, fs.ErrClosed
	}
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return nil, err
	}
	return openManagedAt(root, location, flags, permission)
}

func openManagedAt(root *managedRoot, location ManagedLocation, flags int, permission fs.FileMode) (*os.File, error) {
	fd, err := unix.Openat2(int(root.file.Fd()), location.Relative, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    uint64(permission.Perm()),
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, classifyManagedResolutionError(err)
	}
	opened := os.NewFile(uintptr(fd), location.Canonical)
	if opened == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open managed path")
	}
	return opened, nil
}

func openManagedParent(root *managedRoot, location ManagedLocation) (int, string, error) {
	if location.Relative == "." {
		return -1, "", fmt.Errorf("%w: configured root cannot be modified", ErrUnsafePath)
	}
	base := filepath.Base(location.Relative)
	if err := ValidatePathComponent(base); err != nil {
		return -1, "", err
	}
	parent := filepath.Dir(location.Relative)
	fd, err := unix.Openat2(int(root.file.Fd()), parent, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return -1, "", classifyManagedResolutionError(err)
	}
	return fd, base, nil
}

func createManagedTemporary(parentFD int, prefix string) (*os.File, string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, "", fmt.Errorf("generate managed staging name: %w", err)
	}
	temporaryName := prefix + hex.EncodeToString(randomBytes)
	temporaryFD, err := unix.Openat2(parentFD, temporaryName, &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Mode:    uint64(0o600),
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, "", classifyManagedResolutionError(err)
	}
	temporary := os.NewFile(uintptr(temporaryFD), temporaryName)
	if temporary == nil {
		unix.Close(temporaryFD)
		_ = unix.Unlinkat(parentFD, temporaryName, 0)
		return nil, "", errors.New("create managed staging file")
	}
	return temporary, temporaryName, nil
}

func removeManagedEntryAt(parentFD int, name string, parentMountID uint64, depth int, entries *int64) error {
	if err := ValidatePathComponent(name); err != nil {
		return err
	}
	if depth > maxManagedRemoveDepth {
		return errors.New("managed removal exceeds depth limit")
	}
	if *entries >= maxManagedTreeEntries {
		return errors.New("managed removal exceeds entry limit")
	}
	*entries = *entries + 1
	targetMountID, err := managedMountIDAt(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if targetMountID != parentMountID {
		return fmt.Errorf("%w: refusing to cross a mount boundary during removal", ErrUnsafePath)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parentFD, name, 0)
	}

	directoryFD, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return classifyManagedResolutionError(err)
	}
	openedMountID, err := managedMountIDAt(directoryFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		unix.Close(directoryFD)
		return err
	}
	if openedMountID != parentMountID {
		unix.Close(directoryFD)
		return fmt.Errorf("%w: directory mount changed during removal", ErrUnsafePath)
	}
	directory := os.NewFile(uintptr(directoryFD), name)
	if directory == nil {
		unix.Close(directoryFD)
		return errors.New("open managed directory for removal")
	}
	for {
		batch, readErr := directory.ReadDir(256)
		for _, entry := range batch {
			if err := removeManagedEntryAt(int(directory.Fd()), entry.Name(), openedMountID, depth+1, entries); err != nil {
				_ = directory.Close()
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return readErr
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func managedMountIDAt(directoryFD int, path string, flags int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(directoryFD, path, flags, unix.STATX_TYPE|unix.STATX_MNT_ID, &stat); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return 0, fmt.Errorf("%w: statx mount identifiers: %v", ErrManagedRootsUnsupported, err)
		}
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("%w: kernel did not report a statx mount identifier", ErrManagedRootsUnsupported)
	}
	return stat.Mnt_id, nil
}

func (m *ManagedRoots) matchLocked(absolutePath string) (ManagedLocation, error) {
	paths := make([]string, len(m.roots))
	for i := range m.roots {
		paths[i] = m.roots[i].path
	}
	return MatchManagementPath(paths, absolutePath)
}

func (m *ManagedRoots) resolveLocked(absolutePath string) (*managedRoot, ManagedLocation, error) {
	location, err := m.matchLocked(absolutePath)
	if err != nil {
		return nil, ManagedLocation{}, err
	}
	for i := range m.roots {
		if m.roots[i].path == location.Root {
			return &m.roots[i], location, nil
		}
	}
	return nil, ManagedLocation{}, ErrManagedPathOutsideRoots
}

func openManagedDirectoryAt(parentFD int, component string) (int, error) {
	return unix.Openat2(parentFD, component, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
}

func classifyManagedResolutionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("%w: %v", ErrUnsafePath, err)
	}
	if errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("%w: %v", ErrManagedRootsUnsupported, err)
	}
	return err
}

func validateManagedOpenedFile(opened *os.File, allowDirectory bool) error {
	if opened == nil {
		return ErrUnsafePath
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &stat); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if stat.Nlink != 1 {
			return fmt.Errorf("%w: managed regular file has multiple hard links", ErrUnsafePath)
		}
		return nil
	case unix.S_IFDIR:
		if allowDirectory {
			return nil
		}
	}
	return fmt.Errorf("%w: managed path is not an allowed file type", ErrUnsafePath)
}
