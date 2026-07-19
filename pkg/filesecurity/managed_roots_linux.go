//go:build linux

package filesecurity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	mutationMu                    sync.Mutex
	mu                            sync.RWMutex
	roots                         []managedRoot
	closed                        bool
	directorySync                 func(int) error
	commitCopy                    func(io.Writer, io.Reader) (int64, error)
	commitIdentity                func(int, string) (ManagedFileIdentity, error)
	replaceBeforeExchange         func() error
	replaceBeforeCleanup          func() error
	moveBeforeDirectRename        func() error
	transactionBeforeStageSync    func() error
	transactionBeforeCleanup      func() error
	transactionAfterRmdir         func() error
	transferFilesystemEligibility func(int) (int64, bool, error)
	rewriteBeforePublish          func() error
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
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
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
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	directory, err := openManagedAt(root, location, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	if err := m.validateManagedDestinationFD(root, int(directory.Fd()), location); err != nil {
		_ = directory.Close()
		return err
	}
	if err := directory.Chmod(permission.Perm()); err != nil {
		_ = directory.Close()
		return err
	}
	syncErr := m.syncManagedDirectory(int(directory.Fd()), "sync managed directory permissions", true)
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
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

// RewriteRegular replaces an existing regular file with a completely written,
// destination-local inode. The rename is relative to the already pinned parent
// descriptor, so clients never observe a truncated or partially written file.
func (m *ManagedRoots) RewriteRegular(absolutePath string, data []byte) (resultErr error) {
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
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
	parentLocation, err := m.matchLocked(filepath.Dir(location.Canonical))
	if err != nil {
		return err
	}
	if err := m.validateManagedDestinationFD(root, parentFD, parentLocation); err != nil {
		return err
	}
	temporary, temporaryName, err := m.createManagedTemporary(parentFD, ".recasaos-rewrite-")
	if err != nil {
		return err
	}
	temporaryOpen := true
	temporaryPresent := true
	defer func() {
		if temporaryOpen {
			resultErr = errors.Join(resultErr, temporary.Close())
		}
		if temporaryPresent {
			resultErr = errors.Join(resultErr, m.unlinkManagedNameAndSync(parentFD, temporaryName, 0, "sync rewrite staging cleanup", false))
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
	closeErr := temporary.Close()
	temporaryOpen = false
	if closeErr != nil {
		return closeErr
	}
	if m.rewriteBeforePublish != nil {
		if err := m.rewriteBeforePublish(); err != nil {
			return err
		}
	}
	// verifyManagedNameIdentity performs a no-follow Fstatat and compares the
	// complete dev/inode/mode/nlink/size/mtime/ctime snapshot, so same-inode
	// writes, chmod, chown, and hard-link changes cannot be overwritten using
	// stale metadata captured before staging.
	if err := verifyManagedNameIdentity(parentFD, destinationBase, &existingStat); err != nil {
		return err
	}
	if err := unix.Renameat(parentFD, temporaryName, parentFD, destinationBase); err != nil {
		return err
	}
	temporaryPresent = false
	return m.syncManagedDirectory(parentFD, "sync rewritten regular file parent", true)
}

// MkdirAll creates missing directories one component at a time relative to
// pinned directory descriptors. Existing components are reopened with the
// same no-symlink openat2 policy before they are used as parents.
func (m *ManagedRoots) MkdirAll(absolutePath string, permission fs.FileMode) (resultErr error) {
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return fmt.Errorf("invalid managed directory permissions")
	}
	namespaceChanged := false
	defer func() {
		if namespaceChanged {
			resultErr = managedChangedMutationError("managed directory creation partially completed", ManagedMutationDurabilityUnknown(resultErr), resultErr)
		}
	}()
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
	}
	if location.Relative == "." {
		return nil
	}

	currentFD, err := unix.Openat2(int(root.file.Fd()), ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return err
	}
	defer func() {
		if currentFD >= 0 {
			_ = unix.Close(currentFD)
		}
	}()

	currentCanonical := root.path
	for _, component := range strings.Split(location.Relative, string(filepath.Separator)) {
		currentLocation := ManagedLocation{Root: root.path, Canonical: currentCanonical}
		if err := m.validateManagedDestinationFD(root, currentFD, currentLocation); err != nil {
			return err
		}
		nextFD, openErr := openManagedDirectoryAt(currentFD, component)
		if errors.Is(openErr, unix.ENOENT) {
			mkdirErr := unix.Mkdirat(currentFD, component, uint32(permission.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return classifyManagedResolutionError(mkdirErr)
			}
			created := mkdirErr == nil
			if created {
				namespaceChanged = true
				if err := m.syncManagedDirectory(currentFD, "sync created managed directory parent", true); err != nil {
					return err
				}
			}
			nextFD, openErr = openManagedDirectoryAt(currentFD, component)
			if openErr != nil && created {
				return managedChangedMutationError("open newly created managed directory", false, classifyManagedResolutionError(openErr))
			}
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
		currentCanonical = filepath.Join(currentCanonical, component)
	}
	return nil
}

// Remove removes one non-directory entry relative to its pinned parent.
func (m *ManagedRoots) Remove(absolutePath string) error {
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return err
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
	return m.unlinkManagedNameAndSync(parentFD, base, 0, "sync removed managed entry parent", true)
}

// RemoveAll recursively removes an entry without following links. The
// configured root itself can never be removed.
func (m *ManagedRoots) RemoveAll(absolutePath string) error {
	_, err := m.RemoveAllBatch([]string{absolutePath})
	return err
}

// RemoveAllBatch preflights every tree under one mutation lease before the
// first unlink. Completed contains only paths whose top-level name was fully
// removed; Changed also covers a partially removed current tree.
func (m *ManagedRoots) RemoveAllBatch(absolutePaths []string) (ManagedBatchMutationResult, error) {
	result := ManagedBatchMutationResult{Completed: make([]string, 0, len(absolutePaths))}
	if len(absolutePaths) == 0 {
		return result, fmt.Errorf("no managed removal paths")
	}
	release, err := m.AcquireMutation()
	if err != nil {
		return result, err
	}
	defer release()
	canonicalPaths := make([]string, 0, len(absolutePaths))
	for _, absolutePath := range absolutePaths {
		location, err := m.matchLocked(absolutePath)
		if err != nil || location.Relative == "." {
			if err == nil {
				err = fmt.Errorf("%w: configured root cannot be removed", ErrUnsafePath)
			}
			return result, err
		}
		for _, previous := range canonicalPaths {
			if managedPathsOverlap(previous, location.Canonical) {
				return result, fmt.Errorf("%w: batch removal paths overlap", ErrUnsafePath)
			}
		}
		canonicalPaths = append(canonicalPaths, location.Canonical)
	}
	plans := make([]managedRemovalPlan, 0, len(canonicalPaths))
	for _, absolutePath := range canonicalPaths {
		plan, err := m.preflightRemoveAllLocked(absolutePath)
		if err != nil {
			return result, err
		}
		plans = append(plans, plan)
	}
	for _, plan := range plans {
		if err := m.removeAllPreflightedLocked(plan); err != nil {
			if len(result.Completed) > 0 || ManagedMutationChanged(err) {
				result.Changed = true
				err = managedChangedMutationError("managed batch removal partially completed", false, err)
			}
			return result, err
		}
		result.Completed = append(result.Completed, plan.canonical)
		result.Changed = true
	}
	return result, nil
}

type managedRemovalPlan struct {
	canonical string
	stat      unix.Stat_t
}

func (m *ManagedRoots) preflightRemoveAllLocked(absolutePath string) (managedRemovalPlan, error) {
	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return managedRemovalPlan{}, err
	}
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return managedRemovalPlan{}, err
	}
	defer unix.Close(parentFD)
	parentLocation, err := m.matchLocked(filepath.Dir(location.Canonical))
	if err != nil {
		return managedRemovalPlan{}, err
	}
	if err := m.validateManagedDestinationFD(root, parentFD, parentLocation); err != nil {
		return managedRemovalPlan{}, err
	}
	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return managedRemovalPlan{}, err
	}
	target, err := openManagedTransferChild(parentFD, base)
	if err != nil {
		return managedRemovalPlan{}, err
	}
	if err := m.rejectConfiguredRootAtOrBelow(target, location.Canonical); err != nil {
		_ = target.Close()
		return managedRemovalPlan{}, err
	}
	var targetStat unix.Stat_t
	if err := unix.Fstat(int(target.Fd()), &targetStat); err != nil {
		_ = target.Close()
		return managedRemovalPlan{}, err
	}
	if err := target.Close(); err != nil {
		return managedRemovalPlan{}, err
	}
	budget := int64(0)
	if err := validateManagedRemovableEntryAt(parentFD, base, parentMountID, 0, &budget, false); err != nil {
		return managedRemovalPlan{}, err
	}
	return managedRemovalPlan{canonical: location.Canonical, stat: targetStat}, nil
}

func (m *ManagedRoots) removeAllPreflightedLocked(plan managedRemovalPlan) error {
	root, location, err := m.resolveLocked(plan.canonical)
	if err != nil {
		return err
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
	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if err := verifyManagedNameIdentity(parentFD, base, &plan.stat); err != nil {
		return err
	}
	state := &managedRemovalState{}
	return m.removeManagedEntryAtPrevalidated(parentFD, base, parentMountID, 0, state)
}

// RenameNoReplace moves a managed entry between pinned parent descriptors and
// never replaces the destination. Cross-filesystem moves fail with EXDEV, as
// the legacy os.Rename behavior did.
func (m *ManagedRoots) RenameNoReplace(oldPath, newPath string) error {
	release, err := m.AcquireMutation()
	if err != nil {
		return err
	}
	defer release()
	oldRoot, oldLocation, err := m.resolveLocked(oldPath)
	if err != nil {
		return err
	}
	newRoot, newLocation, err := m.resolveLocked(newPath)
	if err != nil {
		return err
	}
	if managedPathsOverlap(oldLocation.Canonical, newLocation.Canonical) {
		return fmt.Errorf("%w: rename source and destination overlap", ErrUnsafePath)
	}
	if err := m.rejectConfiguredRootCanonicalAtOrBelow(newLocation.Canonical); err != nil {
		return err
	}
	opened, err := openManagedAt(oldRoot, oldLocation, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer opened.Close()
	if err := validateManagedOpenedFile(opened, true); err != nil {
		return err
	}
	var openedStat unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &openedStat); err != nil {
		return err
	}
	if err := m.rejectConfiguredRootAtOrBelow(opened, oldLocation.Canonical); err != nil {
		return err
	}

	oldParentFD, oldBase, err := openManagedParent(oldRoot, oldLocation)
	if err != nil {
		return err
	}
	defer unix.Close(oldParentFD)
	oldParentLocation, err := m.matchLocked(filepath.Dir(oldLocation.Canonical))
	if err != nil {
		return err
	}
	if err := m.validateManagedDestinationFD(oldRoot, oldParentFD, oldParentLocation); err != nil {
		return err
	}
	if err := validateManagedMoveMountBoundary(oldParentFD, int(opened.Fd())); err != nil {
		return err
	}
	newParentFD, newBase, err := openManagedParent(newRoot, newLocation)
	if err != nil {
		return err
	}
	defer unix.Close(newParentFD)
	newParentLocation, err := m.matchLocked(filepath.Dir(newLocation.Canonical))
	if err != nil {
		return err
	}
	if err := m.validateManagedDestinationFD(newRoot, newParentFD, newParentLocation); err != nil {
		return err
	}
	if openedStat.Mode&unix.S_IFMT == unix.S_IFDIR {
		sourceMountID, err := managedMountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return err
		}
		destinationMountID, err := managedMountIDAt(newParentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return err
		}
		if oldRoot != newRoot || sourceMountID != destinationMountID {
			return fmt.Errorf("%w: direct directory rename crosses a configured root or mount", ErrUnsafeManagedDirectoryTransfer)
		}
		destinationInsideSource, err := managedDescriptorIsAncestorOrSame(int(opened.Fd()), newParentFD)
		if err != nil {
			return err
		}
		if destinationInsideSource {
			return fmt.Errorf("%w: direct directory rename destination is inside source", ErrUnsafeManagedDirectoryTransfer)
		}
		entries := int64(0)
		if err := m.validateManagedAtomicMoveTree(opened, &openedStat, sourceMountID, 0, &entries); err != nil {
			return err
		}
	}
	if err := verifyManagedNameIdentity(oldParentFD, oldBase, &openedStat); err != nil {
		return err
	}
	if err := unix.Renameat2(oldParentFD, oldBase, newParentFD, newBase, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	destinationSyncErr := m.syncManagedDirectory(newParentFD, "sync renamed managed destination parent", true)
	sourceSyncErr := m.syncManagedDirectory(oldParentFD, "sync renamed managed source parent", true)
	return errors.Join(destinationSyncErr, sourceSyncErr)
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
	opened, err := m.OpenPath(absolutePath)
	if err != nil {
		return 0, err
	}
	defer opened.Close()
	var entries int64
	return managedOpenedTreeSize(opened, 0, false, 0, &entries)
}

func managedOpenedTreeSize(opened *os.File, parentMountID uint64, enforceParentMount bool, depth int, entries *int64) (int64, error) {
	if depth > maxManagedRemoveDepth {
		return 0, errors.New("managed tree exceeds depth limit")
	}
	if *entries >= maxManagedTreeEntries {
		return 0, errors.New("managed tree exceeds entry limit")
	}
	*entries = *entries + 1
	currentMountID, err := managedMountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return 0, err
	}
	if enforceParentMount && currentMountID != parentMountID {
		return 0, fmt.Errorf("%w: refusing to cross a mount boundary while measuring a tree", ErrUnsafePath)
	}
	info, err := opened.Stat()
	if err != nil {
		return 0, err
	}
	if info.Mode().IsRegular() {
		return info.Size(), nil
	}
	var total int64
	for {
		children, readErr := opened.ReadDir(256)
		for _, child := range children {
			if child.Type()&os.ModeSymlink != 0 {
				continue
			}
			if err := ValidatePathComponent(child.Name()); err != nil {
				return 0, err
			}
			childFile, err := openManagedTransferChild(int(opened.Fd()), child.Name())
			if err != nil {
				return 0, err
			}
			childSize, sizeErr := managedOpenedTreeSize(childFile, currentMountID, true, depth+1, entries)
			closeErr := childFile.Close()
			err = errors.Join(sizeErr, closeErr)
			if err != nil {
				return 0, err
			}
			if childSize > int64(^uint64(0)>>1)-total {
				return 0, errors.New("managed tree size overflow")
			}
			total += childSize
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, readErr
		}
	}
	return total, nil
}

// CommitNoReplace copies a completed staging file into a hidden file created
// relative to the destination parent, then publishes it atomically with
// renameat2(RENAME_NOREPLACE). Both source and destination are opened beneath
// pinned management roots; cross-filesystem uploads remain supported.
func (m *ManagedRoots) CommitNoReplace(stagingPath, destinationPath string) error {
	_, err := m.CommitNoReplaceWithIdentity(stagingPath, destinationPath)
	return err
}

// CommitNoReplaceWithIdentity publishes the staging file and captures the
// destination's descriptor/name-bound stat identity before releasing the
// mutation lease. The identity is returned even when the subsequent parent
// directory sync fails, allowing callers to retain a precise idempotency
// record for a target that was published with uncertain durability.
func (m *ManagedRoots) CommitNoReplaceWithIdentity(stagingPath, destinationPath string) (identity ManagedFileIdentity, resultErr error) {
	return m.commitNoReplaceWithExpectedIdentity(stagingPath, destinationPath, nil, nil)
}

// CommitNoReplaceWithExpectedIdentity rejects a staging pathname that no
// longer identifies the exact file previously published by CreateExclusive.
// Validation happens inside the commit mutation lease, closing the window
// between assembly publication and target-local copy.
func (m *ManagedRoots) CommitNoReplaceWithExpectedIdentity(stagingPath, destinationPath string, expected ManagedFileIdentity) (ManagedFileIdentity, error) {
	return m.commitNoReplaceWithExpectedIdentity(stagingPath, destinationPath, &expected, nil)
}

// CommitNoReplaceWithExpectedIdentityAndDigest additionally binds the exact
// bytes copied from staging. The digest is calculated while the existing
// target-filesystem copy is performed, so this adds no extra file read.
func (m *ManagedRoots) CommitNoReplaceWithExpectedIdentityAndDigest(stagingPath, destinationPath string, expected ManagedFileIdentity, expectedDigest [sha256.Size]byte) (ManagedFileIdentity, error) {
	return m.commitNoReplaceWithExpectedIdentity(stagingPath, destinationPath, &expected, &expectedDigest)
}

func (m *ManagedRoots) commitNoReplaceWithExpectedIdentity(stagingPath, destinationPath string, expected *ManagedFileIdentity, expectedDigest *[sha256.Size]byte) (identity ManagedFileIdentity, resultErr error) {
	release, err := m.AcquireMutation()
	if err != nil {
		return identity, err
	}
	defer release()
	stagingRoot, stagingLocation, err := m.resolveLocked(stagingPath)
	if err != nil {
		return identity, err
	}
	destinationRoot, destinationLocation, err := m.resolveLocked(destinationPath)
	if err != nil {
		return identity, err
	}

	source, err := openManagedAt(stagingRoot, stagingLocation, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return identity, err
	}
	defer source.Close()
	if err := validateManagedOpenedFile(source, false); err != nil {
		return identity, err
	}
	var stagingBefore unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stagingBefore); err != nil {
		return identity, err
	}
	if expected != nil && managedFileIdentityFromStat(&stagingBefore) != *expected {
		return identity, fmt.Errorf("%w: upload staging identity changed before commit", ErrUnsafePath)
	}
	if stagingBefore.Nlink != 1 {
		return identity, fmt.Errorf("%w: upload staging file has multiple hard links", ErrUnsafePath)
	}
	if stagingBefore.Size < 0 || stagingBefore.Size > MaxUploadTotalSize {
		return identity, fmt.Errorf("upload staging file exceeds %d bytes", MaxUploadTotalSize)
	}
	stagingParentFD, stagingBase, err := openManagedParent(stagingRoot, stagingLocation)
	if err != nil {
		return identity, err
	}
	defer unix.Close(stagingParentFD)
	stagingParentLocation, err := m.matchLocked(filepath.Dir(stagingLocation.Canonical))
	if err != nil {
		return identity, err
	}
	if err := m.validateManagedDestinationFD(stagingRoot, stagingParentFD, stagingParentLocation); err != nil {
		return identity, err
	}
	if err := verifyManagedNameIdentity(stagingParentFD, stagingBase, &stagingBefore); err != nil {
		return identity, err
	}

	parentFD, destinationBase, err := openManagedParent(destinationRoot, destinationLocation)
	if err != nil {
		return identity, err
	}
	defer unix.Close(parentFD)
	parentLocation, err := m.matchLocked(filepath.Dir(destinationLocation.Canonical))
	if err != nil {
		return identity, err
	}
	if err := m.validateManagedDestinationFD(destinationRoot, parentFD, parentLocation); err != nil {
		return identity, err
	}

	temporary, temporaryName, err := m.createManagedTemporary(parentFD, ".recasaos-upload-")
	if err != nil {
		return identity, err
	}
	temporaryOpen := true
	temporaryPresent := true
	defer func() {
		if temporaryOpen {
			resultErr = errors.Join(resultErr, temporary.Close())
		}
		if temporaryPresent {
			resultErr = errors.Join(resultErr, m.unlinkManagedNameAndSync(parentFD, temporaryName, 0, "sync upload staging cleanup", false))
		}
	}()

	copyStaging := io.Copy
	if m.commitCopy != nil {
		copyStaging = m.commitCopy
	}
	copyDestination := io.Writer(temporary)
	copiedDigest := sha256.New()
	if expectedDigest != nil {
		copyDestination = io.MultiWriter(temporary, copiedDigest)
	}
	written, err := copyStaging(copyDestination, io.LimitReader(source, stagingBefore.Size+1))
	if err != nil {
		return identity, fmt.Errorf("copy upload to target filesystem: %w", err)
	}
	if written != stagingBefore.Size {
		return identity, fmt.Errorf("upload staging file changed while being committed")
	}
	if expectedDigest != nil {
		actualDigest := copiedDigest.Sum(nil)
		if subtle.ConstantTimeCompare(actualDigest, expectedDigest[:]) != 1 {
			return identity, fmt.Errorf("%w: upload staging digest changed before commit", ErrUnsafePath)
		}
	}
	var stagingAfter unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stagingAfter); err != nil {
		return identity, err
	}
	if !sameManagedTransferStat(&stagingBefore, &stagingAfter) {
		return identity, fmt.Errorf("%w: upload staging file changed while being committed", ErrUnsafePath)
	}
	if err := verifyManagedNameIdentity(stagingParentFD, stagingBase, &stagingBefore); err != nil {
		return identity, err
	}
	if err := temporary.Chmod(fs.FileMode(stagingBefore.Mode & 0o777)); err != nil {
		return identity, fmt.Errorf("set target-local upload permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return identity, fmt.Errorf("sync target-local upload staging file: %w", err)
	}
	closeErr := temporary.Close()
	temporaryOpen = false
	if closeErr != nil {
		return identity, fmt.Errorf("close target-local upload staging file: %w", closeErr)
	}
	var stagingFinal unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stagingFinal); err != nil {
		return identity, err
	}
	if !sameManagedTransferStat(&stagingBefore, &stagingFinal) {
		return identity, fmt.Errorf("%w: upload staging file changed before publication", ErrUnsafePath)
	}
	if err := verifyManagedNameIdentity(stagingParentFD, stagingBase, &stagingBefore); err != nil {
		return identity, err
	}
	if err := unix.Renameat2(parentFD, temporaryName, parentFD, destinationBase, unix.RENAME_NOREPLACE); err != nil {
		return identity, fmt.Errorf("publish upload without replacing destination: %w", err)
	}
	temporaryPresent = false

	captureIdentity := captureManagedPublishedIdentity
	if m.commitIdentity != nil {
		captureIdentity = m.commitIdentity
	}
	identity, err = captureIdentity(parentFD, destinationBase)
	if err != nil {
		return identity, managedChangedMutationError("bind committed upload identity", true, err)
	}
	return identity, m.syncManagedDirectory(parentFD, "sync committed upload parent", true)
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

func (m *ManagedRoots) createManagedTemporary(parentFD int, prefix string) (*os.File, string, error) {
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
		closeErr := unix.Close(temporaryFD)
		cleanupErr := m.unlinkManagedNameAndSync(parentFD, temporaryName, 0, "sync failed managed staging creation cleanup", false)
		return nil, "", errors.Join(errors.New("create managed staging file"), closeErr, cleanupErr)
	}
	return temporary, temporaryName, nil
}

type managedRemovalState struct {
	entries int64
	changed bool
}

func (m *ManagedRoots) removeManagedEntryAt(parentFD int, name string, parentMountID uint64, depth int, entries *int64) error {
	if err := validateManagedRemovableEntryAt(parentFD, name, parentMountID, depth, entries, false); err != nil {
		return err
	}
	state := &managedRemovalState{}
	return m.removeManagedEntryAtPrevalidated(parentFD, name, parentMountID, depth, state)
}

func (m *ManagedRoots) removeManagedEntryAtPrevalidated(parentFD int, name string, parentMountID uint64, depth int, state *managedRemovalState) error {
	if err := ValidatePathComponent(name); err != nil {
		return managedRemovalFailure(state, err)
	}
	if depth > maxManagedRemoveDepth {
		return managedRemovalFailure(state, errors.New("managed removal exceeds depth limit"))
	}
	if state.entries >= maxManagedTreeEntries {
		return managedRemovalFailure(state, errors.New("managed removal exceeds entry limit"))
	}
	state.entries++
	targetMountID, err := managedMountIDAt(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return managedRemovalFailure(state, err)
	}
	if targetMountID != parentMountID {
		return managedRemovalFailure(state, fmt.Errorf("%w: refusing to cross a mount boundary during removal", ErrUnsafePath))
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return managedRemovalFailure(state, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(parentFD, name, 0); err != nil {
			return managedRemovalFailure(state, err)
		}
		state.changed = true
		return m.syncManagedDirectory(parentFD, "sync recursively removed managed entry parent", true)
	}

	directoryFD, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return managedRemovalFailure(state, classifyManagedResolutionError(err))
	}
	openedMountID, err := managedMountIDAt(directoryFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		unix.Close(directoryFD)
		return managedRemovalFailure(state, err)
	}
	if openedMountID != parentMountID {
		unix.Close(directoryFD)
		return managedRemovalFailure(state, fmt.Errorf("%w: directory mount changed during removal", ErrUnsafePath))
	}
	directory := os.NewFile(uintptr(directoryFD), name)
	if directory == nil {
		unix.Close(directoryFD)
		return managedRemovalFailure(state, errors.New("open managed directory for removal"))
	}
	for {
		batch, readErr := directory.ReadDir(256)
		for _, entry := range batch {
			if err := m.removeManagedEntryAtPrevalidated(int(directory.Fd()), entry.Name(), openedMountID, depth+1, state); err != nil {
				_ = directory.Close()
				return managedRemovalFailure(state, err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return managedRemovalFailure(state, readErr)
		}
	}
	if err := directory.Close(); err != nil {
		return managedRemovalFailure(state, err)
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return managedRemovalFailure(state, err)
	}
	state.changed = true
	return m.syncManagedDirectory(parentFD, "sync recursively removed managed directory parent", true)
}

func managedRemovalFailure(state *managedRemovalState, err error) error {
	if err == nil || state == nil || !state.changed {
		return err
	}
	return managedChangedMutationError("managed recursive removal partially completed", false, err)
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
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
}

func classifyManagedResolutionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOTDIR) {
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
