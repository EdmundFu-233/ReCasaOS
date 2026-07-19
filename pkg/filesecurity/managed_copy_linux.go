//go:build linux

package filesecurity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxManagedRenameCandidates = 10_000

type managedTransferBudget struct {
	entries int64
	bytes   int64
}

// CopyInto copies one regular file or directory below destinationDirectory.
// Every source and destination component is resolved relative to a pinned root
// descriptor. The completed copy is published with renameat2, so partially
// copied trees are never exposed under the requested destination name.
func (m *ManagedRoots) CopyInto(sourcePath, destinationDirectory string, style ManagedConflictStyle) (ManagedTransferResult, error) {
	return m.transferInto(sourcePath, destinationDirectory, style, false)
}

// MoveInto moves one regular file or directory below destinationDirectory.
// Directories are accepted only when a non-replacing same-filesystem atomic
// rename succeeds. Regular-file cross-filesystem and replacing moves publish a
// complete copy first and unlink the source only after full identity
// revalidation, so a failed cleanup cannot lose the source.
func (m *ManagedRoots) MoveInto(sourcePath, destinationDirectory string, style ManagedConflictStyle) (ManagedTransferResult, error) {
	return m.transferInto(sourcePath, destinationDirectory, style, true)
}

func (m *ManagedRoots) transferInto(sourcePath, destinationDirectory string, style ManagedConflictStyle, move bool) (ManagedTransferResult, error) {
	if m == nil {
		return ManagedTransferResult{}, ErrManagedPathOutsideRoots
	}
	normalizedStyle, err := ParseManagedConflictStyle(string(style))
	if err != nil {
		return ManagedTransferResult{}, err
	}
	style = normalizedStyle

	// A transfer is a multi-step publication operation. Serialize it with every
	// other managed namespace/content mutation, including complete upload write
	// lifetimes and caller-owned mount transactions.
	release, err := m.AcquireMutation()
	if err != nil {
		return ManagedTransferResult{}, err
	}
	defer release()

	sourceRoot, sourceLocation, err := m.resolveLocked(sourcePath)
	if err != nil {
		return ManagedTransferResult{}, err
	}
	if sourceLocation.Relative == "." {
		return ManagedTransferResult{}, fmt.Errorf("%w: a configured root cannot be copied or moved", ErrUnsafePath)
	}
	destinationRoot, destinationLocation, err := m.resolveLocked(destinationDirectory)
	if err != nil {
		return ManagedTransferResult{}, err
	}

	source, err := openManagedAt(sourceRoot, sourceLocation, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return ManagedTransferResult{}, err
	}
	defer source.Close()
	if err := validateManagedOpenedFile(source, true); err != nil {
		return ManagedTransferResult{}, err
	}
	var sourceStat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &sourceStat); err != nil {
		return ManagedTransferResult{}, err
	}
	if err := m.rejectConfiguredRootAtOrBelow(source, sourceLocation.Canonical); err != nil {
		return ManagedTransferResult{}, err
	}

	destination, err := openManagedAt(destinationRoot, destinationLocation, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return ManagedTransferResult{}, err
	}
	defer destination.Close()
	if err := m.validateManagedDestinationFD(destinationRoot, int(destination.Fd()), destinationLocation); err != nil {
		return ManagedTransferResult{}, err
	}
	destinationMountID, err := managedMountIDAt(int(destination.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return ManagedTransferResult{}, err
	}
	if move {
		sourceParentFD, _, err := openManagedParent(sourceRoot, sourceLocation)
		if err != nil {
			return ManagedTransferResult{}, err
		}
		mountErr := validateManagedMoveMountBoundary(sourceParentFD, int(source.Fd()))
		_ = unix.Close(sourceParentFD)
		if mountErr != nil {
			return ManagedTransferResult{}, mountErr
		}
	}

	base := filepath.Base(sourceLocation.Canonical)
	if err := ValidatePathComponent(base); err != nil {
		return ManagedTransferResult{}, err
	}
	requestedTarget := filepath.Join(destinationLocation.Canonical, base)
	if err := m.rejectConfiguredRootCanonicalAtOrBelow(requestedTarget); err != nil {
		return ManagedTransferResult{}, err
	}
	if filepath.Dir(sourceLocation.Canonical) == destinationLocation.Canonical || managedPathsOverlap(sourceLocation.Canonical, requestedTarget) {
		return ManagedTransferResult{}, fmt.Errorf("%w: source and destination overlap", ErrUnsafePath)
	}
	if sourceStat.Mode&unix.S_IFMT == unix.S_IFDIR && managedPathContains(sourceLocation.Canonical, destinationLocation.Canonical) {
		return ManagedTransferResult{}, fmt.Errorf("%w: destination is inside the source directory", ErrUnsafePath)
	}
	if err := rejectManagedExactTargetAlias(int(destination.Fd()), base, &sourceStat); err != nil {
		return ManagedTransferResult{}, err
	}

	if sourceStat.Mode&unix.S_IFMT == unix.S_IFDIR {
		sourceMountID, err := managedMountIDAt(int(source.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return ManagedTransferResult{}, err
		}
		if sourceRoot != destinationRoot || sourceMountID != destinationMountID {
			return ManagedTransferResult{}, fmt.Errorf("%w: directory source and destination are not provably within one configured root and mount", ErrUnsafeManagedDirectoryTransfer)
		}
		destinationInsideSource, err := managedDescriptorIsAncestorOrSame(int(source.Fd()), int(destination.Fd()))
		if err != nil {
			return ManagedTransferResult{}, err
		}
		if destinationInsideSource {
			return ManagedTransferResult{}, fmt.Errorf("%w: destination descriptor is inside the source directory", ErrUnsafeManagedDirectoryTransfer)
		}
		if move {
			if style == ManagedConflictReplace {
				return ManagedTransferResult{}, fmt.Errorf("%w: replacing directory moves are disabled", ErrManagedDirectoryMoveRequiresAtomicRename)
			}
			budget := int64(0)
			if err := m.validateManagedAtomicMoveTree(source, &sourceStat, sourceMountID, 0, &budget); err != nil {
				return ManagedTransferResult{}, err
			}
			result, completed, renameErr := m.renameManagedSourceNoReplace(sourceRoot, sourceLocation, &sourceStat, int(destination.Fd()), destinationLocation, base, style)
			if !completed && errors.Is(renameErr, unix.EXDEV) {
				return ManagedTransferResult{}, ErrManagedDirectoryMoveRequiresAtomicRename
			}
			return result, renameErr
		}
	}

	if move && style != ManagedConflictReplace {
		result, completed, renameErr := m.renameManagedSourceNoReplace(sourceRoot, sourceLocation, &sourceStat, int(destination.Fd()), destinationLocation, base, style)
		if completed || renameErr != nil && !errors.Is(renameErr, unix.EXDEV) {
			return result, renameErr
		}
	}

	result, err := m.copyManagedTransfer(source, &sourceStat, int(destination.Fd()), destinationMountID, destinationLocation, base, style)
	if err != nil || !move || !result.Changed {
		return result, err
	}

	// Copy-first move fallback. Only unlink the name if it still identifies the
	// inode that was copied; a concurrent pathname replacement is left intact.
	var sourceAfterCopy unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &sourceAfterCopy); err != nil {
		return result, fmt.Errorf("destination published but source revalidation failed: %w", err)
	}
	if !sameManagedTransferStat(&sourceStat, &sourceAfterCopy) {
		return result, errors.New("destination published but source changed before cleanup")
	}
	if err := m.removeManagedTransferSource(sourceRoot, sourceLocation, &sourceStat); err != nil {
		return result, fmt.Errorf("destination published but source cleanup failed: %w", err)
	}
	return result, nil
}

func validateManagedMoveMountBoundary(sourceParentFD, sourceFD int) error {
	sourceParentMountID, err := managedMountIDAt(sourceParentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	sourceMountID, err := managedMountIDAt(sourceFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if sourceMountID != sourceParentMountID {
		return fmt.Errorf("%w: refusing to move a mount boundary", ErrUnsafePath)
	}
	return nil
}

func (m *ManagedRoots) renameManagedSourceNoReplace(sourceRoot *managedRoot, sourceLocation ManagedLocation, sourceStat *unix.Stat_t, destinationFD int, destinationLocation ManagedLocation, base string, style ManagedConflictStyle) (ManagedTransferResult, bool, error) {
	sourceParentFD, sourceBase, err := openManagedParent(sourceRoot, sourceLocation)
	if err != nil {
		return ManagedTransferResult{}, true, err
	}
	defer unix.Close(sourceParentFD)
	if err := verifyManagedNameIdentity(sourceParentFD, sourceBase, sourceStat); err != nil {
		return ManagedTransferResult{}, true, err
	}

	limit := 1
	if style == ManagedConflictRename {
		limit = maxManagedRenameCandidates
	}
	for index := 0; index < limit; index++ {
		candidate, err := managedRenameCandidate(base, index)
		if err != nil {
			return ManagedTransferResult{}, true, err
		}
		target := filepath.Join(destinationLocation.Canonical, candidate)
		if managedPathsOverlap(sourceLocation.Canonical, target) {
			return ManagedTransferResult{}, true, fmt.Errorf("%w: source and destination overlap", ErrUnsafePath)
		}
		if err := verifyManagedNameIdentity(sourceParentFD, sourceBase, sourceStat); err != nil {
			return ManagedTransferResult{}, true, err
		}
		renameErr := unix.Renameat2(sourceParentFD, sourceBase, destinationFD, candidate, unix.RENAME_NOREPLACE)
		if renameErr == nil {
			result := ManagedTransferResult{Destination: target, Changed: true}
			destinationSyncErr := m.syncManagedDirectory(destinationFD, "sync moved managed destination parent", true)
			sourceSyncErr := m.syncManagedDirectory(sourceParentFD, "sync moved managed source parent", true)
			return result, true, errors.Join(destinationSyncErr, sourceSyncErr)
		}
		if errors.Is(renameErr, unix.EXDEV) {
			return ManagedTransferResult{}, false, renameErr
		}
		if errors.Is(renameErr, unix.EEXIST) {
			if style == ManagedConflictSkip {
				return ManagedTransferResult{Destination: target, Changed: false}, true, nil
			}
			continue
		}
		return ManagedTransferResult{}, true, classifyManagedResolutionError(renameErr)
	}
	return ManagedTransferResult{}, true, fmt.Errorf("no available managed destination name after %d attempts", limit)
}

func (m *ManagedRoots) copyManagedTransfer(source *os.File, sourceStat *unix.Stat_t, destinationFD int, destinationMountID uint64, destinationLocation ManagedLocation, base string, style ManagedConflictStyle) (result ManagedTransferResult, resultErr error) {
	temporaryName, err := randomManagedTransferName(".recasaos-transfer-")
	if err != nil {
		return ManagedTransferResult{}, err
	}
	budget := &managedTransferBudget{}
	created, err := copyManagedOpenedToNew(source, sourceStat, destinationFD, temporaryName, 0, budget)
	if err != nil {
		if created {
			var temporaryStat unix.Stat_t
			if statErr := unix.Fstatat(destinationFD, temporaryName, &temporaryStat, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
				err = errors.Join(err, statErr)
			} else {
				cleanupBudget := int64(0)
				err = errors.Join(err, m.removeManagedEntryAt(destinationFD, temporaryName, destinationMountID, 0, &cleanupBudget))
			}
		}
		return ManagedTransferResult{}, err
	}
	var cleanupExpected unix.Stat_t
	if err := unix.Fstatat(destinationFD, temporaryName, &cleanupExpected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ManagedTransferResult{}, err
	}

	temporaryPresent := true
	defer func() {
		if !temporaryPresent {
			return
		}
		present, presenceErr := managedNamePresentAt(destinationFD, temporaryName, &cleanupExpected)
		resultErr = errors.Join(resultErr, presenceErr)
		if !present {
			return
		}
		cleanupBudget := int64(0)
		resultErr = errors.Join(resultErr, m.removeManagedEntryAt(destinationFD, temporaryName, destinationMountID, 0, &cleanupBudget))
	}()

	result, temporaryPresent, err = m.publishManagedTransfer(destinationFD, destinationMountID, temporaryName, destinationLocation, base, style, &cleanupExpected)
	if err != nil {
		return result, err
	}
	return result, nil
}

func copyManagedOpenedToNew(source *os.File, sourceStat *unix.Stat_t, destinationParentFD int, destinationName string, depth int, budget *managedTransferBudget) (bool, error) {
	if err := ValidatePathComponent(destinationName); err != nil {
		return false, err
	}
	if depth > maxManagedRemoveDepth {
		return false, errors.New("managed transfer exceeds depth limit")
	}
	if budget.entries >= maxManagedTreeEntries {
		return false, errors.New("managed transfer exceeds entry limit")
	}
	budget.entries++

	switch sourceStat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if sourceStat.Nlink != 1 {
			return false, fmt.Errorf("%w: managed regular file has multiple hard links", ErrUnsafePath)
		}
		destinationFD, err := unix.Openat2(destinationParentFD, destinationName, &unix.OpenHow{
			Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
			Mode:    0o600,
			Resolve: managedResolvePolicy,
		})
		if err != nil {
			return false, classifyManagedResolutionError(err)
		}
		destination := os.NewFile(uintptr(destinationFD), destinationName)
		if destination == nil {
			unix.Close(destinationFD)
			return true, errors.New("open managed transfer destination")
		}
		copyErr := copyManagedRegular(source, sourceStat, destination, budget)
		closeErr := destination.Close()
		return true, errors.Join(copyErr, closeErr)

	case unix.S_IFDIR:
		if err := unix.Mkdirat(destinationParentFD, destinationName, 0o700); err != nil {
			return false, classifyManagedResolutionError(err)
		}
		destinationFD, err := unix.Openat2(destinationParentFD, destinationName, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
			Resolve: managedResolvePolicy,
		})
		if err != nil {
			return true, classifyManagedResolutionError(err)
		}
		destination := os.NewFile(uintptr(destinationFD), destinationName)
		if destination == nil {
			unix.Close(destinationFD)
			return true, errors.New("open managed transfer directory")
		}
		sourceMountID, err := managedMountIDAt(int(source.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			err = copyManagedDirectory(source, sourceStat, sourceMountID, destination, depth, budget)
		}
		closeErr := destination.Close()
		return true, errors.Join(err, closeErr)

	default:
		return false, fmt.Errorf("%w: managed transfer source has an unsupported type", ErrUnsafePath)
	}
}

func copyManagedRegular(source *os.File, sourceStat *unix.Stat_t, destination *os.File, budget *managedTransferBudget) error {
	if sourceStat.Size < 0 || sourceStat.Size > int64(^uint64(0)>>1)-budget.bytes {
		return errors.New("managed transfer size overflow")
	}
	written, err := io.CopyN(destination, source, sourceStat.Size)
	if err != nil {
		return fmt.Errorf("copy managed regular file: %w", err)
	}
	if written != sourceStat.Size {
		return io.ErrShortWrite
	}
	var extra [1]byte
	n, readErr := source.Read(extra[:])
	if n != 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.New("managed transfer source changed size while being copied")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &after); err != nil {
		return err
	}
	if !sameManagedTransferStat(sourceStat, &after) {
		return errors.New("managed transfer source changed while being copied")
	}
	budget.bytes += written
	if err := unix.Fchmod(int(destination.Fd()), uint32(sourceStat.Mode&0o777)); err != nil {
		return err
	}
	return destination.Sync()
}

func copyManagedDirectory(source *os.File, sourceStat *unix.Stat_t, sourceMountID uint64, destination *os.File, depth int, budget *managedTransferBudget) error {
	for {
		entries, readErr := source.ReadDir(256)
		for _, entry := range entries {
			if err := ValidatePathComponent(entry.Name()); err != nil {
				return err
			}
			childMountID, err := managedMountIDAt(int(source.Fd()), entry.Name(), unix.AT_SYMLINK_NOFOLLOW)
			if err != nil {
				return err
			}
			if childMountID != sourceMountID {
				return fmt.Errorf("%w: refusing to cross a mount boundary during copy", ErrUnsafePath)
			}
			child, err := openManagedTransferChild(int(source.Fd()), entry.Name())
			if err != nil {
				return err
			}
			if err := validateManagedChildMount(sourceMountID, int(child.Fd())); err != nil {
				_ = child.Close()
				return err
			}
			var childStat unix.Stat_t
			if err := unix.Fstat(int(child.Fd()), &childStat); err != nil {
				_ = child.Close()
				return err
			}
			_, copyErr := copyManagedOpenedToNew(child, &childStat, int(destination.Fd()), entry.Name(), depth+1, budget)
			closeErr := child.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &after); err != nil {
		return err
	}
	if !sameManagedTransferStat(sourceStat, &after) {
		return errors.New("managed transfer source directory changed while being copied")
	}
	if err := unix.Fchmod(int(destination.Fd()), uint32(sourceStat.Mode&0o777)); err != nil {
		return err
	}
	return destination.Sync()
}

func validateManagedChildMount(parentMountID uint64, childFD int) error {
	childMountID, err := managedMountIDAt(childFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if childMountID != parentMountID {
		return fmt.Errorf("%w: child mount changed during copy", ErrUnsafePath)
	}
	return nil
}

func (m *ManagedRoots) rejectConfiguredRootCanonicalAtOrBelow(candidate string) error {
	for i := range m.roots {
		if managedPathContains(candidate, m.roots[i].path) {
			return fmt.Errorf("%w: transfer path %q contains configured root %q", ErrUnsafePath, candidate, m.roots[i].path)
		}
	}
	return nil
}

func (m *ManagedRoots) rejectConfiguredRootAtOrBelow(candidate *os.File, canonical string) error {
	if err := m.rejectConfiguredRootCanonicalAtOrBelow(canonical); err != nil {
		return err
	}
	var candidateStat unix.Stat_t
	if err := unix.Fstat(int(candidate.Fd()), &candidateStat); err != nil {
		return err
	}
	candidateMountID, err := managedMountIDAt(int(candidate.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	for i := range m.roots {
		var rootStat unix.Stat_t
		if err := unix.Fstat(int(m.roots[i].file.Fd()), &rootStat); err != nil {
			return err
		}
		if managedStatSameObject(&candidateStat, &rootStat) {
			return fmt.Errorf("%w: transfer descriptor aliases configured root %q", ErrUnsafePath, m.roots[i].path)
		}
		if candidateStat.Mode&unix.S_IFMT != unix.S_IFDIR {
			continue
		}
		ancestor, err := managedDescriptorIsAncestorOrSame(int(candidate.Fd()), int(m.roots[i].file.Fd()))
		if err != nil {
			return err
		}
		if ancestor {
			return fmt.Errorf("%w: transfer descriptor contains configured root %q", ErrUnsafePath, m.roots[i].path)
		}
		rootMountID, err := managedMountIDAt(int(m.roots[i].file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return err
		}
		if candidateStat.Dev == rootStat.Dev && candidateMountID != rootMountID {
			return fmt.Errorf("%w: a same-device configured root is reachable through a different mount alias", ErrUnsafeManagedDirectoryTransfer)
		}
	}
	return nil
}

func rejectManagedExactTargetAlias(destinationFD int, name string, sourceStat *unix.Stat_t) error {
	var targetStat unix.Stat_t
	if err := unix.Fstatat(destinationFD, name, &targetStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if managedStatSameObject(sourceStat, &targetStat) {
		return fmt.Errorf("%w: source and requested target are the same inode", ErrUnsafePath)
	}
	return nil
}

func managedStatSameObject(first, second *unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino
}

// validateManagedDestinationFD binds the audit path's selected configured root
// to the opened destination topology. A bind mount can otherwise make a path
// lexically authorized by one root write into another configured root while
// reporting the first spelling.
func (m *ManagedRoots) validateManagedDestinationFD(selectedRoot *managedRoot, destinationFD int, location ManagedLocation) error {
	if selectedRoot == nil || location.Root != selectedRoot.path {
		return fmt.Errorf("%w: destination root selection changed", ErrUnsafePath)
	}
	withinSelected, err := managedDescriptorIsAncestorOrSame(int(selectedRoot.file.Fd()), destinationFD)
	if err != nil {
		return err
	}
	if !withinSelected {
		return fmt.Errorf("%w: destination descriptor is outside its selected configured root", ErrUnsafePath)
	}
	var destinationStat unix.Stat_t
	if err := unix.Fstat(destinationFD, &destinationStat); err != nil {
		return err
	}
	destinationMountID, err := managedMountIDAt(destinationFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	selectedMountID, err := managedMountIDAt(int(selectedRoot.file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	for i := range m.roots {
		other := &m.roots[i]
		if other == selectedRoot {
			continue
		}
		// A more-specific configured root is legitimately nested beneath a
		// broader configured root. Once the lexical resolver selected the
		// nested root, its configured lexical ancestors are not cross-root
		// aliases.
		if managedPathContains(other.path, selectedRoot.path) {
			continue
		}
		var otherStat unix.Stat_t
		if err := unix.Fstat(int(other.file.Fd()), &otherStat); err != nil {
			return err
		}
		if managedStatSameObject(&destinationStat, &otherStat) {
			return fmt.Errorf("%w: destination descriptor aliases configured root %q", ErrUnsafePath, other.path)
		}
		insideOther, err := managedDescriptorIsAncestorOrSame(int(other.file.Fd()), destinationFD)
		if err != nil {
			return err
		}
		if insideOther {
			return fmt.Errorf("%w: destination descriptor resolves below configured root %q", ErrUnsafePath, other.path)
		}
		// Walking `..` from the root of a bind mount follows the alias mount
		// parent, so an alias of a subdirectory may hide its original ancestor.
		// When the selected root was crossed, fail closed if the destination's
		// backing device is also used by another configured root.
		if destinationMountID != selectedMountID && destinationStat.Dev == otherStat.Dev {
			return fmt.Errorf("%w: destination crosses into a possible configured-root bind alias", ErrUnsafePath)
		}
	}
	return nil
}

// managedDescriptorIsAncestorOrSame walks upward from descendant using only
// directory descriptors. It is an inode guard in addition to lexical path
// checks, catching hard aliases and same-mount bind spellings that resolve to
// the same directory tree.
func managedDescriptorIsAncestorOrSame(ancestorFD, descendantFD int) (bool, error) {
	var ancestorStat unix.Stat_t
	if err := unix.Fstat(ancestorFD, &ancestorStat); err != nil {
		return false, err
	}
	if ancestorStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, nil
	}
	currentFD, err := unix.FcntlInt(uintptr(descendantFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() {
		if currentFD >= 0 {
			_ = unix.Close(currentFD)
		}
	}()
	for depth := 0; depth <= maxManagedRemoveDepth*4; depth++ {
		var currentStat unix.Stat_t
		if err := unix.Fstat(currentFD, &currentStat); err != nil {
			return false, err
		}
		if managedStatSameObject(&ancestorStat, &currentStat) {
			return true, nil
		}
		parentFD, err := unix.Openat(currentFD, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return false, err
		}
		var parentStat unix.Stat_t
		if err := unix.Fstat(parentFD, &parentStat); err != nil {
			unix.Close(parentFD)
			return false, err
		}
		if managedStatSameObject(&currentStat, &parentStat) {
			unix.Close(parentFD)
			return false, nil
		}
		oldFD := currentFD
		currentFD = -1
		if err := unix.Close(oldFD); err != nil {
			unix.Close(parentFD)
			return false, err
		}
		currentFD = parentFD
	}
	return false, errors.New("managed descriptor ancestry exceeds depth limit")
}

func (m *ManagedRoots) validateManagedAtomicMoveTree(opened *os.File, before *unix.Stat_t, expectedMountID uint64, depth int, entries *int64) error {
	if depth > maxManagedRemoveDepth {
		return errors.New("managed atomic move exceeds depth limit")
	}
	if *entries >= maxManagedTreeEntries {
		return errors.New("managed atomic move exceeds entry limit")
	}
	*entries++
	if err := validateManagedChildMount(expectedMountID, int(opened.Fd())); err != nil {
		return err
	}
	for {
		children, readErr := opened.ReadDir(256)
		for _, childEntry := range children {
			if err := ValidatePathComponent(childEntry.Name()); err != nil {
				return err
			}
			child, err := openManagedTransferChild(int(opened.Fd()), childEntry.Name())
			if err != nil {
				return err
			}
			if err := validateManagedChildMount(expectedMountID, int(child.Fd())); err != nil {
				_ = child.Close()
				return err
			}
			var childStat unix.Stat_t
			if err := unix.Fstat(int(child.Fd()), &childStat); err != nil {
				_ = child.Close()
				return err
			}
			switch childStat.Mode & unix.S_IFMT {
			case unix.S_IFREG:
				if childStat.Nlink != 1 {
					_ = child.Close()
					return fmt.Errorf("%w: atomic directory move contains a hard-linked file", ErrUnsafePath)
				}
			case unix.S_IFDIR:
				if err := m.validateManagedAtomicMoveTree(child, &childStat, expectedMountID, depth+1, entries); err != nil {
					_ = child.Close()
					return err
				}
			default:
				_ = child.Close()
				return fmt.Errorf("%w: atomic directory move contains an unsupported entry", ErrUnsafePath)
			}
			if err := child.Close(); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &after); err != nil {
		return err
	}
	if !sameManagedTransferStat(before, &after) {
		return errors.New("managed directory changed during atomic move validation")
	}
	return nil
}

func openManagedTransferChild(parentFD int, name string) (*os.File, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, classifyManagedResolutionError(err)
	}
	opened := os.NewFile(uintptr(fd), name)
	if opened == nil {
		unix.Close(fd)
		return nil, errors.New("open managed transfer source")
	}
	if err := validateManagedOpenedFile(opened, true); err != nil {
		_ = opened.Close()
		return nil, err
	}
	return opened, nil
}

func (m *ManagedRoots) publishManagedTransfer(destinationFD int, destinationMountID uint64, temporaryName string, destinationLocation ManagedLocation, base string, style ManagedConflictStyle, cleanupExpected *unix.Stat_t) (ManagedTransferResult, bool, error) {
	limit := 1
	if style == ManagedConflictRename {
		limit = maxManagedRenameCandidates
	}
	for index := 0; index < limit; index++ {
		candidate, err := managedRenameCandidate(base, index)
		if err != nil {
			return ManagedTransferResult{}, true, err
		}
		target := filepath.Join(destinationLocation.Canonical, candidate)
		renameErr := unix.Renameat2(destinationFD, temporaryName, destinationFD, candidate, unix.RENAME_NOREPLACE)
		if renameErr == nil {
			result := ManagedTransferResult{Destination: target, Changed: true}
			return result, false, m.syncManagedDirectory(destinationFD, "sync published managed destination", true)
		}
		if !errors.Is(renameErr, unix.EEXIST) {
			return ManagedTransferResult{}, true, classifyManagedResolutionError(renameErr)
		}
		switch style {
		case ManagedConflictSkip:
			return ManagedTransferResult{Destination: target, Changed: false}, true, nil
		case ManagedConflictRename:
			continue
		case ManagedConflictReplace:
			replacedStat, err := validateManagedReplacementType(destinationFD, temporaryName, candidate)
			if err != nil {
				return ManagedTransferResult{}, true, err
			}
			if err := m.validateManagedReplacementAt(destinationFD, candidate, destinationMountID, target); err != nil {
				return ManagedTransferResult{}, true, err
			}
			if m.replaceBeforeExchange != nil {
				if err := m.replaceBeforeExchange(); err != nil {
					return ManagedTransferResult{}, true, err
				}
			}
			if err := unix.Renameat2(destinationFD, temporaryName, destinationFD, candidate, unix.RENAME_EXCHANGE); err != nil {
				return ManagedTransferResult{}, true, classifyManagedResolutionError(err)
			}
			if cleanupExpected != nil {
				*cleanupExpected = replacedStat
			}
			result := ManagedTransferResult{Destination: target, Changed: true}
			if err := m.syncManagedDirectory(destinationFD, "sync exchanged managed destination", true); err != nil {
				// The destination was exchanged, but an unsynchronized old target
				// is safer left at the hidden staging name than removed by a later
				// pathname retry.
				return result, false, err
			}
			present, presenceErr := managedNamePresentAt(destinationFD, temporaryName, &replacedStat)
			if presenceErr != nil {
				return result, true, managedChangedMutationError("replacement published but hidden old target identity changed", false, presenceErr)
			}
			if !present {
				return result, false, managedChangedMutationError("replacement published but hidden old target disappeared", false, ErrUnsafePath)
			}
			cleanupBudget := int64(0)
			if err := m.removeManagedEntryAt(destinationFD, temporaryName, destinationMountID, 0, &cleanupBudget); err != nil {
				temporaryPresent, presenceErr := managedNamePresentAt(destinationFD, temporaryName, &replacedStat)
				return result, temporaryPresent, errors.Join(fmt.Errorf("replacement published but old destination cleanup failed: %w", err), presenceErr)
			}
			return result, false, nil
		}
	}
	return ManagedTransferResult{}, true, fmt.Errorf("no available managed destination name after %d attempts", limit)
}

func validateManagedReplacementType(parentFD int, sourceName, targetName string) (unix.Stat_t, error) {
	var sourceStat unix.Stat_t
	if err := unix.Fstatat(parentFD, sourceName, &sourceStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	var targetStat unix.Stat_t
	if err := unix.Fstatat(parentFD, targetName, &targetStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	sourceType := sourceStat.Mode & unix.S_IFMT
	targetType := targetStat.Mode & unix.S_IFMT
	if sourceType != targetType || sourceType != unix.S_IFREG && sourceType != unix.S_IFDIR {
		return unix.Stat_t{}, fmt.Errorf("%w: replacement requires matching regular-file or directory types", ErrUnsafePath)
	}
	return targetStat, nil
}

func managedNamePresentAt(parentFD int, name string, expected *unix.Stat_t) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if expected == nil || !sameManagedTransferStat(expected, &stat) {
		return false, fmt.Errorf("%w: managed cleanup name no longer identifies the expected staging entry", ErrUnsafePath)
	}
	return true, nil
}

func (m *ManagedRoots) validateManagedReplacementAt(parentFD int, name string, parentMountID uint64, canonical string) error {
	opened, err := openManagedTransferChild(parentFD, name)
	if err != nil {
		return err
	}
	if err := m.rejectConfiguredRootAtOrBelow(opened, canonical); err != nil {
		_ = opened.Close()
		return err
	}
	if err := opened.Close(); err != nil {
		return err
	}
	budget := int64(0)
	return validateManagedRemovableEntryAt(parentFD, name, parentMountID, 0, &budget, false)
}

func validateManagedRemovableEntryAt(parentFD int, name string, parentMountID uint64, depth int, entries *int64, nested bool) error {
	if err := ValidatePathComponent(name); err != nil {
		return err
	}
	if depth > maxManagedRemoveDepth {
		return errors.New("managed replacement exceeds depth limit")
	}
	if *entries >= maxManagedTreeEntries {
		return errors.New("managed replacement exceeds entry limit")
	}
	*entries++
	mountID, err := managedMountIDAt(parentFD, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if mountID != parentMountID {
		return fmt.Errorf("%w: refusing to replace a mount boundary", ErrUnsafePath)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if stat.Nlink != 1 {
			return fmt.Errorf("%w: replacement target has multiple hard links", ErrUnsafePath)
		}
		return nil
	case unix.S_IFLNK:
		if nested {
			return nil
		}
		return fmt.Errorf("%w: refusing to replace a symbolic link", ErrUnsafePath)
	case unix.S_IFDIR:
		fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
			Resolve: managedResolvePolicy,
		})
		if err != nil {
			return classifyManagedResolutionError(err)
		}
		directory := os.NewFile(uintptr(fd), name)
		if directory == nil {
			unix.Close(fd)
			return errors.New("open managed replacement target")
		}
		defer directory.Close()
		for {
			children, readErr := directory.ReadDir(256)
			for _, child := range children {
				if err := validateManagedRemovableEntryAt(int(directory.Fd()), child.Name(), mountID, depth+1, entries, true); err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	default:
		return fmt.Errorf("%w: refusing to replace a special file", ErrUnsafePath)
	}
}

func (m *ManagedRoots) removeManagedTransferSource(root *managedRoot, location ManagedLocation, sourceStat *unix.Stat_t) error {
	parentFD, base, err := openManagedParent(root, location)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := verifyManagedNameIdentity(parentFD, base, sourceStat); err != nil {
		return err
	}
	parentMountID, err := managedMountIDAt(parentFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	budget := int64(0)
	return m.removeManagedEntryAt(parentFD, base, parentMountID, 0, &budget)
}

func verifyManagedNameIdentity(parentFD int, name string, expected *unix.Stat_t) error {
	var actual unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameManagedTransferStat(expected, &actual) {
		return fmt.Errorf("%w: managed source name changed during transfer", ErrUnsafePath)
	}
	return nil
}

func sameManagedTransferStat(before, after *unix.Stat_t) bool {
	return before.Dev == after.Dev &&
		before.Ino == after.Ino &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Size == after.Size &&
		before.Mtim == after.Mtim &&
		before.Ctim == after.Ctim
}

func managedRenameCandidate(base string, index int) (string, error) {
	if index == 0 {
		return base, ValidatePathComponent(base)
	}
	extension := filepath.Ext(base)
	stem := strings.TrimSuffix(base, extension)
	candidate := fmt.Sprintf("%s(%d)%s", stem, index, extension)
	if err := ValidatePathComponent(candidate); err != nil {
		return "", fmt.Errorf("cannot derive a safe conflict-free name from %q: %w", base, err)
	}
	return candidate, nil
}

func randomManagedTransferName(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate managed transfer name: %w", err)
	}
	return prefix + hex.EncodeToString(value), nil
}

func managedPathsOverlap(first, second string) bool {
	return managedPathContains(first, second) || managedPathContains(second, first)
}

func managedPathContains(parent, child string) bool {
	if parent == child {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
