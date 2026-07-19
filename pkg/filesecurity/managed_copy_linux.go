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
// rename succeeds. Regular-file cross-filesystem and replacing moves retain
// the source and return ErrManagedMoveSourceRetained once destination namespace
// publication is reported. Normal completion is synchronized and verified;
// joined publication/transaction errors may instead set DurabilityUnknown.
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
	sourceParentFD := -1
	sourceParentBase := ""
	if move {
		sourceParentFD, sourceParentBase, err = openManagedParent(sourceRoot, sourceLocation)
		if err != nil {
			return ManagedTransferResult{}, err
		}
		defer unix.Close(sourceParentFD)
		sourceParentLocation, err := m.matchLocked(filepath.Dir(sourceLocation.Canonical))
		if err != nil {
			return ManagedTransferResult{}, err
		}
		if err := m.validateManagedDestinationFD(sourceRoot, sourceParentFD, sourceParentLocation); err != nil {
			return ManagedTransferResult{}, err
		}
		if err := verifyManagedNameIdentity(sourceParentFD, sourceParentBase, &sourceStat); err != nil {
			return ManagedTransferResult{}, err
		}
		if err := validateManagedMoveMountBoundary(sourceParentFD, int(source.Fd())); err != nil {
			return ManagedTransferResult{}, err
		}
		if err := validateManagedMoveFilesystem(sourceParentFD, "source"); err != nil {
			return ManagedTransferResult{}, err
		}
		if err := validateManagedMoveFilesystem(int(destination.Fd()), "destination"); err != nil {
			return ManagedTransferResult{}, err
		}
	}

	base := filepath.Base(sourceLocation.Canonical)
	if err := ValidatePathComponent(base); err != nil {
		return ManagedTransferResult{}, err
	}
	if move && base != sourceParentBase {
		return ManagedTransferResult{}, fmt.Errorf("%w: pinned source parent basename changed", ErrUnsafePath)
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
			result, completed, renameErr := m.renameManagedSourceNoReplace(sourceParentFD, sourceParentBase, source, sourceLocation, &sourceStat, int(destination.Fd()), destinationLocation, base, style)
			if !completed && errors.Is(renameErr, unix.EXDEV) {
				return ManagedTransferResult{}, ErrManagedDirectoryMoveRequiresAtomicRename
			}
			return result, renameErr
		}
	}

	if move && style != ManagedConflictReplace {
		result, completed, renameErr := m.renameManagedSourceNoReplace(sourceParentFD, sourceParentBase, source, sourceLocation, &sourceStat, int(destination.Fd()), destinationLocation, base, style)
		if completed || renameErr != nil && !errors.Is(renameErr, unix.EXDEV) {
			return result, renameErr
		}
	}

	result, transferErr := m.copyManagedTransfer(source, &sourceStat, int(destination.Fd()), destinationMountID, destinationLocation, base, style)
	if !move || !result.Changed {
		return result, transferErr
	}

	// Until Issue #17 provides a durable move ledger and crash-safe recovery,
	// copy-first moves deliberately retain the original source. The destination
	// has already been published. Always preserve the source-retained contract,
	// while joining any publication/transaction error so its real durability
	// metadata and errors.Is identity remain visible to callers.
	retainedErr := managedChangedMutationError("copy-first managed move retained source", false, ErrManagedMoveSourceRetained)
	return result, errors.Join(transferErr, retainedErr)
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

func (m *ManagedRoots) renameManagedSourceNoReplace(sourceParentFD int, sourceBase string, source *os.File, sourceLocation ManagedLocation, sourceStat *unix.Stat_t, destinationFD int, destinationLocation ManagedLocation, base string, style ManagedConflictStyle) (ManagedTransferResult, bool, error) {
	if sourceParentFD < 0 || destinationFD < 0 || source == nil || sourceStat == nil || sourceBase == "" {
		return ManagedTransferResult{}, true, fmt.Errorf("%w: managed direct move descriptors are incomplete", ErrUnsafePath)
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
		var sourceBeforeRename unix.Stat_t
		if err := unix.Fstat(int(source.Fd()), &sourceBeforeRename); err != nil {
			return ManagedTransferResult{}, true, err
		}
		if !sameManagedTransferStat(sourceStat, &sourceBeforeRename) {
			return ManagedTransferResult{}, true, fmt.Errorf("%w: managed direct move source changed before rename", ErrUnsafePath)
		}
		if err := verifyManagedNameIdentity(sourceParentFD, sourceBase, &sourceBeforeRename); err != nil {
			return ManagedTransferResult{}, true, err
		}
		if m.moveBeforeDirectRename != nil {
			if err := m.moveBeforeDirectRename(); err != nil {
				return ManagedTransferResult{}, true, err
			}
		}
		renameErr := unix.Renameat2(sourceParentFD, sourceBase, destinationFD, candidate, unix.RENAME_NOREPLACE)
		if renameErr == nil {
			result := ManagedTransferResult{Destination: target, Changed: true}
			var sourceAfterRename unix.Stat_t
			if err := unix.Fstat(int(source.Fd()), &sourceAfterRename); err != nil {
				return result, true, managedChangedMutationError("managed direct move published but pinned source revalidation failed", true, err)
			}
			if !sameManagedExchangeStat(&sourceBeforeRename, &sourceAfterRename) {
				return result, true, managedChangedMutationError("managed direct move published but source changed during rename", true, ErrUnsafePath)
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &sourceAfterRename); err != nil {
				return result, true, managedChangedMutationError("managed direct move destination does not identify pinned source", true, err)
			}
			if err := m.syncManagedDirectory(destinationFD, "sync moved managed destination parent", true); err != nil {
				return result, true, err
			}
			if err := m.syncManagedDirectory(sourceParentFD, "sync moved managed source parent", true); err != nil {
				return result, true, err
			}
			var sourceAfterSync unix.Stat_t
			if err := unix.Fstat(int(source.Fd()), &sourceAfterSync); err != nil {
				return result, true, managedChangedMutationError("managed direct move synced but pinned source revalidation failed", false, err)
			}
			if !sameManagedTransferStat(&sourceAfterRename, &sourceAfterSync) {
				return result, true, managedChangedMutationError("managed direct move source changed during sync", false, ErrUnsafePath)
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &sourceAfterSync); err != nil {
				return result, true, managedChangedMutationError("managed direct move destination changed during sync", false, err)
			}
			return result, true, nil
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
	transaction, transactionName, err := createManagedTransferTransaction(destinationFD, destinationMountID)
	if err != nil {
		return ManagedTransferResult{}, err
	}
	cleanupAllowed := true
	entryPresent := false
	stagingSynced := false
	defer func() {
		if !cleanupAllowed {
			retainedErr := errors.Join(resultErr, transaction.Close())
			missingRecordedCause := retainedErr == nil
			if retainedErr == nil {
				retainedErr = errors.New("managed transfer transaction retained without a recorded cause")
			}
			retainedErr = fmt.Errorf("private managed transfer transaction %q retained: %w", transactionName, retainedErr)
			durabilityUnknown := ManagedMutationDurabilityUnknown(retainedErr)
			if !ManagedMutationChanged(retainedErr) {
				durabilityUnknown = durabilityUnknown || (entryPresent && !stagingSynced) || missingRecordedCause
			}
			resultErr = managedChangedMutationError(
				"managed transfer transaction retained after ambiguous outcome",
				durabilityUnknown,
				retainedErr,
			)
			return
		}
		cleanupErr := m.cleanupManagedTransferTransaction(destinationFD, destinationMountID, transactionName, transaction, entryPresent)
		if cleanupErr != nil {
			durabilityUnknown := ManagedMutationDurabilityUnknown(cleanupErr) || (entryPresent && !stagingSynced)
			cleanupErr = managedChangedMutationError(
				"managed transfer transaction cleanup incomplete",
				durabilityUnknown,
				cleanupErr,
			)
		}
		resultErr = errors.Join(resultErr, cleanupErr, transaction.Close())
	}()
	if err := m.syncManagedDirectory(destinationFD, "sync created managed transfer transaction", true); err != nil {
		cleanupAllowed = false
		return ManagedTransferResult{}, err
	}

	const transactionEntry = "entry"
	budget := &managedTransferBudget{}
	created, err := copyManagedOpenedToNew(source, sourceStat, int(transaction.Fd()), transactionEntry, 0, budget)
	entryPresent = created
	if err != nil {
		return ManagedTransferResult{}, err
	}
	var stagingExpected unix.Stat_t
	if err := unix.Fstatat(int(transaction.Fd()), transactionEntry, &stagingExpected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ManagedTransferResult{}, err
	}
	if m.transactionBeforeStageSync != nil {
		if err := m.transactionBeforeStageSync(); err != nil {
			return ManagedTransferResult{}, err
		}
	}
	if err := m.syncManagedDirectory(int(transaction.Fd()), "sync staged managed transfer transaction", true); err != nil {
		cleanupAllowed = false
		return ManagedTransferResult{}, err
	}
	stagingSynced = true
	result, cleanupAllowed, entryPresent, err = m.publishManagedTransaction(destinationFD, destinationMountID, transactionName, transaction, destinationLocation, base, style, &stagingExpected)
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

func (m *ManagedRoots) publishManagedTransaction(destinationFD int, destinationMountID uint64, transactionName string, transaction *os.File, destinationLocation ManagedLocation, base string, style ManagedConflictStyle, stagingExpected *unix.Stat_t) (ManagedTransferResult, bool, bool, error) {
	const transactionEntry = "entry"
	if transaction == nil || stagingExpected == nil {
		return ManagedTransferResult{}, false, true, fmt.Errorf("%w: managed transfer transaction is incomplete", ErrUnsafePath)
	}
	if err := validateManagedTransferTransaction(destinationFD, destinationMountID, transactionName, transaction); err != nil {
		return ManagedTransferResult{}, false, true, err
	}
	staging, err := openManagedTransferChild(int(transaction.Fd()), transactionEntry)
	if err != nil {
		return ManagedTransferResult{}, false, true, err
	}
	closeStaging := func() error {
		if staging == nil {
			return nil
		}
		err := staging.Close()
		staging = nil
		return err
	}
	var stagingOpened unix.Stat_t
	if err := unix.Fstat(int(staging.Fd()), &stagingOpened); err != nil {
		return ManagedTransferResult{}, false, true, errors.Join(err, closeStaging())
	}
	if !sameManagedTransferStat(stagingExpected, &stagingOpened) {
		return ManagedTransferResult{}, false, true, errors.Join(fmt.Errorf("%w: private staging identity changed before publication", ErrUnsafePath), closeStaging())
	}
	if err := verifyManagedNameIdentity(int(transaction.Fd()), transactionEntry, &stagingOpened); err != nil {
		return ManagedTransferResult{}, false, true, errors.Join(err, closeStaging())
	}

	limit := 1
	if style == ManagedConflictRename {
		limit = maxManagedRenameCandidates
	}
	for index := 0; index < limit; index++ {
		candidate, err := managedRenameCandidate(base, index)
		if err != nil {
			return ManagedTransferResult{}, true, true, errors.Join(err, closeStaging())
		}
		target := filepath.Join(destinationLocation.Canonical, candidate)
		var stagingBefore unix.Stat_t
		if err := unix.Fstat(int(staging.Fd()), &stagingBefore); err != nil {
			return ManagedTransferResult{}, false, true, errors.Join(err, closeStaging())
		}
		if !sameManagedTransferStat(&stagingOpened, &stagingBefore) {
			return ManagedTransferResult{}, false, true, errors.Join(fmt.Errorf("%w: private staging changed before publication", ErrUnsafePath), closeStaging())
		}
		if err := verifyManagedNameIdentity(int(transaction.Fd()), transactionEntry, &stagingBefore); err != nil {
			return ManagedTransferResult{}, false, true, errors.Join(err, closeStaging())
		}
		renameErr := unix.Renameat2(int(transaction.Fd()), transactionEntry, destinationFD, candidate, unix.RENAME_NOREPLACE)
		if renameErr == nil {
			result := ManagedTransferResult{Destination: target, Changed: true}
			var publishedStat unix.Stat_t
			if err := unix.Fstat(int(staging.Fd()), &publishedStat); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer published but staging descriptor revalidation failed", true, errors.Join(err, closeStaging()))
			}
			if !sameManagedExchangeStat(&stagingBefore, &publishedStat) {
				return result, false, false, managedChangedMutationError("managed transfer published but staging changed during rename", true, errors.Join(ErrUnsafePath, closeStaging()))
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &publishedStat); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer destination does not identify pinned staging", true, errors.Join(err, closeStaging()))
			}
			if err := m.syncManagedDirectory(destinationFD, "sync published managed destination", true); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer destination publication sync failed", true, errors.Join(err, closeStaging()))
			}
			if err := m.syncManagedDirectory(int(transaction.Fd()), "sync published managed transaction", true); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer transaction publication sync failed", true, errors.Join(err, closeStaging()))
			}
			var publishedAfterSync unix.Stat_t
			if err := unix.Fstat(int(staging.Fd()), &publishedAfterSync); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer published but final staging revalidation failed", false, errors.Join(err, closeStaging()))
			}
			if !sameManagedTransferStat(&publishedStat, &publishedAfterSync) {
				return result, false, false, managedChangedMutationError("managed transfer destination changed during publication sync", false, errors.Join(ErrUnsafePath, closeStaging()))
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &publishedAfterSync); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer destination no longer identifies pinned staging", false, errors.Join(err, closeStaging()))
			}
			if err := closeStaging(); err != nil {
				return result, false, false, managedChangedMutationError("managed transfer published but staging descriptor close failed", false, err)
			}
			return result, true, false, nil
		}
		filesystemEligibility := managedTransactionalFilesystemEligibility
		if m.transferFilesystemEligibility != nil {
			filesystemEligibility = m.transferFilesystemEligibility
		}
		_, filesystemAllowed, filesystemErr := filesystemEligibility(destinationFD)
		if filesystemErr != nil || !filesystemAllowed {
			failureResult, cleanupAllowed, publicationErr := classifyManagedNoReplacePublicationFailure(renameErr, filesystemAllowed, filesystemErr)
			return failureResult, cleanupAllowed, true, errors.Join(publicationErr, closeStaging())
		}
		if !errors.Is(renameErr, unix.EEXIST) {
			failureResult, cleanupAllowed, publicationErr := classifyManagedNoReplacePublicationFailure(renameErr, filesystemAllowed, nil)
			return failureResult, cleanupAllowed, true, errors.Join(publicationErr, closeStaging())
		}
		switch style {
		case ManagedConflictSkip:
			return ManagedTransferResult{Destination: target, Changed: false}, true, true, closeStaging()
		case ManagedConflictRename:
			continue
		case ManagedConflictReplace:
			if err := validateManagedReplaceFilesystem(destinationFD); err != nil {
				return ManagedTransferResult{}, true, true, errors.Join(err, closeStaging())
			}
			replacedStat, err := validateManagedTransactionReplacementType(int(transaction.Fd()), transactionEntry, destinationFD, candidate)
			if err != nil {
				return ManagedTransferResult{}, true, true, errors.Join(err, closeStaging())
			}
			replaced, err := m.validateManagedReplacementAt(destinationFD, candidate, destinationMountID, target, &replacedStat)
			if err != nil {
				return ManagedTransferResult{}, true, true, errors.Join(err, closeStaging())
			}
			closeReplaced := func() error {
				if replaced == nil {
					return nil
				}
				err := replaced.Close()
				replaced = nil
				return err
			}
			closePinned := func() error {
				return errors.Join(closeStaging(), closeReplaced())
			}
			if m.replaceBeforeExchange != nil {
				if err := m.replaceBeforeExchange(); err != nil {
					return ManagedTransferResult{}, false, true, errors.Join(err, closePinned())
				}
			}
			if err := validateManagedTransferTransaction(destinationFD, destinationMountID, transactionName, transaction); err != nil {
				return ManagedTransferResult{}, false, true, errors.Join(err, closePinned())
			}
			if err := unix.Fstat(int(staging.Fd()), &stagingBefore); err != nil {
				return ManagedTransferResult{}, false, true, errors.Join(err, closePinned())
			}
			if !sameManagedTransferStat(&stagingOpened, &stagingBefore) {
				return ManagedTransferResult{}, false, true, errors.Join(fmt.Errorf("%w: private staging changed before exchange", ErrUnsafePath), closePinned())
			}
			if err := verifyManagedNameIdentity(int(transaction.Fd()), transactionEntry, &stagingBefore); err != nil {
				return ManagedTransferResult{}, false, true, errors.Join(err, closePinned())
			}
			var exchangeBefore unix.Stat_t
			if err := unix.Fstat(int(replaced.Fd()), &exchangeBefore); err != nil {
				return ManagedTransferResult{}, true, true, errors.Join(err, closePinned())
			}
			if !sameManagedTransferStat(&replacedStat, &exchangeBefore) {
				return ManagedTransferResult{}, true, true, errors.Join(fmt.Errorf("%w: replacement target changed before exchange", ErrUnsafePath), closePinned())
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &exchangeBefore); err != nil {
				return ManagedTransferResult{}, true, true, errors.Join(err, closePinned())
			}
			if err := unix.Renameat2(int(transaction.Fd()), transactionEntry, destinationFD, candidate, unix.RENAME_EXCHANGE); err != nil {
				return ManagedTransferResult{}, false, true, errors.Join(classifyManagedResolutionError(err), closePinned())
			}

			result := ManagedTransferResult{Destination: target, Changed: true}
			var publishedStat unix.Stat_t
			if err := unix.Fstat(int(staging.Fd()), &publishedStat); err != nil {
				return result, false, true, managedChangedMutationError("replacement published but staging descriptor revalidation failed", true, errors.Join(err, closePinned()))
			}
			if !sameManagedExchangeStat(&stagingBefore, &publishedStat) {
				return result, false, true, managedChangedMutationError("replacement published but staging changed during exchange", true, errors.Join(ErrUnsafePath, closePinned()))
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &publishedStat); err != nil {
				return result, false, true, managedChangedMutationError("replacement destination does not identify pinned staging", true, errors.Join(err, closePinned()))
			}
			var exchangedStat unix.Stat_t
			if err := unix.Fstat(int(replaced.Fd()), &exchangedStat); err != nil {
				return result, false, true, managedChangedMutationError("replacement published but old target descriptor revalidation failed", true, errors.Join(err, closePinned()))
			}
			if !sameManagedExchangeStat(&exchangeBefore, &exchangedStat) {
				return result, false, true, managedChangedMutationError("replacement published but old target changed during exchange", true, errors.Join(ErrUnsafePath, closePinned()))
			}
			if err := verifyManagedNameIdentity(int(transaction.Fd()), transactionEntry, &exchangedStat); err != nil {
				return result, false, true, managedChangedMutationError("private transaction does not identify exchanged old target", true, errors.Join(err, closePinned()))
			}
			if err := m.syncManagedDirectory(destinationFD, "sync exchanged managed destination", true); err != nil {
				return result, false, true, managedChangedMutationError("managed replacement destination sync failed", true, errors.Join(err, closePinned()))
			}
			if err := m.syncManagedDirectory(int(transaction.Fd()), "sync exchanged managed transaction", true); err != nil {
				return result, false, true, managedChangedMutationError("managed replacement transaction sync failed", true, errors.Join(err, closePinned()))
			}
			if m.replaceBeforeCleanup != nil {
				if err := m.replaceBeforeCleanup(); err != nil {
					return result, false, true, managedChangedMutationError("replacement published but cleanup interlock failed", false, errors.Join(err, closePinned()))
				}
			}
			if err := validateManagedTransferTransaction(destinationFD, destinationMountID, transactionName, transaction); err != nil {
				return result, false, true, managedChangedMutationError("replacement private transaction name changed before cleanup", false, errors.Join(err, closePinned()))
			}
			var publishedBeforeCleanup unix.Stat_t
			if err := unix.Fstat(int(staging.Fd()), &publishedBeforeCleanup); err != nil {
				return result, false, true, managedChangedMutationError("replacement published staging revalidation failed before cleanup", false, errors.Join(err, closePinned()))
			}
			if !sameManagedTransferStat(&publishedStat, &publishedBeforeCleanup) {
				return result, false, true, managedChangedMutationError("replacement destination changed before old target cleanup", false, errors.Join(ErrUnsafePath, closePinned()))
			}
			if err := verifyManagedNameIdentity(destinationFD, candidate, &publishedBeforeCleanup); err != nil {
				return result, false, true, managedChangedMutationError("replacement destination no longer identifies pinned staging", false, errors.Join(err, closePinned()))
			}
			var cleanupBefore unix.Stat_t
			if err := unix.Fstat(int(replaced.Fd()), &cleanupBefore); err != nil {
				return result, false, true, managedChangedMutationError("replacement published but cleanup descriptor revalidation failed", false, errors.Join(err, closePinned()))
			}
			if !sameManagedTransferStat(&exchangedStat, &cleanupBefore) {
				return result, false, true, managedChangedMutationError("replacement published but old target changed before cleanup", false, errors.Join(ErrUnsafePath, closePinned()))
			}
			if err := verifyManagedNameIdentity(int(transaction.Fd()), transactionEntry, &cleanupBefore); err != nil {
				return result, false, true, managedChangedMutationError("private transaction old target identity changed before cleanup", false, errors.Join(err, closePinned()))
			}
			unlinkFlags := 0
			if cleanupBefore.Mode&unix.S_IFMT == unix.S_IFDIR {
				unlinkFlags = unix.AT_REMOVEDIR
			}
			if err := unix.Unlinkat(int(transaction.Fd()), transactionEntry, unlinkFlags); err != nil {
				return result, false, true, managedChangedMutationError("replacement published but private old target removal failed", false, errors.Join(err, closePinned()))
			}
			if err := m.syncManagedDirectory(int(transaction.Fd()), "sync removed private replacement target", true); err != nil {
				return result, false, false, errors.Join(err, closePinned())
			}
			var removedStat unix.Stat_t
			if err := unix.Fstat(int(replaced.Fd()), &removedStat); err != nil {
				return result, false, false, managedChangedMutationError("replacement cleanup could not verify removed old target", false, errors.Join(err, closePinned()))
			}
			if removedStat.Nlink != 0 {
				return result, false, false, managedChangedMutationError("replacement cleanup did not unlink expected old target", false, errors.Join(ErrUnsafePath, closePinned()))
			}
			if err := closePinned(); err != nil {
				return result, false, false, managedChangedMutationError("replacement cleanup completed but pinned descriptor close failed", false, err)
			}
			return result, true, false, nil
		}
	}
	return ManagedTransferResult{}, true, true, errors.Join(fmt.Errorf("no available managed destination name after %d attempts", limit), closeStaging())
}

func validateManagedTransactionReplacementType(sourceParentFD int, sourceName string, targetParentFD int, targetName string) (unix.Stat_t, error) {
	var sourceStat unix.Stat_t
	if err := unix.Fstatat(sourceParentFD, sourceName, &sourceStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	var targetStat unix.Stat_t
	if err := unix.Fstatat(targetParentFD, targetName, &targetStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	sourceType := sourceStat.Mode & unix.S_IFMT
	targetType := targetStat.Mode & unix.S_IFMT
	if sourceType != targetType || sourceType != unix.S_IFREG && sourceType != unix.S_IFDIR {
		return unix.Stat_t{}, fmt.Errorf("%w: replacement requires matching regular-file or directory types", ErrUnsafePath)
	}
	return targetStat, nil
}

func createManagedTransferTransaction(parentFD int, parentMountID uint64) (*os.File, string, error) {
	name, err := randomManagedTransferName(managedTransferTransactionPrefix)
	if err != nil {
		return nil, "", err
	}
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil {
		return nil, "", classifyManagedResolutionError(err)
	}
	retained := func(operation string, err error) error {
		return managedChangedMutationError(
			operation,
			true,
			fmt.Errorf("private managed transfer transaction %q retained: %w", name, err),
		)
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, name, retained("open newly created managed transfer transaction", classifyManagedResolutionError(err))
	}
	transaction := os.NewFile(uintptr(fd), name)
	if transaction == nil {
		unix.Close(fd)
		return nil, name, retained("convert newly created managed transfer transaction descriptor", errors.New("descriptor conversion failed"))
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return nil, name, retained("chmod newly created managed transfer transaction", errors.Join(err, transaction.Close()))
	}
	if err := validateManagedTransferTransaction(parentFD, parentMountID, name, transaction); err != nil {
		return nil, name, retained("validate newly created managed transfer transaction", errors.Join(err, transaction.Close()))
	}
	return transaction, name, nil
}

func validateManagedTransferTransactionFD(parentMountID uint64, transaction *os.File) error {
	if transaction == nil {
		return fmt.Errorf("%w: managed transfer transaction is not open", ErrUnsafePath)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(transaction.Fd()), &stat); err != nil {
		return err
	}
	if err := validateManagedTransferTransactionStat(&stat, uint32(os.Geteuid())); err != nil {
		return err
	}
	mountID, err := managedMountIDAt(int(transaction.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if mountID != parentMountID {
		return fmt.Errorf("%w: managed transfer transaction crossed a mount boundary", ErrUnsafePath)
	}
	return nil
}

func validateManagedTransferTransactionStat(stat *unix.Stat_t, effectiveUID uint32) error {
	if stat == nil {
		return fmt.Errorf("%w: managed transfer transaction metadata is unavailable", ErrUnsafePath)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 {
		return fmt.Errorf("%w: managed transfer transaction is not a private directory", ErrUnsafePath)
	}
	if stat.Uid != effectiveUID {
		return fmt.Errorf("%w: managed transfer transaction is not owned by the effective uid", ErrUnsafePath)
	}
	// Btrfs intentionally reports st_nlink=1 for linked directories. The
	// descriptor/name identity check performed by validateManagedTransferTransaction
	// proves which directory is linked; zero alone means this descriptor has no
	// live directory entry.
	if stat.Nlink == 0 {
		return fmt.Errorf("%w: managed transfer transaction has an invalid link count", ErrUnsafePath)
	}
	return nil
}

func validateManagedReplaceFilesystem(fd int) error {
	magic, allowed, err := managedTransactionalFilesystemEligibility(fd)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: replace requires an allowlisted local filesystem; filesystem type %#x is not allowlisted", ErrUnsafePath, uint32(magic))
	}
	return nil
}

func validateManagedMoveFilesystem(fd int, role string) error {
	magic, allowed, err := managedTransactionalFilesystemEligibility(fd)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: move requires an allowlisted local %s filesystem; filesystem type %#x is not allowlisted", ErrUnsafePath, role, uint32(magic))
	}
	return nil
}

func managedTransactionalFilesystemEligibility(fd int) (int64, bool, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil {
		return 0, false, err
	}
	magic := int64(stat.Type)
	return magic, managedTransactionalFilesystemAllowed(magic), nil
}

func classifyManagedNoReplacePublicationFailure(renameErr error, filesystemAllowed bool, filesystemErr error) (ManagedTransferResult, bool, error) {
	classifiedRenameErr := classifyManagedResolutionError(renameErr)
	if filesystemErr == nil && filesystemAllowed {
		return ManagedTransferResult{}, true, classifiedRenameErr
	}
	var eligibilityErr error
	if filesystemErr != nil {
		eligibilityErr = fmt.Errorf("destination filesystem eligibility could not be proven after rename failure: %w", filesystemErr)
	} else {
		eligibilityErr = fmt.Errorf("%w: destination filesystem is not allowlisted for deterministic rename failure handling", ErrUnsafePath)
	}
	return ManagedTransferResult{}, false, managedChangedMutationError(
		"managed transfer publication outcome is ambiguous",
		true,
		errors.Join(classifiedRenameErr, eligibilityErr),
	)
}

func managedTransactionalFilesystemAllowed(magic int64) bool {
	switch uint32(magic) {
	case uint32(unix.EXT4_SUPER_MAGIC), // Shared by ext2, ext3, and ext4.
		uint32(unix.XFS_SUPER_MAGIC),
		uint32(unix.BTRFS_SUPER_MAGIC),
		uint32(unix.TMPFS_MAGIC),
		uint32(unix.F2FS_SUPER_MAGIC):
		return true
	default:
		return false
	}
}

func validateManagedTransferTransaction(parentFD int, parentMountID uint64, name string, transaction *os.File) error {
	if err := validateManagedTransferTransactionFD(parentMountID, transaction); err != nil {
		return err
	}
	var descriptorStat unix.Stat_t
	if err := unix.Fstat(int(transaction.Fd()), &descriptorStat); err != nil {
		return err
	}
	var nameStat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &nameStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("%w: managed transfer transaction name is unavailable: %w", ErrUnsafePath, err)
	}
	if !sameManagedTransferStat(&descriptorStat, &nameStat) {
		return fmt.Errorf("%w: managed transfer transaction name changed", ErrUnsafePath)
	}
	return nil
}

func validateManagedTransferTransactionEmpty(parentFD int, parentMountID uint64, name string, transaction *os.File) error {
	if err := validateManagedTransferTransaction(parentFD, parentMountID, name, transaction); err != nil {
		return err
	}
	entries, err := transaction.ReadDir(1)
	if len(entries) != 0 {
		return fmt.Errorf("%w: managed transfer transaction is not empty", ErrUnsafePath)
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: could not prove managed transfer transaction is empty", ErrUnsafePath)
		}
		return err
	}
	return validateManagedTransferTransaction(parentFD, parentMountID, name, transaction)
}

func (m *ManagedRoots) cleanupManagedTransferTransaction(parentFD int, parentMountID uint64, name string, transaction *os.File, entryPresent bool) error {
	if err := validateManagedTransferTransaction(parentFD, parentMountID, name, transaction); err != nil {
		return fmt.Errorf("private managed transfer transaction %q retained: %w", name, err)
	}
	if m.transactionBeforeCleanup != nil {
		if err := m.transactionBeforeCleanup(); err != nil {
			return fmt.Errorf("private managed transfer transaction %q retained before cleanup: %w", name, err)
		}
	}
	if entryPresent {
		cleanupBudget := int64(0)
		if err := m.removeManagedEntryAt(int(transaction.Fd()), "entry", parentMountID, 0, &cleanupBudget); err != nil {
			return fmt.Errorf("private managed transfer transaction %q retained after entry cleanup failure: %w", name, err)
		}
	}
	if err := validateManagedTransferTransactionEmpty(parentFD, parentMountID, name, transaction); err != nil {
		return fmt.Errorf("private managed transfer transaction %q retained after empty-state validation failure: %w", name, err)
	}
	// Linux has no descriptor-relative rmdir-by-handle operation. The private
	// directory is proven empty immediately above and AT_REMOVEDIR refuses a
	// nonempty substitute. A non-cooperating writer on the parent can therefore
	// race this final step only into removing another empty directory; it cannot
	// make cleanup delete a data-bearing replacement. A same-UID writer could
	// first unlink the original empty directory and then substitute another empty
	// directory, making that substitution undetectable by the pinned Nlink check.
	// Issue #7 tracks this trusted-host race. Issue #17 tracks durable transaction
	// ledger/recovery; until that exists, any transaction retained after an
	// ambiguous namespace outcome is manual-recovery evidence and is not
	// auto-cleaned.
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("private managed transfer transaction %q retained after rmdir failure: %w", name, err)
	}
	if m.transactionAfterRmdir != nil {
		if err := m.transactionAfterRmdir(); err != nil {
			return managedChangedMutationError("managed transfer transaction removed but post-rmdir interlock failed", true, err)
		}
	}
	var removed unix.Stat_t
	if err := unix.Fstat(int(transaction.Fd()), &removed); err != nil {
		return managedChangedMutationError("managed transfer transaction removed but descriptor revalidation failed", true, err)
	}
	if removed.Nlink != 0 {
		return managedChangedMutationError("managed transfer transaction namespace changed but pinned directory remains linked", true, fmt.Errorf("%w: managed transfer transaction removal did not unlink the pinned directory", ErrUnsafePath))
	}
	return m.syncManagedDirectory(parentFD, "sync removed managed transfer transaction", true)
}

func (m *ManagedRoots) validateManagedReplacementAt(parentFD int, name string, parentMountID uint64, canonical string, expected *unix.Stat_t) (*os.File, error) {
	opened, err := openManagedTransferChild(parentFD, name)
	if err != nil {
		return nil, err
	}
	closeWithError := func(err error) (*os.File, error) {
		return nil, errors.Join(err, opened.Close())
	}
	var openedBefore unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &openedBefore); err != nil {
		return closeWithError(err)
	}
	if expected == nil || !sameManagedTransferStat(expected, &openedBefore) {
		return closeWithError(fmt.Errorf("%w: replacement target changed before validation", ErrUnsafePath))
	}
	if err := m.rejectConfiguredRootAtOrBelow(opened, canonical); err != nil {
		return closeWithError(err)
	}
	if openedBefore.Mode&unix.S_IFMT == unix.S_IFDIR {
		mountID, err := managedMountIDAt(int(opened.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			return closeWithError(err)
		}
		if mountID != parentMountID {
			return closeWithError(fmt.Errorf("%w: refusing to replace a directory mount boundary", ErrUnsafePath))
		}
		entries, readErr := opened.ReadDir(1)
		if len(entries) != 0 {
			return closeWithError(fmt.Errorf("%w: replacing nonempty directories is disabled", ErrUnsafePath))
		}
		if !errors.Is(readErr, io.EOF) {
			if readErr == nil {
				return closeWithError(fmt.Errorf("%w: could not prove replacement directory is empty", ErrUnsafePath))
			}
			return closeWithError(readErr)
		}
	} else {
		budget := int64(0)
		if err := validateManagedRemovableEntryAt(parentFD, name, parentMountID, 0, &budget, false); err != nil {
			return closeWithError(err)
		}
	}
	var openedAfter unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &openedAfter); err != nil {
		return closeWithError(err)
	}
	if !sameManagedTransferStat(&openedBefore, &openedAfter) {
		return closeWithError(fmt.Errorf("%w: replacement target changed during validation", ErrUnsafePath))
	}
	if err := verifyManagedNameIdentity(parentFD, name, &openedAfter); err != nil {
		return closeWithError(err)
	}
	return opened, nil
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
		before.Uid == after.Uid &&
		before.Gid == after.Gid &&
		before.Rdev == after.Rdev &&
		before.Size == after.Size &&
		before.Blksize == after.Blksize &&
		before.Blocks == after.Blocks &&
		before.Mtim == after.Mtim &&
		before.Ctim == after.Ctim
}

// sameManagedExchangeStat permits only the inode ctime transition caused by a
// descriptor-relative namespace rename or exchange. The inode remains pinned
// by an open descriptor across the syscall; every other identity and content
// signal must remain unchanged before its private name can be removed.
func sameManagedExchangeStat(before, after *unix.Stat_t) bool {
	return before.Dev == after.Dev &&
		before.Ino == after.Ino &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Uid == after.Uid &&
		before.Gid == after.Gid &&
		before.Rdev == after.Rdev &&
		before.Size == after.Size &&
		before.Blksize == after.Blksize &&
		before.Blocks == after.Blocks &&
		before.Mtim == after.Mtim
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
