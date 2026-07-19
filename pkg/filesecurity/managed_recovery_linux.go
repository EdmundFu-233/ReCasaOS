//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxManagedTransferInventoryEntries    = 4_096
	maxManagedTransferInventoryCandidates = 128
)

// InventoryManagedTransferTransactions performs a bounded, single-directory,
// read-only observation below the startup-pinned management roots. It never
// recursively scans, changes metadata, synchronizes, renames, or removes an
// entry. A returned item is therefore evidence for operator review only.
func (m *ManagedRoots) InventoryManagedTransferTransactions(parentPath string) (ManagedTransferInventoryResult, error) {
	result := ManagedTransferInventoryResult{
		Parent:   parentPath,
		Items:    make([]ManagedTransferInventoryItem, 0),
		Complete: true,
	}
	release, err := m.AcquireMutation()
	if err != nil {
		return result, err
	}
	defer release()

	root, location, err := m.resolveLocked(parentPath)
	if err != nil {
		return result, err
	}
	result.Parent = location.Canonical
	parent, err := openManagedAt(root, location, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	defer parent.Close()
	if err := m.validateManagedDestinationFD(root, int(parent.Fd()), location); err != nil {
		return result, err
	}
	rootFD, err := unix.FcntlInt(root.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return result, err
	}
	defer unix.Close(rootFD)
	var parentBefore unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &parentBefore); err != nil {
		return result, err
	}
	parentMountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return result, err
	}
	baselineGeneration := m.mutationGeneration.Load()
	// Do not hold the global mutation lease while a user-selected mount is
	// enumerated. A stalled remote/FUSE syscall must not freeze all managed
	// writes or Close. Descriptor/name checks and the mutation generation make
	// any concurrent change an incomplete or unverified observation.
	release()

	scanComplete := false
	for {
		entries, readErr := parent.ReadDir(256)
		for _, entry := range entries {
			if result.Scanned >= maxManagedTransferInventoryEntries {
				markManagedTransferInventoryIncomplete(&result, true, ManagedTransferFindingEntryLimitExceeded)
				scanComplete = true
				break
			}
			result.Scanned++
			if !isManagedTransferTransactionName(entry.Name()) {
				continue
			}
			result.CandidateCount++
			if len(result.Items) >= maxManagedTransferInventoryCandidates {
				markManagedTransferInventoryIncomplete(&result, true, ManagedTransferFindingCandidateLimitExceeded)
				continue
			}
			result.Items = append(result.Items, m.inspectManagedTransferTransaction(int(parent.Fd()), parentMountID, entry.Name()))
		}
		if scanComplete {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			markManagedTransferInventoryIncomplete(&result, false, ManagedTransferFindingDirectoryReadFailed)
			break
		}
	}
	if !revalidateManagedTransferInventoryParent(rootFD, location.Relative, parent, &parentBefore, parentMountID) {
		markManagedTransferInventoryIncomplete(&result, false, ManagedTransferFindingParentIdentityChanged)
	}
	if m.mutationGeneration.Load() != baselineGeneration {
		markManagedTransferInventoryIncomplete(&result, false, ManagedTransferFindingConcurrentMutation)
	}
	return result, nil
}

func markManagedTransferInventoryIncomplete(result *ManagedTransferInventoryResult, truncated bool, finding string) {
	if result == nil {
		return
	}
	result.Complete = false
	result.Truncated = result.Truncated || truncated
	for _, existing := range result.Findings {
		if existing == finding {
			return
		}
	}
	result.Findings = append(result.Findings, finding)
}

func isManagedTransferTransactionName(name string) bool {
	if !strings.HasPrefix(name, managedTransferTransactionPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, managedTransferTransactionPrefix)
	if len(suffix) != managedTransferTransactionRandomHexLength {
		return false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func (m *ManagedRoots) inspectManagedTransferTransaction(parentFD int, parentMountID uint64, name string) ManagedTransferInventoryItem {
	item := ManagedTransferInventoryItem{
		Name:          name,
		ObservedState: ManagedTransferObservedUnverified,
		RecoveryRole:  ManagedTransferRecoveryRoleUnknown,
	}
	transactionFD, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		item.Finding = ManagedTransferFindingCandidateOpenFailed
		return item
	}
	transaction := os.NewFile(uintptr(transactionFD), name)
	if transaction == nil {
		_ = unix.Close(transactionFD)
		item.Finding = ManagedTransferFindingCandidateOpenFailed
		return item
	}
	defer transaction.Close()

	if err := validateManagedTransferTransaction(parentFD, parentMountID, name, transaction); err != nil {
		item.Finding = ManagedTransferFindingCandidateMetadataUnsafe
		return item
	}
	var transactionBefore unix.Stat_t
	if err := unix.Fstat(int(transaction.Fd()), &transactionBefore); err != nil {
		item.Finding = ManagedTransferFindingCandidateMetadataUnsafe
		return item
	}
	item.Identity = managedTransferObservedIdentity(&transactionBefore, parentMountID)
	if m.inventoryAfterOpen != nil {
		if err := m.inventoryAfterOpen(parentFD, name); err != nil {
			item.Finding = ManagedTransferFindingCandidateIdentityChanged
			return item
		}
	}

	children, atEnd, readErr := readManagedTransferTransactionShape(transaction)
	if readErr != nil {
		item.Finding = ManagedTransferFindingDirectoryReadFailed
		return item
	}
	if len(children) == 0 && atEnd {
		if !revalidateObservedTransaction(parentFD, parentMountID, name, transaction, &transactionBefore) {
			item.Finding = ManagedTransferFindingCandidateIdentityChanged
			return item
		}
		item.ObservedState = ManagedTransferObservedEmptyUnclassified
		return item
	}
	if len(children) != 1 || children[0].Name() != "entry" || !atEnd {
		item.Finding = ManagedTransferFindingContentsUnexpected
		return item
	}

	entryIdentity, finding := inspectManagedTransferInventoryEntry(int(transaction.Fd()), parentMountID)
	if finding != "" {
		item.Finding = finding
		return item
	}
	if !revalidateObservedTransaction(parentFD, parentMountID, name, transaction, &transactionBefore) {
		item.Finding = ManagedTransferFindingCandidateIdentityChanged
		return item
	}
	item.EntryIdentity = entryIdentity
	item.ObservedState = ManagedTransferObservedEntryPresentUnclassified
	return item
}

func inspectManagedTransferInventoryEntry(transactionFD int, parentMountID uint64) (*ManagedTransferObservedIdentity, string) {
	entryFD, err := unix.Openat2(transactionFD, "entry", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return nil, ManagedTransferFindingEntryOpenFailed
	}
	defer unix.Close(entryFD)
	var entryBefore unix.Stat_t
	if err := unix.Fstat(entryFD, &entryBefore); err != nil {
		return nil, ManagedTransferFindingEntryOpenFailed
	}
	switch entryBefore.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if entryBefore.Nlink != 1 {
			return nil, ManagedTransferFindingEntryMetadataUnsafe
		}
	case unix.S_IFDIR:
	default:
		return nil, ManagedTransferFindingEntryMetadataUnsafe
	}
	entryMountID, err := managedMountIDAt(entryFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || entryMountID != parentMountID {
		return nil, ManagedTransferFindingEntryMountChanged
	}
	if err := verifyManagedNameIdentity(transactionFD, "entry", &entryBefore); err != nil {
		return nil, ManagedTransferFindingEntryIdentityChanged
	}
	var entryAfter unix.Stat_t
	if err := unix.Fstat(entryFD, &entryAfter); err != nil || !sameManagedTransferStat(&entryBefore, &entryAfter) {
		return nil, ManagedTransferFindingEntryIdentityChanged
	}
	if err := verifyManagedNameIdentity(transactionFD, "entry", &entryAfter); err != nil {
		return nil, ManagedTransferFindingEntryIdentityChanged
	}
	return managedTransferObservedIdentity(&entryAfter, entryMountID), ""
}

func readManagedTransferTransactionShape(transaction *os.File) ([]os.DirEntry, bool, error) {
	if transaction == nil {
		return nil, false, errors.New("managed transfer transaction is unavailable")
	}
	children := make([]os.DirEntry, 0, 2)
	for len(children) < 2 {
		batch, err := transaction.ReadDir(2 - len(children))
		children = append(children, batch...)
		if errors.Is(err, io.EOF) {
			return children, true, nil
		}
		if err != nil {
			return children, false, err
		}
		if len(batch) == 0 {
			return children, false, io.ErrNoProgress
		}
	}
	return children, false, nil
}

func revalidateManagedTransferInventoryParent(rootFD int, relative string, parent *os.File, before *unix.Stat_t, expectedMountID uint64) bool {
	if rootFD < 0 || relative == "" || parent == nil || before == nil {
		return false
	}
	var descriptorAfter unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &descriptorAfter); err != nil || !sameManagedTransferStat(before, &descriptorAfter) {
		return false
	}
	descriptorMountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || descriptorMountID != expectedMountID {
		return false
	}
	reopenedFD, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK,
		Resolve: managedResolvePolicy,
	})
	if err != nil {
		return false
	}
	defer unix.Close(reopenedFD)
	var nameAfter unix.Stat_t
	if err := unix.Fstat(reopenedFD, &nameAfter); err != nil || !sameManagedTransferStat(before, &nameAfter) {
		return false
	}
	nameMountID, err := managedMountIDAt(reopenedFD, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	return err == nil && nameMountID == expectedMountID
}

func revalidateObservedTransaction(parentFD int, parentMountID uint64, name string, transaction *os.File, before *unix.Stat_t) bool {
	if transaction == nil || before == nil {
		return false
	}
	if err := validateManagedTransferTransaction(parentFD, parentMountID, name, transaction); err != nil {
		return false
	}
	var after unix.Stat_t
	return unix.Fstat(int(transaction.Fd()), &after) == nil && sameManagedTransferStat(before, &after)
}

func managedTransferObservedIdentity(stat *unix.Stat_t, mountID uint64) *ManagedTransferObservedIdentity {
	if stat == nil {
		return nil
	}
	objectType := "unknown"
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		objectType = "file"
	case unix.S_IFDIR:
		objectType = "directory"
	}
	return &ManagedTransferObservedIdentity{
		MountID: fmt.Sprintf("%016x", mountID),
		Device:  fmt.Sprintf("%016x", uint64(stat.Dev)),
		Inode:   fmt.Sprintf("%016x", stat.Ino),
		Mode:    stat.Mode,
		Links:   strconv.FormatUint(uint64(stat.Nlink), 10),
		Size:    strconv.FormatInt(stat.Size, 10),
		Type:    objectType,
	}
}
