//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestManagedTransferInventoryReportsOnlyProvenShapes(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	emptyName := managedRecoveryTestName(1)
	fileName := managedRecoveryTestName(2)
	directoryName := managedRecoveryTestName(3)
	for _, name := range []string{emptyName, fileName, directoryName} {
		if err := os.Mkdir(filepath.Join(parent, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(parent, fileName, "entry"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, directoryName, "entry"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, ignored := range []string{
		"ordinary-directory",
		managedTransferTransactionPrefix + "ABCDEF0123456789ABCDEF0123456789",
		managedTransferTransactionPrefix + "too-short",
	} {
		if err := os.Mkdir(filepath.Join(parent, ignored), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	roots := openManagedRecoveryTestRoots(t, root)
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Truncated || result.CandidateCount != 3 || len(result.Items) != 3 || result.Scanned != 6 {
		t.Fatalf("inventory = %+v", result)
	}
	items := managedRecoveryItemsByName(result.Items)
	assertManagedRecoveryItem(t, items[emptyName], ManagedTransferObservedEmptyUnclassified, "")
	if items[emptyName].Identity == nil || items[emptyName].Identity.Type != "directory" || items[emptyName].EntryIdentity != nil {
		t.Fatalf("empty identity = %+v", items[emptyName])
	}
	assertManagedRecoveryItem(t, items[fileName], ManagedTransferObservedEntryPresentUnclassified, "")
	if items[fileName].EntryIdentity == nil || items[fileName].EntryIdentity.Type != "file" || items[fileName].EntryIdentity.Size != fmt.Sprint(len("retained")) {
		t.Fatalf("file identity = %+v", items[fileName])
	}
	assertManagedRecoveryItem(t, items[directoryName], ManagedTransferObservedEntryPresentUnclassified, "")
	if items[directoryName].EntryIdentity == nil || items[directoryName].EntryIdentity.Type != "directory" {
		t.Fatalf("directory identity = %+v", items[directoryName])
	}
	contents, err := os.ReadFile(filepath.Join(parent, fileName, "entry"))
	if err != nil || string(contents) != "retained" {
		t.Fatalf("inventory changed retained content: %q, %v", contents, err)
	}
}

func TestManagedTransferInventoryMarksUnsafeCandidatesUnverified(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeMode := managedRecoveryTestName(10)
	unexpected := managedRecoveryTestName(11)
	specialEntry := managedRecoveryTestName(12)
	symlinkName := managedRecoveryTestName(13)
	if err := os.Mkdir(filepath.Join(parent, unsafeMode), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(parent, unsafeMode), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, unexpected), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, unexpected, "other"), []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, specialEntry), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(parent, specialEntry, "entry"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(parent, unexpected), filepath.Join(parent, symlinkName)); err != nil {
		t.Fatal(err)
	}

	roots := openManagedRecoveryTestRoots(t, root)
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Truncated || result.CandidateCount != 4 || len(result.Items) != 4 {
		t.Fatalf("inventory = %+v", result)
	}
	items := managedRecoveryItemsByName(result.Items)
	assertManagedRecoveryItem(t, items[unsafeMode], ManagedTransferObservedUnverified, ManagedTransferFindingCandidateMetadataUnsafe)
	assertManagedRecoveryItem(t, items[unexpected], ManagedTransferObservedUnverified, ManagedTransferFindingContentsUnexpected)
	assertManagedRecoveryItem(t, items[specialEntry], ManagedTransferObservedUnverified, ManagedTransferFindingEntryMetadataUnsafe)
	assertManagedRecoveryItem(t, items[symlinkName], ManagedTransferObservedUnverified, ManagedTransferFindingCandidateOpenFailed)
	if _, err := os.Lstat(filepath.Join(parent, symlinkName)); err != nil {
		t.Fatalf("inventory removed symlink evidence: %v", err)
	}
}

func TestManagedTransferInventoryDetectsCandidateReplacementAndPreservesBoth(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	name := managedRecoveryTestName(20)
	if err := os.Mkdir(filepath.Join(parent, name), 0o700); err != nil {
		t.Fatal(err)
	}

	roots := openManagedRecoveryTestRoots(t, root)
	renamed := name + ".renamed-evidence"
	roots.inventoryAfterOpen = func(parentFD int, candidate string) error {
		if candidate != name {
			return fmt.Errorf("unexpected candidate %q", candidate)
		}
		if err := unix.Renameat(parentFD, candidate, parentFD, renamed); err != nil {
			return err
		}
		return unix.Mkdirat(parentFD, candidate, 0o700)
	}
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.Truncated || !managedRecoveryHasFinding(result, ManagedTransferFindingParentIdentityChanged) || len(result.Items) != 1 {
		t.Fatalf("inventory = %+v", result)
	}
	assertManagedRecoveryItem(t, result.Items[0], ManagedTransferObservedUnverified, ManagedTransferFindingCandidateIdentityChanged)
	for _, retained := range []string{name, renamed} {
		info, err := os.Stat(filepath.Join(parent, retained))
		if err != nil || !info.IsDir() {
			t.Fatalf("inventory failed to preserve %q: %v", retained, err)
		}
	}
}

func TestManagedTransferInventoryDoesNotDiscoverRenamedLegacyTransaction(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(parent, managedRecoveryTestName(30))
	renamed := filepath.Join(parent, "externally-renamed-transaction-evidence")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "entry"), []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}

	roots := openManagedRecoveryTestRoots(t, root)
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.CandidateCount != 0 || len(result.Items) != 0 {
		t.Fatalf("inventory claimed renamed transaction discovery: %+v", result)
	}
	contents, err := os.ReadFile(filepath.Join(renamed, "entry"))
	if err != nil || string(contents) != "preserve" {
		t.Fatalf("renamed evidence changed: %q, %v", contents, err)
	}
}

func TestManagedTransferInventoryDoesNotHoldMutationLeaseWhileScanning(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, managedRecoveryTestName(40)), 0o700); err != nil {
		t.Fatal(err)
	}
	roots := openManagedRecoveryTestRoots(t, root)
	entered := make(chan struct{})
	resume := make(chan struct{})
	roots.inventoryAfterOpen = func(int, string) error {
		close(entered)
		<-resume
		return nil
	}
	type inventoryOutcome struct {
		result ManagedTransferInventoryResult
		err    error
	}
	outcome := make(chan inventoryOutcome, 1)
	go func() {
		result, err := roots.InventoryManagedTransferTransactions(parent)
		outcome <- inventoryOutcome{result: result, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(resume)
		t.Fatal("inventory did not reach candidate observation")
	}
	mutationDone := make(chan error, 1)
	go func() {
		release, err := roots.AcquireMutation()
		if err == nil {
			release()
		}
		mutationDone <- err
	}()
	select {
	case err := <-mutationDone:
		if err != nil {
			close(resume)
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(resume)
		t.Fatal("inventory held the global mutation lease while scanning")
	}
	close(resume)
	completed := <-outcome
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	if completed.result.Complete || !managedRecoveryHasFinding(completed.result, ManagedTransferFindingConcurrentMutation) {
		t.Fatalf("concurrent mutation inventory = %+v", completed.result)
	}
}

func TestManagedTransferInventoryDoesNotBlockCloseAfterRootSnapshot(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := openManagedRecoveryTestRoots(t, root)
	entered := make(chan struct{})
	resume := make(chan struct{})
	roots.inventoryAfterRootSnapshot = func() error {
		close(entered)
		<-resume
		return nil
	}
	type inventoryOutcome struct {
		result ManagedTransferInventoryResult
		err    error
	}
	outcome := make(chan inventoryOutcome, 1)
	go func() {
		result, inventoryErr := roots.InventoryManagedTransferTransactions(parent)
		outcome <- inventoryOutcome{result: result, err: inventoryErr}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(resume)
		t.Fatal("inventory did not finish its root snapshot")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- roots.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			close(resume)
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(resume)
		t.Fatal("inventory held a ManagedRoots lock after duplicating root descriptors")
	}
	close(resume)
	completed := <-outcome
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	if completed.result.Complete || !managedRecoveryHasFinding(completed.result, ManagedTransferFindingConcurrentMutation) {
		t.Fatalf("close-overlap inventory = %+v", completed.result)
	}
}

func TestManagedTransferInventoryDoesNotWaitForActiveMutationLease(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := openManagedRecoveryTestRoots(t, root)
	release, err := roots.AcquireMutation()
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	type inventoryOutcome struct {
		result ManagedTransferInventoryResult
		err    error
	}
	outcome := make(chan inventoryOutcome, 1)
	go func() {
		result, inventoryErr := roots.InventoryManagedTransferTransactions(parent)
		outcome <- inventoryOutcome{result: result, err: inventoryErr}
	}()
	select {
	case completed := <-outcome:
		if completed.err != nil {
			t.Fatal(completed.err)
		}
		if completed.result.Complete || !managedRecoveryHasFinding(completed.result, ManagedTransferFindingConcurrentMutation) {
			t.Fatalf("active mutation inventory = %+v", completed.result)
		}
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("inventory waited for the global mutation lease while pinning its parent")
	}
}

func TestManagedMutationGenerationIsOddOnlyWhileLeaseIsActive(t *testing.T) {
	root := t.TempDir()
	roots := openManagedRecoveryTestRoots(t, root)
	before := roots.mutationGeneration.Load()
	if before&1 != 0 {
		t.Fatalf("initial mutation generation = %d", before)
	}
	release, err := roots.AcquireMutation()
	if err != nil {
		t.Fatal(err)
	}
	during := roots.mutationGeneration.Load()
	if during != before+1 || during&1 == 0 {
		release()
		t.Fatalf("active mutation generation = %d, before = %d", during, before)
	}
	release()
	after := roots.mutationGeneration.Load()
	if after != before+2 || after&1 != 0 {
		t.Fatalf("released mutation generation = %d, before = %d", after, before)
	}
	release()
	if repeated := roots.mutationGeneration.Load(); repeated != after {
		t.Fatalf("repeated release changed generation: before=%d after=%d", after, repeated)
	}
	if err := roots.Close(); err != nil {
		t.Fatal(err)
	}
	if closed := roots.mutationGeneration.Load(); closed != after+2 || closed&1 != 0 {
		t.Fatalf("closed mutation generation = %d, released = %d", closed, after)
	}
}

func TestManagedTransferInventoryRootSnapshotSurvivesManagedRootsClose(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	parent := filepath.Join(secondRoot, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{firstRoot, secondRoot})
	if err != nil {
		t.Fatal(err)
	}
	descriptors, selected, location, _, err := roots.snapshotManagedTransferInventoryRoots(parent)
	if err != nil {
		_ = roots.Close()
		t.Fatal(err)
	}
	defer closeManagedTransferInventoryRoots(descriptors)
	if len(descriptors) != 2 || selected < 0 || selected >= len(descriptors) {
		_ = roots.Close()
		t.Fatalf("root snapshot = %+v, selected=%d", descriptors, selected)
	}
	if err := roots.Close(); err != nil {
		t.Fatal(err)
	}
	for index := range descriptors {
		var stat unix.Stat_t
		if err := unix.Fstat(descriptors[index].fd, &stat); err != nil {
			t.Fatalf("duplicated root %d did not survive Close: %v", index, err)
		}
	}
	opened, err := openManagedAtFD(descriptors[selected].fd, location, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := validateManagedDestinationDescriptors(descriptors, selected, int(opened.Fd()), location); err != nil {
		t.Fatalf("snapshot topology validation failed: %v", err)
	}
	if err := validateManagedDestinationDescriptors(descriptors, -1, int(opened.Fd()), location); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("invalid selected root error = %v", err)
	}
}

func TestManagedTransferInventoryRequiresNoAtimeDirectoryDescriptors(t *testing.T) {
	if managedTransferInventoryDirectoryFlags&unix.O_NOATIME == 0 {
		t.Fatal("inventory directory reads can update forensic access times")
	}
}

func TestManagedTransferInventoryPreservesLocalDirectoryAccessTimes(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(parent, &filesystem); err != nil {
		t.Fatal(err)
	}
	switch uint32(filesystem.Type) {
	case uint32(unix.NFS_SUPER_MAGIC), uint32(unix.CIFS_SUPER_MAGIC), uint32(unix.SMB_SUPER_MAGIC), uint32(unix.SMB2_SUPER_MAGIC), uint32(unix.FUSE_SUPER_MAGIC):
		t.Skip("remote or userspace filesystem controls access-time semantics")
	}
	if filesystem.Flags&(unix.ST_NOATIME|unix.ST_NODIRATIME) != 0 {
		t.Skip("mount options already suppress directory access-time updates")
	}
	transaction := filepath.Join(parent, managedRecoveryTestName(45))
	if err := os.Mkdir(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	for _, path := range []string{parent, transaction} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	beforeParent := managedRecoveryAccessTime(t, parent)
	beforeTransaction := managedRecoveryAccessTime(t, transaction)

	roots := openManagedRecoveryTestRoots(t, root)
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Items) != 1 {
		t.Fatalf("inventory = %+v", result)
	}
	if after := managedRecoveryAccessTime(t, parent); after != beforeParent {
		t.Fatalf("parent access time changed: before=%+v after=%+v", beforeParent, after)
	}
	if after := managedRecoveryAccessTime(t, transaction); after != beforeTransaction {
		t.Fatalf("transaction access time changed: before=%+v after=%+v", beforeTransaction, after)
	}
}

func managedRecoveryAccessTime(t *testing.T, path string) unix.Timespec {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	return stat.Atim
}

func TestManagedTransferInventoryReportsCandidateLimitWithoutClaimingCompleteness(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxManagedTransferInventoryCandidates+1; index++ {
		if err := os.Mkdir(filepath.Join(parent, managedRecoveryTestName(index+100)), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	roots := openManagedRecoveryTestRoots(t, root)
	var generationOnce sync.Once
	var mutationErr error
	roots.inventoryAfterOpen = func(int, string) error {
		generationOnce.Do(func() {
			release, err := roots.AcquireMutation()
			if err != nil {
				mutationErr = err
				return
			}
			release()
		})
		return mutationErr
	}
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.Truncated || !managedRecoveryHasFinding(result, ManagedTransferFindingCandidateLimitExceeded) || !managedRecoveryHasFinding(result, ManagedTransferFindingConcurrentMutation) {
		t.Fatalf("inventory = %+v", result)
	}
	if result.CandidateCount != maxManagedTransferInventoryCandidates+1 || len(result.Items) != maxManagedTransferInventoryCandidates {
		t.Fatalf("candidate bounds = %+v", result)
	}
}

func TestManagedTransferInventoryReportsDirectoryEntryLimit(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxManagedTransferInventoryEntries+1; index++ {
		name := fmt.Sprintf("ordinary-%04d", index)
		if err := os.WriteFile(filepath.Join(parent, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	roots := openManagedRecoveryTestRoots(t, root)
	result, err := roots.InventoryManagedTransferTransactions(parent)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.Truncated || !managedRecoveryHasFinding(result, ManagedTransferFindingEntryLimitExceeded) || result.Scanned != maxManagedTransferInventoryEntries {
		t.Fatalf("inventory = %+v", result)
	}
}

func TestManagedTransferInventoryRejectsUnsafeParents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	filePath := filepath.Join(root, "file")
	if err := os.WriteFile(filePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(root, "link")
	if err := os.Symlink(outside, symlinkPath); err != nil {
		t.Fatal(err)
	}
	roots := openManagedRecoveryTestRoots(t, root)
	for _, candidate := range []string{outside, filePath, symlinkPath, "relative"} {
		if _, err := roots.InventoryManagedTransferTransactions(candidate); err == nil {
			t.Fatalf("unsafe parent %q was accepted", candidate)
		}
	}
}

func TestManagedTransferInventoryParentRevalidationIncludesMountID(t *testing.T) {
	rootPath := t.TempDir()
	parentPath := filepath.Join(rootPath, "destination")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := openManagedRecoveryTestRoots(t, rootPath)
	root, location, err := roots.resolveLocked(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := openManagedAt(root, location, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	rootFD, err := unix.FcntlInt(root.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	var before unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	mountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	if !revalidateManagedTransferInventoryParent(rootFD, location.Relative, parent, &before, mountID) {
		t.Fatal("matching parent identity was rejected")
	}
	if revalidateManagedTransferInventoryParent(rootFD, location.Relative, parent, &before, mountID+1) {
		t.Fatal("mismatched mount ID was accepted")
	}
}

func openManagedRecoveryTestRoots(t *testing.T, root string) *ManagedRoots {
	t.Helper()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := roots.Close(); err != nil {
			t.Errorf("close managed roots: %v", err)
		}
	})
	return roots
}

func managedRecoveryTestName(index int) string {
	return managedTransferTransactionPrefix + fmt.Sprintf("%032x", index)
}

func managedRecoveryItemsByName(items []ManagedTransferInventoryItem) map[string]ManagedTransferInventoryItem {
	result := make(map[string]ManagedTransferInventoryItem, len(items))
	for _, item := range items {
		result[item.Name] = item
	}
	return result
}

func managedRecoveryHasFinding(result ManagedTransferInventoryResult, finding string) bool {
	for _, current := range result.Findings {
		if current == finding {
			return true
		}
	}
	return false
}

func assertManagedRecoveryItem(t *testing.T, item ManagedTransferInventoryItem, state ManagedTransferObservedState, finding string) {
	t.Helper()
	if item.ObservedState != state || item.RecoveryRole != ManagedTransferRecoveryRoleUnknown || item.Finding != finding {
		t.Fatalf("inventory item = %+v, want state=%q role=%q finding=%q", item, state, ManagedTransferRecoveryRoleUnknown, finding)
	}
}

func TestManagedTransferInventoryNameFormat(t *testing.T) {
	tests := map[string]bool{
		managedRecoveryTestName(1): true,
		managedTransferTransactionPrefix + "0123456789abcdef0123456789abcdeF":             false,
		managedTransferTransactionPrefix + "0123456789abcdef0123456789abcdeg":             false,
		managedTransferTransactionPrefix + "0123456789abcdef0123456789abcde":              false,
		"prefix-" + managedTransferTransactionPrefix + "0123456789abcdef0123456789abcdef": false,
	}
	for value, expected := range tests {
		if actual := isManagedTransferTransactionName(value); actual != expected {
			t.Errorf("isManagedTransferTransactionName(%q) = %v, want %v", value, actual, expected)
		}
	}
	generated, err := randomManagedTransferName(managedTransferTransactionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !isManagedTransferTransactionName(generated) {
		t.Fatalf("generated transaction name %q is not inventory-compatible", generated)
	}
}

func TestManagedTransferInventoryClosedRootsFailClosed(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if err := roots.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.InventoryManagedTransferTransactions(root); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed roots error = %v", err)
	}
}
