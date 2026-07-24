//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestManagedRootsCopyIntoConflictStyles(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if err != nil || result.Changed || result.Destination != target {
		t.Fatalf("skip result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "old")

	result, err = roots.CopyInto(source, destination, ManagedConflictReplace)
	if err != nil || !result.Changed || result.Destination != target {
		t.Fatalf("replace result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "new")
	if err := os.WriteFile(target, []byte("legacy-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = roots.CopyInto(source, destination, ManagedConflictStyle("overwrite"))
	if err != nil || !result.Changed || result.Destination != target {
		t.Fatalf("legacy overwrite result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "new")

	result, err = roots.CopyInto(source, destination, ManagedConflictRename)
	renamed := filepath.Join(destination, "source(1).txt")
	if err != nil || !result.Changed || result.Destination != renamed {
		t.Fatalf("rename result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, renamed, "new")
	assertManagedTestContent(t, source, "new")
}

func TestManagedReplaceAllowsExchangeCtimeChangeAndRemovesHiddenTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if err != nil || !result.Changed || result.Destination != target {
		t.Fatalf("replace result = %+v, %v", result, err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("replacement left hidden old target: %v", entries)
	}
	assertManagedTestContent(t, target, "new")
}

func TestSameManagedExchangeStatAllowsOnlyCtimeChange(t *testing.T) {
	before := unix.Stat_t{
		Dev:   11,
		Ino:   22,
		Mode:  unix.S_IFREG | 0o600,
		Nlink: 1,
		Size:  33,
		Mtim:  unix.Timespec{Sec: 44, Nsec: 55},
		Ctim:  unix.Timespec{Sec: 66, Nsec: 77},
	}
	after := before
	after.Ctim = unix.Timespec{Sec: 88, Nsec: 99}
	if !sameManagedExchangeStat(&before, &after) {
		t.Fatal("expected exchange ctime transition was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*unix.Stat_t)
	}{
		{name: "device", mutate: func(stat *unix.Stat_t) { stat.Dev++ }},
		{name: "inode", mutate: func(stat *unix.Stat_t) { stat.Ino++ }},
		{name: "mode", mutate: func(stat *unix.Stat_t) { stat.Mode ^= 0o100 }},
		{name: "links", mutate: func(stat *unix.Stat_t) { stat.Nlink++ }},
		{name: "uid", mutate: func(stat *unix.Stat_t) { stat.Uid++ }},
		{name: "gid", mutate: func(stat *unix.Stat_t) { stat.Gid++ }},
		{name: "rdev", mutate: func(stat *unix.Stat_t) { stat.Rdev++ }},
		{name: "size", mutate: func(stat *unix.Stat_t) { stat.Size++ }},
		{name: "block-size", mutate: func(stat *unix.Stat_t) { stat.Blksize++ }},
		{name: "blocks", mutate: func(stat *unix.Stat_t) { stat.Blocks++ }},
		{name: "mtime", mutate: func(stat *unix.Stat_t) { stat.Mtim.Nsec++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := after
			test.mutate(&changed)
			if sameManagedExchangeStat(&before, &changed) {
				t.Fatalf("exchange comparator accepted changed %s", test.name)
			}
		})
	}
}

func TestManagedTransferTransactionIsPinnedPrivateAndSameMount(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	mountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	transaction, name, err := createManagedTransferTransaction(int(parent.Fd()), mountID)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()
	if !strings.HasPrefix(name, ".recasaos-transfer-") {
		t.Fatalf("transfer transaction name = %q", name)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(transaction.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("transfer transaction metadata = mode %#o uid %d", stat.Mode, stat.Uid)
	}
	if err := validateManagedTransferTransaction(int(parent.Fd()), mountID, name, transaction); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchmod(int(transaction.Fd()), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := validateManagedTransferTransaction(int(parent.Fd()), mountID, name, transaction); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("permissive transfer transaction error = %v", err)
	}
}

func TestValidateManagedTransferTransactionStatAcceptsBtrfsLinkCount(t *testing.T) {
	stat := unix.Stat_t{
		Mode:  unix.S_IFDIR | 0o700,
		Nlink: 1,
		Uid:   1234,
	}
	if err := validateManagedTransferTransactionStat(&stat, stat.Uid); err != nil {
		t.Fatalf("linked Btrfs-style directory metadata rejected: %v", err)
	}
	stat.Nlink = 0
	if err := validateManagedTransferTransactionStat(&stat, stat.Uid); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("unlinked directory metadata error = %v, want ErrUnsafePath", err)
	}
}

func TestManagedTransferTransactionCreationFailureNamesRetainedDirectory(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	mountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	wrongMountID := mountID ^ 1
	transaction, name, err := createManagedTransferTransaction(int(parent.Fd()), wrongMountID)
	if transaction != nil {
		transaction.Close()
		t.Fatal("transaction unexpectedly opened with wrong mount identity")
	}
	if err == nil || name == "" || !strings.Contains(err.Error(), "retained") || !strings.Contains(err.Error(), name) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("transaction creation result = %q, %v", name, err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != name || !entries[0].IsDir() {
		t.Fatalf("failed transaction creation did not retain exact private directory: %v", entries)
	}
	info, err := os.Stat(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("retained transaction permissions = %#o", info.Mode().Perm())
	}
}

func TestManagedTransferTransactionPostRmdirFailureReportsUnknownDurability(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	mountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	transaction, name, err := createManagedTransferTransaction(int(parent.Fd()), mountID)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Close()
	injected := errors.New("injected post-rmdir failure")
	roots := &ManagedRoots{transactionAfterRmdir: func() error { return injected }}

	err = roots.cleanupManagedTransferTransaction(int(parent.Fd()), mountID, name, transaction, false)
	if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("post-rmdir failure = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, name)); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("transaction name remains after rmdir: %v", statErr)
	}
	var removed unix.Stat_t
	if statErr := unix.Fstat(int(transaction.Fd()), &removed); statErr != nil || removed.Nlink != 0 {
		t.Fatalf("removed transaction descriptor = nlink %d, %v", removed.Nlink, statErr)
	}
}

func TestManagedTransactionalFilesystemPolicy(t *testing.T) {
	tests := []struct {
		name        string
		magic       int64
		allowlisted bool
	}{
		{name: "ext2-ext4", magic: int64(unix.EXT4_SUPER_MAGIC), allowlisted: true},
		{name: "xfs", magic: int64(unix.XFS_SUPER_MAGIC), allowlisted: true},
		{name: "btrfs", magic: int64(unix.BTRFS_SUPER_MAGIC), allowlisted: true},
		{name: "tmpfs", magic: int64(unix.TMPFS_MAGIC), allowlisted: true},
		{name: "f2fs", magic: int64(unix.F2FS_SUPER_MAGIC), allowlisted: true},
		{name: "unknown", magic: int64(0x7f7f7f7f)},
		{name: "fuse", magic: int64(unix.FUSE_SUPER_MAGIC)},
		{name: "aafs", magic: int64(unix.AAFS_MAGIC)},
		{name: "afs", magic: int64(unix.AFS_FS_MAGIC)},
		{name: "afs-super", magic: int64(unix.AFS_SUPER_MAGIC)},
		{name: "ceph", magic: int64(unix.CEPH_SUPER_MAGIC)},
		{name: "cifs", magic: int64(unix.CIFS_SUPER_MAGIC)},
		{name: "coda", magic: int64(unix.CODA_SUPER_MAGIC)},
		{name: "ncp", magic: int64(unix.NCP_SUPER_MAGIC)},
		{name: "ocfs2", magic: int64(unix.OCFS2_SUPER_MAGIC)},
		{name: "smb", magic: int64(unix.SMB_SUPER_MAGIC)},
		{name: "smb2", magic: int64(unix.SMB2_SUPER_MAGIC)},
		{name: "nfs", magic: int64(unix.NFS_SUPER_MAGIC)},
		{name: "9p", magic: int64(unix.V9FS_MAGIC)},
		{name: "xenfs", magic: int64(unix.XENFS_SUPER_MAGIC)},
		{name: "fat", magic: int64(unix.MSDOS_SUPER_MAGIC)},
		{name: "exfat", magic: int64(unix.EXFAT_SUPER_MAGIC)},
		{name: "ntfs", magic: int64(0x5346544e)},
		{name: "signed-cifs-386", magic: -11317950},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := managedTransactionalFilesystemAllowed(test.magic); got != test.allowlisted {
				t.Fatalf("allowlisted = %v, want %v for magic %#x", got, test.allowlisted, uint32(test.magic))
			}
		})
	}
}

func TestManagedNoReplaceFailureClassificationRetainsAmbiguousEvidence(t *testing.T) {
	probeErr := errors.New("injected fstatfs failure")
	tests := []struct {
		name               string
		renameErr          error
		filesystemAllowed  bool
		filesystemErr      error
		wantCleanupAllowed bool
		wantAmbiguous      bool
	}{
		{name: "allowlisted-local-error", renameErr: unix.EIO, filesystemAllowed: true, wantCleanupAllowed: true},
		{name: "non-allowlisted-error", renameErr: unix.EIO, wantAmbiguous: true},
		{name: "eligibility-unproven", renameErr: unix.EIO, filesystemErr: probeErr, wantAmbiguous: true},
		{name: "allowlisted-eexist", renameErr: unix.EEXIST, filesystemAllowed: true, wantCleanupAllowed: true},
		{name: "non-allowlisted-eexist", renameErr: unix.EEXIST, wantAmbiguous: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, cleanupAllowed, err := classifyManagedNoReplacePublicationFailure(test.renameErr, test.filesystemAllowed, test.filesystemErr)
			if result.Changed || result.Destination != "" || cleanupAllowed != test.wantCleanupAllowed || !errors.Is(err, test.renameErr) {
				t.Fatalf("classification = result %+v, cleanup %v, error %v", result, cleanupAllowed, err)
			}
			if got := ManagedMutationChanged(err); got != test.wantAmbiguous {
				t.Fatalf("changed metadata = %v, want %v: %v", got, test.wantAmbiguous, err)
			}
			if got := ManagedMutationDurabilityUnknown(err); got != test.wantAmbiguous {
				t.Fatalf("durability metadata = %v, want %v: %v", got, test.wantAmbiguous, err)
			}
			if test.filesystemErr != nil && !errors.Is(err, test.filesystemErr) {
				t.Fatalf("classification did not retain filesystem probe error: %v", err)
			}
		})
	}
}

func TestManagedCopyRetainsTransactionForNonAllowlistedEEXIST(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	destinationIdentity := managedTestPathIdentity(t, destination)
	eligibilityCalls := 0
	roots.transferFilesystemEligibility = func(fd int) (int64, bool, error) {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return 0, false, err
		}
		if identity != destinationIdentity {
			return 0, false, fmt.Errorf("filesystem eligibility probed unexpected fd identity: %+v", identity)
		}
		eligibilityCalls++
		return int64(unix.FUSE_SUPER_MAGIC), false, nil
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if result.Changed || result.Destination != "" || !errors.Is(err, unix.EEXIST) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("non-allowlisted EEXIST result = %+v, %v", result, err)
	}
	if eligibilityCalls != 1 || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("filesystem eligibility calls/error = %d, %v", eligibilityCalls, err)
	}
	assertManagedTestContent(t, source, "new")
	assertManagedTestContent(t, target, "old")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("ambiguous EEXIST did not retain transaction evidence: %v", entries)
	}
	var retainedEntry string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retainedEntry = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if retainedEntry == "" {
		t.Fatalf("ambiguous EEXIST transaction missing: %v", entries)
	}
	assertManagedTestContent(t, retainedEntry, "new")
}

func TestManagedCopyPromotesPlainRetainedCleanupFailureToChanged(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	destinationIdentity := managedTestPathIdentity(t, destination)
	roots.transferFilesystemEligibility = func(fd int) (int64, bool, error) {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return 0, false, err
		}
		if identity != destinationIdentity {
			return 0, false, fmt.Errorf("filesystem eligibility probed unexpected fd identity: %+v", identity)
		}
		return int64(unix.EXT4_SUPER_MAGIC), true, nil
	}
	injected := errors.New("injected plain transaction cleanup failure")
	cleanupCalls := 0
	roots.transactionBeforeCleanup = func() error {
		cleanupCalls++
		return injected
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if result.Changed || result.Destination != target || !errors.Is(err, injected) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("plain retained cleanup result = %+v, %v", result, err)
	}
	if cleanupCalls != 1 || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("cleanup calls/error = %d, %v", cleanupCalls, err)
	}
	assertManagedTestContent(t, source, "new")
	assertManagedTestContent(t, target, "old")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("plain cleanup failure did not retain transaction: %v", entries)
	}
	var retainedEntry string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retainedEntry = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if retainedEntry == "" {
		t.Fatalf("plain cleanup failure transaction missing: %v", entries)
	}
	assertManagedTestContent(t, retainedEntry, "new")
}

func TestManagedCopyMarksUnsyncedRetainedEntryDurabilityUnknown(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	stageErr := errors.New("injected pre-stage-sync failure")
	cleanupErr := errors.New("injected plain transaction cleanup failure")
	stageCalls := 0
	cleanupCalls := 0
	roots.transactionBeforeStageSync = func() error {
		stageCalls++
		return stageErr
	}
	roots.transactionBeforeCleanup = func() error {
		cleanupCalls++
		return cleanupErr
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if result.Changed || result.Destination != "" || !errors.Is(err, stageErr) || !errors.Is(err, cleanupErr) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("unsynced retained entry result = %+v, %v", result, err)
	}
	if stageCalls != 1 || cleanupCalls != 1 || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("stage/cleanup calls/error = %d/%d, %v", stageCalls, cleanupCalls, err)
	}
	assertManagedTestContent(t, source, "new")
	if _, statErr := os.Stat(target); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("unsynced staging entry was published: %v", statErr)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".recasaos-transfer-") {
		t.Fatalf("unsynced entry transaction evidence = %v", entries)
	}
	assertManagedTestContent(t, filepath.Join(destination, entries[0].Name(), "entry"), "new")
}

func TestManagedMoveRejectsNonAllowlistedSourceBeforePublication(t *testing.T) {
	const source = "/proc/version"
	if info, err := os.Stat(source); err != nil || !info.Mode().IsRegular() {
		t.Skipf("regular /proc/version unavailable: %v", err)
	}
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{"/proc", root})
	if err != nil {
		t.Skipf("managed /proc root unavailable: %v", err)
	}
	defer roots.Close()

	result, err := roots.MoveInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "allowlisted local source filesystem") {
		t.Fatalf("non-allowlisted source result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "old-target")
	if _, statErr := os.Stat(source); statErr != nil {
		t.Fatalf("rejected move changed source: %v", statErr)
	}
	if transactions := managedMoveSourceTransactionPaths(t, root); len(transactions) != 0 {
		t.Fatalf("rejected source filesystem created move transactions: %v", transactions)
	}
}

func TestManagedMoveRejectsNonAllowlistedDestinationBeforePublication(t *testing.T) {
	const destination = "/proc"
	if info, err := os.Stat(destination); err != nil || !info.IsDir() {
		t.Skipf("/proc destination unavailable: %v", err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root, destination})
	if err != nil {
		t.Skipf("managed /proc root unavailable: %v", err)
	}
	defer roots.Close()
	renameBoundaryCalls := 0
	roots.moveBeforeDirectRename = func() error {
		renameBoundaryCalls++
		return errors.New("direct rename boundary unexpectedly reached")
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "allowlisted local destination filesystem") {
		t.Fatalf("non-allowlisted destination result = %+v, %v", result, err)
	}
	if renameBoundaryCalls != 0 {
		t.Fatalf("non-allowlisted destination reached direct rename boundary %d times", renameBoundaryCalls)
	}
	assertManagedTestContent(t, source, "source")
	if transactions := managedMoveSourceTransactionPaths(t, root); len(transactions) != 0 {
		t.Fatalf("rejected destination filesystem created move transactions: %v", transactions)
	}
}

func TestManagedReplaceRejectsTopLevelTypeChanges(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	regularSource := filepath.Join(root, "regular")
	regularTarget := filepath.Join(destination, "regular")
	if err := os.WriteFile(regularSource, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(regularTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if result, err := roots.CopyInto(regularSource, destination, ManagedConflictReplace); !errors.Is(err, ErrUnsafePath) || result.Changed {
		t.Fatalf("regular-over-directory result = %+v, %v", result, err)
	}
	if info, err := os.Stat(regularTarget); err != nil || !info.IsDir() {
		t.Fatalf("directory target changed: %v, %v", info, err)
	}

	directorySource := filepath.Join(root, "directory")
	directoryTarget := filepath.Join(destination, "directory")
	if err := os.Mkdir(directorySource, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directoryTarget, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := roots.CopyInto(directorySource, destination, ManagedConflictReplace); !errors.Is(err, ErrUnsafePath) || result.Changed {
		t.Fatalf("directory-over-regular result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, directoryTarget, "old")
}

func TestManagedReplaceRejectsNonemptyDirectoryTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(target, "old")
	if err := os.WriteFile(old, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "nonempty directories") {
		t.Fatalf("nonempty directory replacement result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, old, "keep")
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("source directory changed: %v, %v", info, err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("rejected directory replacement left transaction entries: %v", entries)
	}
}

func TestManagedReplaceAllowsEmptyDirectoryTarget(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "new"), []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if err != nil || !result.Changed || result.Destination != target {
		t.Fatalf("empty directory replacement result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, filepath.Join(target, "new"), "published")
	assertManagedTestContent(t, filepath.Join(source, "new"), "published")
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("directory replacement left transaction entries: %v", entries)
	}
}

func TestManagedReplaceRetainsEmptyDirectoryWhenChildAppearsAfterExchange(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "new"), []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	oldTarget, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer oldTarget.Close()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeCleanup = func() error {
		fd, err := unix.Openat(int(oldTarget.Fd()), "injected", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return err
		}
		injected := os.NewFile(uintptr(fd), "injected")
		if injected == nil {
			unix.Close(fd)
			return errors.New("open injected child")
		}
		_, writeErr := injected.Write([]byte("preserve"))
		return errors.Join(writeErr, injected.Close())
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) {
		t.Fatalf("post-exchange directory mutation result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, filepath.Join(target, "new"), "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("mutated old directory transaction was not retained: %v", entries)
	}
	var retained string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retained = filepath.Join(destination, entry.Name(), "entry", "injected")
		}
	}
	if retained == "" {
		t.Fatalf("retained old directory transaction missing: %v", entries)
	}
	assertManagedTestContent(t, retained, "preserve")
}

func TestManagedTransferWaitsForExclusiveWriterLifecycle(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	source := filepath.Join(root, "source.txt")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	writer, err := roots.CreateExclusive(target, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Abort()
	if _, err := writer.Write([]byte("still-writing")); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		close(started)
		_, err := roots.CopyInto(source, destination, ManagedConflictReplace)
		completed <- err
	}()
	<-started
	select {
	case err := <-completed:
		t.Fatalf("copy bypassed active exclusive writer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("copy did not resume after writer Close")
	}
	assertManagedTestContent(t, target, "copy")
}

func TestManagedRootsCopyDirectoryRejectsSymlinkAndCleansStaging(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	if _, err := roots.CopyInto(source, destination, ManagedConflictSkip); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink copy error = %v", err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed copy left destination entries: %v", entries)
	}
	assertManagedTestContent(t, outside, "secret")
}

func TestManagedFailedCopyRetainsPrivateTransactionWhenCleanupSyncFails(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	outside := filepath.Join(root, "outside")
	for _, directory := range []string{source, destination} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	injected := errors.New("injected staging cleanup sync failure")
	destinationIdentity := managedTestPathIdentity(t, destination)
	destinationSyncCalls := 0
	transactionSyncCalls := 0
	var transactionIdentity managedTestFileIdentity
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		if identity == destinationIdentity {
			destinationSyncCalls++
			return unix.Fsync(fd)
		}
		transactionSyncCalls++
		if transactionIdentity == (managedTestFileIdentity{}) {
			transactionIdentity = identity
		} else if identity != transactionIdentity {
			return fmt.Errorf("unexpected sync fd identity: got %+v, transaction %+v", identity, transactionIdentity)
		}
		return injected
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("failed-copy cleanup result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 1 || transactionSyncCalls != 1 {
		t.Fatalf("sync roles = destination %d, transaction %d", destinationSyncCalls, transactionSyncCalls)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".recasaos-transfer-") || !entries[0].IsDir() {
		t.Fatalf("failed copy did not retain one private transaction: %v", entries)
	}
	retained, err := os.ReadDir(filepath.Join(destination, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 0 {
		t.Fatalf("failed copy transaction retained unexpected data: %v", retained)
	}
}

func TestManagedRootsMoveIntoSkipRenameAndCopyFirstReplaceRetainsSource(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	source := filepath.Join(root, "source.txt")
	target := filepath.Join(destination, "source.txt")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if err != nil || result.Changed {
		t.Fatalf("skip move result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, source, "source")

	result, err = roots.MoveInto(source, destination, ManagedConflictRename)
	renamed := filepath.Join(destination, "source(1).txt")
	if err != nil || !result.Changed || result.Destination != renamed {
		t.Fatalf("rename move result = %+v, %v", result, err)
	}
	if _, err := os.Stat(source); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("renamed source remains: %v", err)
	}
	assertManagedTestContent(t, renamed, "source")

	replacementSource := filepath.Join(root, "source.txt")
	if err := os.WriteFile(replacementSource, []byte("replacement"), 0o640); err != nil {
		t.Fatal(err)
	}
	sourceIdentityBeforeCopyFirstMove := managedTestPathIdentity(t, replacementSource)
	result, err = roots.MoveInto(replacementSource, destination, ManagedConflictReplace)
	if !errors.Is(err, ErrManagedMoveSourceRetained) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != target {
		t.Fatalf("replace move result = %+v, %v", result, err)
	}
	if sourceIdentityAfterCopyFirstMove := managedTestPathIdentity(t, replacementSource); sourceIdentityAfterCopyFirstMove != sourceIdentityBeforeCopyFirstMove {
		t.Fatalf("copy-first move changed source identity: before %+v, after %+v", sourceIdentityBeforeCopyFirstMove, sourceIdentityAfterCopyFirstMove)
	}
	assertManagedTestContent(t, replacementSource, "replacement")
	assertManagedTestContent(t, target, "replacement")
	if transactions := managedMoveSourceTransactionPaths(t, root); len(transactions) != 0 {
		t.Fatalf("copy-first replace created source transactions: %v", transactions)
	}
}

func TestManagedCopyFirstMoveJoinsSourceRetainedWithTransactionCleanupFailure(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	sourceIdentityBefore := managedTestPathIdentity(t, source)
	injected := errors.New("injected post-publication transaction rmdir failure")
	cleanupCalls := 0
	roots.transactionAfterRmdir = func() error {
		cleanupCalls++
		return injected
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, injected) || !errors.Is(err, ErrManagedMoveSourceRetained) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("copy-first move cleanup failure result = %+v, %v", result, err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("post-rmdir cleanup hook calls = %d, want 1", cleanupCalls)
	}
	if sourceIdentityAfter := managedTestPathIdentity(t, source); sourceIdentityAfter != sourceIdentityBefore {
		t.Fatalf("copy-first move cleanup failure changed source identity: before %+v, after %+v", sourceIdentityBefore, sourceIdentityAfter)
	}
	assertManagedTestContent(t, source, "new")
	assertManagedTestContent(t, target, "new")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("post-rmdir cleanup failure left unexpected destination evidence: %v", entries)
	}
}

func TestManagedCopyFirstMoveJoinsSourceRetainedWithDestinationSyncFailure(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	sourceIdentityBefore := managedTestPathIdentity(t, source)
	destinationIdentity := managedTestPathIdentity(t, destination)
	injected := errors.New("injected copy-first move destination publication sync failure")
	destinationSyncCalls := 0
	transactionSyncCalls := 0
	var transactionIdentity managedTestFileIdentity
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		if identity == destinationIdentity {
			destinationSyncCalls++
			if destinationSyncCalls == 2 {
				return injected
			}
			return unix.Fsync(fd)
		}
		transactionSyncCalls++
		if transactionIdentity == (managedTestFileIdentity{}) {
			transactionIdentity = identity
		} else if identity != transactionIdentity {
			return fmt.Errorf("unexpected sync fd identity: got %+v, transaction %+v", identity, transactionIdentity)
		}
		return unix.Fsync(fd)
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, injected) || !errors.Is(err, ErrManagedMoveSourceRetained) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("copy-first move destination sync result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 2 || transactionSyncCalls != 1 {
		t.Fatalf("sync roles = destination %d, transaction %d; destination failure must short-circuit post-exchange transaction sync", destinationSyncCalls, transactionSyncCalls)
	}
	if sourceIdentityAfter := managedTestPathIdentity(t, source); sourceIdentityAfter != sourceIdentityBefore {
		t.Fatalf("copy-first move destination sync failure changed source identity: before %+v, after %+v", sourceIdentityBefore, sourceIdentityAfter)
	}
	assertManagedTestContent(t, source, "new")
	assertManagedTestContent(t, target, "new")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("destination sync failure did not retain transaction evidence: %v", entries)
	}
	var retainedOldTarget string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retainedOldTarget = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if retainedOldTarget == "" {
		t.Fatalf("destination sync failure transaction evidence missing: %v", entries)
	}
	assertManagedTestContent(t, retainedOldTarget, "old")
}

func TestManagedDirectMoveDetectsSourceSwapAtRenameBoundary(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	sourceAside := filepath.Join(root, "source-aside.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.moveBeforeDirectRename = func() error {
		if err := os.Rename(source, sourceAside); err != nil {
			return err
		}
		return os.WriteFile(source, []byte("replacement"), 0o600)
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("direct source swap result = %+v, %v", result, err)
	}
	if !strings.Contains(err.Error(), "destination does not identify pinned source") {
		t.Fatalf("direct source swap error = %v", err)
	}
	assertManagedTestContent(t, sourceAside, "original")
	assertManagedTestContent(t, target, "replacement")
	if _, statErr := os.Stat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("direct source swap unexpectedly left the moved replacement: %v", statErr)
	}
	if transactions := managedMoveSourceTransactionPaths(t, root); len(transactions) != 0 {
		t.Fatalf("direct source swap created copy-first transactions: %v", transactions)
	}
}

func TestManagedNoReplaceDestinationSyncFailureShortCircuitsTransactionSync(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	destinationIdentity := managedTestPathIdentity(t, destination)
	injected := errors.New("injected destination publication sync failure")
	destinationSyncCalls := 0
	transactionSyncCalls := 0
	var transactionIdentity managedTestFileIdentity
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		if identity == destinationIdentity {
			destinationSyncCalls++
			if destinationSyncCalls == 2 {
				return injected
			}
			return unix.Fsync(fd)
		}
		transactionSyncCalls++
		if transactionIdentity == (managedTestFileIdentity{}) {
			transactionIdentity = identity
		} else if identity != transactionIdentity {
			return fmt.Errorf("unexpected sync fd identity: got %+v, transaction %+v", identity, transactionIdentity)
		}
		return unix.Fsync(fd)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	expectedTarget := filepath.Join(destination, filepath.Base(source))
	if !errors.Is(err, injected) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != expectedTarget {
		t.Fatalf("directory-sync copy result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 2 || transactionSyncCalls != 1 {
		t.Fatalf("sync roles = destination %d, transaction %d; destination failure must short-circuit the post-publication transaction sync", destinationSyncCalls, transactionSyncCalls)
	}
	assertManagedTestContent(t, expectedTarget, "new")
	assertManagedTestContent(t, source, "new")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("publish sync failure did not retain empty private transaction: %v", entries)
	}
}

func TestManagedReplaceDestinationSyncFailureShortCircuitsTransactionSync(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	destinationIdentity := managedTestPathIdentity(t, destination)
	injected := errors.New("injected replacement destination sync failure")
	destinationSyncCalls := 0
	transactionSyncCalls := 0
	var transactionIdentity managedTestFileIdentity
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		if identity == destinationIdentity {
			destinationSyncCalls++
			if destinationSyncCalls == 2 {
				return injected
			}
			return unix.Fsync(fd)
		}
		transactionSyncCalls++
		if transactionIdentity == (managedTestFileIdentity{}) {
			transactionIdentity = identity
		} else if identity != transactionIdentity {
			return fmt.Errorf("unexpected sync fd identity: got %+v, transaction %+v", identity, transactionIdentity)
		}
		return unix.Fsync(fd)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != target {
		t.Fatalf("replacement cleanup result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 2 || transactionSyncCalls != 1 {
		t.Fatalf("sync roles = destination %d, transaction %d; destination failure must short-circuit the post-exchange transaction sync", destinationSyncCalls, transactionSyncCalls)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("replacement did not retain private transaction: %v", entries)
	}
	var retained string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retained = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if retained == "" {
		t.Fatalf("replacement private transaction missing: %v", entries)
	}
	assertManagedTestContent(t, target, "new")
	assertManagedTestContent(t, retained, "old")
}

func TestManagedReplaceRejectsTargetPathReplacementBeforeExchange(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeExchange = func() error {
		if err := os.Remove(target); err != nil {
			return err
		}
		return os.WriteFile(target, []byte("unexpected"), 0o600)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || ManagedMutationChanged(err) {
		t.Fatalf("replacement identity race result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "unexpected")
	assertManagedTestContent(t, source, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("rejected target replacement left transaction entries: %v", entries)
	}
}

func TestManagedReplaceRejectsSameInodeTargetMutationBeforeExchange(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeExchange = func() error {
		return os.WriteFile(target, []byte("same-inode mutation"), 0o600)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || ManagedMutationChanged(err) {
		t.Fatalf("replacement same-inode race result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "same-inode mutation")
	assertManagedTestContent(t, source, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("rejected same-inode mutation left transaction entries: %v", entries)
	}
}

func TestManagedReplaceRejectsCtimeOnlyMutationBeforeExchange(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeExchange = func() error {
		var before unix.Stat_t
		if err := unix.Stat(target, &before); err != nil {
			return err
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err := os.Chmod(target, 0o640); err != nil {
				return err
			}
			if err := os.Chmod(target, 0o600); err != nil {
				return err
			}
			var after unix.Stat_t
			if err := unix.Stat(target, &after); err != nil {
				return err
			}
			if sameManagedExchangeStat(&before, &after) && !sameManagedTransferStat(&before, &after) {
				return nil
			}
			if time.Now().After(deadline) {
				return errors.New("could not produce a ctime-only target mutation")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ctime-only replacement race result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "old")
	assertManagedTestContent(t, source, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("rejected pre-exchange mutation left staging entries: %v", entries)
	}
}

func TestManagedReplacePreservesPrivateStagingSubstitution(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeExchange = func() error {
		entries, err := os.ReadDir(destination)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
				continue
			}
			transactionEntry := filepath.Join(destination, entry.Name(), "entry")
			if err := os.Remove(transactionEntry); err != nil {
				return err
			}
			return os.WriteFile(transactionEntry, []byte("attacker payload"), 0o600)
		}
		return errors.New("private transfer transaction not found")
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("private staging replacement result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "old")
	assertManagedTestContent(t, source, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("substituted private staging was not retained: %v", entries)
	}
	var transactionEntry string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			transactionEntry = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if transactionEntry == "" {
		t.Fatalf("substituted private staging missing: %v", entries)
	}
	assertManagedTestContent(t, transactionEntry, "attacker payload")
}

func TestManagedReplacePreservesSubstitutionInsidePrivateTransaction(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeCleanup = func() error {
		entries, err := os.ReadDir(destination)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
				continue
			}
			transactionEntry := filepath.Join(destination, entry.Name(), "entry")
			if err := os.Remove(transactionEntry); err != nil {
				return err
			}
			return os.WriteFile(transactionEntry, []byte("unexpected"), 0o600)
		}
		return errors.New("private transfer transaction not found")
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) {
		t.Fatalf("pre-cleanup replacement race result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("substituted transaction target was not preserved: %v", entries)
	}
	var transactionEntry string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			transactionEntry = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if transactionEntry == "" {
		t.Fatalf("substituted transaction target missing: %v", entries)
	}
	assertManagedTestContent(t, transactionEntry, "unexpected")
}

func TestManagedReplacePreservesPostExchangeDestinationSwap(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	publishedAside := target + ".published-aside"
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.replaceBeforeCleanup = func() error {
		if err := os.Rename(target, publishedAside); err != nil {
			return err
		}
		return os.WriteFile(target, []byte("replacement"), 0o600)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("post-exchange destination swap result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "replacement")
	assertManagedTestContent(t, publishedAside, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 3 {
		t.Fatalf("post-exchange swap did not retain private old target: %v", entries)
	}
	var retained string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			retained = filepath.Join(destination, entry.Name(), "entry")
		}
	}
	if retained == "" {
		t.Fatalf("private old target transaction missing: %v", entries)
	}
	assertManagedTestContent(t, retained, "old")
}

func TestManagedReplacePreservesOldTargetWhenTransactionNameMoves(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	var movedTransaction string
	roots.replaceBeforeCleanup = func() error {
		entries, err := os.ReadDir(destination)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
				continue
			}
			current := filepath.Join(destination, entry.Name())
			movedTransaction = current + ".moved"
			return os.Rename(current, movedTransaction)
		}
		return errors.New("private transfer transaction not found")
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !errors.Is(err, unix.ENOENT) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("transaction name move result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "published")
	if movedTransaction == "" {
		t.Fatal("transaction move hook did not run")
	}
	assertManagedTestContent(t, filepath.Join(movedTransaction, "entry"), "old")
}

func TestManagedAtomicMoveDoesNotReportSuccessWhenParentSyncFails(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	injected := errors.New("injected atomic move sync failure")
	destinationIdentity := managedTestPathIdentity(t, destination)
	sourceParentIdentity := managedTestPathIdentity(t, root)
	destinationSyncCalls := 0
	sourceParentSyncCalls := 0
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		switch identity {
		case destinationIdentity:
			destinationSyncCalls++
			return injected
		case sourceParentIdentity:
			sourceParentSyncCalls++
			return unix.Fsync(fd)
		default:
			return fmt.Errorf("unexpected atomic move sync fd identity: %+v", identity)
		}
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != target {
		t.Fatalf("atomic move sync result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 1 || sourceParentSyncCalls != 0 {
		t.Fatalf("sync roles = destination %d, source parent %d; source parent sync must wait for destination sync", destinationSyncCalls, sourceParentSyncCalls)
	}
	if _, statErr := os.Stat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("atomic rename did not move source: %v", statErr)
	}
	assertManagedTestContent(t, target, "new")
}

func TestManagedAtomicMoveReportsUnknownDurabilityWhenSourceParentSyncFails(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, filepath.Base(source))
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	injected := errors.New("injected atomic move source parent sync failure")
	destinationIdentity := managedTestPathIdentity(t, destination)
	sourceParentIdentity := managedTestPathIdentity(t, root)
	destinationSyncCalls := 0
	sourceParentSyncCalls := 0
	roots.directorySync = func(fd int) error {
		identity, err := managedTestFDIdentity(fd)
		if err != nil {
			return err
		}
		switch identity {
		case destinationIdentity:
			destinationSyncCalls++
			return unix.Fsync(fd)
		case sourceParentIdentity:
			sourceParentSyncCalls++
			return injected
		default:
			return fmt.Errorf("unexpected atomic move sync fd identity: %+v", identity)
		}
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != target {
		t.Fatalf("atomic move source parent sync result = %+v, %v", result, err)
	}
	if destinationSyncCalls != 1 || sourceParentSyncCalls != 1 {
		t.Fatalf("sync roles = destination %d, source parent %d", destinationSyncCalls, sourceParentSyncCalls)
	}
	if _, statErr := os.Stat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("atomic rename did not move source: %v", statErr)
	}
	assertManagedTestContent(t, target, "new")
}

func TestManagedRootsTransferRejectsOverlappingTrees(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(source, "destination")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destination, ManagedConflictSkip); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("overlapping copy error = %v", err)
	}
}

func TestManagedRootsTransferCannotReplaceNestedConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	sourceParent := filepath.Join(root, "source-parent")
	destination := filepath.Join(root, "destination")
	protectedRoot := filepath.Join(destination, "protected")
	source := filepath.Join(sourceParent, "protected")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(protectedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	protectedFile := filepath.Join(protectedRoot, "keep")
	if err := os.WriteFile(protectedFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root, protectedRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destination, ManagedConflictReplace); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("configured-root replacement error = %v", err)
	}
	assertManagedTestContent(t, protectedFile, "keep")
}

func TestManagedRegularCopyAllowsSelectedNestedConfiguredRootDestination(t *testing.T) {
	root := t.TempDir()
	nestedRoot := filepath.Join(root, "nested-root")
	destination := filepath.Join(nestedRoot, "destination")
	source := filepath.Join(root, "source.txt")
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root, nestedRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if err != nil || !result.Changed {
		t.Fatalf("nested-root destination result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, filepath.Join(destination, filepath.Base(source)), "data")
}

func TestManagedRootsTransferRejectsSourceAncestorOfConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	protectedRoot := filepath.Join(source, "protected-root")
	destination := filepath.Join(root, "destination")
	if err := os.MkdirAll(protectedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root, protectedRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destination, ManagedConflictSkip); !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "contains configured root") {
		t.Fatalf("source-ancestor error = %v", err)
	}
}

func TestManagedRootsTransferRejectsTargetAncestorOfConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	sourceParent := filepath.Join(root, "source-parent")
	source := filepath.Join(sourceParent, "container")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, "container")
	protectedRoot := filepath.Join(target, "protected-root")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(protectedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root, protectedRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destination, ManagedConflictReplace); !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "contains configured root") {
		t.Fatalf("target-ancestor error = %v", err)
	}
}

func TestManagedDescriptorAncestorAndExactAliasGuards(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "parent")
	childPath := filepath.Join(parentPath, "child")
	if err := os.MkdirAll(childPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	child, err := os.Open(childPath)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	ancestor, err := managedDescriptorIsAncestorOrSame(int(parent.Fd()), int(child.Fd()))
	if err != nil || !ancestor {
		t.Fatalf("parent ancestor = %v, %v", ancestor, err)
	}
	ancestor, err = managedDescriptorIsAncestorOrSame(int(child.Fd()), int(parent.Fd()))
	if err != nil || ancestor {
		t.Fatalf("child ancestor = %v, %v", ancestor, err)
	}

	filePath := filepath.Join(parentPath, "same-file")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var sourceStat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &sourceStat); err != nil {
		t.Fatal(err)
	}
	if err := rejectManagedExactTargetAlias(int(parent.Fd()), "same-file", &sourceStat); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("exact alias error = %v", err)
	}
}

func TestManagedDirectoryTransferRejectsCrossConfiguredRootAndReplaceMove(t *testing.T) {
	base := t.TempDir()
	sourceRoot := filepath.Join(base, "source-root")
	destinationRoot := filepath.Join(base, "destination-root")
	source := filepath.Join(sourceRoot, "directory")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destinationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{sourceRoot, destinationRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destinationRoot, ManagedConflictSkip); !errors.Is(err, ErrUnsafeManagedDirectoryTransfer) {
		t.Fatalf("cross-root directory copy error = %v", err)
	}

	sameRootDestination := filepath.Join(sourceRoot, "destination")
	if err := os.Mkdir(sameRootDestination, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.MoveInto(source, sameRootDestination, ManagedConflictReplace); !errors.Is(err, ErrManagedDirectoryMoveRequiresAtomicRename) {
		t.Fatalf("replace directory move error = %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("rejected move changed source: %v", err)
	}
}

func TestManagedDirectoryCopyRejectsBindMountAliasIntoSource(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	source := filepath.Join(root, "source")
	boundSourceChild := filepath.Join(source, "child")
	alias := filepath.Join(root, "alias")
	if err := os.MkdirAll(boundSourceChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(alias, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(boundSourceChild, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested bind-alias regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(alias, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount alias: %v", err)
		}
	}()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, alias, ManagedConflictSkip); !errors.Is(err, ErrUnsafeManagedDirectoryTransfer) {
		t.Fatalf("bind alias copy error = %v", err)
	}
}

func TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	base := t.TempDir()
	rootA := filepath.Join(base, "root-a")
	rootB := filepath.Join(base, "root-b")
	backing := filepath.Join(rootB, "backing")
	alias := filepath.Join(rootA, "alias")
	for _, directory := range []string{rootA, backing, alias} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(backing, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested destination-bind regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(alias, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount destination alias: %v", err)
		}
	}()
	roots, err := OpenManagementFileRoots([]string{rootA, rootB})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	legitimateSource := filepath.Join(rootA, "legitimate.txt")
	if err := os.WriteFile(legitimateSource, []byte("legitimate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := roots.CopyInto(legitimateSource, rootB, ManagedConflictSkip); err != nil || !result.Changed {
		t.Fatalf("configured-root destination result = %+v, %v", result, err)
	}

	aliasSource := filepath.Join(rootA, "alias-source.txt")
	if err := os.WriteFile(aliasSource, []byte("must-not-cross"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := roots.CopyInto(aliasSource, alias, ManagedConflictSkip)
	if !errors.Is(err, ErrUnsafePath) || result.Changed {
		t.Fatalf("bind-alias regular copy result = %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(backing, filepath.Base(aliasSource))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("bind alias wrote into another configured root: %v", err)
	}
}

func TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	backing := filepath.Join(root, "backing")
	protectedRoot := filepath.Join(backing, "protected")
	source := filepath.Join(root, "source", "container")
	destination := filepath.Join(root, "destination")
	target := filepath.Join(destination, "container")
	for _, directory := range []string{protectedRoot, source, target} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(backing, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested replace-bind regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount replacement alias: %v", err)
		}
	}()
	roots, err := OpenManagementFileRoots([]string{root, protectedRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.CopyInto(source, destination, ManagedConflictReplace); !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "configured root") {
		t.Fatalf("replacement cleanup alias error = %v", err)
	}
}

func TestValidateManagedMoveMountBoundary(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	child, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := validateManagedMoveMountBoundary(int(parent.Fd()), int(child.Fd())); err != nil {
		t.Fatalf("same-mount boundary error = %v", err)
	}
	parentMountID, err := managedMountIDAt(int(parent.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManagedChildMount(parentMountID, int(child.Fd())); err != nil {
		t.Fatalf("same-mount child error = %v", err)
	}
	proc, err := os.Open("/proc")
	if err != nil {
		t.Skipf("/proc unavailable: %v", err)
	}
	defer proc.Close()
	if err := validateManagedMoveMountBoundary(int(parent.Fd()), int(proc.Fd())); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("different-mount boundary error = %v", err)
	}
	if err := validateManagedChildMount(parentMountID, int(proc.Fd())); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("different-mount child error = %v", err)
	}
}

func TestVerifyManagedNameIdentityRejectsModifiedSource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), "source", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManagedNameIdentity(int(parent.Fd()), "source", &before); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("modified source identity error = %v", err)
	}
}

func TestManagedCleanupIdentityRejectsExternalReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "staging")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var expected unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), "staging", &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManagedNameIdentity(int(parent.Fd()), "staging", &expected); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("replacement cleanup identity error = %v", err)
	}
	assertManagedTestContent(t, path, "replacement")
}

func TestClassifyManagedResolutionErrorTreatsENOTDIRAsUnsafe(t *testing.T) {
	if err := classifyManagedResolutionError(unix.ENOTDIR); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ENOTDIR classification = %v", err)
	}
}

type managedTestFileIdentity struct {
	device uint64
	inode  uint64
}

func managedTestFDIdentity(fd int) (managedTestFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return managedTestFileIdentity{}, err
	}
	return managedTestFileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func managedTestPathIdentity(t *testing.T, path string) managedTestFileIdentity {
	t.Helper()
	opened, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := managedTestFDIdentity(int(opened.Fd()))
	closeErr := opened.Close()
	if err := errors.Join(identityErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return identity
}

func assertManagedTestContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s content = %q, want %q", path, content, expected)
	}
}

func managedMoveSourceTransactionPaths(t *testing.T, parent string) []string {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".recasaos-move-source-") {
			paths = append(paths, filepath.Join(parent, entry.Name()))
		}
	}
	return paths
}

func TestManagedRenameCandidateFailsClosedWhenSuffixExceedsNameLimit(t *testing.T) {
	base := strings.Repeat("a", 255)
	if _, err := managedRenameCandidate(base, 1); err == nil {
		t.Fatal("overlong conflict name was accepted")
	}
}
