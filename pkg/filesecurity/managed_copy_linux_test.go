//go:build linux

package filesecurity

import (
	"errors"
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

func TestManagedFailedCopySurfacesStagingCleanupSyncFailureWithoutLeak(t *testing.T) {
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
	roots.directorySync = func(int) error { return injected }

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	if result.Changed || !errors.Is(err, ErrUnsafePath) || !errors.Is(err, injected) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("failed-copy cleanup result = %+v, %v", result, err)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed copy leaked staging entries: %v", entries)
	}
}

func TestManagedRootsMoveIntoSkipRenameAndReplace(t *testing.T) {
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
	result, err = roots.MoveInto(replacementSource, destination, ManagedConflictReplace)
	if err != nil || !result.Changed || result.Destination != target {
		t.Fatalf("replace move result = %+v, %v", result, err)
	}
	if _, err := os.Stat(replacementSource); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("replacement source remains: %v", err)
	}
	assertManagedTestContent(t, target, "replacement")
}

func TestManagedCopyReportsPublishedResultWhenDestinationSyncFails(t *testing.T) {
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
	injected := errors.New("injected directory sync failure")
	roots.directorySync = func(int) error { return injected }

	result, err := roots.CopyInto(source, destination, ManagedConflictSkip)
	expectedTarget := filepath.Join(destination, filepath.Base(source))
	if !errors.Is(err, injected) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != expectedTarget {
		t.Fatalf("directory-sync copy result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, expectedTarget, "new")
	assertManagedTestContent(t, source, "new")
}

func TestManagedReplaceCleanupSyncFailureDoesNotRetryDeletedTemporaryName(t *testing.T) {
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
	injected := errors.New("injected replacement cleanup sync failure")
	syncCalls := 0
	roots.directorySync = func(fd int) error {
		syncCalls++
		if syncCalls == 2 {
			return injected
		}
		return unix.Fsync(fd)
	}

	result, err := roots.CopyInto(source, destination, ManagedConflictReplace)
	if !errors.Is(err, injected) || !result.Changed || result.Destination != target {
		t.Fatalf("replacement cleanup result = %+v, %v", result, err)
	}
	if syncCalls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", syncCalls)
	}
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("replacement left hidden staging entries: %v", entries)
	}
	assertManagedTestContent(t, target, "new")
}

func TestManagedReplacePreservesUnexpectedTargetExchangedIntoHiddenName(t *testing.T) {
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
	if !result.Changed || result.Destination != target || !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) {
		t.Fatalf("replacement identity race result = %+v, %v", result, err)
	}
	assertManagedTestContent(t, target, "published")
	entries, readErr := os.ReadDir(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected exchanged target was not preserved: %v", entries)
	}
	var hidden string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-transfer-") {
			hidden = filepath.Join(destination, entry.Name())
		}
	}
	if hidden == "" {
		t.Fatalf("hidden exchanged target missing: %v", entries)
	}
	assertManagedTestContent(t, hidden, "unexpected")
}

func TestManagedMoveReportsPartialWhenSourceCleanupSyncFails(t *testing.T) {
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
	injected := errors.New("injected source cleanup sync failure")
	syncCalls := 0
	roots.directorySync = func(fd int) error {
		syncCalls++
		if syncCalls == 3 {
			return injected
		}
		return unix.Fsync(fd)
	}

	result, err := roots.MoveInto(source, destination, ManagedConflictReplace)
	if !errors.Is(err, injected) || !ManagedMutationDurabilityUnknown(err) || !result.Changed || result.Destination != target {
		t.Fatalf("source cleanup result = %+v, %v", result, err)
	}
	if syncCalls != 3 {
		t.Fatalf("directory sync calls = %d, want 3", syncCalls)
	}
	if _, statErr := os.Stat(source); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("source unlink did not occur before sync failure: %v", statErr)
	}
	assertManagedTestContent(t, target, "new")
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
	roots.directorySync = func(int) error { return injected }

	result, err := roots.MoveInto(source, destination, ManagedConflictSkip)
	if !errors.Is(err, injected) || !result.Changed || result.Destination != target {
		t.Fatalf("atomic move sync result = %+v, %v", result, err)
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
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bind mounts are unavailable in this Linux test environment: %v", err)
		}
		t.Fatal(err)
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
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bind mounts are unavailable in this Linux test environment: %v", err)
		}
		t.Fatal(err)
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
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bind mounts are unavailable in this Linux test environment: %v", err)
		}
		t.Fatal(err)
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

func TestManagedCleanupPresenceRejectsExternalReplacement(t *testing.T) {
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
	present, err := managedNamePresentAt(int(parent.Fd()), "staging", &expected)
	if present || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("replacement cleanup presence = %v, %v", present, err)
	}
	assertManagedTestContent(t, path, "replacement")
}

func TestClassifyManagedResolutionErrorTreatsENOTDIRAsUnsafe(t *testing.T) {
	if err := classifyManagedResolutionError(unix.ENOTDIR); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ENOTDIR classification = %v", err)
	}
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

func TestManagedRenameCandidateFailsClosedWhenSuffixExceedsNameLimit(t *testing.T) {
	base := strings.Repeat("a", 255)
	if _, err := managedRenameCandidate(base, 1); err == nil {
		t.Fatal("overlong conflict name was accepted")
	}
}
