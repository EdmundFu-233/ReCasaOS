//go:build linux

package filesecurity

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestManagedRootsRejectRootSymlink(t *testing.T) {
	base := t.TempDir()
	realRoot := filepath.Join(base, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenManagementFileRoots([]string{link}); err == nil {
		t.Fatal("symbolic-link root was accepted")
	}
}

func TestManagedDescriptorNamesAreOpaqueAndStatPreservesBaseName(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "private-root-marker")
	directoryPath := filepath.Join(root, "private-directory-marker")
	filePath := filepath.Join(root, "private-file-marker.txt")
	if err := os.MkdirAll(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if got := roots.roots[0].file.Name(); got != managedRootDescriptorName || strings.Contains(got, "private-root-marker") {
		t.Fatalf("managed root descriptor name = %q", got)
	}

	tests := []struct {
		name string
		open func() (*os.File, error)
	}{
		{name: "regular", open: func() (*os.File, error) { return roots.OpenRegular(filePath) }},
		{name: "path", open: func() (*os.File, error) { return roots.OpenPath(filePath) }},
		{name: "directory", open: func() (*os.File, error) { return roots.OpenDirectory(directoryPath) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opened, err := test.open()
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if got := opened.Name(); got != managedOpenedPathDescriptorName || strings.Contains(got, "private-") {
				t.Fatalf("descriptor name = %q", got)
			}
			info, err := opened.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Name(); got != managedOpenedPathDescriptorName || strings.Contains(got, "private-") {
				t.Fatalf("descriptor stat name = %q", got)
			}
		})
	}

	for _, path := range []string{root, directoryPath, filePath} {
		info, err := roots.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := info.Name(), filepath.Base(path); got != want {
			t.Fatalf("managed Stat(%q) name = %q, want %q", path, got, want)
		}
	}

	opened, err := roots.OpenRegular(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &before); err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	movedPath := filepath.Join(root, "moved-original")
	if err := os.Rename(filePath, movedPath); err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("replacement"), 0o600); err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	content, err := io.ReadAll(opened)
	if err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &after); err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" || before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatalf("descriptor followed a renamed path: content=%q before=%d:%d after=%d:%d", content, before.Dev, before.Ino, after.Dev, after.Ino)
	}

	closed, err := roots.OpenDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := closed.ReadDir(1); err == nil {
		t.Fatal("ReadDir on a closed managed descriptor succeeded")
	} else {
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("closed descriptor error type = %T, want *os.PathError", err)
		}
		if pathErr.Path != managedOpenedPathDescriptorName || strings.Contains(pathErr.Path, "private-") {
			t.Fatalf("closed descriptor error path = %q", pathErr.Path)
		}
	}
}

func TestManagedRootsOpenRegularRejectsEscapesAndSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	insideFile := filepath.Join(root, "inside.txt")
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(insideFile, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	opened, err := roots.OpenRegular(insideFile)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(opened)
	if err != nil {
		t.Fatal(err)
	}
	_ = opened.Close()
	if string(content) != "inside" {
		t.Fatalf("content = %q", content)
	}

	if _, err := roots.OpenRegular(filepath.Join(root, "escape", "secret.txt")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink escape error = %v", err)
	}
	if _, err := roots.Stat(filepath.Join(root, "escape")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("final symlink stat error = %v", err)
	}
	if _, err := roots.OpenRegular(outsideFile); !errors.Is(err, ErrManagedPathOutsideRoots) {
		t.Fatalf("outside path error = %v", err)
	}
}

func TestManagedRootsRejectFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	result := make(chan error, 1)
	go func() {
		opened, err := roots.OpenRegular(fifo)
		if opened != nil {
			_ = opened.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("FIFO open error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
}

func TestManagedRootsRejectHardLinkedRegularFiles(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	alias := filepath.Join(root, "alias")
	if err := os.WriteFile(original, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	if _, err := roots.OpenRegular(original); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hard-linked read error = %v", err)
	}
	if err := roots.RewriteRegular(original, []byte("changed")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hard-linked rewrite error = %v", err)
	}
	content, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("hard-linked content changed to %q", content)
	}
}

func TestManagedRootsRemainPinnedWhenRootPathIsReplaced(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	moved := filepath.Join(base, "managed-original")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "value"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "value"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	opened, err := roots.OpenRegular(filepath.Join(root, "value"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	content := make([]byte, len("original"))
	if _, err := opened.Read(content); err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("pinned root returned %q", content)
	}
}

func TestManagedRootsMkdirAllAndCreateExclusive(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	directory := filepath.Join(root, "one", "two")
	if err := roots.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	createdPath := filepath.Join(directory, "new.txt")
	created, err := roots.CreateExclusive(createdPath, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Abort()
	if _, err := created.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.CreateExclusive(createdPath, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("replacement create error = %v", err)
	}

	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := roots.MkdirAll(filepath.Join(link, "escaped"), 0o750); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink mkdir error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("outside directory was created: %v", err)
	}
}

func TestManagedWritableAbortDoesNotPublishAndReleasesMutationLease(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	target := filepath.Join(root, "target.txt")
	writer, err := roots.CreateExclusive(target, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unclosed exclusive file was published: %v", err)
	}

	started := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		close(started)
		completed <- roots.MkdirAll(filepath.Join(root, "after-abort"), 0o700)
	}()
	<-started
	select {
	case err := <-completed:
		t.Fatalf("mutation bypassed active writer lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation lease was not released by Abort")
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("aborted exclusive file was published: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".recasaos-create-") {
			t.Fatalf("Abort leaked staging file %q", entry.Name())
		}
	}
}

func TestManagedMutationLeaseAllowsReadsWhileCloseWaits(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	release, err := roots.AcquireMutation()
	if err != nil {
		t.Fatal(err)
	}
	closeStarted := make(chan struct{})
	closeCompleted := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeCompleted <- roots.Close()
	}()
	<-closeStarted
	select {
	case err := <-closeCompleted:
		t.Fatalf("Close bypassed active mutation lease: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := roots.Match(root); err != nil {
		t.Fatalf("read under mutation lease failed while Close waited: %v", err)
	}
	directory, err := roots.OpenDirectory(root)
	if err != nil {
		t.Fatalf("open under mutation lease failed while Close waited: %v", err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-closeCompleted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not complete after mutation lease release")
	}
}

func TestManagedNamespaceMutationsExposeInjectedDirectorySyncFailure(t *testing.T) {
	injected := errors.New("injected directory sync failure")
	assertChanged := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
			t.Fatalf("mutation error = %v", err)
		}
	}

	t.Run("rewrite", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "file")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, roots.RewriteRegular(path, []byte("new")))
		content, err := os.ReadFile(path)
		if err != nil || string(content) != "new" {
			t.Fatalf("rewritten content = %q, %v", content, err)
		}
	})

	t.Run("rename", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source")
		destination := filepath.Join(root, "destination")
		if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, roots.RenameNoReplace(source, destination))
		if _, err := os.Stat(destination); err != nil {
			t.Fatalf("renamed destination missing: %v", err)
		}
	})

	t.Run("commit", func(t *testing.T) {
		root := t.TempDir()
		staging := filepath.Join(root, "staging")
		destination := filepath.Join(root, "destination")
		if err := os.WriteFile(staging, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, roots.CommitNoReplace(staging, destination))
		if _, err := os.Stat(destination); err != nil {
			t.Fatalf("committed destination missing: %v", err)
		}
	})

	t.Run("exclusive-create", func(t *testing.T) {
		root := t.TempDir()
		destination := filepath.Join(root, "destination")
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		writer, err := roots.CreateExclusive(destination, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, writer.Close())
		if _, err := os.Stat(destination); err != nil {
			t.Fatalf("exclusive destination missing: %v", err)
		}
	})

	t.Run("mkdir", func(t *testing.T) {
		root := t.TempDir()
		destination := filepath.Join(root, "directory")
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, roots.MkdirAll(destination, 0o700))
		if info, err := os.Stat(destination); err != nil || !info.IsDir() {
			t.Fatalf("created directory = %v, %v", info, err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "file")
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		roots, err := OpenManagementFileRoots([]string{root})
		if err != nil {
			t.Fatal(err)
		}
		defer roots.Close()
		roots.directorySync = func(int) error { return injected }
		assertChanged(t, roots.Remove(path))
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("removed path remains: %v", err)
		}
	})
}

func TestManagedMkdirAllPreservesEarlierCreationWhenLaterComponentBecomesSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	calls := 0
	roots.directorySync = func(int) error {
		calls++
		if calls == 1 {
			return os.Symlink(outside, filepath.Join(root, "first", "second"))
		}
		return nil
	}
	err = roots.MkdirAll(filepath.Join(root, "first", "second", "leaf"), 0o700)
	if !errors.Is(err, ErrUnsafePath) || !ManagedMutationChanged(err) || ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("partial mkdir error = %v", err)
	}
	if info, statErr := os.Stat(filepath.Join(root, "first")); statErr != nil || !info.IsDir() {
		t.Fatalf("first created component missing: %v, %v", info, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "leaf")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("mkdir escaped through injected symlink: %v", statErr)
	}
}

func TestManagedDirectDirectoryRenameRejectsNestedBindMount(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	source := filepath.Join(root, "source")
	mountedChild := filepath.Join(source, "mounted")
	backing := t.TempDir()
	if err := os.MkdirAll(mountedChild, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(backing, mountedChild, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested nested-rename regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(mountedChild, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount nested rename test path: %v", err)
		}
	}()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	destination := filepath.Join(root, "renamed")
	if err := roots.RenameNoReplace(source, destination); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("nested-mount direct rename error = %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("rejected direct rename changed source: %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("rejected direct rename created destination: %v", err)
	}
}

func TestManagedRemoveAllReportsPartialDeletionAfterInjectedSyncFailure(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	injected := errors.New("injected recursive removal sync failure")
	roots.directorySync = func(int) error { return injected }
	err = roots.RemoveAll(target)
	if !errors.Is(err, injected) || !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("partial recursive removal error = %v", err)
	}
	entries, readErr := os.ReadDir(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 {
		t.Fatalf("partial recursive removal entries = %v", entries)
	}
}

func TestManagedRemoveAllBatchRejectsDuplicatesAndOverlapsBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(child, "keep")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	for _, paths := range [][]string{{parent, parent}, {parent, child}} {
		result, err := roots.RemoveAllBatch(paths)
		if !errors.Is(err, ErrUnsafePath) || result.Changed || len(result.Completed) != 0 {
			t.Fatalf("overlapping batch %v result = %+v, %v", paths, result, err)
		}
		assertManagedTestContent(t, keep, "keep")
	}
}

func TestManagedRemovalPlanRejectsExternalTopLevelReplacement(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	moved := filepath.Join(root, "moved")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	release, err := roots.AcquireMutation()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	plan, err := roots.preflightRemoveAllLocked(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := roots.removeAllPreflightedLocked(plan); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("replacement removal error = %v", err)
	}
	assertManagedTestContent(t, target, "replacement")
}

func TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	mountedChild := filepath.Join(target, "mounted")
	backing := t.TempDir()
	if err := os.MkdirAll(mountedChild, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(target, "keep")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(backing, mountedChild, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested nested-removal regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(mountedChild, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount nested removal test path: %v", err)
		}
	}()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	err = roots.RemoveAll(target)
	if !errors.Is(err, ErrUnsafePath) || ManagedMutationChanged(err) {
		t.Fatalf("nested-mount removal preflight error = %v", err)
	}
	assertManagedTestContent(t, keep, "keep")
}

func TestManagedRootsChmodDirectoryDoesNotFollowSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	if err := roots.ChmodDirectory(link, 0o777); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink chmod error = %v", err)
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("outside mode changed to %o", info.Mode().Perm())
	}
	if err := roots.ChmodDirectory(root, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("managed mode = %o", info.Mode().Perm())
	}
}

func TestManagedRootsRewriteRegularIsAtomicAndPreservesMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.txt")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	newContent := strings.Repeat("new-content-", 1024)
	if err := roots.RewriteRegular(path, []byte(newContent)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != newContent {
		t.Fatal("rewritten content is incomplete")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode = %o, want %o", after.Mode().Perm(), before.Mode().Perm())
	}
	if statBefore, ok := before.Sys().(*unix.Stat_t); ok {
		statAfter := after.Sys().(*unix.Stat_t)
		if statAfter.Uid != statBefore.Uid || statAfter.Gid != statBefore.Gid {
			t.Fatalf("ownership changed from %d:%d to %d:%d", statBefore.Uid, statBefore.Gid, statAfter.Uid, statAfter.Gid)
		}
	}
}

func TestManagedRootsRewriteRegularRejectsSameInodeChangesBeforePublish(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(string) error
		wantContent string
		wantMode    fs.FileMode
	}{
		{
			name: "content",
			mutate: func(path string) error {
				return os.WriteFile(path, []byte("external"), 0o600)
			},
			wantContent: "external",
			wantMode:    0o600,
		},
		{
			name: "permissions",
			mutate: func(path string) error {
				return os.Chmod(path, 0o640)
			},
			wantContent: "old",
			wantMode:    0o640,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "file")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			roots, err := OpenManagementFileRoots([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			defer roots.Close()
			roots.rewriteBeforePublish = func() error { return test.mutate(path) }
			if err := roots.RewriteRegular(path, []byte("recasaos")); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("concurrent rewrite error = %v", err)
			}
			content, err := os.ReadFile(path)
			if err != nil || string(content) != test.wantContent {
				t.Fatalf("concurrent content = %q, %v", content, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != test.wantMode {
				t.Fatalf("concurrent mode = %v, %v", info, err)
			}
		})
	}
}

func TestManagedRootsRemoveAllDoesNotFollowSymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "managed")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "inside"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "escape")); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	if err := roots.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("managed tree remains: %v", err)
	}
	if content, err := os.ReadFile(secret); err != nil || string(content) != "secret" {
		t.Fatalf("outside secret changed: %q, %v", content, err)
	}
}

func TestManagedRootsRemoveAllDepthBudget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	current := target
	for depth := 0; depth <= maxManagedRemoveDepth+1; depth++ {
		current = filepath.Join(current, "d")
	}
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if err := roots.RemoveAll(target); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("depth budget error = %v", err)
	}
}

func TestManagedRootsTreeSizeDepthBudget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	current := target
	for depth := 0; depth <= maxManagedRemoveDepth+1; depth++ {
		current = filepath.Join(current, "d")
	}
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.TreeSize(target); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("depth budget error = %v", err)
	}
}

func TestManagedRootsTreeSizeRejectsNestedBindMount(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	source := filepath.Join(root, "source")
	nestedMount := filepath.Join(source, "mounted")
	external := t.TempDir()
	if err := os.MkdirAll(nestedMount, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(external, "data"), []byte("mounted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(external, nestedMount, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested nested-size regression cannot mount: %v", err)
	}
	defer func() {
		if err := unix.Unmount(nestedMount, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount nested test mount: %v", err)
		}
	}()

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if _, err := roots.TreeSize(source); !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "mount boundary") {
		t.Fatalf("nested mount size error = %v", err)
	}
}

func TestManagedRootsCommitNoReplace(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if err := roots.CommitNoReplace(staging, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("destination = %q, %v", content, err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging should remain for private-tree cleanup: %v", err)
	}

	second := filepath.Join(root, "second")
	if err := os.WriteFile(second, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := roots.CommitNoReplace(second, destination); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("replacement commit error = %v", err)
	}
	content, err = os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("destination changed to %q, %v", content, err)
	}
}

func TestManagedRootsCommitNoReplaceReturnsBoundIdentity(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	identity, err := roots.CommitNoReplaceWithIdentity(staging, destination)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Size != int64(len("original")) || identity.Inode == 0 {
		t.Fatalf("published identity = %+v", identity)
	}
	if err := roots.VerifyRegularIdentity(destination, identity); err != nil {
		t.Fatalf("fresh identity did not verify: %v", err)
	}
	if err := os.WriteFile(destination, []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := roots.VerifyRegularIdentity(destination, identity); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("modified target identity error = %v", err)
	}
}

func TestManagedRootsExpectedCommitRejectsAssemblyIdentityChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{
			name: "same inode content",
			mutate: func(path string) error {
				opened, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				_, writeErr := opened.WriteAt([]byte("evil"), 0)
				return errors.Join(writeErr, opened.Close())
			},
		},
		{
			name: "renamed replacement inode",
			mutate: func(path string) error {
				if err := os.Rename(path, path+".original"); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("evil"), 0o600)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			staging := filepath.Join(root, "assembly")
			destination := filepath.Join(root, "destination")
			roots, err := OpenManagementFileRoots([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			defer roots.Close()
			writer, err := roots.CreateExclusive(staging, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("safe")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			expected, err := writer.PublishedIdentity()
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(staging); err != nil {
				t.Fatal(err)
			}
			var current unix.Stat_t
			if err := unix.Stat(staging, &current); err != nil {
				t.Fatal(err)
			}
			if managedFileIdentityFromStat(&current) == expected {
				// Some filesystems coarsen write timestamps. Force a distinct
				// mtime, then assert the exact identity really changed before the
				// commit rejection is evaluated.
				if err := os.Chtimes(staging, time.Unix(1, 0), time.Unix(2, 0)); err != nil {
					t.Fatal(err)
				}
				if err := unix.Stat(staging, &current); err != nil {
					t.Fatal(err)
				}
			}
			if managedFileIdentityFromStat(&current) == expected {
				t.Fatal("test mutation did not change the managed file identity")
			}
			if _, err := roots.CommitNoReplaceWithExpectedIdentity(staging, destination, expected); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("identity change commit error = %v", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("changed assembly was published: %v", err)
			}
			assertManagedTestContent(t, staging, "evil")
		})
	}
}

func TestManagedRootsExpectedCommitRejectsDigestMismatchWithMatchingIdentity(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "assembly")
	destination := filepath.Join(root, "destination")
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	writer, err := roots.CreateExclusive(staging, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("safe")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	expectedIdentity, err := writer.PublishedIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forgedDigest := sha256.Sum256([]byte("evil"))
	if _, err := roots.CommitNoReplaceWithExpectedIdentityAndDigest(staging, destination, expectedIdentity, forgedDigest); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("matching identity with wrong digest error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("digest-mismatched assembly was published: %v", err)
	}
	assertManagedTestContent(t, staging, "safe")
}

func TestManagedRootsCommitIdentityFailureIsPublishedDurabilityUnknown(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("published"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	injected := errors.New("injected post-rename identity failure")
	roots.commitIdentity = func(int, string) (ManagedFileIdentity, error) {
		return ManagedFileIdentity{}, injected
	}
	identity, err := roots.CommitNoReplaceWithIdentity(staging, destination)
	if identity != (ManagedFileIdentity{}) || !errors.Is(err, injected) {
		t.Fatalf("identity failure result = %+v, %v", identity, err)
	}
	if !ManagedMutationChanged(err) || !ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("post-rename failure lost mutation state: %v", err)
	}
	contents, readErr := os.ReadFile(destination)
	if readErr != nil || string(contents) != "published" {
		t.Fatalf("published target = %q, %v", contents, readErr)
	}
}

func TestManagedRootsCommitNoReplaceRejectsHardlinkedStaging(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	hardlink := filepath.Join(root, "staging-link")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(staging, hardlink); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if err := roots.CommitNoReplace(staging, destination); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlinked staging error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("hardlinked staging was published: %v", err)
	}
}

func TestManagedRootsCommitNoReplaceRejectsSameSizeMutationDuringCopy(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.commitCopy = func(destination io.Writer, source io.Reader) (int64, error) {
		written, copyErr := io.Copy(destination, source)
		mutationErr := os.WriteFile(staging, []byte("evil"), 0o600)
		// Filesystems may report multiple writes inside one timestamp quantum
		// with identical mtime and ctime values. Force an observable metadata
		// transition so this test exercises the stat-bound mutation guard
		// deterministically; digest-bound callers are covered separately.
		timestampErr := os.Chtimes(staging, time.Unix(1, 0), time.Unix(2, 0))
		return written, errors.Join(copyErr, mutationErr, timestampErr)
	}
	if err := roots.CommitNoReplace(staging, destination); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("same-size mutation error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("mutated staging was published: %v", err)
	}
}

func TestManagedRootsCommitNoReplaceRejectsStagingNameReplacementDuringCopy(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	original := filepath.Join(root, "original")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(staging, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.commitCopy = func(destination io.Writer, source io.Reader) (int64, error) {
		written, copyErr := io.Copy(destination, source)
		renameErr := os.Rename(staging, original)
		createErr := os.WriteFile(staging, []byte("evil"), 0o600)
		return written, errors.Join(copyErr, renameErr, createErr)
	}
	if err := roots.CommitNoReplace(staging, destination); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("staging replacement error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("replaced staging was published: %v", err)
	}
	content, err := os.ReadFile(staging)
	if err != nil || string(content) != "evil" {
		t.Fatalf("external replacement was removed or changed: %q, %v", content, err)
	}
}

func TestManagedRootsCommitNoReplaceRejectsOversizedStaging(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	destination := filepath.Join(root, "destination")
	file, err := os.Create(staging)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxUploadTotalSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	if err := roots.CommitNoReplace(staging, destination); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized staging error = %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("destination unexpectedly created: %v", err)
	}
}

func TestManagedRootsClosedFailsClosed(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if err := roots.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.OpenDirectory(root); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("closed root error = %v", err)
	}
}
