//go:build linux

package filesecurity

import (
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
