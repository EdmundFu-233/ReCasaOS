//go:build linux

package filesecurity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWalkManagedArchiveReaderIsOpaqueAndSurvivesRootsClose(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	for index, content := range []string{"alpha", "beta", "gamma"} {
		name := filepath.Join(selected, string(rune('a'+index))+".txt")
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	before := managedArchiveOpenDescriptorCount(t)
	seen := make(map[string]string)
	closedRoots := false
	err = roots.WalkManagedArchive(selected, func(relative string, depth int, info os.FileInfo, reader io.Reader) error {
		if relative == "" {
			if depth != 0 || !info.IsDir() || reader != nil {
				t.Fatalf("top entry = relative %q depth %d mode %v reader %T", relative, depth, info.Mode(), reader)
			}
			if err := roots.Close(); err != nil {
				return err
			}
			closedRoots = true
			return nil
		}
		if info.IsDir() || reader == nil {
			t.Fatalf("regular entry %q has mode %v and reader %T", relative, info.Mode(), reader)
		}
		if _, exposed := reader.(interface{ Fd() uintptr }); exposed {
			t.Fatalf("managed archive reader for %q exposes Fd", relative)
		}
		if _, exposed := reader.(io.Closer); exposed {
			t.Fatalf("managed archive reader for %q exposes Close", relative)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		seen[relative] = string(content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !closedRoots {
		t.Fatal("test did not close roots from the visitor")
	}
	if len(seen) != 3 || seen["a.txt"] != "alpha" || seen["b.txt"] != "beta" || seen["c.txt"] != "gamma" {
		t.Fatalf("walked content = %#v", seen)
	}
	if after := managedArchiveOpenDescriptorCount(t); after != before-1 {
		// roots.Close releases the one startup-pinned root descriptor.
		t.Fatalf("open descriptor count after walk = %d, want %d", after, before-1)
	}
}

func TestWalkManagedArchiveRejectsChildReplacementAfterDescriptorSnapshot(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(selected, "child.txt")
	moved := filepath.Join(selected, "child-original.txt")
	if err := os.WriteFile(child, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	before := managedArchiveOpenDescriptorCount(t)
	triggered := false
	roots.archiveAfterChildSnapshot = func(name string) error {
		if name != "child.txt" || triggered {
			return nil
		}
		triggered = true
		if err := os.Rename(child, moved); err != nil {
			return err
		}
		return os.WriteFile(child, []byte("replacement"), 0o600)
	}
	var archived []string
	err = roots.WalkManagedArchive(selected, func(relative string, _ int, _ os.FileInfo, reader io.Reader) error {
		if reader != nil {
			content, readErr := io.ReadAll(reader)
			if readErr != nil {
				return readErr
			}
			archived = append(archived, string(content))
		}
		return nil
	})
	if !triggered {
		t.Fatal("child replacement seam was not reached")
	}
	if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("replacement error = %v", err)
	}
	if len(archived) != 0 {
		t.Fatalf("replacement bytes reached visitor: %q", archived)
	}
	if after := managedArchiveOpenDescriptorCount(t); after != before {
		t.Fatalf("open descriptor count after rejected replacement = %d, want %d", after, before)
	}
}

func TestWalkManagedArchiveRejectsSymlinkSwapAfterDescriptorSnapshot(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(selected, "child.txt")
	moved := filepath.Join(selected, "child-original.txt")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(child, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	before := managedArchiveOpenDescriptorCount(t)
	triggered := false
	roots.archiveAfterChildSnapshot = func(name string) error {
		if name != "child.txt" || triggered {
			return nil
		}
		triggered = true
		if err := os.Rename(child, moved); err != nil {
			return err
		}
		return os.Symlink(outside, child)
	}
	visitedRegular := false
	err = roots.WalkManagedArchive(selected, func(_ string, _ int, _ os.FileInfo, reader io.Reader) error {
		visitedRegular = visitedRegular || reader != nil
		return nil
	})
	if !triggered {
		t.Fatal("symlink replacement seam was not reached")
	}
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink replacement error = %v", err)
	}
	if visitedRegular {
		t.Fatal("symlink replacement reached a regular-file visitor")
	}
	if after := managedArchiveOpenDescriptorCount(t); after != before {
		t.Fatalf("open descriptor count after rejected symlink swap = %d, want %d", after, before)
	}
}

func TestWalkManagedArchiveRejectsSymlinkAndSpecialChildrenWithoutDescriptorLeak(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		setup func(string) error
	}{
		{name: "symlink", setup: func(path string) error { return os.Symlink(outside, path) }},
		{name: "fifo", setup: func(path string) error { return unix.Mkfifo(path, 0o600) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected := filepath.Join(root, test.name)
			if err := os.Mkdir(selected, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := test.setup(filepath.Join(selected, "hostile")); err != nil {
				t.Fatal(err)
			}
			roots, err := OpenManagementFileRoots([]string{root})
			if err != nil {
				t.Fatal(err)
			}
			defer roots.Close()
			before := managedArchiveOpenDescriptorCount(t)
			for attempt := 0; attempt < 32; attempt++ {
				err := roots.WalkManagedArchive(selected, func(string, int, os.FileInfo, io.Reader) error { return nil })
				if !errors.Is(err, ErrUnsafePath) {
					t.Fatalf("attempt %d error = %v", attempt, err)
				}
			}
			if after := managedArchiveOpenDescriptorCount(t); after != before {
				t.Fatalf("open descriptor count after rejected %s = %d, want %d", test.name, after, before)
			}
		})
	}
}

func TestWalkManagedArchiveRejectsDepthBeyondLimit(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	current := selected
	for depth := 0; depth <= maxManagedArchiveTraversalDepth+1; depth++ {
		if err := os.Mkdir(current, 0o700); err != nil {
			t.Fatal(err)
		}
		current = filepath.Join(current, "d")
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	before := managedArchiveOpenDescriptorCount(t)
	err = roots.WalkManagedArchive(selected, func(string, int, os.FileInfo, io.Reader) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("depth error = %v", err)
	}
	if after := managedArchiveOpenDescriptorCount(t); after != before {
		t.Fatalf("open descriptor count after depth rejection = %d, want %d", after, before)
	}
}

func TestWalkManagedArchiveClosesChildDescriptorsWhenVisitorPanics(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	nested := filepath.Join(selected, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	before := managedArchiveOpenDescriptorCount(t)
	func() {
		defer func() {
			if recovered := recover(); recovered != "injected visitor panic" {
				t.Fatalf("recovered value = %v", recovered)
			}
		}()
		_ = roots.WalkManagedArchive(selected, func(relative string, _ int, _ os.FileInfo, _ io.Reader) error {
			if relative == "nested" {
				panic("injected visitor panic")
			}
			return nil
		})
	}()
	if after := managedArchiveOpenDescriptorCount(t); after != before {
		t.Fatalf("open descriptor count after visitor panic = %d, want %d", after, before)
	}
}

func TestWalkManagedArchiveMountIdentitySeamAllowsStableCrossing(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	child := filepath.Join(selected, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(child, "file")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var childStat unix.Stat_t
	if err := unix.Stat(child, &childStat); err != nil {
		t.Fatal(err)
	}
	var fileStat unix.Stat_t
	if err := unix.Stat(filePath, &fileStat); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.archiveMountIDAt = func(fd int, path string, flags int) (uint64, error) {
		var stat unix.Stat_t
		if path == "" {
			if err := unix.Fstat(fd, &stat); err != nil {
				return 0, err
			}
		} else if err := unix.Fstatat(fd, path, &stat, flags&unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, err
		}
		if (stat.Dev == childStat.Dev && stat.Ino == childStat.Ino) || (stat.Dev == fileStat.Dev && stat.Ino == fileStat.Ino) {
			return 202, nil
		}
		return 101, nil
	}
	var content string
	err = roots.WalkManagedArchive(selected, func(_ string, _ int, _ os.FileInfo, reader io.Reader) error {
		if reader == nil {
			return nil
		}
		bytes, err := io.ReadAll(reader)
		content = string(bytes)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if content != "data" {
		t.Fatalf("stable synthetic nested mount content = %q", content)
	}
}

func TestWalkManagedArchiveMountIdentitySeamRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	child := filepath.Join(selected, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	var childStat unix.Stat_t
	if err := unix.Stat(child, &childStat); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	roots.archiveMountIDAt = func(fd int, path string, flags int) (uint64, error) {
		if path == "child" {
			return 202, nil
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return 0, err
		}
		if stat.Dev == childStat.Dev && stat.Ino == childStat.Ino {
			return 203, nil
		}
		return 101, nil
	}
	err = roots.WalkManagedArchive(selected, func(string, int, os.FileInfo, io.Reader) error { return nil })
	if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "mount changed") {
		t.Fatalf("synthetic mount-replacement error = %v", err)
	}
}

func TestWalkManagedArchiveRejectsChildMountReplacement(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	child := filepath.Join(selected, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	// A self-bind keeps the inode identical while assigning a distinct mount ID,
	// so the test proves mount identity rather than relying on an inode change.
	if err := unix.Mount(child, child, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	mounted := true
	defer func() {
		if mounted {
			if err := unix.Unmount(child, unix.MNT_DETACH); err != nil {
				t.Errorf("unmount child after failed test: %v", err)
			}
		}
	}()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	unmounted := false
	roots.archiveAfterChildSnapshot = func(name string) error {
		if name != "child" || unmounted {
			return nil
		}
		if err := unix.Unmount(child, unix.MNT_DETACH); err != nil {
			return err
		}
		mounted = false
		unmounted = true
		return nil
	}
	err = roots.WalkManagedArchive(selected, func(string, int, os.FileInfo, io.Reader) error { return nil })
	if !unmounted {
		t.Fatal("mount replacement seam was not reached")
	}
	if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "mount changed") {
		t.Fatalf("mount-replacement error = %v", err)
	}
}

func TestWalkManagedArchiveAllowsStableNestedMount(t *testing.T) {
	requireIsolatedPrivilegedMountTest(t)
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	child := filepath.Join(selected, "child")
	backing := filepath.Join(root, "backing")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "underlying"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "mounted"), []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(backing, child, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(child, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount stable child: %v", err)
		}
	}()

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	seen := make(map[string]string)
	err = roots.WalkManagedArchive(selected, func(relative string, _ int, _ os.FileInfo, reader io.Reader) error {
		if reader == nil {
			return nil
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		seen[relative] = string(content)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := seen[filepath.Join("child", "mounted")]; got != "visible" {
		t.Fatalf("stable mounted content = %q, want visible; all entries %#v", got, seen)
	}
	if _, leaked := seen[filepath.Join("child", "underlying")]; leaked {
		t.Fatalf("underlying mountpoint content was traversed: %#v", seen)
	}
}

func managedArchiveOpenDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
