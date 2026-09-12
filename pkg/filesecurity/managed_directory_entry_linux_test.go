//go:build linux

package filesecurity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedDirectoryEntryMetadataIsDescriptorRelativeAndOpaque(t *testing.T) {
	root := t.TempDir()
	directoryPath := filepath.Join(root, "private-directory-marker")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directoryPath, "regular-private-marker"), []byte("regular"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directoryPath, "directory-private-marker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular-private-marker", filepath.Join(directoryPath, "symlink-private-marker")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(directoryPath, "fifo-private-marker"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	directory, err := roots.OpenDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	tests := []struct {
		name string
		mode fs.FileMode
	}{
		{name: "regular-private-marker", mode: 0},
		{name: "directory-private-marker", mode: fs.ModeDir},
		{name: "symlink-private-marker", mode: fs.ModeSymlink},
		{name: "fifo-private-marker", mode: fs.ModeNamedPipe},
	}
	for _, testCase := range tests {
		info, err := roots.StatDirectoryEntry(directory, testCase.name)
		if err != nil {
			t.Fatalf("StatDirectoryEntry(%q) error = %v", testCase.name, err)
		}
		if info.Mode().Type() != testCase.mode {
			t.Fatalf("StatDirectoryEntry(%q) mode = %v, want %v", testCase.name, info.Mode().Type(), testCase.mode)
		}
		if got := info.Name(); got != managedDirectoryEntryDescriptorName || strings.Contains(got, "private-marker") {
			t.Fatalf("StatDirectoryEntry(%q) name = %q", testCase.name, got)
		}
	}
	for _, invalid := range []string{"", ".", "..", "child/name"} {
		if _, err := roots.StatDirectoryEntry(directory, invalid); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("StatDirectoryEntry(%q) error = %v, want ErrUnsafePath", invalid, err)
		}
	}
}

func TestManagedDirectoryEntryDescriptorDoesNotFollowPathReplacement(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	original := []byte("original-long")
	replacement := []byte("new")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	directory, err := roots.OpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	opened, err := openManagedDirectoryEntryAt(int(directory.Fd()), "target")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if got := opened.Name(); got != managedDirectoryEntryDescriptorName {
		t.Fatalf("descriptor name = %q", got)
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(target, filepath.Join(root, "moved-original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := opened.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(opened.Fd()), &after); err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len(original)) || before.Dev != after.Dev || before.Ino != after.Ino {
		t.Fatalf("descriptor followed replacement: size=%d before=%d:%d after=%d:%d", info.Size(), before.Dev, before.Ino, after.Dev, after.Ino)
	}
}

func TestManagedDirectoryEntryMetadataDoesNotLeakDescriptors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular", filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	directory, err := roots.OpenDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	before := managedDirectoryEntryOpenFDCount(t)
	for iteration := 0; iteration < 256; iteration++ {
		for _, name := range []string{"regular", "symlink", "fifo"} {
			if _, err := roots.StatDirectoryEntry(directory, name); err != nil {
				t.Fatalf("iteration %d StatDirectoryEntry(%q) error = %v", iteration, name, err)
			}
		}
		if _, err := roots.StatDirectoryEntry(directory, "missing"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("iteration %d missing error = %v", iteration, err)
		}
	}
	after := managedDirectoryEntryOpenFDCount(t)
	if after != before {
		t.Fatalf("open descriptor count changed from %d to %d", before, after)
	}
}

func managedDirectoryEntryOpenFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
