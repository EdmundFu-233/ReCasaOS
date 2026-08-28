//go:build linux

package filesecurity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedRootsMountInspectionAndEmptyDirectoryRemoval(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	mounted, err := roots.IsMountPoint(empty)
	if err != nil {
		t.Fatal(err)
	}
	if mounted {
		t.Fatal("ordinary directory reported as a mount point")
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	mounted, err = roots.IsMountPoint(regular)
	if err != nil {
		t.Fatal(err)
	}
	if mounted {
		t.Fatal("ordinary regular file reported as a mount point")
	}
	if err := roots.RemoveEmptyDirectory(empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty directory remains: %v", err)
	}
}

func TestManagedRootsAvailableBytesUsesPinnedDirectory(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	available, err := roots.AvailableBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if available == 0 {
		t.Fatal("managed filesystem reported no available bytes for a temporary directory")
	}
}

func TestManagedRootsRemoveEmptyDirectoryRefusesFilesAndNonEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := roots.RemoveEmptyDirectory(regular); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("regular-file removal error = %v", err)
	}

	nonEmpty := filepath.Join(root, "non-empty")
	if err := os.Mkdir(nonEmpty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "keep"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := roots.RemoveEmptyDirectory(nonEmpty); !errors.Is(err, unix.ENOTEMPTY) {
		t.Fatalf("non-empty directory removal error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(nonEmpty, "keep")); err != nil {
		t.Fatalf("non-empty directory content changed: %v", err)
	}
}
