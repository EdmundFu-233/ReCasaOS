//go:build linux

package v1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

func TestEnsureSambaMountDirectoryAcceptsOnlyExistingEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	managementRoots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer managementRoots.Close()

	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	created, err := ensureSambaMountDirectory(managementRoots, empty)
	if err != nil {
		t.Fatalf("existing empty directory rejected: %v", err)
	}
	if created {
		t.Fatal("existing empty directory reported as newly created")
	}

	testCases := []struct {
		name  string
		setup func(string) (string, error)
	}{
		{
			name: "file",
			setup: func(directory string) (string, error) {
				entry := filepath.Join(directory, "file.txt")
				return entry, os.WriteFile(entry, []byte("preserve"), 0o600)
			},
		},
		{
			name: "symlink",
			setup: func(directory string) (string, error) {
				entry := filepath.Join(directory, "link")
				return entry, os.Symlink("missing-target", entry)
			},
		},
		{
			name: "subdirectory",
			setup: func(directory string) (string, error) {
				entry := filepath.Join(directory, "child")
				return entry, os.Mkdir(entry, 0o700)
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := filepath.Join(root, testCase.name)
			if err := os.Mkdir(directory, 0o750); err != nil {
				t.Fatal(err)
			}
			entry, err := testCase.setup(directory)
			if err != nil {
				t.Fatal(err)
			}
			created, err := ensureSambaMountDirectory(managementRoots, directory)
			if err == nil {
				t.Fatal("non-empty mount directory unexpectedly accepted")
			}
			if created {
				t.Fatal("existing non-empty directory reported as newly created")
			}
			if _, err := os.Lstat(entry); err != nil {
				t.Fatalf("existing entry was removed: %v", err)
			}
		})
	}
}
