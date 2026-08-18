//go:build linux

package publicfiles

import (
	"os"
	"testing"
)

// protectedTestDirectory makes security-sensitive path fixtures independent
// of the caller's umask. Ubuntu login sessions commonly use 0002, while these
// tests require the directory itself to reject group and world writes.
func protectedTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
