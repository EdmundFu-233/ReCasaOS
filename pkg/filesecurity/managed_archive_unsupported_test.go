//go:build !linux

package filesecurity

import (
	"errors"
	"io"
	"os"
	"testing"
)

func TestWalkManagedArchiveFailsClosedOutsideLinux(t *testing.T) {
	called := false
	err := (&ManagedRoots{}).WalkManagedArchive("/managed/path", func(string, int, os.FileInfo, io.Reader) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrManagedRootsUnsupported) {
		t.Fatalf("WalkManagedArchive error = %v", err)
	}
	if called {
		t.Fatal("unsupported managed archive visitor was invoked")
	}
}
