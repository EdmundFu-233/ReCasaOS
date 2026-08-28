//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

func TestManagedDirectoryListingToleratesConcurrentEntryMutation(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	stop := make(chan struct{})
	mutationErrors := make(chan error, 1)
	var mutator sync.WaitGroup
	mutator.Add(1)
	go func() {
		defer mutator.Done()
		mutateManagedDirectoryListingEntries(root, stop, mutationErrors)
	}()
	var stopOnce sync.Once
	stopMutator := func() {
		stopOnce.Do(func() { close(stop) })
		mutator.Wait()
	}
	defer stopMutator()

	for iteration := 0; iteration < 500; iteration++ {
		select {
		case err := <-mutationErrors:
			t.Fatalf("mutator error: %v", err)
		default:
		}

		directory, err := roots.OpenDirectory(root)
		if err != nil {
			t.Fatalf("iteration %d OpenDirectory error = %v", iteration, err)
		}
		page, total, listErr := readManagedDirectoryPage(
			context.Background(),
			directory,
			root,
			0,
			8,
			nil,
			pagedDirectoryFilterInternal,
			func(name string) (fs.FileInfo, error) { return roots.StatDirectoryEntry(directory, name) },
		)
		if listErr != nil {
			if errors.Is(listErr, fs.ErrNotExist) || errors.Is(listErr, filesecurity.ErrUnsafePath) {
				continue
			}
			t.Fatalf("iteration %d listing error = %v", iteration, listErr)
		}
		// Concurrent namespace changes may produce different valid results on
		// successive scans; this test intentionally asserts no cross-request
		// snapshot consistency.
		if total < int64(len(page)) || total > 2 || len(page) > 2 {
			t.Fatalf("iteration %d page len=%d total=%d", iteration, len(page), total)
		}
		for _, entry := range page {
			if entry.Name != "volatile" && entry.Name != "moved" {
				t.Fatalf("iteration %d unexpected entry = %+v", iteration, entry)
			}
			if entry.Path != filepath.Join(root, entry.Name) {
				t.Fatalf("iteration %d entry escaped root = %+v", iteration, entry)
			}
		}
		runtime.Gosched()
	}

	stopMutator()
	select {
	case err := <-mutationErrors:
		t.Fatalf("mutator error: %v", err)
	default:
	}
}

func mutateManagedDirectoryListingEntries(root string, stop <-chan struct{}, result chan<- error) {
	volatile := filepath.Join(root, "volatile")
	moved := filepath.Join(root, "moved")
	report := func(err error) {
		select {
		case result <- err:
		default:
		}
	}
	for iteration := 0; ; iteration++ {
		select {
		case <-stop:
			return
		default:
		}
		if err := os.RemoveAll(volatile); err != nil {
			report(fmt.Errorf("remove volatile: %w", err))
			return
		}
		if err := os.RemoveAll(moved); err != nil {
			report(fmt.Errorf("remove moved: %w", err))
			return
		}

		var createErr error
		switch iteration % 3 {
		case 0:
			createErr = os.WriteFile(volatile, []byte("data"), 0o600)
		case 1:
			createErr = os.Mkdir(volatile, 0o700)
		case 2:
			createErr = os.Symlink("missing-target", volatile)
		}
		if createErr != nil {
			report(fmt.Errorf("create iteration %d: %w", iteration, createErr))
			return
		}
		runtime.Gosched()
		if err := os.Rename(volatile, moved); err != nil {
			report(fmt.Errorf("rename iteration %d: %w", iteration, err))
			return
		}
		runtime.Gosched()
		if iteration%2 == 0 {
			if err := os.Rename(moved, volatile); err != nil {
				report(fmt.Errorf("rename back iteration %d: %w", iteration, err))
				return
			}
		} else if err := os.RemoveAll(moved); err != nil {
			report(fmt.Errorf("remove renamed iteration %d: %w", iteration, err))
			return
		}
	}
}
