//go:build linux

package file

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

type descriptorArchiveRecorder struct {
	hook    func(ArchiveEntry) error
	content map[string]string
}

func (recorder *descriptorArchiveRecorder) Create(io.Writer) error { return nil }

func (recorder *descriptorArchiveRecorder) Write(entry ArchiveEntry) error {
	if recorder.hook != nil {
		if err := recorder.hook(entry); err != nil {
			return err
		}
	}
	if recorder.content == nil {
		recorder.content = make(map[string]string)
	}
	if entry.Reader == nil {
		return nil
	}
	content, err := io.ReadAll(entry.Reader)
	if err != nil {
		return err
	}
	recorder.content[entry.Name] = string(content)
	return nil
}

func (recorder *descriptorArchiveRecorder) Close() error { return nil }

func TestAddManagedFileFollowsPinnedDirectoryAfterPathReplacement(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	moved := filepath.Join(root, "selected-original")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selected, "child.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	replaced := false
	recorder := &descriptorArchiveRecorder{
		content: make(map[string]string),
		hook: func(entry ArchiveEntry) error {
			if replaced || entry.Name != "selected" || !entry.Info.IsDir() {
				return nil
			}
			replaced = true
			if err := os.Rename(selected, moved); err != nil {
				return err
			}
			if err := os.Mkdir(selected, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(selected, "child.txt"), []byte("replacement"), 0o600)
		},
	}
	if err := AddManagedFile(recorder, roots, selected, root); err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("selected directory pathname was not replaced")
	}
	if got := recorder.content["selected/child.txt"]; got != "original" {
		t.Fatalf("archived child content = %q, want pinned original", got)
	}
	if len(recorder.content) != 1 {
		t.Fatalf("unexpected replacement pathname content was archived: %#v", recorder.content)
	}
}

func TestAddManagedFilePreservesWriterSizeLimit(t *testing.T) {
	root := t.TempDir()
	large := filepath.Join(root, "large.bin")
	if err := os.WriteFile(large, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(large, maxArchiveInputSize+1); err != nil {
		t.Skipf("sparse files are unavailable: %v", err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	_, writer, err := GetCompressionAlgorithm("zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Create(io.Discard); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	err = AddManagedFile(writer, roots, large, large)
	if err == nil || err.Error() != "archive input exceeds entry or byte budget" {
		t.Fatalf("oversized managed archive error = %v", err)
	}
}
