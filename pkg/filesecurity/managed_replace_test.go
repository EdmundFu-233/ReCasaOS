package filesecurity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceRegularFileWithCommitReportsPublication(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "casaos.conf")
	published, err := ReplaceRegularFileWithCommit(destination, []byte("v1"), 0o600)
	if err != nil || !published {
		t.Fatalf("first publish = (%v, %v), want published", published, err)
	}
	published, err = ReplaceRegularFileWithCommit(destination, []byte("v2-longer-content"), 0o600)
	if err != nil || !published {
		t.Fatalf("replacement publish = (%v, %v), want published", published, err)
	}
	data, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "v2-longer-content" {
		t.Fatalf("content = %q", data)
	}
	info, statErr := os.Stat(destination)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestReplaceRegularFileWithCommitReportsUnpublishedFailure(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "casaos.conf")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	published, err := ReplaceRegularFileWithCommit(destination, []byte("v1"), 0o600)
	if err == nil {
		t.Fatal("publishing over a directory must fail")
	}
	if published {
		t.Fatal("failed publish reported as committed")
	}
	info, statErr := os.Stat(destination)
	if statErr != nil {
		t.Fatalf("destination changed: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("destination mode = %v, want directory retained", info.Mode())
	}
}

func TestReplaceRegularFileWithCommitReportsRejectionsAsUnpublished(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "casaos.conf")
	for name, test := range map[string]struct {
		path       string
		data       []byte
		permission os.FileMode
	}{
		"relative":       {path: "relative.conf", data: []byte("x"), permission: 0o600},
		"empty":          {path: "", data: []byte("x"), permission: 0o600},
		"zero perm":      {path: destination, data: []byte("x"), permission: 0},
		"missing parent": {path: filepath.Join(t.TempDir(), "no-such-dir", "casaos.conf"), data: []byte("x"), permission: 0o600},
	} {
		published, err := ReplaceRegularFileWithCommit(test.path, test.data, test.permission)
		if err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
		if published {
			t.Fatalf("%s: rejected publish reported as committed", name)
		}
	}
}
