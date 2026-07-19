package filesecurity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestJoinWithinBaseRejectsTraversalAndAbsolutePaths(t *testing.T) {
	base := t.TempDir()
	cases := []string{
		"",
		"..",
		"../escape",
		"nested/../../escape",
		filepath.Join(string(filepath.Separator), "absolute"),
	}

	for _, relative := range cases {
		t.Run(relative, func(t *testing.T) {
			_, err := JoinWithinBase(base, relative)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("JoinWithinBase(%q) error = %v, want ErrUnsafePath", relative, err)
			}
		})
	}
}

func TestJoinWithinBaseAvoidsPrefixConfusion(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "data")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := JoinWithinBase(base, filepath.Join("..", "data-backup", "file"))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error = %v, want ErrUnsafePath", err)
	}
}

func TestJoinWithinBaseRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := JoinWithinBase(base, filepath.Join("outside-link", "payload"))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error = %v, want ErrUnsafePath", err)
	}
}

func TestJoinWithinBaseAllowsContainedNonexistentTarget(t *testing.T) {
	base := t.TempDir()
	target, err := JoinWithinBase(base, filepath.Join("nested", "payload"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "nested", "payload")
	if target != want {
		t.Fatalf("target = %q, want %q", target, want)
	}
}

func TestValidateChunkBounds(t *testing.T) {
	tests := []struct {
		name        string
		totalChunks int64
		chunkNumber int64
		wantError   bool
	}{
		{name: "first", totalChunks: 1, chunkNumber: 1},
		{name: "zero chunk", totalChunks: 1, chunkNumber: 0, wantError: true},
		{name: "past end", totalChunks: 2, chunkNumber: 3, wantError: true},
		{name: "zero total", totalChunks: 0, chunkNumber: 1, wantError: true},
		{name: "too many chunks", totalChunks: MaxUploadChunks + 1, chunkNumber: 1, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateChunk(test.totalChunks, test.chunkNumber)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateChunk(%d, %d) error = %v, wantError %v", test.totalChunks, test.chunkNumber, err, test.wantError)
			}
		})
	}
}

func TestValidateUploadSizesBounds(t *testing.T) {
	tests := []struct {
		name             string
		chunkSize        int64
		currentChunkSize int64
		totalSize        int64
		totalChunks      int64
		wantError        bool
	}{
		{name: "valid", chunkSize: 1024, currentChunkSize: 512, totalSize: 1536, totalChunks: 2},
		{name: "empty", chunkSize: 1024, currentChunkSize: 0, totalSize: 0, totalChunks: 1},
		{name: "oversized request", chunkSize: MaxUploadChunkSize + 1, currentChunkSize: 1, totalSize: 1, totalChunks: 1, wantError: true},
		{name: "oversized total", chunkSize: MaxUploadChunkSize, currentChunkSize: 1, totalSize: MaxUploadTotalSize + 1, totalChunks: MaxUploadChunks, wantError: true},
		{name: "negative total", chunkSize: 1024, currentChunkSize: 1, totalSize: -1, totalChunks: 1, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUploadSizes(test.chunkSize, test.currentChunkSize, test.totalSize, test.totalChunks)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateUploadSizes() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestCommitNoReplace(t *testing.T) {
	directory := t.TempDir()
	staging := filepath.Join(directory, "staging")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(staging, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitNoReplace(staging, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging still exists: %v", err)
	}

	secondStaging := filepath.Join(directory, "second-staging")
	if err := os.WriteFile(secondStaging, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitNoReplace(secondStaging, destination); err == nil {
		t.Fatal("existing destination was replaced")
	}
	content, err = os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("destination changed to %q, error = %v", content, err)
	}
}
