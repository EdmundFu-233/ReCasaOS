//go:build linux

package v1

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

type failingV1UploadReader struct{}

func (failingV1UploadReader) Read([]byte) (int, error) {
	return 0, errors.New("injected v1 upload reader failure")
}

func TestWriteV1ChunkAbortsBeforePublishOnReaderAndSizeErrors(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	readerFailureTarget := filepath.Join(root, "reader-failure")
	reader := io.MultiReader(strings.NewReader("partial"), failingV1UploadReader{})
	if err := writeUploadChunkWithLimit(roots, readerFailureTarget, reader, 32); err == nil {
		t.Fatal("reader failure was accepted")
	}
	if _, err := os.Stat(readerFailureTarget); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reader failure published target: %v", err)
	}

	oversizeTarget := filepath.Join(root, "oversize")
	if err := writeUploadChunkWithLimit(roots, oversizeTarget, strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversize chunk was accepted")
	}
	if _, err := os.Stat(oversizeTarget); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("oversize failure published target: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed chunk writes leaked entries: %v", entries)
	}
}

func TestBuildV1UploadPathsSeparatesDifferentTargets(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	first, err := buildV1UploadPaths(roots, root, filepath.Join("first", "target.bin"), "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildV1UploadPaths(roots, root, filepath.Join("second", "target.bin"), "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.target == second.target || first.tempDir == second.tempDir {
		t.Fatalf("different targets share namespace: first=%+v second=%+v", first, second)
	}
}

func TestAssembleV1UploadPreservesOldAssemblyRemovalOnLaterFailure(t *testing.T) {
	root := t.TempDir()
	tempRelative := filepath.Join(".temp", "session")
	tempDir := filepath.Join(root, tempRelative)
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(tempDir, ".complete")
	if err := os.WriteFile(assembly, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	_, err = assembleV1Upload(roots, root, "target", tempRelative, assembly, filepath.Join(root, "target"), 1)
	if err == nil || !filesecurity.ManagedMutationChanged(err) || filesecurity.ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("assembly failure = %v", err)
	}
	if _, err := os.Stat(assembly); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("old assembly removal was not reflected on disk: %v", err)
	}
}

func TestAssembleV1UploadRejectsAssemblyReplacementBeforeCommit(t *testing.T) {
	root := t.TempDir()
	tempRelative := filepath.Join(".temp", "replacement-session")
	tempDir := filepath.Join(root, tempRelative)
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "1"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(tempDir, ".complete")
	target := filepath.Join(root, "target")
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	result, err := assembleV1Upload(roots, root, "target", tempRelative, assembly, target, 1, func() error {
		if err := os.Rename(assembly, assembly+".original"); err != nil {
			return err
		}
		return os.WriteFile(assembly, []byte("evil"), 0o600)
	})
	if result.TargetPublished || !errors.Is(err, filesecurity.ErrUnsafePath) || !filesecurity.ManagedMutationChanged(err) {
		t.Fatalf("assembly replacement result = %+v, %v", result, err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("replacement assembly reached target: %v", err)
	}
	contents, err := os.ReadFile(assembly)
	if err != nil || string(contents) != "evil" {
		t.Fatalf("external replacement changed: %q, %v", contents, err)
	}
}
