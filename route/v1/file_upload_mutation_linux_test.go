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
	first, err := buildV1UploadPaths(roots, 41, root, filepath.Join("first", "target.bin"), "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildV1UploadPaths(roots, 41, root, filepath.Join("second", "target.bin"), "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.target == second.target || first.tempDir == second.tempDir {
		t.Fatalf("different targets share namespace: first=%+v second=%+v", first, second)
	}
}

func TestBuildV1UploadPathsKeepsSamePrincipalGenerationStable(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "existing", "subdirectory")
	if err := os.MkdirAll(base, 0o750); err != nil {
		t.Fatal(err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	first, err := buildV1UploadPaths(roots, 41, base, filepath.Join("nested", "target.bin"), "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildV1UploadPaths(roots, 41, base+string(filepath.Separator), filepath.Join("nested", "target.bin"), "target.bin", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.base != filepath.Clean(base) || second.base != first.base {
		t.Fatalf("existing subdirectory base was not canonicalized compatibly: first=%q second=%q", first.base, second.base)
	}
	if first.target != second.target || first.tempDir != second.tempDir || first.tempRelative != second.tempRelative || first.assembly != second.assembly {
		t.Fatalf("same-principal chunks do not share a generation: first=%+v second=%+v", first, second)
	}
	if first.chunk == second.chunk {
		t.Fatalf("different chunk numbers share a chunk path: %q", first.chunk)
	}
}

func TestV1UploadPrincipalNamespacesPreventMixedChunkAssembly(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	relative := filepath.Join("shared", "target.bin")
	firstChunkOne, err := buildV1UploadPaths(roots, 41, root, relative, "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstChunkTwo, err := buildV1UploadPaths(roots, 41, root, relative, "target.bin", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	secondChunkOne, err := buildV1UploadPaths(roots, 42, root, relative, "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondChunkTwo, err := buildV1UploadPaths(roots, 42, root, relative, "target.bin", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if firstChunkOne.target != secondChunkOne.target {
		t.Fatalf("test principals do not address the same target: %q != %q", firstChunkOne.target, secondChunkOne.target)
	}
	if firstChunkOne.tempDir == secondChunkOne.tempDir || firstChunkOne.tempRelative == secondChunkOne.tempRelative || firstChunkOne.chunk == secondChunkOne.chunk || firstChunkOne.assembly == secondChunkOne.assembly {
		t.Fatalf("different principals share upload staging: first=%+v second=%+v", firstChunkOne, secondChunkOne)
	}
	// PostFileUpload creates the target parent before it publishes chunks. Keep
	// this direct assembly fixture faithful to that handler ordering on Linux.
	if err := roots.MkdirAll(filepath.Dir(firstChunkOne.target), 0o750); err != nil {
		t.Fatal(err)
	}

	for _, tempDir := range []string{firstChunkOne.tempDir, secondChunkOne.tempDir} {
		if err := roots.MkdirAll(tempDir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeUploadChunk(roots, firstChunkOne.chunk, strings.NewReader("A1")); err != nil {
		t.Fatal(err)
	}
	if err := writeUploadChunk(roots, secondChunkTwo.chunk, strings.NewReader("B2")); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.Stat(secondChunkOne.chunk); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second principal's chunk-one probe saw first principal's chunk: %v", err)
	}
	if _, err := roots.Stat(firstChunkTwo.chunk); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("first principal's chunk-two probe saw second principal's chunk: %v", err)
	}
	for _, paths := range []v1UploadPaths{firstChunkOne, secondChunkOne} {
		complete, err := allV1ChunksPresent(roots, paths.base, paths.tempRelative, 2)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			t.Fatalf("principal %d completed using another principal's chunk", paths.principalID)
		}
	}
	if _, err := roots.Stat(firstChunkOne.target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("mixed chunks published a target: %v", err)
	}

	if err := writeUploadChunk(roots, firstChunkTwo.chunk, strings.NewReader("A2")); err != nil {
		t.Fatal(err)
	}
	firstResult, err := assembleV1Upload(
		roots,
		firstChunkOne.base,
		firstChunkOne.targetRelative,
		firstChunkOne.tempRelative,
		firstChunkOne.assembly,
		firstChunkOne.target,
		2,
	)
	if err != nil || !firstResult.TargetPublished {
		t.Fatalf("first principal assembly = %+v, %v", firstResult, err)
	}
	contents, err := os.ReadFile(firstChunkOne.target)
	if err != nil || string(contents) != "A1A2" {
		t.Fatalf("first principal target = %q, %v", contents, err)
	}

	if err := writeUploadChunk(roots, secondChunkOne.chunk, strings.NewReader("B1")); err != nil {
		t.Fatal(err)
	}
	secondResult, err := assembleV1Upload(
		roots,
		secondChunkOne.base,
		secondChunkOne.targetRelative,
		secondChunkOne.tempRelative,
		secondChunkOne.assembly,
		secondChunkOne.target,
		2,
	)
	if err == nil || secondResult.TargetPublished {
		t.Fatalf("second principal replaced an existing target: %+v, %v", secondResult, err)
	}
	contents, readErr := os.ReadFile(firstChunkOne.target)
	if readErr != nil || string(contents) != "A1A2" {
		t.Fatalf("failed second commit changed first target = %q, %v", contents, readErr)
	}
}

func TestV1UploadDoesNotConsumeOrDeleteLegacyUnscopedStaging(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	relative := filepath.Join("legacy", "target.bin")
	paths, err := buildV1UploadPaths(roots, 41, root, relative, "target.bin", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := v1UploadNamespaceHash([]byte(filepath.Clean(relative) + "\x00" + "target.bin"))
	legacyTempRelative := filepath.Join(".temp", "upload-"+legacyHash+"-2", filepath.Dir(filepath.Clean(relative)))
	legacyTempDir := filepath.Join(root, legacyTempRelative)
	if legacyTempDir == paths.tempDir {
		t.Fatal("principal-bound staging reused the legacy unscoped namespace")
	}
	if err := os.MkdirAll(legacyTempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyChunk := filepath.Join(legacyTempDir, "1")
	if err := os.WriteFile(legacyChunk, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}

	var removed []string
	registry := v1UploadSessionRegistry{
		sessions: make(map[string]*v1UploadSession),
		removeTree: func(path string) error {
			removed = append(removed, path)
			return os.RemoveAll(path)
		},
	}
	session, err := registry.acquire(paths, 2)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := allV1ChunksPresent(roots, paths.base, paths.tempRelative, 2)
	if err != nil {
		session.lock.Unlock()
		t.Fatal(err)
	}
	if complete {
		session.lock.Unlock()
		t.Fatal("principal-bound upload completed from legacy unscoped chunks")
	}
	if _, err := roots.Stat(paths.chunk); !errors.Is(err, fs.ErrNotExist) {
		session.lock.Unlock()
		t.Fatalf("principal-bound chunk probe saw legacy unscoped chunk: %v", err)
	}
	registry.finish(paths.tempDir, session)
	for _, removedPath := range removed {
		if removedPath == legacyTempDir {
			t.Fatalf("legacy unscoped staging was recursively deleted: %q", removedPath)
		}
	}
	contents, err := os.ReadFile(legacyChunk)
	if err != nil || string(contents) != "legacy" {
		t.Fatalf("legacy staging was consumed or changed: %q, %v", contents, err)
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
