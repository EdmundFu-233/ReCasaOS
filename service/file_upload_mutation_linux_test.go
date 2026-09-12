//go:build linux

package service

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
	"golang.org/x/sys/unix"
)

func linuxTestManagedFileIdentity(path string) (filesecurity.ManagedFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return filesecurity.ManagedFileIdentity{}, err
	}
	return filesecurity.ManagedFileIdentity{
		Device:              uint64(stat.Dev),
		Inode:               stat.Ino,
		Mode:                stat.Mode,
		Links:               uint64(stat.Nlink),
		Size:                stat.Size,
		ModifiedSeconds:     int64(stat.Mtim.Sec),
		ModifiedNanoseconds: int64(stat.Mtim.Nsec),
		ChangedSeconds:      int64(stat.Ctim.Sec),
		ChangedNanoseconds:  int64(stat.Ctim.Nsec),
	}, nil
}

type failingUploadReader struct{}

func (failingUploadReader) Read([]byte) (int, error) {
	return 0, errors.New("injected upload reader failure")
}

type uploadReadCloser struct {
	io.Reader
	closeErr error
}

type injectedServiceChunkWriter struct {
	bytes.Buffer
	closeErr error
	aborts   int
}

func (writer *injectedServiceChunkWriter) Sync() error {
	return nil
}

func (writer *injectedServiceChunkWriter) Close() error {
	return writer.closeErr
}

func (writer *injectedServiceChunkWriter) Abort() error {
	writer.aborts++
	return nil
}

func (source uploadReadCloser) Close() error {
	return source.closeErr
}

func TestWriteServiceChunkAbortsBeforePublishOnReaderAndSizeErrors(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	readerFailureTarget := filepath.Join(root, "reader-failure")
	reader := io.MultiReader(strings.NewReader("partial"), failingUploadReader{})
	if _, err := writeServiceChunkWithLimit(roots, readerFailureTarget, reader, 32); err == nil {
		t.Fatal("reader failure was accepted")
	}
	if _, err := os.Stat(readerFailureTarget); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("reader failure published target: %v", err)
	}

	oversizeTarget := filepath.Join(root, "oversize")
	if _, err := writeServiceChunkWithLimit(roots, oversizeTarget, strings.NewReader("12345"), 4); err == nil {
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

func TestWriteValidatedServiceChunkKeepsCloseAndSizeFailuresRetryable(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	tests := []struct {
		name     string
		data     string
		expected int64
		closeErr error
	}{
		{name: "source close", data: "data", expected: 4, closeErr: errors.New("injected multipart close failure")},
		{name: "declared size", data: "data", expected: 5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-"))
			source := uploadReadCloser{Reader: strings.NewReader(test.data), closeErr: test.closeErr}
			if _, err := writeValidatedServiceChunk(roots, target, source, test.expected); err == nil {
				t.Fatal("invalid chunk was accepted")
			}
			if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("invalid chunk published target: %v", err)
			}

			retry := uploadReadCloser{Reader: strings.NewReader(test.data)}
			if _, err := writeValidatedServiceChunk(roots, target, retry, int64(len(test.data))); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			contents, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != test.data {
				t.Fatalf("retry contents = %q", contents)
			}
		})
	}
}

func TestPublishedChunkSyncFailureIsRecordedAndRetryReconciles(t *testing.T) {
	injected := errors.New("injected directory sync failure")
	writer := &injectedServiceChunkWriter{closeErr: &filesecurity.ManagedMutationError{
		Operation:         "sync exclusively created file parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               injected,
	}}
	result, err := writeValidatedServiceChunkTo(
		writer,
		uploadReadCloser{Reader: strings.NewReader("data")},
		4,
		32,
	)
	if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) || !result.Published {
		t.Fatalf("published result = %+v, error = %v", result, err)
	}
	if writer.aborts != 0 {
		t.Fatalf("published chunk was aborted %d times", writer.aborts)
	}

	root := t.TempDir()
	target := filepath.Join(root, "chunk")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	fileInfo := &FileInfo{uploaded: []bool{true}, chunkDigests: [][sha256.Size]byte{result.Digest}, uploadedChunkNum: 1}
	reconciled, err := reconcileRecordedServiceChunk(fileInfo, 0, roots, target, result.Written)
	if err != nil || !reconciled {
		t.Fatalf("recorded retry reconciliation = %t, %v", reconciled, err)
	}
	if _, err := roots.CreateExclusive(target, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("test did not exercise the EEXIST retry condition: %v", err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "data" {
		t.Fatalf("reconciliation changed published chunk: %q, %v", contents, err)
	}
}

func TestAssembleServiceUploadPreservesOldAssemblyRemovalOnLaterFailure(t *testing.T) {
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
	fileInfo := &FileInfo{
		uploaded:       []bool{true},
		chunkDigests:   make([][sha256.Size]byte, 1),
		base:           root,
		targetPath:     filepath.Join(root, "target"),
		targetRelative: "target",
		tempRelative:   tempRelative,
		assemblyPath:   assembly,
		totalChunks:    1,
		roots:          roots,
	}
	_, err = assembleServiceUpload(fileInfo)
	if err == nil || !filesecurity.ManagedMutationChanged(err) || filesecurity.ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("assembly failure = %v", err)
	}
	if _, err := os.Stat(assembly); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("old assembly removal was not reflected on disk: %v", err)
	}
}

func TestAssembleServiceUploadRejectsAssemblyReplacementBeforeCommit(t *testing.T) {
	root := t.TempDir()
	tempRelative := filepath.Join(".temp", "replacement-session")
	tempDir := filepath.Join(root, tempRelative)
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	chunk := filepath.Join(tempDir, "1")
	if err := os.WriteFile(chunk, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(tempDir, ".complete")
	target := filepath.Join(root, "target")
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	fileInfo := &FileInfo{
		uploaded:       []bool{true},
		chunkDigests:   [][sha256.Size]byte{sha256.Sum256([]byte("safe"))},
		base:           root,
		targetPath:     target,
		targetRelative: "target",
		tempRelative:   tempRelative,
		assemblyPath:   assembly,
		totalChunks:    1,
		totalSize:      4,
		roots:          roots,
		assemblyBeforeCommit: func() error {
			if err := os.Rename(assembly, assembly+".original"); err != nil {
				return err
			}
			return os.WriteFile(assembly, []byte("evil"), 0o600)
		},
	}
	result, err := assembleServiceUpload(fileInfo)
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

func TestVerifyCompletedServiceUploadPinsFullPublishedIdentity(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	target := filepath.Join(root, "target")
	content := []byte("data")
	if err := os.WriteFile(staging, content, 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	identity, err := roots.CommitNoReplaceWithIdentity(staging, target)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo := &FileInfo{
		completed:          true,
		targetPath:         target,
		completionSize:     int64(len(content)),
		completionDigest:   sha256.Sum256(content),
		completionIdentity: identity,
	}
	if err := verifyCompletedServiceUpload(fileInfo, roots); err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.WriteAt([]byte("evil"), 0); err != nil {
		_ = opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	changedIdentity, err := linuxTestManagedFileIdentity(target)
	if err != nil {
		t.Fatal(err)
	}
	if changedIdentity == identity {
		if err := os.Chtimes(target, time.Unix(1, 0), time.Unix(2, 0)); err != nil {
			t.Fatal(err)
		}
		changedIdentity, err = linuxTestManagedFileIdentity(target)
		if err != nil {
			t.Fatal(err)
		}
	}
	if changedIdentity == identity {
		t.Fatal("same-inode content mutation did not change the test identity")
	}
	if err := verifyCompletedServiceUpload(fileInfo, roots); !errors.Is(err, filesecurity.ErrUnsafePath) {
		t.Fatalf("same-inode completed target mutation error = %v", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompletedServiceUpload(fileInfo, roots); !errors.Is(err, filesecurity.ErrUnsafePath) {
		t.Fatalf("replacement-inode completed target error = %v", err)
	}
}

func TestV2UploadCapacityIsReservedBeforeTargetParentMutation(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	upload := NewFileUploadService()
	upload.managementRoots = func() (*filesecurity.ManagedRoots, error) { return roots, nil }
	upload.removeTree = os.RemoveAll
	mkdirCalls := 0
	upload.mkdirAll = func(roots *filesecurity.ManagedRoots, path string, mode fs.FileMode) error {
		mkdirCalls++
		return roots.MkdirAll(path, mode)
	}
	for index := int64(0); index < maxActiveUploadSessions; index++ {
		upload.uploadStatus[fmt.Sprintf("active-%d", index)] = &FileInfo{
			init:         true,
			tempDir:      filepath.Join(root, fmt.Sprintf("active-%d", index)),
			lastActivity: time.Now(),
		}
	}
	targetParent := filepath.Join(root, "capacity-parent")
	err = upload.UploadFile(nil, root, 1, 1, 1, 1, 1, "capacity", filepath.Join("capacity-parent", "target.bin"), "target.bin", &multipart.FileHeader{Size: 1})
	if err == nil || !strings.Contains(err.Error(), "too many active") {
		t.Fatalf("capacity error = %v", err)
	}
	if mkdirCalls != 0 {
		t.Fatalf("capacity rejection attempted %d directory mutations", mkdirCalls)
	}
	if _, err := os.Stat(targetParent); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("capacity rejection created target parent: %v", err)
	}
}

func TestV2UploadParentAndStagingCreationFailuresAreTerminalAndConservative(t *testing.T) {
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()

	t.Run("partial parent creation", func(t *testing.T) {
		upload := NewFileUploadService()
		upload.managementRoots = func() (*filesecurity.ManagedRoots, error) { return roots, nil }
		upload.removeTree = os.RemoveAll
		injected := errors.New("injected parent sync failure")
		upload.mkdirAll = func(*filesecurity.ManagedRoots, string, fs.FileMode) error {
			return &filesecurity.ManagedMutationError{Operation: "sync created parent", Changed: true, DurabilityUnknown: true, Err: injected}
		}
		err := upload.UploadFile(nil, root, 1, 1, 1, 1, 1, "parent-partial", filepath.Join("partial", "target.bin"), "target.bin", &multipart.FileHeader{Size: 1})
		if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) || !filesecurity.ManagedMutationDurabilityUnknown(err) {
			t.Fatalf("partial parent error = %v", err)
		}
		if len(upload.uploadStatus) != 0 {
			t.Fatalf("failed parent session was retained: %+v", upload.uploadStatus)
		}
	})

	t.Run("parent created before staging failure", func(t *testing.T) {
		upload := NewFileUploadService()
		upload.managementRoots = func() (*filesecurity.ManagedRoots, error) { return roots, nil }
		upload.removeTree = os.RemoveAll
		injected := errors.New("injected staging mkdir failure")
		calls := 0
		upload.mkdirAll = func(managed *filesecurity.ManagedRoots, path string, mode fs.FileMode) error {
			calls++
			if calls == 2 {
				return injected
			}
			return managed.MkdirAll(path, mode)
		}
		parent := filepath.Join(root, "created")
		err := upload.UploadFile(nil, root, 1, 1, 1, 1, 1, "staging-failure", filepath.Join("created", "target.bin"), "target.bin", &multipart.FileHeader{Size: 1})
		if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) || filesecurity.ManagedMutationDurabilityUnknown(err) {
			t.Fatalf("staging failure error = %v", err)
		}
		if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
			t.Fatalf("created parent missing: %v", statErr)
		}
		if len(upload.uploadStatus) != 0 {
			t.Fatalf("failed staging session was retained: %+v", upload.uploadStatus)
		}
	})
}

func TestV2UploadSessionRejectsSameTargetThroughDifferentBaseBeforeMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer roots.Close()
	upload := NewFileUploadService()
	upload.managementRoots = func() (*filesecurity.ManagedRoots, error) { return roots, nil }
	upload.removeTree = os.RemoveAll

	firstChunk := multipartFileHeader(t, "target.bin", "a")
	err = upload.UploadFile(
		nil,
		root,
		1,
		1,
		1,
		2,
		2,
		"same-target-alias",
		filepath.Join("nested", "target.bin"),
		"target.bin",
		firstChunk,
	)
	if err != nil {
		t.Fatalf("first upload chunk failed: %v", err)
	}
	target := filepath.Join(root, "nested", "target.bin")
	key := boundUploadIdentifier("same-target-alias", target)
	session := upload.uploadStatus[key]
	if session == nil || session.uploadedChunkNum != 1 {
		t.Fatalf("first upload session = %+v", session)
	}
	originalStaging := session.tempDir
	if _, err := os.Stat(filepath.Join(originalStaging, "1")); err != nil {
		t.Fatalf("first staging chunk is missing: %v", err)
	}

	canonicalRetry := multipartFileHeader(t, "target.bin", "a")
	err = upload.UploadFile(
		nil,
		root+string(filepath.Separator),
		1,
		1,
		1,
		2,
		2,
		"same-target-alias",
		filepath.Join("nested", "target.bin"),
		"target.bin",
		canonicalRetry,
	)
	if err != nil {
		t.Fatalf("canonical retry failed: %v", err)
	}
	if upload.uploadStatus[key] != session || session.uploadedChunkNum != 1 {
		t.Fatal("canonical retry replaced or duplicated the upload generation")
	}

	aliasBase := filepath.Join(root, "nested")
	aliasStaging := filepath.Join(aliasBase, ".temp", "v2-upload-"+key)
	activityBeforeAlias := session.lastActivity
	aliasChunk := multipartFileHeader(t, "target.bin", "a")
	err = upload.UploadFile(
		nil,
		aliasBase,
		1,
		1,
		1,
		2,
		2,
		"same-target-alias",
		"target.bin",
		"target.bin",
		aliasChunk,
	)
	if err == nil || !strings.Contains(err.Error(), "different upload metadata") {
		t.Fatalf("same target through a different base was not rejected: %v", err)
	}
	if upload.uploadStatus[key] != session || session.uploadedChunkNum != 1 {
		t.Fatal("alias request changed the existing upload generation")
	}
	if !session.lastActivity.Equal(activityBeforeAlias) {
		t.Fatal("alias request refreshed the existing upload session TTL")
	}
	if _, err := os.Stat(aliasStaging); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("alias request created untracked staging: %v", err)
	}
	if _, err := os.Stat(filepath.Join(originalStaging, "1")); err != nil {
		t.Fatalf("alias rejection changed the owned staging chunk: %v", err)
	}

	query := make(url.Values)
	query.Set("path", aliasBase)
	query.Set("relativePath", "target.bin")
	request := httptest.NewRequest("GET", "/v2/file/upload?"+query.Encode(), nil)
	context := echo.New().NewContext(request, httptest.NewRecorder())
	activityBeforeProbe := session.lastActivity
	if err := upload.TestChunk(context, "same-target-alias", 1); err == nil {
		t.Fatal("same target alias reported the bound chunk as uploaded")
	}
	if !session.lastActivity.Equal(activityBeforeProbe) {
		t.Fatal("alias chunk probe refreshed the existing upload session TTL")
	}
}

func multipartFileHeader(t *testing.T, name, contents string) *multipart.FileHeader {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	form, err := multipart.NewReader(&body, writer.Boundary()).ReadForm(int64(body.Len()) + 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = form.RemoveAll() })
	files := form.File["file"]
	if len(files) != 1 {
		t.Fatalf("multipart fixture produced %d files", len(files))
	}
	return files[0]
}
