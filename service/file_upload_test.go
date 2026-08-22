package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

type partialPublishChunkWriter struct {
	bytes.Buffer
	closeErr error
	aborts   int
}

type recordingCompletedIdentityVerifier struct {
	path     string
	identity filesecurity.ManagedFileIdentity
	calls    int
	err      error
}

func (verifier *recordingCompletedIdentityVerifier) VerifyRegularIdentity(path string, identity filesecurity.ManagedFileIdentity) error {
	verifier.calls++
	verifier.path = path
	verifier.identity = identity
	return verifier.err
}

func (writer *partialPublishChunkWriter) Sync() error  { return nil }
func (writer *partialPublishChunkWriter) Close() error { return writer.closeErr }
func (writer *partialPublishChunkWriter) Abort() error {
	writer.aborts++
	return nil
}

func TestWriteValidatedServiceChunkToReportsPublishedCloseFailure(t *testing.T) {
	injected := errors.New("injected directory sync failure")
	writer := &partialPublishChunkWriter{closeErr: &filesecurity.ManagedMutationError{
		Operation:         "sync exclusively created file parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               injected,
	}}
	result, err := writeValidatedServiceChunkTo(writer, io.NopCloser(strings.NewReader("data")), 4, 32)
	if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) || !filesecurity.ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("close error = %v", err)
	}
	if !result.Published || result.Written != 4 {
		t.Fatalf("write result = %+v", result)
	}
	if writer.aborts != 0 {
		t.Fatalf("published chunk was aborted %d times", writer.aborts)
	}
}

func TestVerifyCompletedServiceUploadUsesOnlyConstantTimeIdentityCheck(t *testing.T) {
	identity := filesecurity.ManagedFileIdentity{Device: 1, Inode: 2, Mode: 0o100600, Links: 1, Size: filesecurity.MaxUploadTotalSize}
	fileInfo := &FileInfo{
		completed:          true,
		targetPath:         "/managed/large-target",
		completionSize:     filesecurity.MaxUploadTotalSize,
		completionIdentity: identity,
		// Deliberately leave all per-chunk state and content readers absent.
		// The verifier contract exposes only a stat-identity operation.
	}
	verifier := &recordingCompletedIdentityVerifier{}
	if err := verifyCompletedServiceUpload(fileInfo, verifier); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.path != fileInfo.targetPath || verifier.identity != identity {
		t.Fatalf("identity verification = %+v", verifier)
	}
}

func TestV2UploadRegistryPublishesSameKeyOnce(t *testing.T) {
	service := NewFileUploadService()
	service.removeTree = os.RemoveAll
	const callers = 64
	results := make(chan *FileInfo, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			candidate := &FileInfo{init: true, tempDir: filepath.Join(t.TempDir(), "candidate")}
			actual, _, err := service.getOrCreateUploadSession("same", candidate)
			if err != nil {
				t.Errorf("getOrCreateUploadSession: %v", err)
				return
			}
			results <- actual
		}()
	}
	wait.Wait()
	close(results)
	var first *FileInfo
	for result := range results {
		if first == nil {
			first = result
		}
		if result != first {
			t.Fatal("same upload key published multiple session objects")
		}
	}
	if len(service.uploadStatus) != 1 {
		t.Fatalf("registry contains %d sessions, want 1", len(service.uploadStatus))
	}
}

func TestV2UploadRegistryCapAndTerminalCleanup(t *testing.T) {
	service := NewFileUploadService()
	service.removeTree = os.RemoveAll
	base := t.TempDir()
	for index := int64(0); index < maxActiveUploadSessions; index++ {
		candidate := &FileInfo{init: true, tempDir: filepath.Join(base, fmt.Sprintf("temp-%d", index))}
		if _, _, err := service.getOrCreateUploadSession(fmt.Sprintf("key-%d", index), candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := service.getOrCreateUploadSession("overflow", &FileInfo{init: true, tempDir: filepath.Join(base, "overflow")}); err == nil {
		t.Fatal("seventeenth active v2 upload session was accepted")
	}

	key := "key-0"
	session := service.uploadStatus[key]
	if err := os.Mkdir(session.tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := service.deleteUploadSession(key, session, false); err != nil {
		t.Fatal(err)
	}
	if _, exists := service.uploadStatus[key]; exists {
		t.Fatal("terminal upload session was not released")
	}
	if _, err := os.Stat(session.tempDir); !os.IsNotExist(err) {
		t.Fatalf("terminal upload staging remains: %v", err)
	}
	if _, _, err := service.getOrCreateUploadSession("replacement", &FileInfo{init: true, tempDir: filepath.Join(base, "replacement")}); err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
}

func TestV2UploadRegistryCountsLockedSessionAsActiveWithoutBlocking(t *testing.T) {
	service := NewFileUploadService()
	service.removeTree = os.RemoveAll
	base := t.TempDir()
	var locked *FileInfo
	for index := int64(0); index < maxActiveUploadSessions; index++ {
		session := &FileInfo{init: true, tempDir: filepath.Join(base, fmt.Sprintf("active-%d", index)), lastActivity: time.Now()}
		service.uploadStatus[fmt.Sprintf("active-%d", index)] = session
		if index == 0 {
			locked = session
		}
	}
	locked.lock.Lock()
	_, _, err := service.getOrCreateUploadSession("overflow", &FileInfo{init: true, tempDir: filepath.Join(base, "overflow")})
	locked.lock.Unlock()
	if err == nil || !strings.Contains(err.Error(), "too many active") {
		t.Fatalf("locked active session was undercounted: %v", err)
	}
}

func TestV2UploadCleanupSkipsLockedSessionAndOldGeneration(t *testing.T) {
	service := NewFileUploadService()
	service.removeTree = os.RemoveAll
	base := t.TempDir()
	old := &FileInfo{init: true, tempDir: filepath.Join(base, "old"), lastActivity: time.Now().Add(-uploadSessionTTL - time.Minute)}
	service.uploadStatus["key"] = old
	old.lock.Lock()
	service.cleanupExpiredUploads(time.Now())
	if service.uploadStatus["key"] != old {
		t.Fatal("cleanup deleted an upload currently holding its session lock")
	}
	old.lock.Unlock()

	replacement := &FileInfo{init: true, tempDir: filepath.Join(base, "replacement"), lastActivity: time.Now()}
	service.uploadStatus["key"] = replacement
	if err := service.deleteUploadSession("key", old, false); err != nil {
		t.Fatal(err)
	}
	if service.uploadStatus["key"] != replacement {
		t.Fatal("old generation cleanup deleted its replacement")
	}
}

func TestV2UploadCleanupFailureKeepsRetryableTombstone(t *testing.T) {
	service := NewFileUploadService()
	tempDir := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected staging cleanup failure")
	calls := 0
	service.removeTree = func(path string) error {
		calls++
		if calls == 1 {
			return injected
		}
		return os.RemoveAll(path)
	}
	session := &FileInfo{init: true, tempDir: tempDir, uploadedChunkNum: 1}
	service.uploadStatus["key"] = session
	err := service.deleteUploadSession("key", session, true)
	if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) {
		t.Fatalf("cleanup failure = %v", err)
	}
	if service.uploadStatus["key"] != session || session.init || session.cleanupErr == nil {
		t.Fatalf("cleanup tombstone was not retained: %+v", session)
	}

	service.cleanupExpiredUploads(time.Now())
	if _, exists := service.uploadStatus["key"]; exists {
		t.Fatal("successful cleanup retry did not release tombstone")
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("staging remains after cleanup retry: %v", err)
	}
	if _, _, err := service.getOrCreateUploadSession("key", &FileInfo{init: true, tempDir: filepath.Join(t.TempDir(), "replacement")}); err != nil {
		t.Fatalf("same upload key was not reusable after cleanup: %v", err)
	}
}

func TestV2UploadCapacityRejectsBeforeCleanupAndRetryTracksFailure(t *testing.T) {
	service := NewFileUploadService()
	base := t.TempDir()
	orphan := filepath.Join(base, "orphan")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected orphan cleanup failure")
	failOrphanCleanup := true
	service.removeTree = func(path string) error {
		if path == orphan && failOrphanCleanup {
			failOrphanCleanup = false
			return injected
		}
		return os.RemoveAll(path)
	}
	for index := int64(0); index < maxActiveUploadSessions; index++ {
		candidate := &FileInfo{init: true, tempDir: filepath.Join(base, fmt.Sprintf("active-%d", index))}
		if _, _, err := service.getOrCreateUploadSession(fmt.Sprintf("active-%d", index), candidate); err != nil {
			t.Fatal(err)
		}
	}
	overflow := &FileInfo{init: true, tempDir: orphan}
	if _, _, err := service.getOrCreateUploadSession("overflow", overflow); err == nil {
		t.Fatal("capacity overflow was accepted")
	}
	if service.uploadStatus["overflow"] != nil {
		t.Fatal("capacity rejection published an unowned candidate")
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("capacity rejection mutated pre-existing staging: %v", err)
	}

	first := service.uploadStatus["active-0"]
	if err := service.deleteUploadSession("active-0", first, false); err != nil {
		t.Fatal(err)
	}
	actual, created, err := service.getOrCreateUploadSession("overflow", overflow)
	if !errors.Is(err, injected) || !created || actual != overflow {
		t.Fatalf("reserved cleanup failure = %v, created=%t, session=%p", err, created, actual)
	}
	if service.uploadStatus["overflow"] != overflow || overflow.init || overflow.cleanupErr == nil {
		t.Fatal("cleanup failure was not retained as an owned tombstone")
	}
	service.cleanupExpiredUploads(time.Now())
	if _, exists := service.uploadStatus["overflow"]; exists {
		t.Fatal("cleanup retry did not release reserved tombstone")
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan remains after cleanup retry: %v", err)
	}
}

func TestV2CompletedUploadRetainsIdempotencyTombstoneAcrossCleanupRetry(t *testing.T) {
	service := NewFileUploadService()
	tempDir := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected completed cleanup failure")
	calls := 0
	service.removeTree = func(path string) error {
		calls++
		if calls == 1 {
			return injected
		}
		return os.RemoveAll(path)
	}
	completed := &FileInfo{
		init:           false,
		completed:      true,
		completedAt:    time.Now(),
		tempDir:        tempDir,
		targetPath:     "/completed-target",
		completionSize: 4,
	}
	service.uploadStatus["key"] = completed
	if err := service.deleteUploadSession("key", completed, true); !errors.Is(err, injected) {
		t.Fatalf("completed cleanup failure = %v", err)
	}
	service.cleanupExpiredUploads(time.Now())
	if service.uploadStatus["key"] != completed || !completed.stagingClean || completed.cleanupErr != nil {
		t.Fatalf("completed tombstone was released after cleanup: %+v", completed)
	}
	actual, created, err := service.getOrCreateUploadSession("key", &FileInfo{init: true})
	if err != nil || created || actual != completed {
		t.Fatalf("matching key did not resolve to completion tombstone: %v, created=%t", err, created)
	}
	completed.completedAt = time.Now().Add(-uploadCompletionTTL - time.Minute)
	service.cleanupExpiredUploads(time.Now())
	if _, exists := service.uploadStatus["key"]; exists {
		t.Fatal("expired completion tombstone was not released")
	}
}

func TestV2CompletedUploadTombstonesAreBoundedWithoutEvictingActive(t *testing.T) {
	service := NewFileUploadService()
	service.removeTree = os.RemoveAll
	base := t.TempDir()
	active := &FileInfo{init: true, tempDir: filepath.Join(base, "active"), lastActivity: time.Now()}
	service.uploadStatus["active"] = active
	for index := 0; index < maxCompletedUploadTombstones+32; index++ {
		service.uploadStatus[fmt.Sprintf("completed-%03d", index)] = &FileInfo{
			completed:    true,
			completedAt:  time.Now().Add(time.Duration(index) * time.Millisecond),
			stagingClean: true,
		}
	}
	service.sessionsMu.Lock()
	service.pruneCompletedUploadTombstonesLocked(time.Now())
	service.sessionsMu.Unlock()
	if service.uploadStatus["active"] != active {
		t.Fatal("completed tombstone pruning evicted an active upload")
	}
	completed := 0
	for _, session := range service.uploadStatus {
		if session != nil && session.completed {
			completed++
		}
	}
	if completed != maxCompletedUploadTombstones || len(service.uploadStatus) != maxCompletedUploadTombstones+1 {
		t.Fatalf("registry size = %d, completed = %d", len(service.uploadStatus), completed)
	}
	if service.uploadStatus["completed-000"] != nil {
		t.Fatal("oldest clean completion tombstone was not evicted")
	}
}

func TestV2UploadMetadataBindsEveryStagingIdentityField(t *testing.T) {
	roots := &filesecurity.ManagedRoots{}
	candidate := &FileInfo{
		base:           "/managed/base",
		targetPath:     "/managed/base/target.bin",
		targetRelative: "target.bin",
		tempRelative:   ".temp/v2-upload-key",
		tempDir:        "/managed/base/.temp/v2-upload-key",
		assemblyPath:   "/managed/base/.temp/v2-upload-key/.complete",
		totalChunks:    2,
		totalSize:      8,
		chunkSize:      4,
		roots:          roots,
	}
	if !sameServiceUploadMetadata(candidate, candidate) {
		t.Fatal("identical upload metadata did not match")
	}
	cloneMetadata := func(value *FileInfo) *FileInfo {
		return &FileInfo{
			base:           value.base,
			targetPath:     value.targetPath,
			targetRelative: value.targetRelative,
			tempRelative:   value.tempRelative,
			tempDir:        value.tempDir,
			assemblyPath:   value.assemblyPath,
			totalChunks:    value.totalChunks,
			totalSize:      value.totalSize,
			chunkSize:      value.chunkSize,
			roots:          value.roots,
		}
	}

	tests := map[string]func(*FileInfo){
		"roots":          func(value *FileInfo) { value.roots = nil },
		"base":           func(value *FileInfo) { value.base += "-alias" },
		"targetPath":     func(value *FileInfo) { value.targetPath += "-alias" },
		"targetRelative": func(value *FileInfo) { value.targetRelative += "-alias" },
		"tempRelative":   func(value *FileInfo) { value.tempRelative += "-alias" },
		"tempDir":        func(value *FileInfo) { value.tempDir += "-alias" },
		"assemblyPath":   func(value *FileInfo) { value.assemblyPath += "-alias" },
		"totalChunks":    func(value *FileInfo) { value.totalChunks++ },
		"totalSize":      func(value *FileInfo) { value.totalSize++ },
		"chunkSize":      func(value *FileInfo) { value.chunkSize++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := cloneMetadata(candidate)
			mutate(changed)
			if sameServiceUploadMetadata(candidate, changed) {
				t.Fatal("changed upload metadata matched the existing session")
			}
		})
	}
}
