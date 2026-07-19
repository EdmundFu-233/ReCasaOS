package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestV2UploadRegistryPublishesSameKeyOnce(t *testing.T) {
	service := NewFileUploadService()
	const callers = 64
	results := make(chan *FileInfo, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			candidate := &FileInfo{init: true, tempDir: filepath.Join(t.TempDir(), "candidate")}
			actual, err := service.getOrCreateUploadSession("same", candidate)
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
		if _, err := service.getOrCreateUploadSession(fmt.Sprintf("key-%d", index), candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.getOrCreateUploadSession("overflow", &FileInfo{init: true, tempDir: filepath.Join(base, "overflow")}); err == nil {
		t.Fatal("seventeenth active v2 upload session was accepted")
	}

	key := "key-0"
	session := service.uploadStatus[key]
	if err := os.Mkdir(session.tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	service.deleteUploadSession(key, session)
	if _, exists := service.uploadStatus[key]; exists {
		t.Fatal("terminal upload session was not released")
	}
	if _, err := os.Stat(session.tempDir); !os.IsNotExist(err) {
		t.Fatalf("terminal upload staging remains: %v", err)
	}
	if _, err := service.getOrCreateUploadSession("replacement", &FileInfo{init: true, tempDir: filepath.Join(base, "replacement")}); err != nil {
		t.Fatalf("released slot was not reusable: %v", err)
	}
}

func TestV2UploadCleanupSkipsLockedSessionAndOldGeneration(t *testing.T) {
	service := NewFileUploadService()
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
	service.deleteUploadSession("key", old)
	if service.uploadStatus["key"] != replacement {
		t.Fatal("old generation cleanup deleted its replacement")
	}
}
