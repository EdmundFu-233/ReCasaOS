package v1

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestV1UploadSessionSerializesSameUploadAndCleansOnFinish(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession)}
	tempDir := filepath.Join(t.TempDir(), "upload")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := v1UploadPaths{target: filepath.Join(filepath.Dir(tempDir), "target"), tempDir: tempDir}
	first, err := registry.acquire(paths, 2)
	if err != nil {
		t.Fatal(err)
	}

	acquired := make(chan *v1UploadSession, 1)
	go func() {
		session, err := registry.acquire(paths, 2)
		if err == nil {
			acquired <- session
		}
	}()
	select {
	case <-acquired:
		t.Fatal("same upload acquired concurrently")
	case <-time.After(25 * time.Millisecond):
	}
	first.lock.Unlock()

	var second *v1UploadSession
	select {
	case second = <-acquired:
	case <-time.After(time.Second):
		t.Fatal("waiting upload did not acquire after unlock")
	}
	registry.finish(paths.tempDir, second)
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("finished upload temp directory still exists: %v", err)
	}
	if len(registry.sessions) != 0 {
		t.Fatalf("finished registry contains %d sessions", len(registry.sessions))
	}
}

func TestV1UploadSessionCapAndExpiry(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession)}
	base := t.TempDir()
	for index := 0; index < maxActiveV1UploadSessions; index++ {
		paths := v1UploadPaths{target: filepath.Join(base, fmt.Sprintf("target-%d", index)), tempDir: filepath.Join(base, fmt.Sprintf("temp-%d", index))}
		if err := os.Mkdir(paths.tempDir, 0o700); err != nil {
			t.Fatal(err)
		}
		session, err := registry.acquire(paths, 1)
		if err != nil {
			t.Fatal(err)
		}
		session.lastActivity = time.Now().Add(-v1UploadSessionTTL - time.Minute)
		session.lock.Unlock()
	}
	// cleanup happens before cap evaluation, so expired slots are reclaimed.
	paths := v1UploadPaths{target: filepath.Join(base, "replacement"), tempDir: filepath.Join(base, "replacement-temp")}
	replacement, err := registry.acquire(paths, 1)
	if err != nil {
		t.Fatalf("expired sessions were not reclaimed: %v", err)
	}
	if len(registry.sessions) != 1 {
		t.Fatalf("registry contains %d sessions after expiry cleanup, want 1", len(registry.sessions))
	}
	registry.finish(paths.tempDir, replacement)
}

func TestV1UploadSessionRejectsSeventeenthActiveUpload(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession)}
	base := t.TempDir()
	for index := 0; index < maxActiveV1UploadSessions; index++ {
		paths := v1UploadPaths{target: filepath.Join(base, fmt.Sprintf("target-%d", index)), tempDir: filepath.Join(base, fmt.Sprintf("temp-%d", index))}
		session, err := registry.acquire(paths, 1)
		if err != nil {
			t.Fatal(err)
		}
		session.lock.Unlock()
	}
	if _, err := registry.acquire(v1UploadPaths{target: filepath.Join(base, "overflow"), tempDir: filepath.Join(base, "overflow-temp")}, 1); err == nil {
		t.Fatal("seventeenth active v1 upload session was accepted")
	}
}
