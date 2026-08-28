package v1

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

type recordingV1CompletedIdentityVerifier struct {
	path     string
	identity filesecurity.ManagedFileIdentity
	calls    int
	err      error
}

func (verifier *recordingV1CompletedIdentityVerifier) VerifyRegularIdentity(path string, identity filesecurity.ManagedFileIdentity) error {
	verifier.calls++
	verifier.path = path
	verifier.identity = identity
	return verifier.err
}

func TestV1UploadSessionSerializesSameUploadAndCleansOnFinish(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
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

func TestV1UploadNamespaceHashSeparatesKnownMD5Collision(t *testing.T) {
	decode := func(value string) []byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	first := decode("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
	second := decode("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")
	if md5.Sum(first) != md5.Sum(second) {
		t.Fatal("test vectors are not the expected MD5 collision")
	}
	if v1UploadNamespaceHash(first) == v1UploadNamespaceHash(second) {
		t.Fatal("SHA-256 upload namespace key collided for known MD5 collision vectors")
	}
}

func TestV1UploadSessionCapAndExpiry(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
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
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
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

func TestV1UploadRegistryCountsLockedSessionAsActiveWithoutBlocking(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
	base := t.TempDir()
	var locked *v1UploadSession
	for index := 0; index < maxActiveV1UploadSessions; index++ {
		session := &v1UploadSession{
			target:       filepath.Join(base, fmt.Sprintf("target-%d", index)),
			tempDir:      filepath.Join(base, fmt.Sprintf("temp-%d", index)),
			lastActivity: time.Now(),
		}
		registry.sessions[session.tempDir] = session
		if index == 0 {
			locked = session
		}
	}
	locked.lock.Lock()
	_, err := registry.acquire(v1UploadPaths{target: filepath.Join(base, "overflow"), tempDir: filepath.Join(base, "overflow-temp")}, 1)
	locked.lock.Unlock()
	if err == nil || !strings.Contains(err.Error(), "too many active") {
		t.Fatalf("locked active session was undercounted: %v", err)
	}
}

func TestV1UploadLaterDirectoryFailureIsConservativelyChanged(t *testing.T) {
	injected := errors.New("injected staging directory failure")
	err := changedV1UploadErrorIf(true, "target parent created", injected)
	if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) || filesecurity.ManagedMutationDurabilityUnknown(err) {
		t.Fatalf("conservative directory error = %v", err)
	}
}

func TestVerifyCompletedV1UploadUsesOnlyConstantTimeIdentityCheck(t *testing.T) {
	identity := filesecurity.ManagedFileIdentity{Device: 1, Inode: 2, Mode: 0o100600, Links: 1, Size: filesecurity.MaxUploadTotalSize}
	session := &v1UploadSession{
		completed:          true,
		target:             "/managed/large-target",
		completionSize:     filesecurity.MaxUploadTotalSize,
		completionIdentity: identity,
	}
	verifier := &recordingV1CompletedIdentityVerifier{}
	if err := verifyCompletedV1Upload(session, verifier); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 || verifier.path != session.target || verifier.identity != identity {
		t.Fatalf("identity verification = %+v", verifier)
	}
}

func TestV1CompletedUploadCleanupFailureRetainsIdempotencyTombstone(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession)}
	tempDir := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected cleanup failure")
	calls := 0
	registry.removeTree = func(path string) error {
		calls++
		if calls == 1 {
			return injected
		}
		return os.RemoveAll(path)
	}
	session := &v1UploadSession{
		target:         filepath.Join(filepath.Dir(tempDir), "target"),
		tempDir:        tempDir,
		totalChunks:    1,
		completed:      true,
		completedAt:    time.Now(),
		completionSize: 4,
	}
	registry.sessions[tempDir] = session
	session.lock.Lock()
	err := registry.finishSession(tempDir, session, true)
	if !errors.Is(err, injected) || !filesecurity.ManagedMutationChanged(err) {
		t.Fatalf("cleanup failure = %v", err)
	}
	if registry.sessions[tempDir] != session || !session.closed || session.cleanupErr == nil {
		t.Fatalf("completion tombstone = %+v", session)
	}
	registry.cleanup(time.Now())
	if registry.sessions[tempDir] != session || !session.stagingClean || session.cleanupErr != nil {
		t.Fatalf("cleanup retry released completion tombstone: %+v", session)
	}
	paths := v1UploadPaths{target: session.target, tempDir: tempDir}
	acquired, err := registry.acquire(paths, 1)
	if err != nil || acquired != session || !acquired.completed {
		t.Fatalf("completion retry = %p, %v", acquired, err)
	}
	acquired.lock.Unlock()
	session.lock.Lock()
	session.completedAt = time.Now().Add(-v1UploadCompletionTTL - time.Minute)
	session.lock.Unlock()
	registry.cleanup(time.Now())
	if registry.sessions[tempDir] != nil {
		t.Fatal("expired completion tombstone was not released")
	}
}

func TestV1CompletedUploadTombstonesAreBoundedWithoutEvictingActive(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
	active := &v1UploadSession{target: "/managed/active", tempDir: "/managed/temp-active", lastActivity: time.Now()}
	registry.sessions["active"] = active
	for index := 0; index < maxCompletedV1UploadTombstones+32; index++ {
		registry.sessions[fmt.Sprintf("completed-%03d", index)] = &v1UploadSession{
			closed:       true,
			completed:    true,
			completedAt:  time.Now().Add(time.Duration(index) * time.Millisecond),
			stagingClean: true,
		}
	}
	registry.mu.Lock()
	registry.pruneCompletedLocked(time.Now())
	registry.mu.Unlock()
	if registry.sessions["active"] != active {
		t.Fatal("completed tombstone pruning evicted active upload")
	}
	completed := 0
	for _, session := range registry.sessions {
		if session != nil && session.completed {
			completed++
		}
	}
	if completed != maxCompletedV1UploadTombstones || len(registry.sessions) != maxCompletedV1UploadTombstones+1 {
		t.Fatalf("registry size = %d, completed = %d", len(registry.sessions), completed)
	}
	if registry.sessions["completed-000"] != nil {
		t.Fatal("oldest clean completion tombstone was not evicted")
	}
}

func TestV1UploadSpaceFailureUsesStorageStatus(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/file/upload", nil)
	response := httptest.NewRecorder()
	context := echo.New().NewContext(request, response)

	if err := respondV1UploadFailure(context, filesecurity.ErrUploadSpaceInsufficient); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInsufficientStorage, response.Body.String())
	}
}
