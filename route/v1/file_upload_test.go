package v1

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

type trackingV1UploadBody struct {
	read bool
}

func (body *trackingV1UploadBody) Read([]byte) (int, error) {
	body.read = true
	return 0, io.EOF
}

func TestAuthenticatedV1UploadPrincipalRequiresPositiveTypedClaims(t *testing.T) {
	var nilClaims *commonjwt.Claims
	tests := []struct {
		name    string
		value   interface{}
		setUser bool
		wantID  int
	}{
		{name: "missing"},
		{name: "wrong type", value: "1", setUser: true},
		{name: "typed nil", value: nilClaims, setUser: true},
		{name: "zero id", value: &commonjwt.Claims{ID: 0, Username: "admin"}, setUser: true},
		{name: "negative id", value: &commonjwt.Claims{ID: -1, Username: "admin"}, setUser: true},
		{name: "verified id", value: &commonjwt.Claims{ID: 42, Username: "admin"}, setUser: true, wantID: 42},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/file/upload", nil)
			request.Header.Set("user_id", "999")
			ctx := echo.New().NewContext(request, httptest.NewRecorder())
			if test.setUser {
				ctx.Set("user", test.value)
			}
			actual, err := authenticatedV1UploadPrincipalID(ctx)
			if test.wantID == 0 {
				if err != echo.ErrUnauthorized || actual != 0 {
					t.Fatalf("principal = %d, %v; want unauthorized", actual, err)
				}
				return
			}
			if err != nil || actual != test.wantID {
				t.Fatalf("principal = %d, %v; want %d", actual, err, test.wantID)
			}
		})
	}
}

func TestV1UploadHandlersRejectPrincipalLessRequestsBeforeMultipartOrStorage(t *testing.T) {
	body := &trackingV1UploadBody{}
	postRequest := httptest.NewRequest(http.MethodPost, "/v1/file/upload", body)
	postRequest.Header.Set("user_id", "999")
	postContext := echo.New().NewContext(postRequest, httptest.NewRecorder())
	if err := PostFileUpload(postContext); err != echo.ErrUnauthorized {
		t.Fatalf("POST error = %v, want unauthorized", err)
	}
	if body.read {
		t.Fatal("principal-less POST read the multipart body")
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/v1/file/upload?totalChunks=1&chunkNumber=1", nil)
	getRequest.Header.Set("user_id", "999")
	getContext := echo.New().NewContext(getRequest, httptest.NewRecorder())
	if err := GetFileUpload(getContext); err != echo.ErrUnauthorized {
		t.Fatalf("GET error = %v, want unauthorized", err)
	}
}

func TestV1UploadPrincipalBindingRemainsStableAcrossRenewedClaims(t *testing.T) {
	principal := func(username string) int {
		ctx := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
		ctx.Set("user", &commonjwt.Claims{ID: 42, Username: username})
		id, err := authenticatedV1UploadPrincipalID(ctx)
		if err != nil {
			t.Fatalf("principal for %q: %v", username, err)
		}
		return id
	}
	if first, renewed := principal("admin"), principal("renamed-admin"); first != renewed || first != 42 {
		t.Fatalf("renewed claims principals = %d and %d", first, renewed)
	}
}

func testV1UploadPaths(base string, principalID int, namespace string) v1UploadPaths {
	targetRelative := filepath.Join("files", "target.bin")
	tempRelative := filepath.Join(".temp", "upload-"+namespace)
	return v1UploadPaths{
		principalID:    principalID,
		base:           base,
		target:         filepath.Join(base, targetRelative),
		targetRelative: targetRelative,
		tempDir:        filepath.Join(base, tempRelative),
		tempRelative:   tempRelative,
		chunk:          filepath.Join(base, tempRelative, "1"),
		assembly:       filepath.Join(base, tempRelative, ".complete"),
	}
}

func completedV1UploadSession(paths v1UploadPaths, totalChunks int64, completedAt, lastActivity time.Time) *v1UploadSession {
	return &v1UploadSession{
		closed:         true,
		principalID:    paths.principalID,
		base:           paths.base,
		target:         paths.target,
		targetRelative: paths.targetRelative,
		tempDir:        paths.tempDir,
		tempRelative:   paths.tempRelative,
		totalChunks:    totalChunks,
		lastActivity:   lastActivity,
		completed:      true,
		completedAt:    completedAt,
		stagingClean:   true,
	}
}

func TestV1UploadSessionMetadataIncludesPrincipalAndCanonicalPaths(t *testing.T) {
	paths := testV1UploadPaths("/managed", 41, "principal-41")
	session := completedV1UploadSession(paths, 2, time.Now(), time.Now())
	if !sameV1UploadMetadata(session, paths, 2) {
		t.Fatal("matching immutable upload metadata was rejected")
	}

	tests := map[string]func(*v1UploadPaths){
		"principal":       func(changed *v1UploadPaths) { changed.principalID++ },
		"base":            func(changed *v1UploadPaths) { changed.base += "-changed" },
		"target":          func(changed *v1UploadPaths) { changed.target += "-changed" },
		"target relative": func(changed *v1UploadPaths) { changed.targetRelative += "-changed" },
		"temp directory":  func(changed *v1UploadPaths) { changed.tempDir += "-changed" },
		"temp relative":   func(changed *v1UploadPaths) { changed.tempRelative += "-changed" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := paths
			mutate(&changed)
			if sameV1UploadMetadata(session, changed, 2) {
				t.Fatal("changed immutable upload metadata was accepted")
			}
		})
	}
	if sameV1UploadMetadata(session, paths, 3) {
		t.Fatal("changed total chunk count was accepted")
	}
}

func TestV1UploadProbeAndRegistryTTLArePrincipalIsolated(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
	base := t.TempDir()
	firstPaths := testV1UploadPaths(base, 41, "principal-41")
	secondPaths := testV1UploadPaths(base, 42, "principal-42")
	lastActivity := time.Now().Add(-time.Hour)
	firstSession := completedV1UploadSession(firstPaths, 2, time.Now(), lastActivity)
	registry.sessions[firstPaths.tempDir] = firstSession

	if completed, ok, err := registry.lockCompleted(secondPaths, 2); err != nil || ok || completed != nil {
		t.Fatalf("cross-principal completed probe = %p, %v, %v; want no match", completed, ok, err)
	}
	if !firstSession.lastActivity.Equal(lastActivity) {
		t.Fatalf("cross-principal probe renewed activity from %v to %v", lastActivity, firstSession.lastActivity)
	}

	forgedPaths := firstPaths
	forgedPaths.principalID = secondPaths.principalID
	if completed, ok, err := registry.lockCompleted(forgedPaths, 2); err == nil || ok || completed != nil {
		t.Fatalf("same-namespace forged probe = %p, %v, %v; want metadata error", completed, ok, err)
	}
	if !firstSession.lastActivity.Equal(lastActivity) {
		t.Fatalf("forged probe renewed activity from %v to %v", lastActivity, firstSession.lastActivity)
	}
	if acquired, err := registry.acquire(forgedPaths, 2); err == nil || acquired != nil {
		t.Fatalf("same-namespace forged acquire = %p, %v; want metadata error", acquired, err)
	}
	if !firstSession.lastActivity.Equal(lastActivity) {
		t.Fatalf("forged acquire renewed activity from %v to %v", lastActivity, firstSession.lastActivity)
	}

	completed, ok, err := registry.lockCompleted(firstPaths, 2)
	if err != nil || !ok || completed != firstSession {
		t.Fatalf("same-principal completed probe = %p, %v, %v", completed, ok, err)
	}
	completed.lock.Unlock()
}

func TestV1CompletedUploadExpiryPrunesOnlyExpiredPrincipal(t *testing.T) {
	registry := v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: os.RemoveAll}
	base := t.TempDir()
	now := time.Now()
	expiredPaths := testV1UploadPaths(base, 41, "principal-41")
	currentPaths := testV1UploadPaths(base, 42, "principal-42")
	registry.sessions[expiredPaths.tempDir] = completedV1UploadSession(
		expiredPaths,
		2,
		now.Add(-v1UploadCompletionTTL-time.Minute),
		now.Add(time.Hour),
	)
	currentSession := completedV1UploadSession(currentPaths, 2, now, now.Add(-time.Hour))
	registry.sessions[currentPaths.tempDir] = currentSession

	registry.cleanup(now)
	if registry.sessions[expiredPaths.tempDir] != nil {
		t.Fatal("expired principal completion survived its completion TTL")
	}
	if registry.sessions[currentPaths.tempDir] != currentSession {
		t.Fatal("current principal completion was pruned with another principal")
	}
}

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
