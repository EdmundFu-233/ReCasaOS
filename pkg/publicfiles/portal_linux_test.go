//go:build linux

package publicfiles

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var testToken = testPublicBearer(11)

type portalFixture struct {
	portal       *Portal
	root         string
	verifierFile string
}

func writeTestVerifierFile(t *testing.T, path, bearer string, mode os.FileMode) {
	t.Helper()
	serialized := serializeTestPublicVerifier(digestPublicBearer(bearer))
	if err := os.WriteFile(path, serialized, mode); err != nil {
		t.Fatal(err)
	}
}

func newPortalFixture(t *testing.T, maxEntries int) portalFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	verifierFile := filepath.Join(base, "bearer-verifier")
	writeTestVerifierFile(t, verifierFile, testToken, 0o600)
	portal, err := New(Config{Root: root, VerifierFile: verifierFile, MaxEntries: maxEntries})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = portal.Close() })
	return portalFixture{portal: portal, root: root, verifierFile: verifierFile}
}

func requestWithBearer(t *testing.T, method, endpoint, bearer string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	return request
}

func authorizedRequest(t *testing.T, method, endpoint string) *http.Request {
	t.Helper()
	return requestWithBearer(t, method, endpoint, testToken)
}

func serve(portal *Portal, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, request)
	return recorder
}

func TestNewRejectsUnsafeRootsAndVerifierFiles(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	verifier := filepath.Join(base, "verifier")
	writeTestVerifierFile(t, verifier, testToken, 0o600)

	tests := []struct {
		name         string
		root         string
		verifierFile string
		prepare      func(t *testing.T) string
	}{
		{name: "filesystem root", root: "/", verifierFile: verifier},
		{name: "relative root", root: "relative", verifierFile: verifier},
		{
			name:         "group-readable verifier",
			root:         root,
			verifierFile: filepath.Join(base, "group-verifier"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "group-verifier")
				writeTestVerifierFile(t, path, testToken, 0o640)
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:         "malformed verifier",
			root:         root,
			verifierFile: filepath.Join(base, "malformed-verifier"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "malformed-verifier")
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:         "verifier symlink",
			root:         root,
			verifierFile: filepath.Join(base, "verifier-link"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "verifier-link")
				if err := os.Symlink(verifier, path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:         "root symlink",
			root:         filepath.Join(base, "root-link"),
			verifierFile: verifier,
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "root-link")
				if err := os.Symlink(root, path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.prepare != nil {
				prepared := test.prepare(t)
				if strings.Contains(test.name, "root") {
					test.root = prepared
				} else {
					test.verifierFile = prepared
				}
			}
			portal, err := New(Config{Root: test.root, VerifierFile: test.verifierFile})
			if portal != nil {
				portal.Close()
				t.Fatal("unsafe configuration unexpectedly created a portal")
			}
			if err == nil {
				t.Fatal("unsafe configuration unexpectedly succeeded")
			}
		})
	}
}

func TestAuthorizationUsesHeaderOnly(t *testing.T) {
	fixture := newPortalFixture(t, 0)

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, BasePath+"/api/list", nil),
		httptest.NewRequest(http.MethodGet, BasePath+"/api/list?token="+url.QueryEscape(testToken), nil),
		authorizedRequest(t, http.MethodGet, BasePath+"/api/list"),
	}
	requests[2].Header.Set("Authorization", "Bearer wrong-token")
	for _, request := range requests {
		response := serve(fixture.portal, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("request %q returned %d, want 401", request.URL.String(), response.Code)
		}
		if strings.Contains(response.Body.String(), testToken) {
			t.Fatal("response leaked bearer token")
		}
	}

	request := authorizedRequest(t, http.MethodGet, BasePath+"/api/list")
	request.Header.Add("Authorization", "Bearer "+testToken)
	if response := serve(fixture.portal, request); response.Code != http.StatusUnauthorized {
		t.Fatalf("multiple Authorization headers returned %d, want 401", response.Code)
	}

	request = authorizedRequest(t, http.MethodGet, BasePath+"/api/list?token=ignored")
	if response := serve(fixture.portal, request); response.Code != http.StatusBadRequest {
		t.Fatalf("credential query with valid header returned %d, want 400", response.Code)
	}
}

func TestVerifierMaterialCannotAuthenticate(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "secret"), []byte("protected-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifier := digestPublicBearer(testToken)
	candidates := []string{
		string(serializeTestPublicVerifier(verifier)),
		hex.EncodeToString(verifier[:]),
		base64.RawURLEncoding.EncodeToString(verifier[:]),
		publicBearerPrefix + base64.RawURLEncoding.EncodeToString(verifier[:]),
	}
	endpoints := []string{
		BasePath + "/api/list",
		BasePath + "/api/file?path=secret",
	}

	for _, candidate := range candidates {
		for _, endpoint := range endpoints {
			response := serve(fixture.portal, requestWithBearer(t, http.MethodGet, endpoint, candidate))
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("verifier-derived candidate at %s returned %d, want 401", endpoint, response.Code)
			}
			if got := response.Header().Get("WWW-Authenticate"); got != `Bearer realm="ReCasaOS public files"` {
				t.Fatalf("WWW-Authenticate = %q, want public-files bearer realm", got)
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			if got := response.Body.String(); got != `{"error":"authorization required"}` {
				t.Fatalf("authentication body = %q, want generic error", got)
			}
			for _, protected := range []string{candidate, testToken, fixture.root, "protected-content"} {
				if protected != "" && strings.Contains(response.Body.String(), protected) {
					t.Fatal("authentication failure reflected credential, host path, or file content")
				}
			}
		}
	}

	if response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list")); response.Code != http.StatusOK {
		t.Fatalf("real bearer returned %d after verifier probes, want 200", response.Code)
	}
}

func TestVerifierRotationRequiresRestartAndRollsBack(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	newBearer := testPublicBearer(77)
	replaceVerifier := func(name, bearer string) {
		t.Helper()
		replacement := filepath.Join(filepath.Dir(fixture.verifierFile), name)
		writeTestVerifierFile(t, replacement, bearer, 0o600)
		if err := os.Rename(replacement, fixture.verifierFile); err != nil {
			t.Fatal(err)
		}
	}

	if response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list")); response.Code != http.StatusOK {
		t.Fatalf("old bearer before rotation returned %d, want 200", response.Code)
	}
	if response := serve(fixture.portal, requestWithBearer(t, http.MethodGet, BasePath+"/api/list", newBearer)); response.Code != http.StatusUnauthorized {
		t.Fatalf("new bearer before rotation returned %d, want 401", response.Code)
	}

	replaceVerifier("verifier.next", newBearer)
	serialized, err := os.ReadFile(fixture.verifierFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(serialized) != string(serializeTestPublicVerifier(digestPublicBearer(newBearer))) ||
		strings.Contains(string(serialized), testToken) ||
		strings.Contains(string(serialized), newBearer) {
		t.Fatal("rotated verifier file did not contain only the expected serialized digest")
	}
	rotated, err := New(Config{Root: fixture.root, VerifierFile: fixture.verifierFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rotated.Close() })
	if response := serve(rotated, authorizedRequest(t, http.MethodGet, BasePath+"/api/list")); response.Code != http.StatusUnauthorized {
		t.Fatalf("old bearer after controlled restart returned %d, want 401", response.Code)
	}
	if response := serve(rotated, requestWithBearer(t, http.MethodGet, BasePath+"/api/list", newBearer)); response.Code != http.StatusOK {
		t.Fatalf("new bearer after controlled restart returned %d, want 200", response.Code)
	}
	if response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list")); response.Code != http.StatusOK {
		t.Fatalf("existing process did not retain its pinned in-memory verifier: %d", response.Code)
	}
	if response := serve(fixture.portal, requestWithBearer(t, http.MethodGet, BasePath+"/api/list", newBearer)); response.Code != http.StatusUnauthorized {
		t.Fatalf("existing process accepted new bearer before restart: %d", response.Code)
	}

	invalid := filepath.Join(filepath.Dir(fixture.verifierFile), "verifier.invalid")
	if err := os.WriteFile(invalid, []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(invalid, fixture.verifierFile); err != nil {
		t.Fatal(err)
	}
	if portal, err := New(Config{Root: fixture.root, VerifierFile: fixture.verifierFile}); portal != nil || err == nil {
		if portal != nil {
			_ = portal.Close()
		}
		t.Fatalf("restart with invalid verifier = (%v, %v), want fail closed", portal, err)
	}
	if response := serve(rotated, requestWithBearer(t, http.MethodGet, BasePath+"/api/list", newBearer)); response.Code != http.StatusOK {
		t.Fatalf("running portal stopped using its pinned verifier after invalid publication: %d", response.Code)
	}

	replaceVerifier("verifier.rollback", testToken)
	rolledBack, err := New(Config{Root: fixture.root, VerifierFile: fixture.verifierFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rolledBack.Close() })
	if response := serve(rolledBack, authorizedRequest(t, http.MethodGet, BasePath+"/api/list")); response.Code != http.StatusOK {
		t.Fatalf("old bearer after rollback returned %d, want 200", response.Code)
	}
	if response := serve(rolledBack, requestWithBearer(t, http.MethodGet, BasePath+"/api/list", newBearer)); response.Code != http.StatusUnauthorized {
		t.Fatalf("new bearer after rollback returned %d, want 401", response.Code)
	}
}

func TestListExposesOnlySafeMinimalEntries(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "visible.txt"), []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, ".hidden"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, `windows\name.txt`), []byte("unaddressable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(fixture.root, "folder"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(fixture.root), "outside-secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(fixture.root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(fixture.root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(fixture.root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}

	response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list"))
	if response.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Path    string  `json:"path"`
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Path != "" {
		t.Fatalf("root list path = %q, want empty relative path", body.Path)
	}
	if len(body.Entries) != 2 || body.Entries[0].Name != "folder" || body.Entries[0].Type != "directory" || body.Entries[1].Name != "visible.txt" || body.Entries[1].Type != "file" {
		t.Fatalf("unexpected public entries: %#v", body.Entries)
	}
	if strings.Contains(response.Body.String(), fixture.root) || strings.Contains(response.Body.String(), outside) {
		t.Fatal("listing leaked a host path")
	}
}

func TestTraversalHiddenAndLinkEscapesAreDenied(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	outsideDirectory := filepath.Join(filepath.Dir(fixture.root), "outside-directory")
	if err := os.Mkdir(outsideDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(outsideDirectory, "outside")
	if err := os.WriteFile(outside, []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(fixture.root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDirectory, filepath.Join(fixture.root, "escape-directory")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(fixture.root, "hardlink-escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, ".secret"), []byte("hidden-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path string
		want int
	}{
		{path: "../outside", want: http.StatusBadRequest},
		{path: "/etc/passwd", want: http.StatusBadRequest},
		{path: "a//b", want: http.StatusBadRequest},
		{path: ".secret", want: http.StatusBadRequest},
		{path: "escape", want: http.StatusNotFound},
		{path: "escape-directory/outside", want: http.StatusNotFound},
		{path: "hardlink-escape", want: http.StatusNotFound},
	}
	for _, test := range tests {
		request := authorizedRequest(t, http.MethodGet, BasePath+"/api/file?"+url.Values{"path": []string{test.path}}.Encode())
		response := serve(fixture.portal, request)
		if response.Code != test.want {
			t.Errorf("path %q returned %d, want %d", test.path, response.Code, test.want)
		}
		if strings.Contains(response.Body.String(), "secret-value") || strings.Contains(response.Body.String(), "hidden-value") || strings.Contains(response.Body.String(), fixture.root) {
			t.Errorf("path %q leaked protected content or root metadata", test.path)
		}
	}
}

func TestFileStreamingHeadAndRange(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	content := "0123456789"
	if err := os.WriteFile(filepath.Join(fixture.root, "report.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := BasePath + "/api/file?" + url.Values{"path": []string{"report.txt"}}.Encode()

	response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, endpoint))
	if response.Code != http.StatusOK || response.Body.String() != content {
		t.Fatalf("GET returned (%d, %q)", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("unsafe download headers: %#v", response.Header())
	}
	for key, expected := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	} {
		if got := response.Header().Get(key); got != expected {
			t.Errorf("%s = %q, want %q", key, got, expected)
		}
	}

	head := serve(fixture.portal, authorizedRequest(t, http.MethodHead, endpoint))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != "10" {
		t.Fatalf("HEAD returned status=%d length=%q body=%q", head.Code, head.Header().Get("Content-Length"), head.Body.String())
	}

	rangeRequest := authorizedRequest(t, http.MethodGet, endpoint)
	rangeRequest.Header.Set("Range", "bytes=2-5")
	ranged := serve(fixture.portal, rangeRequest)
	if ranged.Code != http.StatusPartialContent || ranged.Body.String() != "2345" {
		t.Fatalf("range returned (%d, %q)", ranged.Code, ranged.Body.String())
	}
}

func TestDirectoryEntryLimitFailsClosed(t *testing.T) {
	fixture := newPortalFixture(t, 2)
	for _, name := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(fixture.root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list"))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized directory returned %d, want 413", response.Code)
	}
}

func TestDownloadConcurrencyLimitFailsFast(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "report.txt"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.portal.downloadSlots = make(chan struct{}, 1)
	fixture.portal.downloadSlots <- struct{}{}
	endpoint := BasePath + "/api/file?" + url.Values{"path": []string{"report.txt"}}.Encode()
	response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, endpoint))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
		t.Fatalf("saturated download returned status=%d retry-after=%q", response.Code, response.Header().Get("Retry-After"))
	}
}

func TestPinnedRootDescriptorSurvivesPathReplacement(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "original"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := fixture.root + "-moved"
	if err := os.Rename(fixture.root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "replacement"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	response := serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/list"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "original") || strings.Contains(response.Body.String(), "replacement") {
		t.Fatalf("portal did not stay pinned to the opened root: %d %s", response.Code, response.Body.String())
	}
}

func TestPortalAssetsUseStrictCSPAndPageMemory(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	html := serve(fixture.portal, httptest.NewRequest(http.MethodGet, BasePath+"/", nil))
	if html.Code != http.StatusOK || strings.Contains(html.Body.String(), testToken) {
		t.Fatalf("HTML response is unsafe: %d %s", html.Code, html.Body.String())
	}
	csp := html.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "worker-src 'self'") || !strings.Contains(csp, "frame-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
	javascript := serve(fixture.portal, httptest.NewRequest(http.MethodGet, BasePath+"/app.js", nil))
	if !strings.Contains(javascript.Body.String(), "let accessToken=''") || strings.Contains(javascript.Body.String(), "sessionStorage") || strings.Contains(javascript.Body.String(), "localStorage") {
		t.Fatal("client token is not confined to ephemeral page memory")
	}
}

func TestMutatingMethodsAreRejected(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	for _, endpoint := range []string{BasePath + "/api/list", BasePath + "/api/file?path=x", BasePath + "/", BasePath + "/download-frame", BasePath + "/download-frame.js", BasePath + "/download-worker.js"} {
		response := serve(fixture.portal, authorizedRequest(t, http.MethodPost, endpoint))
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s returned %d, want 405", endpoint, response.Code)
		}
	}
}
