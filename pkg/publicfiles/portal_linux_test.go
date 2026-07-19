//go:build linux

package publicfiles

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const testToken = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

type portalFixture struct {
	portal    *Portal
	root      string
	tokenFile string
}

func newPortalFixture(t *testing.T, maxEntries int) portalFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(base, "access-token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	portal, err := New(Config{Root: root, TokenFile: tokenFile, MaxEntries: maxEntries})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = portal.Close() })
	return portalFixture{portal: portal, root: root, tokenFile: tokenFile}
}

func authorizedRequest(t *testing.T, method, endpoint string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	return request
}

func serve(portal *Portal, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, request)
	return recorder
}

func TestNewFromEnvIsExplicitlyDisabled(t *testing.T) {
	t.Setenv("RECASAOS_PUBLIC_FILE_ENABLED", "")
	t.Setenv("RECASAOS_PUBLIC_FILE_ROOT", "/should/not/be/read")
	t.Setenv("RECASAOS_PUBLIC_FILE_TOKEN_FILE", "/should/not/be/read")
	portal, err := NewFromEnv()
	if portal != nil || !errors.Is(err, ErrDisabled) {
		t.Fatalf("NewFromEnv() = (%v, %v), want (nil, ErrDisabled)", portal, err)
	}
}

func TestNewFromEnvRequiresCompleteSafeConfiguration(t *testing.T) {
	t.Setenv("RECASAOS_PUBLIC_FILE_ENABLED", "1")
	t.Setenv("RECASAOS_PUBLIC_FILE_ROOT", "")
	t.Setenv("RECASAOS_PUBLIC_FILE_TOKEN_FILE", "")
	if portal, err := NewFromEnv(); portal != nil || err == nil {
		t.Fatalf("enabled incomplete configuration must fail closed: (%v, %v)", portal, err)
	}
}

func TestNewFromEnvEnablesOnlyWithExplicitSafeConfiguration(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(base, "token")
	if err := os.WriteFile(tokenFile, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECASAOS_PUBLIC_FILE_ENABLED", "1")
	t.Setenv("RECASAOS_PUBLIC_FILE_ROOT", root)
	t.Setenv("RECASAOS_PUBLIC_FILE_TOKEN_FILE", tokenFile)
	portal, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if portal == nil {
		t.Fatal("explicit safe configuration returned a nil portal")
	}
	if err := portal.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsUnsafeRootsAndTokenFiles(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(base, "token")
	if err := os.WriteFile(token, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		root      string
		tokenFile string
		prepare   func(t *testing.T) string
	}{
		{name: "filesystem root", root: "/", tokenFile: token},
		{name: "relative root", root: "relative", tokenFile: token},
		{
			name:      "token within root",
			root:      root,
			tokenFile: filepath.Join(root, "token"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(root, "token")
				if err := os.WriteFile(path, []byte(testToken), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:      "group-readable token",
			root:      root,
			tokenFile: filepath.Join(base, "group-token"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "group-token")
				if err := os.WriteFile(path, []byte(testToken), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:      "weak token",
			root:      root,
			tokenFile: filepath.Join(base, "weak-token"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "weak-token")
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:      "token symlink",
			root:      root,
			tokenFile: filepath.Join(base, "token-link"),
			prepare: func(t *testing.T) string {
				path := filepath.Join(base, "token-link")
				if err := os.Symlink(token, path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name:      "root symlink",
			root:      filepath.Join(base, "root-link"),
			tokenFile: token,
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
				if strings.Contains(test.name, "root") && test.name != "token within root" {
					test.root = prepared
				} else {
					test.tokenFile = prepared
				}
			}
			portal, err := New(Config{Root: test.root, TokenFile: test.tokenFile})
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

func TestListExposesOnlySafeMinimalEntries(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "visible.txt"), []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, ".hidden"), []byte("hidden"), 0o600); err != nil {
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

func TestPortalAssetsUseStrictCSPAndSessionStorage(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	html := serve(fixture.portal, httptest.NewRequest(http.MethodGet, BasePath+"/", nil))
	if html.Code != http.StatusOK || strings.Contains(html.Body.String(), testToken) {
		t.Fatalf("HTML response is unsafe: %d %s", html.Code, html.Body.String())
	}
	csp := html.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
	javascript := serve(fixture.portal, httptest.NewRequest(http.MethodGet, BasePath+"/app.js", nil))
	if !strings.Contains(javascript.Body.String(), "sessionStorage") || strings.Contains(javascript.Body.String(), "localStorage") {
		t.Fatal("client token is not scoped to sessionStorage")
	}
}

func TestMutatingMethodsAreRejected(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	for _, endpoint := range []string{BasePath + "/api/list", BasePath + "/api/file?path=x", BasePath + "/"} {
		response := serve(fixture.portal, authorizedRequest(t, http.MethodPost, endpoint))
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s returned %d, want 405", endpoint, response.Code)
		}
	}
}
