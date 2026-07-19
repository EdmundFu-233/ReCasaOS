package publicfiles

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateRelativePath(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		allowRoot bool
		want      string
		wantError bool
	}{
		{name: "root", value: "", allowRoot: true, want: ""},
		{name: "file", value: "folder/report 2026.pdf", want: "folder/report 2026.pdf"},
		{name: "unicode", value: "photos/旅行.jpg", want: "photos/旅行.jpg"},
		{name: "empty file", value: "", wantError: true},
		{name: "absolute", value: "/etc/passwd", wantError: true},
		{name: "parent traversal", value: "../secret", wantError: true},
		{name: "embedded parent", value: "safe/../secret", wantError: true},
		{name: "hidden", value: "safe/.secret", wantError: true},
		{name: "empty component", value: "safe//file", wantError: true},
		{name: "backslash", value: `safe\file`, wantError: true},
		{name: "control", value: "safe/file\nname", wantError: true},
		{name: "invalid utf8", value: string([]byte{0xff}), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateRelativePath(test.value, test.allowRoot)
			if (err != nil) != test.wantError {
				t.Fatalf("validateRelativePath(%q) error = %v, wantError=%v", test.value, err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("validateRelativePath(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestParseSafeQueryIsStrictAndRejectsCredentials(t *testing.T) {
	tests := []struct {
		query     string
		wantPath  string
		wantError bool
	}{
		{query: "", wantPath: ""},
		{query: "path=folder%2Ffile", wantPath: "folder/file"},
		{query: "path=one&path=two", wantError: true},
		{query: "unknown=value", wantError: true},
		{query: "token=secret", wantError: true},
		{query: "ACCESS_TOKEN=secret", wantError: true},
		{query: "authorization=Bearer", wantError: true},
		{query: "%zz", wantError: true},
	}
	for _, test := range tests {
		values, err := parseSafeQuery(test.query)
		if (err != nil) != test.wantError {
			t.Errorf("parseSafeQuery(%q) error = %v, wantError=%v", test.query, err, test.wantError)
			continue
		}
		if err == nil && values.Get("path") != test.wantPath {
			t.Errorf("parseSafeQuery(%q) path = %q, want %q", test.query, values.Get("path"), test.wantPath)
		}
	}
}

func TestBearerAuthorizationRequiresOneExactHeaderToken(t *testing.T) {
	const token = "test-only-token"
	portal := &Portal{tokenDigest: sha256.Sum256([]byte(token))}
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{name: "valid", headers: []string{"Bearer " + token}, want: true},
		{name: "case-insensitive scheme", headers: []string{"bearer " + token}, want: true},
		{name: "missing"},
		{name: "wrong", headers: []string{"Bearer wrong"}},
		{name: "basic", headers: []string{"Basic " + token}},
		{name: "space in token", headers: []string{"Bearer " + token + " extra"}},
		{name: "multiple", headers: []string{"Bearer " + token, "Bearer " + token}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/api/list", nil)
			for _, header := range test.headers {
				request.Header.Add("Authorization", header)
			}
			if got := portal.authorized(request); got != test.want {
				t.Fatalf("authorized() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPublicAssetsRequireNoCredentialAndContainNoInlineScript(t *testing.T) {
	portal := &Portal{}
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("asset status = %d, want 200", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "<script>") || !strings.Contains(recorder.Body.String(), `src="app.js"`) {
		t.Fatal("HTML must load only the same-origin external script")
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("unsafe CSP: %q", csp)
	}
}
