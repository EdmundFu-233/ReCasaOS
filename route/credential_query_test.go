package route

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestHasCredentialQueryParameterRejectsCredentialShapedNames(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "token", query: "token=secret", want: true},
		{name: "case insensitive token", query: "ToKeN=secret", want: true},
		{name: "access token", query: "access_token=secret", want: true},
		{name: "authorization", query: "authorization=secret", want: true},
		{name: "api key", query: "api_key=secret", want: true},
		{name: "apikey", query: "apikey=secret", want: true},
		{name: "ordinary query", query: "path=%2FDATA", want: false},
		{name: "empty ordinary query", query: "tokenized=value", want: false},
		{name: "malformed query", query: "token=%ZZ", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://device.test/path?"+test.query, nil)
			if got := hasCredentialQueryParameter(request); got != test.want {
				t.Fatalf("hasCredentialQueryParameter() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAccessTokenFromRequestRequiresOneAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		authorizes []string
		wantToken  string
		wantValid  bool
	}{
		{name: "header bearer", authorizes: []string{"Bearer header-token"}, wantToken: "header-token", wantValid: true},
		{name: "query token", query: "token=query-token"},
		{name: "header and query token", query: "token=query-token", authorizes: []string{"Bearer header-token"}},
		{name: "duplicate headers", authorizes: []string{"Bearer first", "Bearer second"}},
		{name: "wrong scheme", authorizes: []string{"Basic header-token"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://device.test/path?"+test.query, nil)
			for _, authorization := range test.authorizes {
				request.Header.Add(echo.HeaderAuthorization, authorization)
			}
			gotToken, gotValid := accessTokenFromRequest(request)
			if gotToken != test.wantToken || gotValid != test.wantValid {
				t.Fatalf("accessTokenFromRequest() = (%q, %v), want (%q, %v)", gotToken, gotValid, test.wantToken, test.wantValid)
			}
		})
	}
}

func TestCredentialTransportRejectsDuplicateAuthorizationHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://device.test/path", nil)
	request.Header.Add(echo.HeaderAuthorization, "Bearer first")
	request.Header.Add(echo.HeaderAuthorization, "Bearer second")

	if !hasDuplicateAuthorizationHeader(request) {
		t.Fatal("duplicate Authorization headers were not detected")
	}
}

func TestInitV1RouterRejectsQueryCredentialsBeforeAuthentication(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://device.test/v1/sys/version?token=secret", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	response := httptest.NewRecorder()

	InitV1Router().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestInitV2RouterRejectsQueryCredentialsBeforeAuthentication(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services?token=secret", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	response := httptest.NewRecorder()

	InitV2Router().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestManagementRoutersRejectDuplicateAuthorizationBeforeAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		target  string
	}{
		{name: "v1", handler: InitV1Router(), target: "http://device.test/v1/sys/version"},
		{name: "v2", handler: InitV2Router(), target: "http://device.test" + V2APIPath + "/health/services"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.RemoteAddr = "198.51.100.20:43120"
			request.Header.Add(echo.HeaderAuthorization, "Bearer first")
			request.Header.Add(echo.HeaderAuthorization, "Bearer second")
			response := httptest.NewRecorder()

			test.handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
			}
		})
	}
}

func TestInitFileRejectsQueryCredentialsBeforeFilesystemAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, V3FilePath+"?token=secret", nil)
	response := httptest.NewRecorder()

	InitFile().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
}
