package route

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
)

func TestManagedTransferInventoryRouteRequiresAuthentication(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")
	var logs bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&logs, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	for _, authorization := range []string{"", "Bearer invalid-token"} {
		request := httptest.NewRequest(http.MethodPost, "/v1/file/recovery/inventory", strings.NewReader(`{"parent":"/DATA"}`))
		request.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		request.RemoteAddr = "198.51.100.20:43120"
		response := httptest.NewRecorder()
		InitV1Router().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest && response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q status = %d", authorization, response.Code)
		}
		if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
			t.Fatalf("authorization %q Cache-Control = %q", authorization, got)
		}
		if got := response.Header().Get("Pragma"); got != "no-cache" {
			t.Fatalf("authorization %q Pragma = %q", authorization, got)
		}
	}
}

func TestManagedTransferInventoryRouteIsPrivateAndNoStore(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	var logs bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&logs, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	request := httptest.NewRequest(http.MethodPost, "/v1/file/recovery/inventory", strings.NewReader(`{"parent":"/DATA"}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:43120"
	response := httptest.NewRecorder()
	InitV1Router().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("loopback test status = %d, body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
	if strings.Contains(logs.String(), "/DATA") {
		t.Fatalf("request body path appeared in log: %s", logs.String())
	}
}
