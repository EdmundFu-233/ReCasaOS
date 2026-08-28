package route

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
)

func TestManagedDirectoryListingRouteAuthenticatesBeforeAccess(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")
	var logs bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&logs, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	for _, authorization := range []string{"", "Bearer invalid-token"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/folder?path=%2Fmust-not-be-opened&index=1&size=1", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		request.RemoteAddr = "198.51.100.20:43120"
		response := httptest.NewRecorder()
		InitV1Router().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest && response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q status = %d, body = %s", authorization, response.Code, response.Body.String())
		}
		if response.Code == http.StatusInternalServerError {
			t.Fatalf("authorization %q reached directory service", authorization)
		}
	}
}
