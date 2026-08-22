package route

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/labstack/echo/v4"
)

type trackedV1RouteUploadBody struct {
	reads int
}

func (body *trackedV1RouteUploadBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func TestInitV1RouterRejectsPrincipalLessLoopbackUploadsBeforeParsing(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	previousLogger := requestLogger
	requestLogger = log.New(io.Discard, "", 0)
	t.Cleanup(func() { requestLogger = previousLogger })

	handler := InitV1Router()
	postBody := &trackedV1RouteUploadBody{}
	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        io.Reader
	}{
		{
			name:   "GET invalid query",
			method: http.MethodGet,
			target: "/v1/file/upload?totalChunks=invalid&chunkNumber=invalid",
		},
		{
			name:        "POST multipart",
			method:      http.MethodPost,
			target:      "/v1/file/upload",
			contentType: "multipart/form-data; boundary=test-boundary",
			body:        postBody,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, test.body)
			request.RemoteAddr = "127.0.0.1:43120"
			request.Header.Set("user_id", "999")
			if test.contentType != "" {
				request.Header.Set(echo.HeaderContentType, test.contentType)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
		})
	}
	if postBody.reads != 0 {
		t.Fatalf("principal-less loopback POST read its multipart body %d times", postBody.reads)
	}
}
