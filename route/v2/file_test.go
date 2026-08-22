package v2

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS/codegen"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/labstack/echo/v4"
)

type trackedUploadBody struct {
	reads int
}

func (body *trackedUploadBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func (body *trackedUploadBody) Close() error { return nil }

func TestAuthenticatedUploadPrincipalIDRejectsForgedOrInvalidContext(t *testing.T) {
	if _, err := authenticatedUploadPrincipalID(nil); err != echo.ErrUnauthorized {
		t.Fatalf("nil context error = %v, want unauthorized", err)
	}

	var nilClaims *commonjwt.Claims
	tests := []struct {
		name    string
		value   interface{}
		setUser bool
		wantID  int
		wantErr bool
	}{
		{name: "missing", wantErr: true},
		{name: "wrong type", value: "attacker-controlled", setUser: true, wantErr: true},
		{name: "nil claims", value: nilClaims, setUser: true, wantErr: true},
		{name: "zero id", value: &commonjwt.Claims{ID: 0, Username: "admin"}, setUser: true, wantErr: true},
		{name: "negative id", value: &commonjwt.Claims{ID: -1, Username: "admin"}, setUser: true, wantErr: true},
		{name: "verified id", value: &commonjwt.Claims{ID: 42, Username: "admin"}, setUser: true, wantID: 42},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v2/file/upload", nil)
			request.Header.Set("user_id", "999")
			context := echo.New().NewContext(request, httptest.NewRecorder())
			if test.setUser {
				context.Set("user", test.value)
			}

			got, err := authenticatedUploadPrincipalID(context)
			if test.wantErr {
				if err != echo.ErrUnauthorized {
					t.Fatalf("error = %v, want unauthorized", err)
				}
				return
			}
			if err != nil || got != test.wantID {
				t.Fatalf("principal = %d, error = %v, want %d", got, err, test.wantID)
			}
		})
	}
}

func TestUploadHandlersRejectPrincipalLessLoopbackBeforeBodyOrService(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")

	body := &trackedUploadBody{}
	postRequest := httptest.NewRequest(http.MethodPost, "/v2/file/upload", http.NoBody)
	postRequest.RemoteAddr = "127.0.0.1:43120"
	postRequest.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test-boundary")
	postRequest.Header.Set("user_id", "1")
	postRequest.Body = body
	postContext := echo.New().NewContext(postRequest, httptest.NewRecorder())
	server := &CasaOS{}

	if err := server.PostUploadFile(postContext); err != echo.ErrUnauthorized {
		t.Fatalf("POST error = %v, want unauthorized", err)
	}
	if body.reads != 0 {
		t.Fatalf("unauthorized POST read multipart body %d times", body.reads)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/v2/file/upload?chunkNumber=not-a-number", nil)
	getRequest.RemoteAddr = "127.0.0.1:43120"
	getRequest.Header.Set("user_id", "1")
	getContext := echo.New().NewContext(getRequest, httptest.NewRecorder())
	if err := server.CheckUploadChunk(getContext, codegen.CheckUploadChunkParams{}); err != echo.ErrUnauthorized {
		t.Fatalf("GET error = %v, want unauthorized", err)
	}
}

func TestRespondUploadMutationFailureReportsPublishedPartialState(t *testing.T) {
	injected := &filesecurity.ManagedMutationError{
		Operation:         "sync published upload chunk parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               errors.New("injected"),
	}
	request := httptest.NewRequest(http.MethodPost, "/v2/file/upload", nil)
	response := httptest.NewRecorder()
	context := echo.New().NewContext(request, response)
	if err := respondUploadMutationFailure(context, injected); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`"status":"PARTIAL"`, `"changed":true`, `"durability_unknown":true`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("response does not contain %s: %s", expected, response.Body.String())
		}
	}
}
