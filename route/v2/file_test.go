package v2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

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

func TestRespondUploadMutationFailureUsesStorageStatus(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v2/file/upload", nil)
	response := httptest.NewRecorder()
	context := echo.New().NewContext(request, response)

	if err := respondUploadMutationFailure(context, filesecurity.ErrUploadSpaceInsufficient); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusInsufficientStorage, response.Body.String())
	}
}
