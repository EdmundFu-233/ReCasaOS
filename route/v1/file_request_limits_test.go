package v1

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/labstack/echo/v4"
)

func TestManagedDeleteFailureStatusReportsPartialChanges(t *testing.T) {
	injected := errors.New("injected")
	changedErr := &filesecurity.ManagedMutationError{Operation: "remove", Changed: true, Err: injected}
	if status := managedDeleteFailureStatus(filesecurity.ManagedBatchMutationResult{}, changedErr); status != "PARTIAL" {
		t.Fatalf("changed error status = %q", status)
	}
	if status := managedDeleteFailureStatus(filesecurity.ManagedBatchMutationResult{Changed: true}, injected); status != "PARTIAL" {
		t.Fatalf("changed result status = %q", status)
	}
	if status := managedDeleteFailureStatus(filesecurity.ManagedBatchMutationResult{}, injected); status != "FAILED" {
		t.Fatalf("unchanged error status = %q", status)
	}
}

func TestManagedDeleteFailureDataPreservesDurabilityUnknown(t *testing.T) {
	injected := &filesecurity.ManagedMutationError{
		Operation:         "sync removed batch parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               errors.New("injected"),
	}
	data := managedDeleteFailureData(filesecurity.ManagedBatchMutationResult{Changed: true, Completed: []string{"/managed/a"}}, injected)
	if data["status"] != "PARTIAL" || data["changed"] != true || data["durability_unknown"] != true {
		t.Fatalf("delete failure data = %#v", data)
	}
}

func TestManagedMutationFailureResponseReportsPartialState(t *testing.T) {
	injected := &filesecurity.ManagedMutationError{
		Operation:         "sync mutation parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               errors.New("injected"),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/file/test", nil)
	response := httptest.NewRecorder()
	context := echo.New().NewContext(request, response)
	if err := respondManagedMutationFailure(context, injected); err != nil {
		t.Fatal(err)
	}
	if response.Code != common_err.SERVICE_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`"message":"PARTIAL"`, `"status":"PARTIAL"`, `"changed":true`, `"durability_unknown":true`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("response does not contain %s: %s", expected, response.Body.String())
		}
	}
}

func TestRespondV1UploadFailureReportsPartialBeforeTooLarge(t *testing.T) {
	injected := &filesecurity.ManagedMutationError{
		Operation:         "sync published upload chunk parent",
		Changed:           true,
		DurabilityUnknown: true,
		Err:               errors.New("injected"),
	}
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   []string
	}{
		{
			name:       "published partial takes priority",
			err:        errors.Join(errUploadTooLarge, injected),
			wantStatus: common_err.SERVICE_ERROR,
			wantBody:   []string{`"message":"PARTIAL"`, `"status":"PARTIAL"`, `"changed":true`, `"durability_unknown":true`},
		},
		{
			name:       "unchanged too large",
			err:        errUploadTooLarge,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantBody:   []string{`"status":"FAILED"`, `"changed":false`, `"durability_unknown":false`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/file/upload", nil)
			response := httptest.NewRecorder()
			context := echo.New().NewContext(request, response)
			if err := respondV1UploadFailure(context, test.err); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			for _, expected := range test.wantBody {
				if !strings.Contains(response.Body.String(), expected) {
					t.Fatalf("response does not contain %s: %s", expected, response.Body.String())
				}
			}
		})
	}
}

func TestSmallFileJSONHandlersRejectMalformedRelativeAndOversizedBodies(t *testing.T) {
	tests := []struct {
		name    string
		handler echo.HandlerFunc
		body    string
	}{
		{name: "rename malformed", handler: RenamePath, body: "{"},
		{name: "rename unknown field", handler: RenamePath, body: `{"old_path":"/DATA/a","new_path":"/DATA/b","extra":"x"}`},
		{name: "mkdir relative", handler: MkdirAll, body: `{"path":"relative"}`},
		{name: "create oversized", handler: PostCreateFile, body: `{"path":"/DATA/` + strings.Repeat("a", int(maxSmallFileJSONRequestBodySize)) + `"}`},
		{name: "size malformed", handler: GetSize, body: "{"},
		{name: "count oversized", handler: GetFileCount, body: strings.Repeat(" ", int(maxSmallFileJSONRequestBodySize)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := invokeBoundedFileJSONHandler(t, test.handler, test.body)
			if response.Code != common_err.CLIENT_ERROR {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPutFileContentCapsJSONBeforeBinding(t *testing.T) {
	body := `{"path":"/DATA/file","content":"` + strings.Repeat("a", int(maxManagedTextUpdateRequestBodySize)) + `"}`
	response := invokeBoundedFileJSONHandler(t, PutFileContent, body)
	if response.Code != common_err.CLIENT_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestDeleteFileRejectsOversizedBatchesAndOverlapsBeforeRootLookup(t *testing.T) {
	items := make([]string, maxFileDeleteItems+1)
	for index := range items {
		items[index] = fmt.Sprintf("\"/DATA/%d\"", index)
	}
	for _, body := range []string{
		"[" + strings.Join(items, ",") + "]",
		`["/DATA/parent","/DATA/parent/child"]`,
		strings.Repeat(" ", int(maxFileOperationRequestBodySize)+1),
	} {
		response := invokeBoundedFileJSONHandler(t, DeleteFile, body)
		if response.Code != common_err.CLIENT_ERROR {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	}
}

func TestPostOperateFileOrDirRejectsUnknownAndOversizedJSONBeforeRootLookup(t *testing.T) {
	for _, body := range []string{
		`{"type":"copy","style":"skip","to":"/DATA","item":[],"extra":true}`,
		strings.Repeat(" ", int(maxFileOperationRequestBodySize)+1),
	} {
		response := invokeBoundedFileJSONHandler(t, PostOperateFileOrDir, body)
		if response.Code != common_err.CLIENT_ERROR {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	}
}

func invokeBoundedFileJSONHandler(t *testing.T, handler echo.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/file/test", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()
	context := echo.New().NewContext(request, response)
	if err := handler(context); err != nil {
		t.Fatal(err)
	}
	return response
}
