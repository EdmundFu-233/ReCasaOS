package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/labstack/echo/v4"
)

func TestPostManagedTransferInventoryRejectsInvalidBodiesBeforeRootLookup(t *testing.T) {
	tests := []string{
		``,
		`{`,
		`{}`,
		`{"parent":""}`,
		`{"parent":"relative"}`,
		`{"parent":"/DATA","extra":true}`,
		`{"parent":"/DATA"}{"parent":"/mnt"}`,
	}
	for _, body := range tests {
		request := httptest.NewRequest(http.MethodPost, "/v1/file/recovery/inventory", strings.NewReader(body))
		request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		response := httptest.NewRecorder()
		ctx := echo.New().NewContext(request, response)
		if err := PostManagedTransferInventory(ctx); err != nil {
			t.Fatalf("body %q: handler error = %v", body, err)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d", body, response.Code)
		}
	}
}

func TestPostManagedTransferInventoryBoundsRequestBody(t *testing.T) {
	body := `{"parent":"/` + strings.Repeat("a", int(maxManagedTransferInventoryRequestBodySize)) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/file/recovery/inventory", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := PostManagedTransferInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestManagedTransferInventoryUnavailableDoesNotExposeRawError(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/file/recovery/inventory", nil)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := managedTransferInventoryUnavailable(ctx, http.StatusServiceUnavailable); err != nil {
		t.Fatal(err)
	}
	var result model.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || result.Message != "managed transfer inventory unavailable" {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"operation not permitted", "no such file", "/DATA/"} {
		if strings.Contains(strings.ToLower(response.Body.String()), forbidden) {
			t.Fatalf("response exposed host detail %q: %s", forbidden, response.Body.String())
		}
	}
}
