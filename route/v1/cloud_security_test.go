package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestUnmountStorageRejectsOversizedBodyBeforeServiceAccess(t *testing.T) {
	e := echo.New()
	body := `{"mount_point":"/mnt/cloud","padding":"` + strings.Repeat("x", 5<<10) + `"}`
	request := httptest.NewRequest(http.MethodDelete, "/v1/cloud", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := UmountStorage(e.NewContext(request, response)); err != nil {
		t.Fatalf("UmountStorage() error = %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
