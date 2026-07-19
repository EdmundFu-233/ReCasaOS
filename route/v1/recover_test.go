package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestGetRecoverStorageIsFailClosed(t *testing.T) {
	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/v1/recover/GoogleDrive?code=attacker-code", nil)
	recorder := httptest.NewRecorder()
	ctx := e.NewContext(request, recorder)

	if err := GetRecoverStorage(ctx); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGone)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}
