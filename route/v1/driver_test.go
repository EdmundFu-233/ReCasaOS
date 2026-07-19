package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestListDriverInfoHidesDisabledOAuthProviders(t *testing.T) {
	e := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/v1/driver/list", nil)
	recorder := httptest.NewRecorder()
	if err := ListDriverInfo(e.NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data == nil || len(response.Data) != 0 {
		t.Fatalf("disabled OAuth provider list = %#v, want empty array", response.Data)
	}
}
