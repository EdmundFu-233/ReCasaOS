package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/labstack/echo/v4"
)

func TestPostOperateFileOrDirRejectsMalformedJSON(t *testing.T) {
	response := invokeFileOperationHandler(t, `{`)
	if response.Code != common_err.CLIENT_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPostOperateFileOrDirRejectsRelativeSourceWithoutPanicking(t *testing.T) {
	response := invokeFileOperationHandler(t, `{"type":"copy","style":"overwrite","to":"/DATA","item":[{"from":"no-slash"}]}`)
	if response.Code != common_err.CLIENT_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPostOperateFileOrDirRejectsUnknownStyleBeforeQueueing(t *testing.T) {
	response := invokeFileOperationHandler(t, `{"type":"copy","style":"delete-existing","to":"/DATA","item":[{"from":"/DATA/source"}]}`)
	if response.Code != common_err.CLIENT_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPostOperateFileOrDirRejectsOversizedBody(t *testing.T) {
	body := strings.Repeat(" ", int(maxFileOperationRequestBodySize)+1)
	response := invokeFileOperationHandler(t, body)
	if response.Code != common_err.CLIENT_ERROR {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func invokeFileOperationHandler(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/file/operate", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := PostOperateFileOrDir(ctx); err != nil {
		t.Fatal(err)
	}
	return response
}
