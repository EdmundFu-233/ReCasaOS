package route

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSafeRequestLoggerOmitsQueryAndEscapesFields(t *testing.T) {
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	e := echo.New()
	e.Use(safeRequestLogger())
	e.GET("/test", func(ctx echo.Context) error { return ctx.NoContent(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/test?token=must-not-be-logged", nil)
	request.Header.Set("User-Agent", "agent\"}\n{\"forged\":true}")
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, request)

	line := strings.TrimSpace(output.String())
	if strings.Contains(line, "must-not-be-logged") {
		t.Fatalf("query secret appeared in log: %s", line)
	}
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log is not valid JSON: %v: %s", err, line)
	}
	if entry["path"] != "/test" {
		t.Fatalf("path = %#v", entry["path"])
	}
	if entry["user_agent"] != request.UserAgent() {
		t.Fatalf("user_agent = %#v", entry["user_agent"])
	}
}
