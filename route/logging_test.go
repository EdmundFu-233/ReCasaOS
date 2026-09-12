package route

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
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

func TestSafeRequestLoggerBoundsAttackerControlledFields(t *testing.T) {
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	const (
		remoteTail    = "REMOTE_TAIL_MUST_NOT_BE_LOGGED"
		hostTail      = "HOST_TAIL_MUST_NOT_BE_LOGGED"
		pathTail      = "PATH_TAIL_MUST_NOT_BE_LOGGED"
		userAgentTail = "USER_AGENT_TAIL_MUST_NOT_BE_LOGGED"
		errorSecret   = "ERROR_SECRET_MUST_NOT_BE_LOGGED"
	)

	e := echo.New()
	e.Use(safeRequestLogger())
	e.Any("/*", func(echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, errorSecret)
	})
	request := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("p", 4096)+pathTail, nil)
	request.RemoteAddr = strings.Repeat("r", 1024) + remoteTail
	request.Host = strings.Repeat("h", 1024) + hostTail
	request.Header.Set("User-Agent", strings.Repeat("u", 4096)+userAgentTail)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, request)

	if output.Len() > requestLogMaxRecordBytes {
		t.Fatalf("log record has %d bytes, want at most %d", output.Len(), requestLogMaxRecordBytes)
	}
	line := strings.TrimSuffix(output.String(), "\n")
	for _, tail := range []string{remoteTail, hostTail, pathTail, userAgentTail, errorSecret} {
		if strings.Contains(line, tail) {
			t.Fatalf("discarded suffix %q appeared in log", tail)
		}
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log is not valid JSON: %v: %s", err, line)
	}
	truncatedFields, ok := entry["truncated_fields"].([]interface{})
	if !ok {
		t.Fatalf("truncated_fields = %#v", entry["truncated_fields"])
	}
	wantFields := []string{"remote", "host", "path", "user_agent"}
	if len(truncatedFields) != len(wantFields) {
		t.Fatalf("truncated_fields = %#v", truncatedFields)
	}
	for index, want := range wantFields {
		if truncatedFields[index] != want {
			t.Fatalf("truncated_fields[%d] = %#v, want %q", index, truncatedFields[index], want)
		}
	}
	if entry["error_class"] != "client_error" {
		t.Fatalf("error_class = %#v", entry["error_class"])
	}
}

func TestSafeRequestLoggerOmitsFieldsWhenEscapingExceedsLimit(t *testing.T) {
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	e := echo.New()
	e.Use(safeRequestLogger())
	e.GET("/test", func(echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, "safe classification only")
	})
	request := httptest.NewRequest(http.MethodGet, "/test?token=must-not-be-logged", nil)
	request.Host = strings.Repeat("<", requestLogHostMaxBytes)
	request.Header.Set("User-Agent", strings.Repeat("<", requestLogUserAgentMaxBytes))
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, request)

	if output.Len() > requestLogMaxRecordBytes {
		t.Fatalf("log record has %d bytes, want at most %d", output.Len(), requestLogMaxRecordBytes)
	}
	line := strings.TrimSuffix(output.String(), "\n")
	if strings.Contains(line, "must-not-be-logged") {
		t.Fatalf("query secret appeared in fallback log: %s", line)
	}
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("log is not valid JSON: %v: %s", err, line)
	}
	if entry["request_fields_omitted"] != true {
		t.Fatalf("request_fields_omitted = %#v", entry["request_fields_omitted"])
	}
	if entry["error_class"] != "client_error" {
		t.Fatalf("error_class = %#v", entry["error_class"])
	}
	if encodedBytes, ok := entry["encoded_record_bytes"].(float64); !ok || encodedBytes <= requestLogMaxRecordBytes {
		t.Fatalf("encoded_record_bytes = %#v", entry["encoded_record_bytes"])
	}
	for _, field := range []string{"remote", "host", "method", "path", "user_agent", "error"} {
		if _, ok := entry[field]; ok {
			t.Fatalf("fallback retained attacker-controlled field %q", field)
		}
	}
}

func TestBoundedRequestLogFieldPreservesUTF8(t *testing.T) {
	const maxBytes = 31
	value := strings.Repeat("界", 32)
	bounded, truncated := boundedRequestLogField(value, maxBytes)
	if !truncated {
		t.Fatal("long field was not marked truncated")
	}
	if len(bounded) > maxBytes {
		t.Fatalf("bounded field has %d bytes, want at most %d", len(bounded), maxBytes)
	}
	if !utf8.ValidString(bounded) {
		t.Fatalf("bounded field is not valid UTF-8: %q", bounded)
	}
	if !strings.HasSuffix(bounded, requestLogTruncationMarker) {
		t.Fatalf("bounded field lacks truncation marker: %q", bounded)
	}
}

func TestBoundedRequestLogFieldEnforcesExactBoundary(t *testing.T) {
	const maxBytes = 32
	atLimit := strings.Repeat("a", maxBytes)
	if bounded, truncated := boundedRequestLogField(atLimit, maxBytes); truncated || bounded != atLimit {
		t.Fatalf("at-limit field = %q, truncated = %t", bounded, truncated)
	}

	overLimit := atLimit + "b"
	bounded, truncated := boundedRequestLogField(overLimit, maxBytes)
	if !truncated {
		t.Fatal("over-limit field was not marked truncated")
	}
	if len(bounded) != maxBytes {
		t.Fatalf("bounded field has %d bytes, want %d", len(bounded), maxBytes)
	}
	if !strings.HasSuffix(bounded, requestLogTruncationMarker) {
		t.Fatalf("bounded field lacks truncation marker: %q", bounded)
	}
}

func TestRequestLogRecordLimitIncludesLoggerNewline(t *testing.T) {
	if !requestLogRecordFits(bytes.Repeat([]byte{'a'}, requestLogMaxRecordBytes-1)) {
		t.Fatal("payload that exactly fits with its newline was rejected")
	}
	if requestLogRecordFits(bytes.Repeat([]byte{'a'}, requestLogMaxRecordBytes)) {
		t.Fatal("payload that exceeds the record limit after its newline was accepted")
	}
}

func TestSafeRequestLoggerInvalidUTF8RemainsBounded(t *testing.T) {
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	e := echo.New()
	e.Use(safeRequestLogger())
	e.GET("/test", func(ctx echo.Context) error { return ctx.NoContent(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Host = string(bytes.Repeat([]byte{0xff}, requestLogHostMaxBytes))
	request.Header.Set("User-Agent", string(bytes.Repeat([]byte{0xff}, requestLogUserAgentMaxBytes)))
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, request)

	if output.Len() > requestLogMaxRecordBytes {
		t.Fatalf("log record has %d bytes, want at most %d", output.Len(), requestLogMaxRecordBytes)
	}
	line := strings.TrimSuffix(output.String(), "\n")
	if !json.Valid([]byte(line)) {
		t.Fatalf("log is not valid JSON: %s", line)
	}
}

func TestRequestLoggerBoundsLargeUnauthenticatedV1AndV2Requests(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	const (
		authorizationSecret = "AUTHORIZATION_SECRET_MUST_NOT_BE_LOGGED"
		proxySecret         = "PROXY_SECRET_MUST_NOT_BE_LOGGED"
		cookieSecret        = "COOKIE_SECRET_MUST_NOT_BE_LOGGED"
		zerotierSecret      = "ZEROTIER_SECRET_MUST_NOT_BE_LOGGED"
		apiKeySecret        = "API_KEY_SECRET_MUST_NOT_BE_LOGGED"
		querySecret         = "QUERY_SECRET_MUST_NOT_BE_LOGGED"
		userAgentTail       = "USER_AGENT_TAIL_MUST_NOT_BE_LOGGED"
	)
	largeUserAgent := strings.Repeat("u", 900<<10) + userAgentTail
	tests := []struct {
		name       string
		handler    http.Handler
		method     string
		target     string
		wantStatus map[int]bool
	}{
		{
			name:       "v1",
			handler:    InitV1Router(),
			method:     http.MethodPost,
			target:     "http://device.test/v1/file/recovery/inventory?token=" + querySecret,
			wantStatus: map[int]bool{http.StatusBadRequest: true, http.StatusUnauthorized: true},
		},
		{
			name:       "v2",
			handler:    InitV2Router(),
			method:     http.MethodGet,
			target:     "http://device.test" + V2APIPath + "/file/upload?token=" + querySecret,
			wantStatus: map[int]bool{http.StatusUnauthorized: true},
		},
	}

	for _, test := range tests {
		request := httptest.NewRequest(test.method, test.target, nil)
		request.RemoteAddr = "198.51.100.20:43120"
		request.Header.Set("Authorization", "Bearer "+authorizationSecret)
		request.Header.Set("Proxy-Authorization", proxySecret)
		request.Header.Set("Cookie", "session="+cookieSecret)
		request.Header.Set("X-ZT1-AUTH", zerotierSecret)
		request.Header.Set("X-API-Key", apiKeySecret)
		request.Header.Set("User-Agent", largeUserAgent)
		response := httptest.NewRecorder()
		test.handler.ServeHTTP(response, request)
		if !test.wantStatus[response.Code] {
			t.Fatalf("%s status = %d, body = %s", test.name, response.Code, response.Body.String())
		}
	}

	logs := output.String()
	for _, secret := range []string{
		authorizationSecret,
		proxySecret,
		cookieSecret,
		zerotierSecret,
		apiKeySecret,
		querySecret,
		userAgentTail,
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("secret %q appeared in request logs", secret)
		}
	}
	lines := strings.Split(strings.TrimSuffix(logs, "\n"), "\n")
	if len(lines) != len(tests) {
		t.Fatalf("got %d log lines, want %d: %s", len(lines), len(tests), logs)
	}
	for index, line := range lines {
		if len(line)+1 > requestLogMaxRecordBytes {
			t.Fatalf("record %d has %d bytes, want at most %d", index, len(line)+1, requestLogMaxRecordBytes)
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d is not valid JSON: %v: %s", index, err, line)
		}
		if entry["error_class"] != "authentication_error" {
			t.Fatalf("line %d error_class = %#v", index, entry["error_class"])
		}
	}
}

func TestSafeRequestLoggerConcurrentEntriesRemainBounded(t *testing.T) {
	var output bytes.Buffer
	previous := requestLogger
	requestLogger = log.New(&output, "", 0)
	t.Cleanup(func() { requestLogger = previous })

	e := echo.New()
	e.Use(safeRequestLogger())
	e.GET("/test", func(ctx echo.Context) error { return ctx.NoContent(http.StatusNoContent) })

	const requestCount = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(requestCount)
	for range requestCount {
		go func() {
			defer waitGroup.Done()
			request := httptest.NewRequest(http.MethodGet, "/test", nil)
			request.Header.Set("User-Agent", strings.Repeat("u", 64<<10))
			recorder := httptest.NewRecorder()
			e.ServeHTTP(recorder, request)
		}()
	}
	waitGroup.Wait()

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != requestCount {
		t.Fatalf("got %d log lines, want %d", len(lines), requestCount)
	}
	for index, line := range lines {
		if len(line)+1 > requestLogMaxRecordBytes {
			t.Fatalf("record %d has %d bytes, want at most %d", index, len(line)+1, requestLogMaxRecordBytes)
		}
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %s", index, line)
		}
	}
}
