package route

import (
	"encoding/json"
	"log"
	"os"
	"time"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
)

var requestLogger = log.New(os.Stdout, "", 0)

const (
	requestLogMaxRecordBytes    = 4 << 10
	requestLogTruncationMarker  = "...[truncated]"
	requestLogRemoteMaxBytes    = 128
	requestLogHostMaxBytes      = 256
	requestLogMethodMaxBytes    = 32
	requestLogPathMaxBytes      = 1536
	requestLogUserAgentMaxBytes = 512
)

// safeRequestLogger intentionally records URL.Path rather than RequestURI.
// Structured JSON encoding and strict field/entry limits prevent request
// metadata from injecting forged log lines or amplifying log output. Error
// messages are reduced to fixed classes so they cannot disclose request data.
func safeRequestLogger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			start := time.Now()
			err := next(ctx)
			request := ctx.Request()
			response := ctx.Response()
			timestamp := time.Now().UTC().Format(time.RFC3339Nano)
			latency := time.Since(start).Nanoseconds()
			status := response.Status
			if err != nil {
				status = 500
				if httpError, ok := err.(*echo.HTTPError); ok {
					status = httpError.Code
				}
			}
			entry := map[string]interface{}{
				"time":       timestamp,
				"status":     status,
				"latency_ns": latency,
				"bytes_in":   request.ContentLength,
				"bytes_out":  response.Size,
			}
			var truncatedFields []string
			addBoundedRequestLogField(entry, &truncatedFields, "remote", request.RemoteAddr, requestLogRemoteMaxBytes)
			addBoundedRequestLogField(entry, &truncatedFields, "host", request.Host, requestLogHostMaxBytes)
			addBoundedRequestLogField(entry, &truncatedFields, "method", request.Method, requestLogMethodMaxBytes)
			addBoundedRequestLogField(entry, &truncatedFields, "path", request.URL.Path, requestLogPathMaxBytes)
			addBoundedRequestLogField(entry, &truncatedFields, "user_agent", request.UserAgent(), requestLogUserAgentMaxBytes)
			if err != nil {
				entry["error_class"] = requestLogErrorClass(status)
			}
			if len(truncatedFields) > 0 {
				entry["truncated_fields"] = truncatedFields
			}
			encoded, marshalErr := json.Marshal(entry)
			if marshalErr == nil && !requestLogRecordFits(encoded) {
				encodedRecordBytes := len(encoded) + 1
				entry = map[string]interface{}{
					"time":                   timestamp,
					"status":                 status,
					"latency_ns":             latency,
					"bytes_in":               request.ContentLength,
					"bytes_out":              response.Size,
					"request_fields_omitted": true,
					"encoded_record_bytes":   encodedRecordBytes,
				}
				if err != nil {
					entry["error_class"] = requestLogErrorClass(status)
				}
				encoded, marshalErr = json.Marshal(entry)
			}
			if marshalErr == nil && requestLogRecordFits(encoded) {
				requestLogger.Print(string(encoded))
			}
			return err
		}
	}
}

func requestLogRecordFits(encoded []byte) bool {
	// requestLogger has no prefix or flags, and Print appends exactly one
	// newline because JSON cannot contain an unescaped trailing newline.
	return len(encoded)+1 <= requestLogMaxRecordBytes
}

func requestLogErrorClass(status int) string {
	switch {
	case status == 401 || status == 403:
		return "authentication_error"
	case status >= 400 && status < 500:
		return "client_error"
	default:
		return "server_error"
	}
}

func addBoundedRequestLogField(entry map[string]interface{}, truncatedFields *[]string, name, value string, maxBytes int) {
	bounded, truncated := boundedRequestLogField(value, maxBytes)
	entry[name] = bounded
	if truncated {
		*truncatedFields = append(*truncatedFields, name)
	}
}

func boundedRequestLogField(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	if maxBytes <= 0 {
		return "", true
	}
	if maxBytes <= len(requestLogTruncationMarker) {
		return requestLogTruncationMarker[:maxBytes], true
	}

	prefixBytes := maxBytes - len(requestLogTruncationMarker)
	for prefixBytes > 0 && !utf8.RuneStart(value[prefixBytes]) {
		prefixBytes--
	}
	return value[:prefixBytes] + requestLogTruncationMarker, true
}

func privateNoStoreResponses() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			header := ctx.Response().Header()
			header.Set("Cache-Control", "private, no-store")
			header.Set("Pragma", "no-cache")
			header.Set("Referrer-Policy", "no-referrer")
			return next(ctx)
		}
	}
}
