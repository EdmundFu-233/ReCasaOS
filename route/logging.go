package route

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/labstack/echo/v4"
)

var requestLogger = log.New(os.Stdout, "", 0)

// safeRequestLogger intentionally records URL.Path rather than RequestURI.
// Structured JSON encoding prevents Host, User-Agent, and error text from
// injecting fields or forged log lines.
func safeRequestLogger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			start := time.Now()
			err := next(ctx)
			request := ctx.Request()
			response := ctx.Response()
			status := response.Status
			if err != nil {
				status = 500
				if httpError, ok := err.(*echo.HTTPError); ok {
					status = httpError.Code
				}
			}
			entry := map[string]interface{}{
				"time":       time.Now().UTC().Format(time.RFC3339Nano),
				"remote":     request.RemoteAddr,
				"host":       request.Host,
				"method":     request.Method,
				"path":       request.URL.Path,
				"user_agent": request.UserAgent(),
				"status":     status,
				"latency_ns": time.Since(start).Nanoseconds(),
				"bytes_in":   request.ContentLength,
				"bytes_out":  response.Size,
			}
			if err != nil {
				entry["error"] = err.Error()
			}
			if encoded, marshalErr := json.Marshal(entry); marshalErr == nil {
				requestLogger.Print(string(encoded))
			}
			return err
		}
	}
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
