package route

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

// credentialQueryParameterNames is deliberately broader than the legacy
// `token` lookup. Rejecting common credential-shaped names prevents a future
// route from accidentally reintroducing a URL credential even when the
// current authentication middleware ignores that name.
var credentialQueryParameterNames = map[string]struct{}{
	"token":         {},
	"access_token":  {},
	"authorization": {},
	"api_key":       {},
	"apikey":        {},
}

func hasCredentialQueryParameter(request *http.Request) bool {
	if request == nil || request.URL == nil {
		return false
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		// A malformed query is rejected as part of the credential transport
		// boundary instead of being silently discarded by URL.Query().
		return true
	}
	for key := range query {
		if _, forbidden := credentialQueryParameterNames[strings.ToLower(key)]; forbidden {
			return true
		}
	}
	return false
}

func hasDuplicateAuthorizationHeader(request *http.Request) bool {
	return request != nil && len(request.Header.Values(echo.HeaderAuthorization)) > 1
}

// rejectCredentialTransport runs before JWT extraction. A valid header must
// not make a request containing a credential-shaped query parameter safe: the
// URL has already become observable to browser history, Referer, and
// intermediary logs by that point. Duplicate Authorization fields are also
// rejected rather than leaving header-combination behavior to a proxy or
// authentication library.
func rejectCredentialTransport() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(context echo.Context) error {
			if hasCredentialQueryParameter(context.Request()) || hasDuplicateAuthorizationHeader(context.Request()) {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid credential transport")
			}
			return next(context)
		}
	}
}

func rejectCredentialTransportHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if hasCredentialQueryParameter(request) || hasDuplicateAuthorizationHeader(request) {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(writer, request)
	})
}
