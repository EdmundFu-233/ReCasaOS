package oauthsecurity

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	// ErrProviderAccessDenied reports a provider refusal the operator cannot
	// retry: access denied, invalid grant, or interaction required.
	ErrProviderAccessDenied = errors.New("OAuth provider denied the request")
	// ErrProviderBadRequest reports a malformed token request. It signals a
	// configuration bug, never a provider outage.
	ErrProviderBadRequest = errors.New("OAuth provider rejected the token request")
	// ErrProviderRateLimited reports provider throttling. Callers may retry
	// with backoff.
	ErrProviderRateLimited = errors.New("OAuth provider throttled the request")
	// ErrProviderServer reports a provider-side failure. Callers may retry
	// with backoff.
	ErrProviderServer = errors.New("OAuth provider failed the request")
)

// ProviderError classifies one token-endpoint failure. Code is always drawn
// from the curated tables below or the literal "unmapped": raw provider
// strings (descriptions, URIs, trace IDs) never reach callers or logs.
type ProviderError struct {
	Provider   string
	Code       string
	StatusCode int
	Retryable  bool
	kind       error
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("OAuth provider %s token error %s (status %d)", e.Provider, e.Code, e.StatusCode)
}

func (e *ProviderError) Unwrap() []error { return []error{e.kind, ErrExchange} }

// ClassifyTokenError maps one token-endpoint failure to a redacted sentinel.
// Unknown providers fall back to status-based classification; unrecognized
// codes collapse to "unmapped" so provider internals cannot leak.
func ClassifyTokenError(provider string, status int, code string) *ProviderError {
	name := "unknown"
	if ValidProviderName(provider) {
		name = provider
	}
	normalized := normalizeErrorCode(code)
	sentinel, mapped := lookupProviderCode(name, normalized)
	if !mapped {
		sentinel, normalized = classifyByStatus(status), "unmapped"
	}
	return &ProviderError{
		Provider:   name,
		Code:       normalized,
		StatusCode: status,
		Retryable:  sentinel == ErrProviderRateLimited || sentinel == ErrProviderServer,
		kind:       sentinel,
	}
}

func normalizeErrorCode(code string) string {
	trimmed := strings.ToLower(strings.TrimSpace(code))
	if trimmed == "" || len(trimmed) > 64 {
		return ""
	}
	for i := 0; i < len(trimmed); i++ {
		switch character := trimmed[i]; {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '_', character == '-', character == '.':
		default:
			return ""
		}
	}
	return trimmed
}

func lookupProviderCode(provider, code string) (error, bool) {
	if code == "" {
		return nil, false
	}
	if table, known := providerErrorCodes[provider]; known {
		if sentinel, mapped := table[code]; mapped {
			return sentinel, true
		}
	}
	if sentinel, mapped := rfcErrorCodes[code]; mapped {
		return sentinel, true
	}
	return nil, false
}

func classifyByStatus(status int) error {
	switch {
	case status == http.StatusTooManyRequests:
		return ErrProviderRateLimited
	case status >= 500 || status == http.StatusRequestTimeout || status == http.StatusLocked:
		return ErrProviderServer
	case status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrProviderBadRequest
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusGone:
		return ErrProviderBadRequest
	default:
		return ErrExchange
	}
}

// rfcErrorCodes covers RFC 6749 section 5.2 token error codes.
var rfcErrorCodes = map[string]error{
	"invalid_request":         ErrProviderBadRequest,
	"invalid_client":          ErrProviderBadRequest,
	"invalid_grant":           ErrProviderAccessDenied,
	"unauthorized_client":     ErrProviderAccessDenied,
	"unsupported_grant_type":  ErrProviderBadRequest,
	"invalid_scope":           ErrProviderBadRequest,
	"access_denied":           ErrProviderAccessDenied,
	"server_error":            ErrProviderServer,
	"temporarily_unavailable": ErrProviderServer,
}

// providerErrorCodes adds per-provider codes that are not in RFC 6749.
// Every key is a stable documented provider code; values are the same
// redacted sentinels, so adding a provider cannot leak new detail.
var providerErrorCodes = map[string]map[string]error{
	"google": {
		"slow_down":             ErrProviderRateLimited,
		"authorization_pending": ErrProviderRateLimited,
		"expired_token":         ErrProviderAccessDenied,
	},
	"microsoft": {
		"interaction_required":      ErrProviderAccessDenied,
		"consent_required":          ErrProviderAccessDenied,
		"bad_verification_code":     ErrProviderBadRequest,
		"expired_verification_code": ErrProviderAccessDenied,
	},
	"dropbox": {
		"expired_access_token": ErrProviderAccessDenied,
		"invalid_access_token": ErrProviderAccessDenied,
		"rate_limit":           ErrProviderRateLimited,
	},
	"onedrive": {
		"interaction_required":      ErrProviderAccessDenied,
		"consent_required":          ErrProviderAccessDenied,
		"bad_verification_code":     ErrProviderBadRequest,
		"expired_verification_code": ErrProviderAccessDenied,
	},
}
