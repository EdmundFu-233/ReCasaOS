package oauthsecurity

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestClassifyRFCcodes(t *testing.T) {
	cases := map[string]error{
		"invalid_grant":           ErrProviderAccessDenied,
		"access_denied":           ErrProviderAccessDenied,
		"unauthorized_client":     ErrProviderAccessDenied,
		"invalid_request":         ErrProviderBadRequest,
		"invalid_client":          ErrProviderBadRequest,
		"server_error":            ErrProviderServer,
		"temporarily_unavailable": ErrProviderServer,
	}
	for code, sentinel := range cases {
		classified := ClassifyTokenError("google", http.StatusBadRequest, code)
		if !errors.Is(classified, sentinel) {
			t.Fatalf("%s: got %v, want %v", code, classified, sentinel)
		}
		if !errors.Is(classified, ErrExchange) {
			t.Fatalf("%s: must wrap ErrExchange", code)
		}
		if classified.Code != code || classified.Provider != "google" {
			t.Fatalf("%s: identity not preserved: %+v", code, classified)
		}
	}
}

func TestClassifyProviderCodes(t *testing.T) {
	cases := []struct {
		provider string
		code     string
		sentinel error
	}{
		{"google", "slow_down", ErrProviderRateLimited},
		{"microsoft", "interaction_required", ErrProviderAccessDenied},
		{"onedrive", "consent_required", ErrProviderAccessDenied},
		{"dropbox", "rate_limit", ErrProviderRateLimited},
		{"dropbox", "expired_access_token", ErrProviderAccessDenied},
	}
	for _, tc := range cases {
		classified := ClassifyTokenError(tc.provider, http.StatusBadRequest, tc.code)
		if !errors.Is(classified, tc.sentinel) {
			t.Fatalf("%s/%s: got %v, want %v", tc.provider, tc.code, classified, tc.sentinel)
		}
	}
}

func TestClassifyStatusFallback(t *testing.T) {
	if got := ClassifyTokenError("google", http.StatusTooManyRequests, "something_new"); !errors.Is(got, ErrProviderRateLimited) || got.Code != "unmapped" {
		t.Fatalf("429 fallback: %+v", got)
	}
	if got := ClassifyTokenError("google", http.StatusBadGateway, ""); !errors.Is(got, ErrProviderServer) || got.Code != "unmapped" {
		t.Fatalf("502 fallback: %+v", got)
	}
	if got := ClassifyTokenError("google", http.StatusUnauthorized, ""); !errors.Is(got, ErrProviderBadRequest) {
		t.Fatalf("401 fallback: %+v", got)
	}
	if got := ClassifyTokenError("google", http.StatusTeapot, ""); !errors.Is(got, ErrExchange) {
		t.Fatalf("418 fallback: %+v", got)
	}
}

func TestClassifyNeverLeaksRawCodes(t *testing.T) {
	leaky := []string{
		"AADSTS9002325: proof of presence required. trace-id=abc",
		"https://login.microsoftonline.com/error?code=50058",
		"  INVALID_GRANT  ",
		"code with spaces and\ttabs",
		strings.Repeat("x", 65),
		"",
		"../../../etc/passwd",
	}
	for _, raw := range leaky {
		classified := ClassifyTokenError("microsoft", http.StatusBadRequest, raw)
		if strings.Contains(classified.Error(), "AADSTS") ||
			strings.Contains(classified.Error(), "trace-id") ||
			strings.Contains(classified.Error(), "http") ||
			strings.Contains(classified.Error(), "..") {
			t.Fatalf("raw code leaked for %q: %v", raw, classified)
		}
		if classified.Code == "" {
			t.Fatalf("code must never be empty for %q", raw)
		}
	}
	// Case-insensitive known codes still classify.
	if got := ClassifyTokenError("google", http.StatusBadRequest, "  Invalid_Grant "); !errors.Is(got, ErrProviderAccessDenied) || got.Code != "invalid_grant" {
		t.Fatalf("normalization: %+v", got)
	}
}

func TestClassifyUnknownProvider(t *testing.T) {
	classified := ClassifyTokenError("../../evil", http.StatusBadRequest, "invalid_grant")
	if classified.Provider != "unknown" {
		t.Fatalf("provider must collapse, got %q", classified.Provider)
	}
	if !errors.Is(classified, ErrProviderAccessDenied) {
		t.Fatalf("RFC code still applies: %+v", classified)
	}
}

func TestClassifyRetryable(t *testing.T) {
	if got := ClassifyTokenError("dropbox", 400, "rate_limit"); !got.Retryable {
		t.Fatalf("rate limit must be retryable")
	}
	if got := ClassifyTokenError("google", 502, ""); !got.Retryable {
		t.Fatalf("server error must be retryable")
	}
	if got := ClassifyTokenError("google", 400, "invalid_grant"); got.Retryable {
		t.Fatalf("denied must not be retryable")
	}
}
