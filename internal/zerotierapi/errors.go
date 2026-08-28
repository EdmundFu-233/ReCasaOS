package zerotierapi

import (
	"context"
	"errors"
)

// FailureClass maps transport and boundary failures to a fixed diagnostic
// vocabulary. Callers may log the returned value without disclosing state-file
// paths, credentials, daemon responses, or attacker-controlled error text.
func FailureClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrZeroTierUnsafeEndpoint):
		return "unsafe_endpoint"
	case errors.Is(err, ErrZeroTierRequestTooLarge):
		return "request_too_large"
	case errors.Is(err, ErrZeroTierResponseTooLarge):
		return "response_too_large"
	case errors.Is(err, ErrZeroTierRedirect):
		return "redirect"
	case errors.Is(err, ErrZeroTierUntrustedPeer):
		return "untrusted_peer"
	case errors.Is(err, ErrZeroTierPeerVerificationUnavailable):
		return "peer_verification_unavailable"
	default:
		return "upstream_error"
	}
}
