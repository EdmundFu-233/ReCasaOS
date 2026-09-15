package oauthsecurity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

const (
	// codeVerifierBytes is the RFC 7636 entropy floor for an S256 verifier.
	codeVerifierBytes = 32
	// MaxCodeVerifierLength is the RFC 7636 maximum verifier length.
	MaxCodeVerifierLength = 128
	// MinCodeVerifierLength is the RFC 7636 minimum verifier length. A
	// base64url-encoded 32-byte value is 43 characters.
	MinCodeVerifierLength = 43
)

// ErrInvalidPKCE reports a verifier or challenge that violates RFC 7636.
var ErrInvalidPKCE = errors.New("invalid PKCE value")

// NewCodeVerifier returns a fresh high-entropy RFC 7636 code verifier from the
// supplied random source. Production callers must pass crypto/rand.Reader.
func NewCodeVerifier(random io.Reader) (string, error) {
	return newCodeVerifier(random)
}

func newCodeVerifier(random io.Reader) (string, error) {
	if random == nil {
		return "", ErrInvalidPKCE
	}
	buffer := make([]byte, codeVerifierBytes)
	if _, err := io.ReadFull(random, buffer); err != nil {
		clear(buffer)
		return "", ErrInvalidPKCE
	}
	verifier := base64.RawURLEncoding.EncodeToString(buffer)
	clear(buffer)
	return verifier, nil
}

// NewCodeVerifierSecure returns a verifier from the operating system CSPRNG.
func NewCodeVerifierSecure() (string, error) {
	return newCodeVerifier(rand.Reader)
}

// CodeChallengeS256 derives the RFC 7636 S256 challenge for a code verifier.
// The verifier must be a canonical base64url value of the reviewed length.
func CodeChallengeS256(verifier string) (string, error) {
	if !ValidCodeVerifier(verifier) {
		return "", ErrInvalidPKCE
	}
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// ValidCodeVerifier reports whether a value is a canonical unreserved
// base64url code verifier within the RFC 7636 length bounds.
func ValidCodeVerifier(verifier string) bool {
	if len(verifier) < MinCodeVerifierLength || len(verifier) > MaxCodeVerifierLength {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		switch character := verifier[i]; {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_', character == '~':
		default:
			return false
		}
	}
	return true
}
