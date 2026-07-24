package publicfiles

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	publicVerifierPrefix = "recasaos-public-verifier-v1:sha256:"

	publicBearerPrefix      = "rc1_"
	publicBearerRandomBytes = 32
	publicBearerEncodedLen  = (publicBearerRandomBytes*8 + 5) / 6
	publicBearerLen         = len(publicBearerPrefix) + publicBearerEncodedLen
	publicBearerMinDistinct = 16

	// publicVerifierFileMaxBytes is also the only accepted verifier-file size.
	// The final LF is part of the versioned format; CRLF and missing or
	// additional whitespace are deliberately rejected.
	publicVerifierFileMaxBytes = len(publicVerifierPrefix) + sha256.Size*2 + 1
)

var (
	strictPublicBearerEncoding = base64.RawURLEncoding.Strict()
	errInvalidPublicVerifier   = errors.New("public verifier must use the exact recasaos-public-verifier-v1 SHA-256 format")
)

// parsePublicVerifier accepts only:
//
//	recasaos-public-verifier-v1:sha256:<64 lowercase hexadecimal characters>\n
//
// The versioned prefix keeps a legacy 64-character bearer from being
// interpreted as a verifier. The decoded verifier is always exactly one
// SHA-256 digest.
func parsePublicVerifier(serialized []byte) ([sha256.Size]byte, error) {
	var verifier [sha256.Size]byte
	if len(serialized) != publicVerifierFileMaxBytes ||
		string(serialized[:len(publicVerifierPrefix)]) != publicVerifierPrefix ||
		serialized[len(serialized)-1] != '\n' {
		return verifier, errInvalidPublicVerifier
	}

	encoded := serialized[len(publicVerifierPrefix) : len(serialized)-1]
	for _, value := range encoded {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return verifier, errInvalidPublicVerifier
		}
	}
	if _, err := hex.Decode(verifier[:], encoded); err != nil {
		return [sha256.Size]byte{}, errInvalidPublicVerifier
	}
	return verifier, nil
}

// validPublicBearer recognizes only the versioned bearer format: rc1_ followed
// by the canonical, unpadded base64url encoding of exactly 32 bytes. The
// diversity floor rejects obvious repeated-byte mistakes, but cannot prove
// that the administrator used a cryptographically secure random generator.
func validPublicBearer(candidate string) bool {
	if len(candidate) != publicBearerLen ||
		candidate[:len(publicBearerPrefix)] != publicBearerPrefix {
		return false
	}

	var decoded [publicBearerRandomBytes]byte
	count, err := strictPublicBearerEncoding.Decode(
		decoded[:],
		[]byte(candidate[len(publicBearerPrefix):]),
	)
	if err != nil || count != len(decoded) {
		return false
	}

	var distinct [256]bool
	distinctCount := 0
	for _, value := range decoded {
		if !distinct[value] {
			distinct[value] = true
			distinctCount++
		}
	}
	return distinctCount >= publicBearerMinDistinct
}

// digestPublicBearer intentionally hashes every candidate, including malformed
// candidates. Callers can combine this fixed-size digest with
// validPublicBearer and subtle.ConstantTimeCompare without introducing a
// malformed-input path that skips hashing.
func digestPublicBearer(candidate string) [sha256.Size]byte {
	return sha256.Sum256([]byte(candidate))
}
