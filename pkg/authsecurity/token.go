package authsecurity

import (
	"crypto/ecdsa"
	"errors"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
)

const AccessTokenIssuer = "casaos"

var ErrInvalidAccessToken = errors.New("invalid access token")

// ValidateAccessToken verifies the signature, time-based claims, and the token
// class. CasaOS access and refresh tokens currently share a signing key, so an
// explicit issuer check is required to prevent a refresh token from being used
// as a long-lived bearer access token.
func ValidateAccessToken(token string, publicKey func() (*ecdsa.PublicKey, error)) (*commonjwt.Claims, error) {
	valid, claims, err := commonjwt.Validate(token, publicKey)
	if err != nil || !valid || claims == nil || claims.Issuer != AccessTokenIssuer {
		return nil, ErrInvalidAccessToken
	}
	return claims, nil
}
