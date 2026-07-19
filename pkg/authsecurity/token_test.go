package authsecurity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
)

func TestValidateAccessTokenSeparatesAccessAndRefreshTokens(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := func() (*ecdsa.PublicKey, error) { return &privateKey.PublicKey, nil }

	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateAccessToken(accessToken, publicKey)
	if err != nil {
		t.Fatalf("access token rejected: %v", err)
	}
	if claims.ID != 42 || claims.Username != "admin" {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	refreshToken, err := commonjwt.GetRefreshToken("admin", privateKey, 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(refreshToken, publicKey); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("refresh token error = %v, want ErrInvalidAccessToken", err)
	}
}

func TestValidateAccessTokenRejectsExpiredAndWrongKeyTokens(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expired, err := commonjwt.GenerateToken("admin", privateKey, 1, AccessTokenIssuer, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(expired, func() (*ecdsa.PublicKey, error) { return &privateKey.PublicKey, nil }); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expired token error = %v, want ErrInvalidAccessToken", err)
	}

	accessToken, err := commonjwt.GetAccessToken("admin", privateKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAccessToken(accessToken, func() (*ecdsa.PublicKey, error) { return &otherKey.PublicKey, nil }); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong-key token error = %v, want ErrInvalidAccessToken", err)
	}
}
