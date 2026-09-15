package oauthsecurity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxTokenResponseBytes bounds the token-endpoint response body.
	MaxTokenResponseBytes = 64 << 10
	// DefaultExchangeTimeout bounds one authorization-code exchange.
	DefaultExchangeTimeout = 15 * time.Second
	maxCodeBytes           = 2048
	maxTokenFieldBytes     = 4096
	maxExpiresInSeconds    = 7 * 24 * 60 * 60
)

// ErrExchange reports a failed or malformed token exchange. It intentionally
// carries no response body, authorization code, verifier, or secret.
var ErrExchange = errors.New("OAuth token exchange failed")

// ExchangeError reports a non-200 token endpoint response without its body.
type ExchangeError struct {
	StatusCode int
}

func (e *ExchangeError) Error() string {
	return fmt.Sprintf("OAuth token endpoint returned status %d", e.StatusCode)
}

func (e *ExchangeError) Unwrap() error { return ErrExchange }

// Token is a bounded successful token-endpoint result.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    time.Duration
	Scope        string
}

// Doer performs one HTTP request. Production uses a hardened client; tests
// inject fakes. It must not follow redirects.
type Doer interface {
	Do(request *http.Request) (*http.Response, error)
}

// Exchanger performs authorization-code exchanges.
type Exchanger struct {
	client  Doer
	timeout time.Duration
}

// NewExchanger builds an Exchanger with the hardened production client.
func NewExchanger() (*Exchanger, error) {
	client := &http.Client{
		// Environment proxies, redirects, and compression are deliberately
		// disabled: the token request carries a secret and must go to exactly
		// the configured endpoint.
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			DisableCompression:    true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return NewExchangerWithClient(client, DefaultExchangeTimeout)
}

// NewExchangerWithClient builds an Exchanger over an injected Doer.
func NewExchangerWithClient(client Doer, timeout time.Duration) (*Exchanger, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	if timeout == 0 {
		timeout = DefaultExchangeTimeout
	}
	if timeout < time.Second || timeout > 2*time.Minute {
		return nil, ErrInvalidConfiguration
	}
	return &Exchanger{client: client, timeout: timeout}, nil
}

// Exchange redeems one authorization code with its PKCE verifier. The request
// is posted to exactly provider.TokenURL and the response is bounded; no
// provider response body reaches the returned error.
func (e *Exchanger) Exchange(ctx context.Context, provider Provider, code, verifier string) (Token, error) {
	if e == nil || e.client == nil || ctx == nil {
		return Token{}, ErrInvalidConfiguration
	}
	if err := validateProviderForExchange(provider); err != nil {
		return Token{}, err
	}
	if !validAuthorizationCode(code) || !ValidCodeVerifier(verifier) {
		return Token{}, ErrInvalidRequest
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("client_id", provider.ClientID)
	form.Set("redirect_uri", provider.RedirectURI)
	if provider.AuthStyle == AuthStyleBody {
		form.Set("client_secret", provider.ClientSecret)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, ErrInvalidRequest
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if provider.AuthStyle == AuthStyleBasic {
		request.SetBasicAuth(provider.ClientID, provider.ClientSecret)
	}

	operationContext, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	response, err := e.client.Do(request.WithContext(operationContext))
	if err != nil {
		return Token{}, ErrExchange
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return Token{}, ErrExchange
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return Token{}, &ExchangeError{StatusCode: response.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxTokenResponseBytes+1))
	if err != nil {
		clear(body)
		return Token{}, ErrExchange
	}
	defer clear(body)
	if len(body) > MaxTokenResponseBytes {
		return Token{}, ErrExchange
	}
	return parseTokenResponse(body)
}

func parseTokenResponse(body []byte) (Token, error) {
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil {
		return Token{}, ErrExchange
	}
	if !validTokenField(payload.AccessToken) || (payload.RefreshToken != "" && !validTokenField(payload.RefreshToken)) {
		return Token{}, ErrExchange
	}
	if !strings.EqualFold(payload.TokenType, "bearer") {
		return Token{}, ErrExchange
	}
	if payload.ExpiresIn < 0 || payload.ExpiresIn > maxExpiresInSeconds {
		return Token{}, ErrExchange
	}
	if len(payload.Scope) > maxTokenFieldBytes {
		return Token{}, ErrExchange
	}
	return Token{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    time.Duration(payload.ExpiresIn) * time.Second,
		Scope:        payload.Scope,
	}, nil
}

func validTokenField(value string) bool {
	if value == "" || len(value) > maxTokenFieldBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validAuthorizationCode(code string) bool {
	if code == "" || len(code) > maxCodeBytes || strings.TrimSpace(code) != code {
		return false
	}
	for i := 0; i < len(code); i++ {
		character := code[i]
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateProviderForExchange(provider Provider) error {
	if !ValidProviderName(provider.Name) || !validClientID(provider.ClientID) || !validClientSecret(provider.ClientSecret) {
		return ErrInvalidConfiguration
	}
	if _, err := ParsePublicHTTPSURL(provider.TokenURL); err != nil {
		return ErrInvalidConfiguration
	}
	if _, err := ParsePublicHTTPSURL(provider.RedirectURI); err != nil {
		return ErrInvalidConfiguration
	}
	if provider.AuthStyle != AuthStyleBody && provider.AuthStyle != AuthStyleBasic {
		return ErrInvalidConfiguration
	}
	if len(provider.Scopes) == 0 || len(provider.Scopes) > maxScopes {
		return ErrInvalidConfiguration
	}
	for _, scope := range provider.Scopes {
		if len(scope) > maxScopeBytes || !validScopeToken(scope) {
			return ErrInvalidConfiguration
		}
	}
	return nil
}
