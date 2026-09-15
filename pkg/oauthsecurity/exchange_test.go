package oauthsecurity

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

func exchangeProvider() Provider {
	return Provider{
		Name:         "google_drive",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		ClientID:     "1234567890.apps.googleusercontent.com",
		ClientSecret: "s3cret-value",
		RedirectURI:  "https://casaos.example.com/api/v1/recover/GoogleDrive",
		Scopes:       []string{"drive.readonly"},
		AuthStyle:    AuthStyleBody,
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestExchangeHappyPathBodyAuthStyle(t *testing.T) {
	var captured *http.Request
	var capturedBody string
	exchanger, err := NewExchangerWithClient(doerFunc(func(request *http.Request) (*http.Response, error) {
		captured = request
		content, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatalf("read request body: %v", readErr)
		}
		capturedBody = string(content)
		return jsonResponse(http.StatusOK, `{
			"access_token": "access-token",
			"refresh_token": "refresh-token",
			"token_type": "bearer",
			"expires_in": 3599,
			"scope": "drive.readonly"
		}`), nil
	}), time.Second)
	if err != nil {
		t.Fatalf("NewExchangerWithClient: %v", err)
	}
	token, err := exchanger.Exchange(context.Background(), exchangeProvider(), "auth-code", testVerifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "access-token" || token.RefreshToken != "refresh-token" ||
		token.TokenType != "Bearer" || token.ExpiresIn != 3599*time.Second || token.Scope != "drive.readonly" {
		t.Fatalf("token = %+v", token)
	}
	if captured == nil || captured.Method != http.MethodPost {
		t.Fatalf("request = %+v", captured)
	}
	if captured.URL.String() != "https://oauth2.googleapis.com/token" || captured.URL.RawQuery != "" {
		t.Fatalf("request URL = %q", captured.URL.String())
	}
	if captured.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", captured.Header.Get("Content-Type"))
	}
	if captured.Header.Get("Authorization") != "" {
		t.Fatal("body auth style sent an authorization header")
	}
	form := capturedBody
	for _, required := range []string{
		"grant_type=authorization_code",
		"code=auth-code",
		"code_verifier=" + testVerifier,
		"client_id=1234567890.apps.googleusercontent.com",
		"client_secret=s3cret-value",
		"redirect_uri=https%3A%2F%2Fcasaos.example.com%2Fapi%2Fv1%2Frecover%2FGoogleDrive",
	} {
		if !strings.Contains(form, required) {
			t.Fatalf("form %q is missing %q", form, required)
		}
	}
	if deadline, present := captured.Context().Deadline(); !present || time.Until(deadline) > time.Second {
		t.Fatal("exchange did not apply its timeout to the request context")
	}
}

func TestExchangeBasicAuthStyleOmitsSecretFromBody(t *testing.T) {
	provider := exchangeProvider()
	provider.AuthStyle = AuthStyleBasic
	var captured *http.Request
	var capturedBody string
	exchanger, err := NewExchangerWithClient(doerFunc(func(request *http.Request) (*http.Response, error) {
		captured = request
		content, _ := io.ReadAll(request.Body)
		capturedBody = string(content)
		return jsonResponse(http.StatusOK, `{"access_token":"at","token_type":"Bearer"}`), nil
	}), time.Second)
	if err != nil {
		t.Fatalf("NewExchangerWithClient: %v", err)
	}
	if _, err := exchanger.Exchange(context.Background(), provider, "auth-code", testVerifier); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	user, password, ok := captured.BasicAuth()
	if !ok || user != provider.ClientID || password != provider.ClientSecret {
		t.Fatal("basic auth credentials were not set")
	}
	if strings.Contains(capturedBody, "client_secret") {
		t.Fatal("basic auth style leaked the secret into the body")
	}
}

func TestExchangeFailureModesAreRedactedAndBounded(t *testing.T) {
	const sentinel = "provider-error-body-should-never-leak"
	cases := map[string]struct {
		response func() (*http.Response, error)
		expected error
	}{
		"non 200": {
			response: func() (*http.Response, error) { return jsonResponse(http.StatusBadRequest, sentinel), nil },
			expected: ErrExchange,
		},
		"oversized": {
			response: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"access_token":"`+strings.Repeat("a", MaxTokenResponseBytes)+`"}`), nil
			},
			expected: ErrExchange,
		},
		"malformed json": {
			response: func() (*http.Response, error) { return jsonResponse(http.StatusOK, "{not json"), nil },
			expected: ErrExchange,
		},
		"missing access token": {
			response: func() (*http.Response, error) { return jsonResponse(http.StatusOK, `{"token_type":"Bearer"}`), nil },
			expected: ErrExchange,
		},
		"wrong token type": {
			response: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"access_token":"at","token_type":"mac"}`), nil
			},
			expected: ErrExchange,
		},
		"negative expiry": {
			response: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"access_token":"at","token_type":"Bearer","expires_in":-1}`), nil
			},
			expected: ErrExchange,
		},
		"expiry overflow": {
			response: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"access_token":"at","token_type":"Bearer","expires_in":999999999}`), nil
			},
			expected: ErrExchange,
		},
		"control byte in token": {
			response: func() (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{"access_token":"a\u0000b","token_type":"Bearer"}`), nil
			},
			expected: ErrExchange,
		},
		"transport error": {
			response: func() (*http.Response, error) { return nil, errors.New("dial failed") },
			expected: ErrExchange,
		},
	}
	for name, testCase := range cases {
		exchanger, err := NewExchangerWithClient(doerFunc(func(*http.Request) (*http.Response, error) {
			return testCase.response()
		}), time.Second)
		if err != nil {
			t.Fatalf("%s: NewExchangerWithClient: %v", name, err)
		}
		_, err = exchanger.Exchange(context.Background(), exchangeProvider(), "auth-code", testVerifier)
		if !errors.Is(err, testCase.expected) {
			t.Fatalf("%s error = %v, want %v", name, err, testCase.expected)
		}
		if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "auth-code") ||
			strings.Contains(err.Error(), testVerifier) || strings.Contains(err.Error(), "s3cret-value") {
			t.Fatalf("%s error leaked sensitive material: %v", name, err)
		}
	}
}

func TestExchangeRejectsInvalidInputBeforeDispatch(t *testing.T) {
	called := false
	exchanger, err := NewExchangerWithClient(doerFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return jsonResponse(http.StatusOK, `{"access_token":"at","token_type":"Bearer"}`), nil
	}), time.Second)
	if err != nil {
		t.Fatalf("NewExchangerWithClient: %v", err)
	}
	if _, err := exchanger.Exchange(context.Background(), exchangeProvider(), "", testVerifier); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty code error = %v", err)
	}
	if _, err := exchanger.Exchange(context.Background(), exchangeProvider(), "auth-code", "short"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad verifier error = %v", err)
	}
	if _, err := exchanger.Exchange(context.Background(), exchangeProvider(), "auth code", testVerifier); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("code with space error = %v", err)
	}

	broken := exchangeProvider()
	broken.TokenURL = "http://oauth2.googleapis.com/token"
	if _, err := exchanger.Exchange(context.Background(), broken, "auth-code", testVerifier); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("insecure token URL error = %v", err)
	}
	broken = exchangeProvider()
	broken.AuthStyle = 0
	if _, err := exchanger.Exchange(context.Background(), broken, "auth-code", testVerifier); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing auth style error = %v", err)
	}
	if called {
		t.Fatal("invalid input reached the HTTP client")
	}
}

func TestExchangeErrorTypeCarriesOnlyStatus(t *testing.T) {
	exchanger, err := NewExchangerWithClient(doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, "unauthorized details"), nil
	}), time.Second)
	if err != nil {
		t.Fatalf("NewExchangerWithClient: %v", err)
	}
	_, err = exchanger.Exchange(context.Background(), exchangeProvider(), "auth-code", testVerifier)
	var exchangeErr *ExchangeError
	if !errors.As(err, &exchangeErr) || exchangeErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %v", err)
	}
	if errors.Unwrap(exchangeErr) != ErrExchange {
		t.Fatal("ExchangeError does not unwrap to ErrExchange")
	}
}
