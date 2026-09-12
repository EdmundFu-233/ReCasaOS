package zerotierapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type zeroTierRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip zeroTierRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newTestZeroTierAPI(roundTrip http.RoundTripper) *zeroTierAPI {
	client := newZeroTierHTTPClient()
	client.Transport = roundTrip
	return &zeroTierAPI{
		client: client,
		readFile: func(path string, maximum int64, secret bool) ([]byte, error) {
			switch path {
			case zeroTierPortFile:
				if maximum != zeroTierMaximumPortFileBytes || secret {
					return nil, errors.New("unexpected port read policy")
				}
				return []byte("9993\n"), nil
			case zeroTierAuthTokenFile:
				if maximum != zeroTierMaximumTokenFileBytes || !secret {
					return nil, errors.New("unexpected token read policy")
				}
				return []byte("local-service-secret\n"), nil
			default:
				return nil, errors.New("unexpected ZeroTier state path")
			}
		},
		timeout: 200 * time.Millisecond,
	}
}

func TestZeroTierRequestOwnsEndpointCredentialAndHeaders(t *testing.T) {
	var capturedBody []byte
	api := newTestZeroTierAPI(zeroTierRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPut {
			t.Fatalf("method = %q", request.Method)
		}
		if got := request.URL.String(); got != "http://127.0.0.1:9993/controller/network/a%2Fb?jsonp=callback&jsonp=callback.two" {
			t.Fatalf("target URL = %q", got)
		}
		if got := request.Header.Values("X-Zt1-Auth"); len(got) != 1 || got[0] != "local-service-secret" {
			t.Fatalf("X-ZT1-AUTH = %#v", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := request.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("Accept = %q", got)
		}
		if got := request.Header.Get("User-Agent"); got != "ReCasaOS/zerotier-local-api" {
			t.Fatalf("User-Agent = %q", got)
		}
		for _, forbidden := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Forwarded-For", "Forwarded", "Connection"} {
			if value := request.Header.Values(forbidden); len(value) != 0 {
				t.Fatalf("outbound request contains %s = %#v", forbidden, value)
			}
		}
		var err error
		capturedBody, err = io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Header: http.Header{
				"Content-Type":     []string{"application/json"},
				"Set-Cookie":       []string{"daemon=session"},
				"Www-Authenticate": []string{"secret realm"},
				"Connection":       []string{"close"},
			},
		}, nil
	}))

	response, err := api.request(
		context.Background(),
		http.MethodPut,
		"/controller/network/a%2Fb?jsonp=callback&jsonp=callback.two",
		[]byte(`{"name":"private"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(capturedBody) != `{"name":"private"}` {
		t.Fatalf("request body = %q", capturedBody)
	}
	if response.StatusCode != http.StatusCreated || response.ContentType != "application/json" || string(response.Body) != `{"ok":true}` {
		t.Fatalf("response = %+v", response)
	}
}

func TestZeroTierPortFailureCannotFallBackToLocalhostPort80(t *testing.T) {
	secretReads := 0
	networkCalls := 0
	api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("network must not be reached")
	}))
	api.readFile = func(path string, _ int64, _ bool) ([]byte, error) {
		if path == zeroTierAuthTokenFile {
			secretReads++
		}
		return nil, os.ErrNotExist
	}

	if _, err := api.request(context.Background(), http.MethodGet, "/status", nil); err == nil {
		t.Fatal("missing port file was accepted")
	}
	if secretReads != 0 || networkCalls != 0 {
		t.Fatalf("secret reads = %d, network calls = %d; want zero", secretReads, networkCalls)
	}
}

func TestZeroTierPortValidationPrecedesSecretAndNetwork(t *testing.T) {
	invalidPorts := []string{"", "0", "65536", "+9993", "09993", "9993:80", "9993/path", "99\n93", "not-a-port", strings.Repeat("9", 17)}
	for _, rawPort := range invalidPorts {
		t.Run(strings.ReplaceAll(rawPort, "\n", "newline"), func(t *testing.T) {
			secretReads := 0
			networkCalls := 0
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
				networkCalls++
				return nil, errors.New("network must not be reached")
			}))
			api.readFile = func(path string, _ int64, _ bool) ([]byte, error) {
				if path == zeroTierPortFile {
					return []byte(rawPort), nil
				}
				secretReads++
				return []byte("secret"), nil
			}
			if _, err := api.request(context.Background(), http.MethodGet, "/status", nil); !errors.Is(err, ErrZeroTierUnsafeEndpoint) {
				t.Fatalf("error = %v", err)
			}
			if secretReads != 0 || networkCalls != 0 {
				t.Fatalf("secret reads = %d, network calls = %d; want zero", secretReads, networkCalls)
			}
		})
	}
	for _, port := range []string{"1", "9993", "65535"} {
		if got, err := parseZeroTierPort(port); err != nil || got != port {
			t.Fatalf("parseZeroTierPort(%q) = %q, %v", port, got, err)
		}
	}
}

func TestZeroTierRejectsUnsafeMethodsEndpointsAndRequestSizeBeforeStateRead(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		endpoint  string
		body      []byte
		wantError error
	}{
		{name: "method", method: http.MethodConnect, endpoint: "/status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "absolute URL", method: http.MethodGet, endpoint: "http://attacker.invalid/status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "network path", method: http.MethodGet, endpoint: "//attacker.invalid/status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded network path", method: http.MethodGet, endpoint: "/%2Fattacker.invalid/status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded backslash", method: http.MethodGet, endpoint: "/status/%5Cadmin", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded tab", method: http.MethodGet, endpoint: "/status/%09admin", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded unit separator", method: http.MethodGet, endpoint: "/status/%1Fadmin", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded delete", method: http.MethodGet, endpoint: "/status/%7Fadmin", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "dot segment", method: http.MethodGet, endpoint: "/network/../status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "encoded dot segment", method: http.MethodGet, endpoint: "/network/%2e%2e/status", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "auth query", method: http.MethodGet, endpoint: "/status?auth=caller", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "token query", method: http.MethodGet, endpoint: "/status?token=caller", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "undocumented query", method: http.MethodGet, endpoint: "/status?api_key=caller", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "fragment", method: http.MethodGet, endpoint: "/status#fragment", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "malformed query", method: http.MethodGet, endpoint: "/status?value=%zz", wantError: ErrZeroTierUnsafeEndpoint},
		{name: "request size", method: http.MethodPost, endpoint: "/network", body: bytes.Repeat([]byte{'x'}, zeroTierMaximumRequestBytes+1), wantError: ErrZeroTierRequestTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateReads := 0
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsafe request reached the transport")
				return nil, nil
			}))
			api.readFile = func(string, int64, bool) ([]byte, error) {
				stateReads++
				return nil, errors.New("state must not be read")
			}
			_, err := api.request(context.Background(), test.method, test.endpoint, test.body)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if stateReads != 0 {
				t.Fatalf("state reads = %d, want zero", stateReads)
			}
		})
	}
}

func TestZeroTierClientRefusesRedirectBeforeCredentialSecondHop(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					t.Fatalf("credential followed redirect to %s", request.URL)
				}
				return &http.Response{
					StatusCode: status,
					Body:       io.NopCloser(strings.NewReader("redirect")),
					Header:     http.Header{"Location": []string{"http://attacker.invalid/collect"}},
				}, nil
			}))

			_, err := api.request(context.Background(), http.MethodPost, "/network", []byte(`{}`))
			if !errors.Is(err, ErrZeroTierRedirect) {
				t.Fatalf("error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("transport calls = %d, want one", calls)
			}
		})
	}
}

func TestZeroTierTransportErrorsDoNotDiscloseEndpointQuery(t *testing.T) {
	const secretQueryValue = "browser-secret-callback"
	api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failed near " + secretQueryValue)
	}))
	_, err := api.request(context.Background(), http.MethodGet, "/status?jsonp="+secretQueryValue, nil)
	if err == nil || strings.Contains(err.Error(), secretQueryValue) || FailureClass(err) != "upstream_error" {
		t.Fatalf("transport error = %v, class = %q", err, FailureClass(err))
	}
}

func TestZeroTierRequestHonorsBoundedAndEarlierContextDeadlines(t *testing.T) {
	for _, test := range []struct {
		name       string
		apiTimeout time.Duration
		parent     func() (context.Context, context.CancelFunc)
	}{
		{
			name:       "client bound",
			apiTimeout: 25 * time.Millisecond,
			parent: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
		{
			name:       "earlier parent",
			apiTimeout: time.Second,
			parent: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 20*time.Millisecond)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(request *http.Request) (*http.Response, error) {
				<-request.Context().Done()
				return nil, request.Context().Err()
			}))
			api.timeout = test.apiTimeout
			parent, cancel := test.parent()
			defer cancel()
			started := time.Now()
			_, err := api.request(parent, http.MethodGet, "/status", nil)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error = %v", err)
			}
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("bounded request took %s", elapsed)
			}
		})
	}
}

func TestZeroTierCanceledContextsStopBeforeCredentialsOrNetwork(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		stateReads := 0
		networkCalls := 0
		api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("network must not be reached")
		}))
		api.readFile = func(string, int64, bool) ([]byte, error) {
			stateReads++
			return nil, errors.New("state must not be read")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := api.request(ctx, http.MethodGet, "/status", nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
		if stateReads != 0 || networkCalls != 0 {
			t.Fatalf("state/network calls = %d, %d; want zero", stateReads, networkCalls)
		}
	})

	t.Run("canceled after port", func(t *testing.T) {
		stateReads := 0
		networkCalls := 0
		ctx, cancel := context.WithCancel(context.Background())
		api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
			networkCalls++
			return nil, errors.New("network must not be reached")
		}))
		api.readFile = func(path string, _ int64, _ bool) ([]byte, error) {
			stateReads++
			if path != zeroTierPortFile {
				t.Fatalf("credential read after cancellation: %s", path)
			}
			cancel()
			return []byte("9993"), nil
		}
		_, err := api.request(ctx, http.MethodGet, "/status", nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
		if stateReads != 1 || networkCalls != 0 {
			t.Fatalf("state/network calls = %d, %d; want 1, 0", stateReads, networkCalls)
		}
	})
}

func TestZeroTierResponseBoundaryAndErrorDisclosure(t *testing.T) {
	for _, size := range []int64{zeroTierMaximumResponseBytes, zeroTierMaximumResponseBytes + 1} {
		t.Run(strings.Join([]string{"bytes", time.Duration(size).String()}, "-"), func(t *testing.T) {
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(io.LimitReader(zeroTierInfiniteReader{}, size)),
					Header:     make(http.Header),
				}, nil
			}))
			response, err := api.request(context.Background(), http.MethodGet, "/status", nil)
			if size > zeroTierMaximumResponseBytes {
				if !errors.Is(err, ErrZeroTierResponseTooLarge) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || int64(len(response.Body)) != size {
				t.Fatalf("response length = %d, error = %v", len(response.Body), err)
			}
		})
	}

	const daemonBody = "daemon-secret-response-must-not-enter-error"
	api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(daemonBody)),
			Header:     make(http.Header),
		}, nil
	}))
	_, err := api.get(context.Background(), "/status")
	if err == nil || strings.Contains(err.Error(), daemonBody) || strings.Contains(err.Error(), "local-service-secret") {
		t.Fatalf("unsafe helper error = %v", err)
	}
}

func TestZeroTierResponseContentTypeIsStrictlyNormalized(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "json", raw: "application/json", want: "application/json"},
		{name: "json charset", raw: "application/json; charset=UTF-8", want: "application/json"},
		{name: "plain", raw: "text/plain", want: "text/plain; charset=utf-8"},
		{name: "plain ASCII", raw: "text/plain; charset=us-ascii", want: "text/plain; charset=utf-8"},
		{name: "HTML", raw: "text/html", want: "application/octet-stream"},
		{name: "script", raw: "application/javascript", want: "application/octet-stream"},
		{name: "invalid charset", raw: "application/json; charset=iso-8859-1", want: "application/octet-stream"},
		{name: "malformed", raw: "application/json; bad", want: "application/octet-stream"},
		{name: "missing", want: "application/octet-stream"},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := newTestZeroTierAPI(zeroTierRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("body")),
					Header:     http.Header{"Content-Type": []string{test.raw}},
				}, nil
			}))
			response, err := api.request(context.Background(), http.MethodGet, "/status", nil)
			if err != nil {
				t.Fatal(err)
			}
			if response.ContentType != test.want {
				t.Fatalf("Content-Type = %q, want %q", response.ContentType, test.want)
			}
		})
	}
}

type zeroTierInfiniteReader struct{}

func (zeroTierInfiniteReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = 'x'
	}
	return len(destination), nil
}

func TestZeroTierHTTPClientIsDirectBoundedAndNonRedirecting(t *testing.T) {
	client := newZeroTierHTTPClient()
	if client.Timeout != zeroTierRequestTimeout || client.CheckRedirect == nil {
		t.Fatalf("client timeout/redirect policy is incomplete: timeout=%s", client.Timeout)
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || !transport.DisableCompression {
		t.Fatalf("unsafe transport = %#v", client.Transport)
	}
	if transport.ResponseHeaderTimeout != zeroTierResponseHeaderTimeout || transport.MaxResponseHeaderBytes != zeroTierMaximumHeaderBytes || transport.MaxConnsPerHost != 4 {
		t.Fatalf("transport bounds = %+v", transport)
	}
}

func TestZeroTierStateFilesRejectSymlinksAndUnsafePermissions(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "authtoken.secret")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		if _, err := readZeroTierStateFile(tokenPath, 256, true); err == nil {
			t.Fatal("non-root-owned state file was accepted")
		}
	} else if content, err := readZeroTierStateFile(tokenPath, 256, true); err != nil || string(content) != "secret\n" {
		t.Fatalf("secure token read = %q, %v", content, err)
	}

	if err := os.Chmod(tokenPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readZeroTierStateFile(tokenPath, 256, true); err == nil {
		t.Fatal("group-readable token was accepted")
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "token-link")
	if err := os.Symlink(tokenPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readZeroTierStateFile(symlinkPath, 256, true); err == nil {
		t.Fatal("symlinked token was accepted")
	}
}

type zeroTierGetSignature func(string) ([]byte, error)
type zeroTierPostSignature func(string, string) ([]byte, error)

func TestZeroTierExportedHelperSignaturesRemainCompatible(t *testing.T) {
	get := zeroTierGetSignature(Get)
	post := zeroTierPostSignature(Post)
	if get == nil || post == nil {
		t.Fatal("exported ZeroTier helpers are unavailable")
	}
}
