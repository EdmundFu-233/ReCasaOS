package httpsecurity

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestIsDirectLoopbackRequestIgnoresForwardingHeaders(t *testing.T) {
	t.Setenv(TrustLoopbackAuthBypassEnv, "1")
	req := httptest.NewRequest(http.MethodGet, "http://device.local/v1", nil)
	req.RemoteAddr = "198.51.100.24:43120"
	req.Header.Set("Forwarded", "for=127.0.0.1")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "::1")

	if LoopbackAuthBypassAllowed(req) {
		t.Fatal("forwarding headers must not turn a remote socket peer into loopback")
	}

	req.RemoteAddr = "[::1]:43120"
	req.Header.Set("X-Forwarded-For", "198.51.100.24")
	if !LoopbackAuthBypassAllowed(req) {
		t.Fatal("the direct loopback socket peer should be accepted")
	}
}

func TestLoopbackAuthBypassIsDisabledByDefault(t *testing.T) {
	t.Setenv(TrustLoopbackAuthBypassEnv, "")
	req := httptest.NewRequest(http.MethodGet, "http://device.local/v1", nil)
	req.RemoteAddr = "127.0.0.1:43120"

	if LoopbackAuthBypassAllowed(req) {
		t.Fatal("a loopback socket must not bypass authentication unless explicitly enabled")
	}

	t.Setenv(TrustLoopbackAuthBypassEnv, "true")
	if LoopbackAuthBypassAllowed(req) {
		t.Fatal("only the exact opt-in value 1 may enable the bypass")
	}
}

func TestIsDirectLoopbackRejectsHostnamesAndNonLoopbackIPs(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:1234":          true,
		"[::1]:1234":              true,
		"::1":                     true,
		"[::ffff:127.0.0.1]:1234": true,
		"localhost:1234":          false,
		"0.0.0.0:1234":            false,
		"192.0.2.20:1234":         false,
		"127.0.0.1.example:1234":  false,
		"":                        false,
	}

	for remoteAddr, want := range tests {
		if got := IsDirectLoopback(remoteAddr); got != want {
			t.Errorf("IsDirectLoopback(%q) = %v, want %v", remoteAddr, got, want)
		}
	}
}

func TestParseAllowedOriginsNormalizesAndRejectsInvalidEntries(t *testing.T) {
	got := ParseAllowedOrigins(" HTTPS://Example.COM:443/, http://Example.com:80, http://example.com:8080, https://example.com, *, https://*.example.com, https://exa$mple.com, ftp://example.com, https://user@example.com, https://example.com/path, https://example.com?query, https://example.com:99999 ")
	want := []string{
		"https://example.com",
		"http://example.com",
		"http://example.com:8080",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseAllowedOrigins() = %#v, want %#v", got, want)
	}
}

func TestWebSocketOriginAllowed(t *testing.T) {
	t.Setenv(AllowedOriginsEnv, "https://trusted.example:443, http://dashboard.example:8080")

	tests := []struct {
		name   string
		target string
		host   string
		origin string
		xfp    string
		want   bool
	}{
		{name: "non-browser client", target: "http://device.local/ws", host: "device.local", want: true},
		{name: "same HTTP origin", target: "http://device.local/ws", host: "device.local", origin: "http://DEVICE.local/", want: true},
		{name: "same HTTPS origin", target: "https://device.local/ws", host: "device.local", origin: "https://DEVICE.local/", want: true},
		{name: "same origin and port", target: "http://device.local:8080/ws", host: "device.local:8080", origin: "http://device.local:8080", want: true},
		{name: "explicit origin", target: "http://device.local/ws", host: "device.local", origin: "https://trusted.example", want: true},
		{name: "explicit origin and port", target: "http://device.local/ws", host: "device.local", origin: "http://dashboard.example:8080", want: true},
		{name: "evil origin", target: "http://device.local/ws", host: "device.local", origin: "https://evil.example", want: false},
		{name: "HTTP request rejects HTTPS same host", target: "http://device.local/ws", host: "device.local", origin: "https://device.local", want: false},
		{name: "HTTPS request rejects HTTP same host", target: "https://device.local/ws", host: "device.local", origin: "http://device.local", want: false},
		{name: "forwarded proto is ignored", target: "http://device.local/ws", host: "device.local", origin: "https://device.local", xfp: "https", want: false},
		{name: "same hostname different port", target: "http://device.local:8080/ws", host: "device.local:8080", origin: "http://device.local:9090", want: false},
		{name: "origin with credentials", target: "http://device.local/ws", host: "device.local", origin: "http://user@device.local", want: false},
		{name: "multiple origins", target: "http://device.local/ws", host: "device.local", origin: "http://device.local, https://evil.example", want: false},
		{name: "opaque origin", target: "http://device.local/ws", host: "device.local", origin: "null", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.target, nil)
			req.Host = test.host
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			if test.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", test.xfp)
			}

			if got := WebSocketOriginAllowed(req); got != test.want {
				t.Fatalf("WebSocketOriginAllowed() = %v, want %v", got, test.want)
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "http://device.local/ws", nil)
	req.Header.Add("Origin", "http://device.local")
	req.Header.Add("Origin", "https://evil.example")
	if WebSocketOriginAllowed(req) {
		t.Fatal("repeated Origin headers must be rejected")
	}
}

func TestWithCORSDefaultsToSameOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := WithCORS(next, nil)

	t.Run("request without origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://device.local/v1", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}
	})

	t.Run("same origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://device.local/v1", nil)
		req.Header.Set("Origin", "http://device.local")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
		}
		if got := response.Header().Get("Access-Control-Allow-Origin"); got != "http://device.local" {
			t.Fatalf("Access-Control-Allow-Origin = %q", got)
		}
	})

	t.Run("cross origin denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://device.local/v1", nil)
		req.Header.Set("Origin", "https://evil.example")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
		if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("unexpected Access-Control-Allow-Origin %q", got)
		}
	})

	t.Run("scheme mismatch denied even with forwarded proto", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://device.local/v1", nil)
		req.Header.Set("Origin", "https://device.local")
		req.Header.Set("X-Forwarded-Proto", "https")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
	})

	t.Run("repeated origin headers denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://device.local/v1", nil)
		req.Header.Add("Origin", "http://device.local")
		req.Header.Add("Origin", "https://evil.example")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
	})
}

func TestWithCORSAllowsConfiguredPreflightWithoutWildcard(t *testing.T) {
	handler := WithCORS(http.NotFoundHandler(), []string{"https://Dashboard.Example:443/"})
	req := httptest.NewRequest(http.MethodOptions, "http://device.local/v1", nil)
	req.Header.Set("Origin", "https://dashboard.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("credentialed CORS must never emit a wildcard origin")
	}
}

func TestWithSecurityHeaders(t *testing.T) {
	handler := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://device.local/v1", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)

	if response.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
	}
	want := map[string]string{
		"Content-Security-Policy":           "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":                   "no-referrer",
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"X-Permitted-Cross-Domain-Policies": "none",
	}
	for name, expected := range want {
		if got := response.Header().Get(name); got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}
}
