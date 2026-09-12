package route

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/IceWhaleTech/CasaOS/service"
)

func TestNotifyRoutesRequireAuthenticationBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name         string
		bypass       string
		forwardedFor string
	}{
		{name: "bypass disabled", bypass: ""},
		{name: "forwarded loopback is not trusted", bypass: "1", forwardedFor: "127.0.0.1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, test.bypass)
			spy := installNotifyRouteSpy(t)

			body := &notifyRouteRejectReadBody{}
			request := httptest.NewRequest(http.MethodPost, "/v1/notify/system_status", nil)
			request.Body = body
			request.ContentLength = 1<<20 + 1
			request.Header.Set("Content-Type", "application/json")
			if test.forwardedFor != "" {
				request.Header.Set("X-Forwarded-For", test.forwardedFor)
			}
			request.RemoteAddr = "198.51.100.20:43120"
			response := httptest.NewRecorder()
			InitV1Router().ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
			if sendCalls, patchCalls := spy.counts(); sendCalls != 0 || patchCalls != 0 {
				t.Fatalf("side effects before authentication: send=%d patch=%d", sendCalls, patchCalls)
			}
			if got := body.reads.Load(); got != 0 {
				t.Fatalf("authentication middleware read request body %d times", got)
			}
			if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if got := response.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma = %q", got)
			}
		})
	}
}

func TestSystemStatusStaticRouteWinsOverRetiredWildcard(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	spy := installNotifyRouteSpy(t)

	request := httptest.NewRequest(http.MethodPost, "/v1/notify/system_status", strings.NewReader(`{"sys_disk":{"generation":1}}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:43120"
	response := httptest.NewRecorder()
	InitV1Router().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	sendCalls, patchCalls := spy.counts()
	if sendCalls != 0 || patchCalls != 1 {
		t.Fatalf("route side effects: send=%d patch=%d, want send=0 patch=1", sendCalls, patchCalls)
	}
	patched := spy.lastPatch()
	if _, ok := patched["sys_disk"]; !ok {
		t.Fatalf("static route patch = %#v", patched)
	}
}

func TestRetiredNotifyWildcardDoesNotReadOrPublish(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	spy := installNotifyRouteSpy(t)
	body := &notifyRouteRejectReadBody{}
	request := httptest.NewRequest(http.MethodPost, "/v1/notify/casaos:file:recover", nil)
	request.Body = body
	request.ContentLength = 1<<20 + 1
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:43120"
	response := httptest.NewRecorder()
	InitV1Router().ServeHTTP(response, request)

	if response.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusGone, response.Body.String())
	}
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("retired wildcard read body %d times", got)
	}
	if sendCalls, patchCalls := spy.counts(); sendCalls != 0 || patchCalls != 0 {
		t.Fatalf("retired wildcard side effects: send=%d patch=%d", sendCalls, patchCalls)
	}
}

func TestEncodedSystemStatusAliasFailsClosed(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	spy := installNotifyRouteSpy(t)
	body := &notifyRouteRejectReadBody{}
	request := httptest.NewRequest(http.MethodPost, "/v1/notify/system%5Fstatus", nil)
	request.Body = body
	request.ContentLength = 1<<20 + 1
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "127.0.0.1:43120"
	if request.URL.Path != "/v1/notify/system_status" || request.URL.RawPath != "/v1/notify/system%5Fstatus" {
		t.Fatalf("unexpected URL normalization: Path=%q RawPath=%q", request.URL.Path, request.URL.RawPath)
	}
	response := httptest.NewRecorder()
	InitV1Router().ServeHTTP(response, request)
	// Echo v4.15 routes the preserved RawPath through the retired wildcard even
	// though net/url exposes a decoded Path. It therefore fails closed without
	// reaching the static status validator.
	if response.Code != http.StatusGone {
		t.Fatalf("encoded alias status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("encoded alias read request body %d times", got)
	}
	if sendCalls, patchCalls := spy.counts(); sendCalls != 0 || patchCalls != 0 {
		t.Fatalf("encoded alias side effects: send=%d patch=%d", sendCalls, patchCalls)
	}
}

func TestEncodedAndExtraWildcardPathsHaveNoSideEffects(t *testing.T) {
	tests := []struct {
		path       string
		wantStatus int
	}{
		{path: "/v1/notify/casaos%3Afile%3Arecover", wantStatus: http.StatusGone},
		{path: "/v1/notify/system_status/extra", wantStatus: http.StatusGone},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
			spy := installNotifyRouteSpy(t)
			body := &notifyRouteRejectReadBody{}
			request := httptest.NewRequest(http.MethodPost, test.path, nil)
			request.Body = body
			request.ContentLength = 1<<20 + 1
			request.Header.Set("Content-Type", "application/json")
			request.RemoteAddr = "127.0.0.1:43120"
			response := httptest.NewRecorder()
			InitV1Router().ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if got := body.reads.Load(); got != 0 {
				t.Fatalf("path %q read request body %d times", test.path, got)
			}
			if sendCalls, patchCalls := spy.counts(); sendCalls != 0 || patchCalls != 0 {
				t.Fatalf("path %q side effects: send=%d patch=%d", test.path, sendCalls, patchCalls)
			}
		})
	}
}

type notifyRouteRepository struct {
	service.Repository
	notifier service.NotifyServer
}

func (r notifyRouteRepository) Notify() service.NotifyServer {
	return r.notifier
}

type notifyRouteSpy struct {
	service.NotifyServer
	mu         sync.Mutex
	sendCalls  int
	patchCalls int
	patched    map[string]interface{}
}

func (s *notifyRouteSpy) SendNotify(string, map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendCalls++
}

func (s *notifyRouteSpy) SettingSystemTempData(message map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patchCalls++
	s.patched = message
}

func (s *notifyRouteSpy) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendCalls, s.patchCalls
}

func (s *notifyRouteSpy) lastPatch() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.patched
}

func installNotifyRouteSpy(t *testing.T) *notifyRouteSpy {
	t.Helper()
	spy := &notifyRouteSpy{}
	previousService := service.MyService
	service.MyService = notifyRouteRepository{notifier: spy}
	t.Cleanup(func() { service.MyService = previousService })

	var logs bytes.Buffer
	previousLogger := requestLogger
	requestLogger = log.New(&logs, "", 0)
	t.Cleanup(func() { requestLogger = previousLogger })
	return spy
}

type notifyRouteRejectReadBody struct {
	reads atomic.Int64
}

func (b *notifyRouteRejectReadBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, errors.New("request body must not be read")
}

func (*notifyRouteRejectReadBody) Close() error { return nil }
