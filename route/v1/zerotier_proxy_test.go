package v1

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/internal/zerotierapi"
	"github.com/labstack/echo/v4"
)

func newZeroTierProxyTestContext(method, target string, body io.Reader) (echo.Context, *httptest.ResponseRecorder) {
	logger.LogInitConsoleOnly()
	request := httptest.NewRequest(method, target, body)
	recorder := httptest.NewRecorder()
	return echo.New().NewContext(request, recorder), recorder
}

func TestZeroTierProxyStripsIdentityRoutingAndUndocumentedQueryData(t *testing.T) {
	ctx, recorder := newZeroTierProxyTestContext(
		http.MethodPut,
		"http://recasaos.test/v1/zt/controller/network/a%2Fb?token=jwt-secret&%61uth=caller-secret&api_key=other-secret&jsonp=callback&jsonp=callback.two",
		strings.NewReader(`{"name":"private"}`),
	)
	request := ctx.Request()
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Authorization", "Bearer management-jwt")
	request.Header.Set("Cookie", "session=browser-secret")
	request.Header.Set("X-ZT1-AUTH", "caller-token")
	request.Header.Set("User_Id", "42")
	request.Header.Set("Connection", "X-Remove-Me")
	request.Header.Set("X-Remove-Me", "hop-secret")
	request.Header.Set("Forwarded", "for=public-client")

	calls := 0
	requester := func(ctx context.Context, method, endpoint string, body []byte) (*zerotierapi.ZeroTierResponse, error) {
		calls++
		if ctx != request.Context() {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > zeroTierProxyTimeout {
				t.Fatalf("unexpected proxy deadline: %v, %t", deadline, ok)
			}
		}
		if method != http.MethodPut || endpoint != "/controller/network/a%2Fb?jsonp=callback&jsonp=callback.two" {
			t.Fatalf("outbound method/endpoint = %q %q", method, endpoint)
		}
		if string(body) != `{"name":"private"}` {
			t.Fatalf("outbound body = %q", body)
		}
		return &zerotierapi.ZeroTierResponse{
			StatusCode:  http.StatusCreated,
			ContentType: "application/json",
			Body:        []byte(`{"ok":true}`),
		}, nil
	}

	if err := zerotierProxy(ctx, requester, zeroTierProxyTimeout); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || recorder.Code != http.StatusCreated || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("calls/status/body = %d, %d, %q", calls, recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("response Content-Type = %q", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("response X-Content-Type-Options = %q", got)
	}
	for _, forbidden := range []string{"Set-Cookie", "Location", "Www-Authenticate", "Connection", "Content-Length"} {
		if value := recorder.Header().Get(forbidden); value != "" {
			t.Fatalf("response reflected %s = %q", forbidden, value)
		}
	}
}

func TestZeroTierProxyMethodAndBodyPolicy(t *testing.T) {
	neverCall := func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
		t.Fatal("rejected request reached ZeroTier requester")
		return nil, nil
	}
	tests := []struct {
		name        string
		method      string
		body        io.Reader
		contentType string
		wantStatus  int
	}{
		{name: "connect", method: http.MethodConnect, wantStatus: http.StatusMethodNotAllowed},
		{name: "patch", method: http.MethodPatch, wantStatus: http.StatusMethodNotAllowed},
		{name: "head", method: http.MethodHead, wantStatus: http.StatusMethodNotAllowed},
		{name: "get body", method: http.MethodGet, body: strings.NewReader("unexpected"), wantStatus: http.StatusBadRequest},
		{name: "delete body", method: http.MethodDelete, body: strings.NewReader("unexpected"), wantStatus: http.StatusBadRequest},
		{name: "post wrong media", method: http.MethodPost, body: strings.NewReader(`{}`), contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "put malformed media", method: http.MethodPut, body: strings.NewReader(`{}`), contentType: "application/json; bad", wantStatus: http.StatusUnsupportedMediaType},
		{name: "post non-UTF8 JSON", method: http.MethodPost, body: strings.NewReader(`{}`), contentType: "application/json; charset=iso-8859-1", wantStatus: http.StatusUnsupportedMediaType},
		{name: "post unknown JSON parameter", method: http.MethodPost, body: strings.NewReader(`{}`), contentType: "application/json; profile=private", wantStatus: http.StatusUnsupportedMediaType},
		{name: "known oversized", method: http.MethodPost, body: strings.NewReader(strings.Repeat("x", zeroTierProxyMaximumRequestBytes+1)), contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
		{name: "oversized", method: http.MethodPost, body: io.LimitReader(zeroTierEndlessBody{}, zeroTierProxyMaximumRequestBytes+1), contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, recorder := newZeroTierProxyTestContext(test.method, "http://recasaos.test/v1/zt/status", test.body)
			if test.contentType != "" {
				ctx.Request().Header.Set("Content-Type", test.contentType)
			}
			if err := zerotierProxy(ctx, neverCall, time.Second); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body %q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestZeroTierProxyRejectsOversizedEndpointBeforeBodyOrRequester(t *testing.T) {
	body := newZeroTierBlockingBody()
	ctx, recorder := newZeroTierProxyTestContext(
		http.MethodGet,
		"http://recasaos.test/v1/zt/"+strings.Repeat("a", zeroTierProxyMaximumEndpointBytes),
		body,
	)
	if err := zerotierProxy(ctx, func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
		t.Fatal("oversized endpoint reached requester")
		return nil, nil
	}, time.Second); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; body %q", recorder.Code, recorder.Body.String())
	}
	select {
	case <-body.readStarted:
		t.Fatal("oversized endpoint read the request body")
	default:
	}
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("oversized endpoint did not close the request body")
	}
}

func TestSanitizedZeroTierEndpointRejectsEncodedAuthorityAndTraversal(t *testing.T) {
	for _, target := range []string{
		"http://recasaos.test/v1/zt/%2Fattacker.invalid/status",
		"http://recasaos.test/v1/zt/network/%2e%2e/status",
		"http://recasaos.test/v1/zt/status/%5Cadmin",
		"http://recasaos.test/v1/zt/status/%09admin",
		"http://recasaos.test/v1/zt/status/%1Fadmin",
		"http://recasaos.test/v1/zt/status/%7Fadmin",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if endpoint, err := sanitizedZeroTierEndpoint(request); err == nil {
			t.Fatalf("unsafe target %q became endpoint %q", target, endpoint)
		}
	}
}

type zeroTierEndlessBody struct{}

func (zeroTierEndlessBody) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = 'x'
	}
	return len(destination), nil
}

func TestZeroTierProxyAcceptsDocumentedMethodsAndNormalizesJSON(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			body := io.Reader(nil)
			if method == http.MethodPost || method == http.MethodPut {
				body = strings.NewReader(`{}`)
			}
			ctx, recorder := newZeroTierProxyTestContext(method, "http://recasaos.test/v1/zt/status", body)
			called := 0
			requester := func(_ context.Context, gotMethod, endpoint string, gotBody []byte) (*zerotierapi.ZeroTierResponse, error) {
				called++
				if gotMethod != method || endpoint != "/status" {
					t.Fatalf("request = %q %q", gotMethod, endpoint)
				}
				if method == http.MethodPost || method == http.MethodPut {
					if string(gotBody) != `{}` {
						t.Fatalf("JSON request = %q", gotBody)
					}
				} else if len(gotBody) != 0 {
					t.Fatalf("bodyless request = %q", gotBody)
				}
				return &zerotierapi.ZeroTierResponse{StatusCode: http.StatusNoContent}, nil
			}
			if err := zerotierProxy(ctx, requester, time.Second); err != nil {
				t.Fatal(err)
			}
			if called != 1 || recorder.Code != http.StatusNoContent {
				t.Fatalf("calls/status = %d, %d", called, recorder.Code)
			}
		})
	}
}

func TestZeroTierProxyBoundsSlowRequestBodyAndOutboundStall(t *testing.T) {
	t.Run("slow request body", func(t *testing.T) {
		body := newZeroTierBlockingBody()
		ctx, recorder := newZeroTierProxyTestContext(http.MethodPost, "http://recasaos.test/v1/zt/network", body)
		ctx.Request().Header.Set("Content-Type", "application/json")
		started := time.Now()
		err := zerotierProxy(ctx, func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
			t.Fatal("timed-out body reached requester")
			return nil, nil
		}, 25*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusGatewayTimeout || time.Since(started) > 500*time.Millisecond {
			t.Fatalf("status/elapsed = %d, %s", recorder.Code, time.Since(started))
		}
	})

	t.Run("outbound stall", func(t *testing.T) {
		ctx, recorder := newZeroTierProxyTestContext(http.MethodGet, "http://recasaos.test/v1/zt/status", nil)
		started := time.Now()
		err := zerotierProxy(ctx, func(ctx context.Context, _, _ string, _ []byte) (*zerotierapi.ZeroTierResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, 25*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusGatewayTimeout || time.Since(started) > 500*time.Millisecond {
			t.Fatalf("status/elapsed = %d, %s", recorder.Code, time.Since(started))
		}
	})
}

type zeroTierBlockingBody struct {
	closed      chan struct{}
	readStarted chan struct{}
	closeOnce   sync.Once
	readOnce    sync.Once
}

func newZeroTierBlockingBody() *zeroTierBlockingBody {
	return &zeroTierBlockingBody{
		closed:      make(chan struct{}),
		readStarted: make(chan struct{}),
	}
}

func (body *zeroTierBlockingBody) Read([]byte) (int, error) {
	body.readOnce.Do(func() { close(body.readStarted) })
	<-body.closed
	return 0, errors.New("request body closed")
}

func (body *zeroTierBlockingBody) Close() error {
	body.closeOnce.Do(func() { close(body.closed) })
	return nil
}

func TestZeroTierProxyAdmissionRejectsBeforeReadingBodyOrCallingRequester(t *testing.T) {
	body := newZeroTierBlockingBody()
	ctx, recorder := newZeroTierProxyTestContext(http.MethodPost, "http://recasaos.test/v1/zt/network", body)
	ctx.Request().Header.Set("Content-Type", "application/json")
	if err := zerotierProxyWithAdmission(
		ctx,
		func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
			t.Fatal("busy proxy called the ZeroTier requester")
			return nil, nil
		},
		time.Second,
		func() (func(), bool) { return nil, false },
	); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; body %q", recorder.Code, recorder.Body.String())
	}
	select {
	case <-body.readStarted:
		t.Fatal("busy proxy read the request body")
	default:
	}
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("busy proxy did not close the request body")
	}
}

func TestZeroTierProxyRealSocketEarlyRejectionsDoNotDrainSlowBodies(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		admission  zeroTierAdmission
		wantStatus int
	}{
		{
			name:       "unsupported method",
			method:     http.MethodPatch,
			path:       "/v1/zt/status",
			admission:  func() (func(), bool) { return func() {}, true },
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "invalid endpoint",
			method:     http.MethodPost,
			path:       "/v1/zt//attacker.invalid/status",
			admission:  func() (func(), bool) { return func() {}, true },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "admission full",
			method:     http.MethodPost,
			path:       "/v1/zt/network",
			admission:  func() (func(), bool) { return nil, false },
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requesterCalled := make(chan struct{}, 1)
			address, settled := startZeroTierProxySocketServer(t, func(ctx echo.Context) error {
				return zerotierProxyWithAdmission(
					ctx,
					func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
						requesterCalled <- struct{}{}
						return nil, errors.New("unexpected requester call")
					},
					time.Second,
					test.admission,
				)
			})
			started := time.Now()
			status, _, state := rawZeroTierProxyResponse(t, address, test.method, test.path, "Transfer-Encoding: chunked\r\n", "", settled)
			if status != test.wantStatus || time.Since(started) > time.Second {
				t.Fatalf("status/state/elapsed = %d, %s, %s", status, state, time.Since(started))
			}
			select {
			case <-requesterCalled:
				t.Fatal("early rejection reached requester")
			default:
			}
		})
	}
}

func TestZeroTierProxyRealSocketSlowBodyCanReceiveGatewayTimeout(t *testing.T) {
	requesterCalled := make(chan struct{}, 1)
	address, settled := startZeroTierProxySocketServer(t, func(ctx echo.Context) error {
		return zerotierProxyWithAdmission(
			ctx,
			func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
				requesterCalled <- struct{}{}
				return nil, errors.New("unexpected requester call")
			},
			25*time.Millisecond,
			func() (func(), bool) { return func() {}, true },
		)
	})
	status, body, state := rawZeroTierProxyResponse(
		t,
		address,
		http.MethodPost,
		"/v1/zt/network",
		"Content-Type: application/json\r\nContent-Length: 2\r\n",
		"{",
		settled,
	)
	if status != http.StatusGatewayTimeout || body != "ZeroTier request body timed out\n" {
		t.Fatalf("status/body/state = %d, %q, %s", status, body, state)
	}
	select {
	case <-requesterCalled:
		t.Fatal("timed-out request body reached requester")
	default:
	}
}

func startZeroTierProxySocketServer(t *testing.T, handler echo.HandlerFunc) (string, <-chan http.ConnState) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("loopback listener is unavailable in this sandbox: %v", err)
		}
		t.Fatal(err)
	}
	e := echo.New()
	e.Any("/v1/zt/*", handler)
	settled := make(chan http.ConnState, 1)
	var settledOnce sync.Once
	server := &http.Server{
		Handler:           e,
		ReadHeaderTimeout: time.Second,
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateIdle || state == http.StateClosed || state == http.StateHijacked {
				settledOnce.Do(func() { settled <- state })
			}
		},
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close socket test server: %v", err)
		}
		if err := <-serveResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve socket test server: %v", err)
		}
	})
	return listener.Addr().String(), settled
}

func rawZeroTierProxyResponse(t *testing.T, address, method, path, extraHeaders, partialBody string, settled <-chan http.ConnState) (int, string, http.ConnState) {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := method + " " + path + " HTTP/1.1\r\nHost: " + address + "\r\n" + extraHeaders + "\r\n" + partialBody
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	state := waitForZeroTierProxyConnectionToSettle(t, settled)
	return response.StatusCode, string(body), state
}

func waitForZeroTierProxyConnectionToSettle(t *testing.T, settled <-chan http.ConnState) http.ConnState {
	t.Helper()
	select {
	case state := <-settled:
		return state
	case <-time.After(time.Second):
		t.Fatal("HTTP connection remained active while draining an abandoned request body")
		return http.StateActive
	}
}

func TestZeroTierProxyErrorsAreSingleAndDoNotDiscloseSecrets(t *testing.T) {
	for _, test := range []struct {
		name       string
		response   *zerotierapi.ZeroTierResponse
		err        error
		wantStatus int
	}{
		{name: "transport", err: errors.New("secret-token at /var/lib/zerotier-one/authtoken.secret"), wantStatus: http.StatusBadGateway},
		{name: "nil response", response: nil, wantStatus: http.StatusBadGateway},
		{name: "invalid status", response: &zerotierapi.ZeroTierResponse{StatusCode: 0}, wantStatus: http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, recorder := newZeroTierProxyTestContext(http.MethodGet, "http://recasaos.test/v1/zt/status", nil)
			err := zerotierProxy(ctx, func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error) {
				return test.response, test.err
			}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if recorder.Code != test.wantStatus || strings.Contains(recorder.Body.String(), "secret-token") || strings.Contains(recorder.Body.String(), "/var/lib") {
				t.Fatalf("status/body = %d, %q", recorder.Code, recorder.Body.String())
			}
			if strings.Count(recorder.Body.String(), "ZeroTier service unavailable") != 1 {
				t.Fatalf("response was not written exactly once: %q", recorder.Body.String())
			}
		})
	}
}
