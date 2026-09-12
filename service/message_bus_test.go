package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/codegen/message_bus"
)

const (
	messageBusTestTimeout    = 100 * time.Millisecond
	messageBusParentTimeout  = 50 * time.Millisecond
	messageBusSuccessTimeout = 2 * time.Second
)

func TestMessageBusUsesBoundedUnaryClient(t *testing.T) {
	client, ok := unaryMessageBusFor(&store{}).(*boundedUnaryMessageBusClient)
	if !ok {
		t.Fatalf("unexpected unary MessageBus client type %T", unaryMessageBusFor(&store{}))
	}
	if client.delegate == nil {
		t.Fatal("MessageBus returned an empty generated client")
	}
	if client.requestTimeout != messageBusRequestTimeout {
		t.Fatalf("MessageBus request timeout = %s, want %s", client.requestTimeout, messageBusRequestTimeout)
	}
	generated, ok := client.delegate.(*message_bus.ClientWithResponses)
	if !ok {
		t.Fatalf("unexpected MessageBus delegate type %T", client.delegate)
	}
	underlying, ok := generated.ClientInterface.(*message_bus.Client)
	if !ok {
		t.Fatalf("unexpected generated MessageBus client type %T", generated.ClientInterface)
	}
	if underlying.Client != messageBusHTTPClient {
		t.Fatal("MessageBus did not inject the dedicated HTTP client")
	}
	if messageBusHTTPClient.Timeout != 0 {
		t.Fatalf("generated HTTP client timeout = %s, want no client-wide timeout", messageBusHTTPClient.Timeout)
	}
	if messageBusDialer.Timeout != messageBusRequestTimeout {
		t.Fatalf("MessageBus dial timeout = %s, want %s", messageBusDialer.Timeout, messageBusRequestTimeout)
	}
	if messageBusHTTPClient.Transport == http.DefaultTransport {
		t.Fatal("MessageBus must not mutate or directly reuse the global default transport")
	}
}

func TestMessageBusRequestTimeoutCoversDial(t *testing.T) {
	dialStarted := make(chan struct{})
	dialExited := make(chan struct{})
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialStarted)
			defer close(dialExited)
			timer := time.NewTimer(messageBusTestTimeout)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, context.DeadlineExceeded
			}
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := newMessageBusTestClient(t, "http://message-bus.invalid/v2/message_bus", &http.Client{Transport: transport}, messageBusTestTimeout)

	requireMessageBusRequestTimesOut(t, client)
	select {
	case <-dialStarted:
	default:
		t.Fatal("request did not reach the dial stage")
	}
	select {
	case <-dialExited:
	case <-time.After(time.Second):
		t.Fatal("dial did not exit after the request deadline")
	}
}

func TestMessageBusRequestTimeoutCoversResponseHeaders(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.CloseClientConnections()
		server.Close()
	})

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusTestTimeout)
	requireMessageBusRequestTimesOut(t, client)

	select {
	case <-requestStarted:
	default:
		t.Fatal("request did not reach the response-header stage")
	}
}

func TestMessageBusRequestTimeoutCoversResponseBody(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.CloseClientConnections()
		server.Close()
	})

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusTestTimeout)
	requireMessageBusRequestTimesOut(t, client)

	select {
	case <-requestStarted:
	default:
		t.Fatal("request did not reach the response-body stage")
	}
}

func TestMessageBusPublishRequestTimeoutCoversResponseHeaders(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.CloseClientConnections()
		server.Close()
	})

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusTestTimeout)
	requireMessageBusOperationTimesOut(t, func() error {
		_, err := client.PublishEventWithResponse(context.Background(), "casaos", "casaos:test", message_bus.PublishEventJSONRequestBody{"key": "value"})
		return err
	})

	select {
	case <-requestStarted:
	default:
		t.Fatal("publish request did not reach the response-header stage")
	}
}

func TestMessageBusRequestHonorsEarlierParentDeadline(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseHandler:
		}
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.CloseClientConnections()
		server.Close()
	})

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusSuccessTimeout)
	parent, cancel := context.WithTimeout(context.Background(), messageBusParentTimeout)
	defer cancel()

	startedAt := time.Now()
	_, err := client.RegisterEventTypesWithResponse(parent, message_bus.RegisterEventTypesJSONRequestBody{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request error = %v, want parent deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= messageBusTestTimeout*5 {
		t.Fatalf("request honored wrapper timeout instead of earlier parent deadline: %s", elapsed)
	}

	select {
	case <-requestStarted:
	default:
		t.Fatal("request did not reach the response-header stage")
	}
}

func TestMessageBusRequestSucceedsNormally(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v2/message_bus/event_type" {
			t.Errorf("path = %q, want /v2/message_bus/event_type", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusSuccessTimeout)
	response, err := client.RegisterEventTypesWithResponse(context.Background(), message_bus.RegisterEventTypesJSONRequestBody{})
	if err != nil {
		t.Fatalf("RegisterEventTypesWithResponse returned error: %v", err)
	}
	if response == nil || response.HTTPResponse == nil {
		t.Fatal("RegisterEventTypesWithResponse returned an empty response")
	}
	if response.StatusCode() != http.StatusOK {
		t.Fatalf("status = %s, want 200 OK", response.Status())
	}
	if response.JSON200 == nil {
		t.Fatal("200 response was not decoded")
	}
}

func TestMessageBusPublishForwardsRequestAndEditor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v2/message_bus/event/casaos/casaos:test" {
			t.Errorf("path = %q, want /v2/message_bus/event/casaos/casaos:test", r.URL.Path)
		}
		if got := r.Header.Get("X-ReCasaOS-Test"); got != "request-editor" {
			t.Errorf("X-ReCasaOS-Test = %q, want request-editor", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		if got := body["key"]; got != "value" {
			t.Errorf("request body key = %q, want value", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusSuccessTimeout)
	response, err := client.PublishEventWithResponse(
		context.Background(),
		"casaos",
		"casaos:test",
		message_bus.PublishEventJSONRequestBody{"key": "value"},
		func(_ context.Context, request *http.Request) error {
			request.Header.Set("X-ReCasaOS-Test", "request-editor")
			return nil
		},
	)
	if err != nil {
		t.Fatalf("PublishEventWithResponse returned error: %v", err)
	}
	if response == nil || response.HTTPResponse == nil {
		t.Fatal("PublishEventWithResponse returned an empty response")
	}
	if response.StatusCode() != http.StatusOK {
		t.Fatalf("status = %s, want 200 OK", response.Status())
	}
	if response.JSON200 == nil {
		t.Fatal("200 response was not decoded")
	}
}

func newMessageBusTestClient(t *testing.T, server string, httpClient *http.Client, timeout time.Duration) UnaryMessageBusClient {
	t.Helper()
	client, err := message_bus.NewClientWithResponses(server, message_bus.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("NewClientWithResponses returned error: %v", err)
	}
	return newBoundedUnaryMessageBusClient(client, timeout)
}

func requireMessageBusRequestTimesOut(t *testing.T, client UnaryMessageBusClient) {
	t.Helper()
	requireMessageBusOperationTimesOut(t, func() error {
		_, err := client.RegisterEventTypesWithResponse(context.Background(), message_bus.RegisterEventTypesJSONRequestBody{})
		return err
	})
}

func requireMessageBusOperationTimesOut(t *testing.T, operation func() error) {
	t.Helper()
	completed := make(chan error, 1)
	go func() {
		completed <- operation()
	}()

	select {
	case err := <-completed:
		if err == nil {
			t.Fatal("request unexpectedly succeeded")
		}
		var netErr net.Error
		if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
			t.Fatalf("request returned a non-timeout error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not return within the bounded test window")
	}
}
