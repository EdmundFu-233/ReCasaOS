package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/codegen/message_bus"
)

type messageBusRoundTripperFunc func(*http.Request) (*http.Response, error)

func (function messageBusRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type messageBusTrackingReadCloser struct {
	reader io.Reader
	closed bool
	reads  int
}

func (body *messageBusTrackingReadCloser) Read(destination []byte) (int, error) {
	body.reads++
	return body.reader.Read(destination)
}

func (body *messageBusTrackingReadCloser) Close() error {
	body.closed = true
	return nil
}

func messageBusRequest(method, path string) *http.Request {
	return &http.Request{
		Method: method,
		URL:    &url.URL{Scheme: "http", Host: "message-bus.invalid", Path: path},
	}
}

func TestMessageBusUnaryResponseLimitRejectsDeclaredOversize(t *testing.T) {
	body := &messageBusTrackingReadCloser{reader: strings.NewReader("must not be read")}
	transport := newMessageBusUnaryResponseLimitTransport(messageBusRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          body,
			ContentLength: messageBusMaximumUnaryResponseBytes + 1,
		}, nil
	}), messageBusMaximumUnaryResponseBytes)

	response, err := transport.RoundTrip(messageBusRequest(http.MethodPost, "/v2/message_bus/event_type"))
	if !errors.Is(err, errMessageBusResponseTooLarge) {
		t.Fatalf("RoundTrip error = %v, want response-size error", err)
	}
	if response != nil {
		t.Fatal("RoundTrip returned a response after rejecting its declared size")
	}
	if !body.closed {
		t.Fatal("oversized response body was not closed")
	}
	if body.reads != 0 {
		t.Fatalf("oversized response body was read %d times, want zero", body.reads)
	}
}

func TestMessageBusUnaryResponseLimitRejectsChunkedOversize(t *testing.T) {
	body := &messageBusTrackingReadCloser{reader: strings.NewReader(strings.Repeat("x", int(messageBusMaximumUnaryResponseBytes)+1))}
	transport := newMessageBusUnaryResponseLimitTransport(messageBusRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          body,
			ContentLength: -1,
		}, nil
	}), messageBusMaximumUnaryResponseBytes)

	response, err := transport.RoundTrip(messageBusRequest(http.MethodPost, "/v2/message_bus/event/casaos/casaos:test"))
	if err != nil {
		t.Fatalf("RoundTrip returned error before body read: %v", err)
	}
	_, err = io.ReadAll(response.Body)
	if !errors.Is(err, errMessageBusResponseTooLarge) {
		t.Fatalf("ReadAll error = %v, want response-size error", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !body.closed {
		t.Fatal("chunked oversized response body was not closed")
	}
}

func TestMessageBusUnaryResponseLimitAcceptsBoundedBody(t *testing.T) {
	body := &messageBusTrackingReadCloser{reader: strings.NewReader(strings.Repeat("x", int(messageBusMaximumUnaryResponseBytes)))}
	transport := newMessageBusUnaryResponseLimitTransport(messageBusRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          body,
			ContentLength: -1,
		}, nil
	}), messageBusMaximumUnaryResponseBytes)

	response, err := transport.RoundTrip(messageBusRequest(http.MethodPost, "/v2/message_bus/event_type"))
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if len(content) != int(messageBusMaximumUnaryResponseBytes) {
		t.Fatalf("bounded response length = %d, want %d", len(content), messageBusMaximumUnaryResponseBytes)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestMessageBusUnaryResponseLimitLeavesStreamingPathUnchanged(t *testing.T) {
	body := &messageBusTrackingReadCloser{reader: strings.NewReader(strings.Repeat("x", int(messageBusMaximumUnaryResponseBytes)+1))}
	transport := newMessageBusUnaryResponseLimitTransport(messageBusRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          body,
			ContentLength: -1,
		}, nil
	}), messageBusMaximumUnaryResponseBytes)

	response, err := transport.RoundTrip(messageBusRequest(http.MethodPost, "/v2/message_bus/socket.io/"))
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("streaming response ReadAll returned error: %v", err)
	}
	if len(content) != int(messageBusMaximumUnaryResponseBytes)+1 {
		t.Fatalf("streaming response length = %d, want %d", len(content), int(messageBusMaximumUnaryResponseBytes)+1)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestMessageBusGeneratedUnaryResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Content-Length", strconv.FormatInt(messageBusMaximumUnaryResponseBytes+1, 10))
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := newMessageBusTestClient(t, server.URL+"/v2/message_bus", messageBusHTTPClient, messageBusSuccessTimeout)
	_, err := client.RegisterEventTypesWithResponse(context.Background(), message_bus.RegisterEventTypesJSONRequestBody{})
	if !errors.Is(err, errMessageBusResponseTooLarge) {
		t.Fatalf("generated unary request error = %v, want response-size error", err)
	}
}
