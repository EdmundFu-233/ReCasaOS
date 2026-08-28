package service

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

// MessageBus unary response helpers buffer the complete response body before
// decoding it. Keep that generated behavior bounded for the two in-tree
// request/response operations without imposing a lifetime or body limit on
// streaming/WebSocket capabilities exposed by the raw client accessor.
const messageBusMaximumUnaryResponseBytes int64 = 1 << 20

var errMessageBusResponseTooLarge = errors.New("message bus unary response exceeds size limit")

type messageBusUnaryResponseLimitTransport struct {
	base    http.RoundTripper
	maximum int64
}

func newMessageBusUnaryResponseLimitTransport(base http.RoundTripper, maximum int64) http.RoundTripper {
	return &messageBusUnaryResponseLimitTransport{base: base, maximum: maximum}
}

func (t *messageBusUnaryResponseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil || response == nil || !isMessageBusUnaryRequest(request) || response.Body == nil {
		return response, err
	}

	if response.ContentLength > t.maximum {
		_ = response.Body.Close()
		return nil, errMessageBusResponseTooLarge
	}

	response.Body = &messageBusBoundedResponseBody{
		body:      response.Body,
		remaining: t.maximum,
	}
	return response, nil
}

func isMessageBusUnaryRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Method != http.MethodPost {
		return false
	}

	path := strings.TrimRight(request.URL.Path, "/")
	if strings.HasSuffix(path, "/event_type") {
		return true
	}
	return strings.Contains(path, "/event/")
}

type messageBusBoundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
}

func (body *messageBusBoundedResponseBody) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}

	if body.remaining == 0 {
		var probe [1]byte
		read, err := body.body.Read(probe[:])
		if read > 0 {
			return 0, errMessageBusResponseTooLarge
		}
		if err == nil {
			return 0, io.ErrNoProgress
		}
		return 0, err
	}

	if int64(len(destination)) > body.remaining {
		destination = destination[:body.remaining]
	}
	read, err := body.body.Read(destination)
	body.remaining -= int64(read)
	return read, err
}

func (body *messageBusBoundedResponseBody) Close() error {
	return body.body.Close()
}
