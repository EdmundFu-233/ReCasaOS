package httper

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/config"
)

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (function httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type trackingReadCloser struct {
	reader io.Reader
	closed atomic.Bool
}

func (body *trackingReadCloser) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer)
}

func (body *trackingReadCloser) Close() error {
	body.closed.Store(true)
	return nil
}

type partialErrorReader struct {
	err  error
	done bool
}

func (reader *partialErrorReader) Read(buffer []byte) (int, error) {
	if reader.done {
		return 0, reader.err
	}
	reader.done = true
	return copy(buffer, "partial"), reader.err
}

type repeatingByteReader byte

func (reader repeatingByteReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = byte(reader)
	}
	return len(buffer), nil
}

type contextBlockingReader struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

func (reader *contextBlockingReader) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.ctx.Done()
	return 0, reader.ctx.Err()
}

func TestLegacyHTTPHelpersRejectMalformedURLWithoutPanic(t *testing.T) {
	const malformedURL = "http://[::1"

	tests := []struct {
		name string
		call func() bool
	}{
		{
			name: "Get with headers",
			call: func() bool {
				return Get(malformedURL, map[string]string{"X-Test": "value"}) == ""
			},
		},
		{
			name: "PersonGet",
			call: func() bool {
				return PersonGet(malformedURL) == ""
			},
		},
		{
			name: "Post",
			call: func() bool {
				return Post(malformedURL, []byte(`{"test":true}`), "application/json", nil) == ""
			},
		},
		{
			name: "ZeroTierGet",
			call: func() bool {
				content, code := ZeroTierGet(malformedURL, map[string]string{"X-Test": "value"})
				return content == "" && code == 0
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("helper panicked for malformed URL: %v", recovered)
				}
			}()
			if !test.call() {
				t.Fatal("helper did not return its documented zero value")
			}
		})
	}
}

func TestOasisGetRejectsMalformedConfiguredURLWithoutPanic(t *testing.T) {
	previousServerAPI := config.ServerInfo.ServerApi
	config.ServerInfo.ServerApi = "http://[::1"
	t.Cleanup(func() { config.ServerInfo.ServerApi = previousServerAPI })

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("OasisGet panicked for malformed configured URL: %v", recovered)
		}
	}()
	if response := OasisGet("http://[::1"); response != "" {
		t.Fatalf("OasisGet response = %q, want empty", response)
	}
}

func TestZeroTierGetReturnsZeroValuesOnTransportError(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ZeroTierGet panicked for transport error: %v", recovered)
		}
	}()
	content, code := ZeroTierGet("unsupported://device.test", nil)
	if content != "" || code != 0 {
		t.Fatalf("ZeroTierGet = (%q, %d), want empty zero values", content, code)
	}
}

func TestDoBoundedEnforcesActualBodyAndClosesIt(t *testing.T) {
	const maximum = int64(8)

	t.Run("exact limit ignores oversized declared length", func(t *testing.T) {
		body := &trackingReadCloser{reader: strings.NewReader("12345678")}
		client := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.URL.String() != "http://device.test/resource" {
				t.Errorf("request = %s %s", request.Method, request.URL)
			}
			if got := request.Header.Values("X-Test"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
				t.Errorf("X-Test headers = %#v", got)
			}
			requestContent, err := io.ReadAll(request.Body)
			if err != nil || string(requestContent) != "request" {
				t.Errorf("request body = %q, err = %v", requestContent, err)
			}
			return &http.Response{
				StatusCode:    http.StatusTeapot,
				ContentLength: maximum + 100,
				Body:          body,
			}, nil
		})

		response, err := doBounded(
			context.Background(),
			client,
			http.MethodPost,
			"http://device.test/resource",
			strings.NewReader("request"),
			http.Header{"X-Test": []string{"one", "two"}},
			maximum,
		)
		if err != nil {
			t.Fatalf("doBounded() error = %v", err)
		}
		if got := string(response.body); got != "12345678" {
			t.Fatalf("response body = %q", got)
		}
		if response.statusCode != http.StatusTeapot {
			t.Fatalf("status = %d", response.statusCode)
		}
		if !body.closed.Load() {
			t.Fatal("response body was not closed")
		}
	})

	t.Run("limit plus one ignores undersized declared length", func(t *testing.T) {
		body := &trackingReadCloser{reader: strings.NewReader("123456789")}
		client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusTooManyRequests,
				ContentLength: 1,
				Body:          body,
			}, nil
		})

		response, err := doBounded(
			context.Background(),
			client,
			http.MethodGet,
			"http://device.test/resource",
			nil,
			nil,
			maximum,
		)
		if !errors.Is(err, errLegacyResponseTooLarge) {
			t.Fatalf("error = %v, want errLegacyResponseTooLarge", err)
		}
		if len(response.body) != 0 || response.statusCode != http.StatusTooManyRequests {
			t.Fatalf("response = {body:%q status:%d}", response.body, response.statusCode)
		}
		if !body.closed.Load() {
			t.Fatal("over-limit response body was not closed")
		}
	})

	t.Run("read error discards partial body", func(t *testing.T) {
		readError := errors.New("injected read error")
		body := &trackingReadCloser{reader: &partialErrorReader{err: readError}}
		client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusPartialContent, ContentLength: -1, Body: body}, nil
		})

		response, err := doBounded(
			context.Background(),
			client,
			http.MethodGet,
			"http://device.test/resource",
			nil,
			nil,
			maximum,
		)
		if !errors.Is(err, readError) {
			t.Fatalf("error = %v, want injected read error", err)
		}
		if len(response.body) != 0 || response.statusCode != http.StatusPartialContent {
			t.Fatalf("response = {body:%q status:%d}", response.body, response.statusCode)
		}
		if !body.closed.Load() {
			t.Fatal("failed response body was not closed")
		}
	})

	t.Run("nil response body preserves received status", func(t *testing.T) {
		client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent}, nil
		})
		response, err := doBounded(
			context.Background(),
			client,
			http.MethodGet,
			"http://device.test/resource",
			nil,
			nil,
			maximum,
		)
		if !errors.Is(err, errLegacyInvalidResponse) || response.statusCode != http.StatusNoContent {
			t.Fatalf("response = %#v, error = %v", response, err)
		}
	})
}

func TestDoBoundedRejectsInvalidInputBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected network call")
	})

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		target  string
		maximum int64
	}{
		{name: "nil context", ctx: nil, target: "http://device.test", maximum: 1},
		{name: "cancelled context", ctx: cancelledContext, target: "http://device.test", maximum: 1},
		{name: "malformed URL", ctx: context.Background(), target: "http://[::1", maximum: 1},
		{name: "negative maximum", ctx: context.Background(), target: "http://device.test", maximum: -1},
		{name: "overflowing maximum", ctx: context.Background(), target: "http://device.test", maximum: math.MaxInt64},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := doBounded(test.ctx, client, http.MethodGet, test.target, nil, nil, test.maximum)
			if err == nil {
				t.Fatal("doBounded() unexpectedly succeeded")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("network calls = %d, want 0", calls.Load())
	}
}

func TestDoBoundedClosesBodyReturnedWithTransportError(t *testing.T) {
	transportError := errors.New("injected transport error")
	body := &trackingReadCloser{reader: strings.NewReader("untrusted")}
	client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: body}, transportError
	})

	response, err := doBounded(
		context.Background(),
		client,
		http.MethodGet,
		"http://device.test/resource",
		nil,
		nil,
		8,
	)
	var wrappedTransportError *legacyTransportError
	if !errors.As(err, &wrappedTransportError) || !errors.Is(err, transportError) {
		t.Fatalf("error = %v, want legacy transport error", err)
	}
	if len(response.body) != 0 || response.statusCode != 0 {
		t.Fatalf("response = %#v, want zero value", response)
	}
	if !body.closed.Load() {
		t.Fatal("transport-error response body was not closed")
	}
}

func TestDoBoundedStopsAndClosesBodyOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var body *trackingReadCloser
	client := httpDoerFunc(func(request *http.Request) (*http.Response, error) {
		body = &trackingReadCloser{reader: &contextBlockingReader{ctx: request.Context(), started: started}}
		return &http.Response{StatusCode: http.StatusServiceUnavailable, ContentLength: -1, Body: body}, nil
	})

	type callResult struct {
		response boundedResponse
		err      error
	}
	resultChannel := make(chan callResult, 1)
	go func() {
		response, err := doBounded(
			ctx,
			client,
			http.MethodGet,
			"http://device.test/resource",
			nil,
			nil,
			8,
		)
		resultChannel <- callResult{response: response, err: err}
	}()

	select {
	case <-started:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("response body read did not start")
	}

	select {
	case result := <-resultChannel:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", result.err)
		}
		if len(result.response.body) != 0 || result.response.statusCode != http.StatusServiceUnavailable {
			t.Fatalf("response = %#v", result.response)
		}
		if body == nil || !body.closed.Load() {
			t.Fatal("cancelled response body was not closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("doBounded did not return after cancellation")
	}
}

func newLegacyStreamingServer(
	t *testing.T,
	size int64,
	status int,
	verify func(*testing.T, *http.Request),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if verify != nil {
			verify(t, request)
		}
		writer.WriteHeader(status)
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = io.CopyN(writer, repeatingByteReader('x'), size)
	}))
}

func TestLegacyHTTPHelpersBoundChunkedResponsesAndPreserveStatus(t *testing.T) {
	tests := []struct {
		name       string
		maximum    int64
		call       func(string) (string, int)
		verify     func(*testing.T, *http.Request)
		tracksCode bool
	}{
		{
			name:    "Get",
			maximum: legacyGetMaximumResponseBytes,
			call: func(target string) (string, int) {
				return Get(target, map[string]string{"X-Test": "get"}), 0
			},
			verify: func(t *testing.T, request *http.Request) {
				if request.Method != http.MethodGet || request.Header.Get("X-Test") != "get" {
					t.Errorf("Get request = %s, X-Test %q", request.Method, request.Header.Get("X-Test"))
				}
			},
		},
		{
			name:    "PersonGet",
			maximum: legacyPersonGetMaximumResponseBytes,
			call: func(target string) (string, int) {
				return PersonGet(target), 0
			},
			verify: func(t *testing.T, request *http.Request) {
				if request.Method != http.MethodGet {
					t.Errorf("PersonGet method = %s", request.Method)
				}
			},
		},
		{
			name:    "Post",
			maximum: legacyPostMaximumResponseBytes,
			call: func(target string) (string, int) {
				return Post(target, []byte("payload"), "application/json", map[string]string{"X-Test": "post"}), 0
			},
			verify: func(t *testing.T, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Errorf("read Post body: %v", err)
				}
				if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-Test") != "post" || string(body) != "payload" {
					t.Errorf("Post request = method %s content-type %q X-Test %q body %q", request.Method, request.Header.Get("Content-Type"), request.Header.Get("X-Test"), body)
				}
			},
		},
		{
			name:    "ZeroTierGet",
			maximum: legacyZeroTierMaximumResponseBytes,
			call: func(target string) (string, int) {
				return ZeroTierGet(target, map[string]string{"X-Test": "zerotier"})
			},
			verify: func(t *testing.T, request *http.Request) {
				if request.Method != http.MethodGet || request.Header.Get("X-Test") != "zerotier" {
					t.Errorf("ZeroTierGet request = %s, X-Test %q", request.Method, request.Header.Get("X-Test"))
				}
			},
			tracksCode: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("exact limit", func(t *testing.T) {
				server := newLegacyStreamingServer(t, test.maximum, http.StatusTeapot, test.verify)
				defer server.Close()

				content, code := test.call(server.URL)
				if int64(len(content)) != test.maximum || content[0] != 'x' || content[len(content)-1] != 'x' {
					t.Fatalf("body length = %d, want %d", len(content), test.maximum)
				}
				if test.tracksCode && code != http.StatusTeapot {
					t.Fatalf("status = %d, want %d", code, http.StatusTeapot)
				}
			})

			t.Run("limit plus one", func(t *testing.T) {
				server := newLegacyStreamingServer(t, test.maximum+1, http.StatusTooManyRequests, test.verify)
				defer server.Close()

				content, code := test.call(server.URL)
				if content != "" {
					t.Fatalf("over-limit body length = %d, want 0", len(content))
				}
				if test.tracksCode && code != http.StatusTooManyRequests {
					t.Fatalf("status = %d, want %d", code, http.StatusTooManyRequests)
				}
			})
		})
	}
}

func TestPersonGetBoundsFixedLengthResponses(t *testing.T) {
	tests := []struct {
		name     string
		size     int64
		wantBody bool
	}{
		{name: "exact limit", size: legacyPersonGetMaximumResponseBytes, wantBody: true},
		{name: "limit plus one", size: legacyPersonGetMaximumResponseBytes + 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Length", strconv.FormatInt(test.size, 10))
				_, _ = io.CopyN(writer, repeatingByteReader('f'), test.size)
			}))
			defer server.Close()

			content := PersonGet(server.URL)
			if test.wantBody {
				if int64(len(content)) != test.size {
					t.Fatalf("body length = %d, want %d", len(content), test.size)
				}
				return
			}
			if content != "" {
				t.Fatalf("over-limit body length = %d, want 0", len(content))
			}
		})
	}
}

func TestGetBoundsTransparentlyDecompressedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding = %q, want gzip", request.Header.Get("Accept-Encoding"))
		}
		writer.Header().Set("Content-Encoding", "gzip")
		gzipWriter := gzip.NewWriter(writer)
		_, _ = io.CopyN(gzipWriter, repeatingByteReader('z'), legacyGetMaximumResponseBytes+1)
		_ = gzipWriter.Close()
	}))
	defer server.Close()

	if content := Get(server.URL, nil); content != "" {
		t.Fatalf("decompressed over-limit body length = %d, want 0", len(content))
	}
}

func TestZeroTierGetPreservesStatusOnResponseReadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", "1024")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("partial"))
	}))
	defer server.Close()

	content, code := ZeroTierGet(server.URL, nil)
	if content != "" || code != http.StatusPartialContent {
		t.Fatalf("ZeroTierGet() = (%q, %d), want empty body and %d", content, code, http.StatusPartialContent)
	}
}

func jsonDataBodyAtSize(t *testing.T, value string, size int64) string {
	t.Helper()
	prefix := `{"data":"` + value + `","padding":"`
	suffix := `"}`
	paddingLength := size - int64(len(prefix)) - int64(len(suffix))
	if paddingLength < 0 {
		t.Fatalf("JSON body size %d is too small", size)
	}
	return prefix + strings.Repeat("p", int(paddingLength)) + suffix
}

func TestOasisGetUsesSeparateTokenAndTargetLimits(t *testing.T) {
	const token = "Bearer oasis-test"

	t.Run("exact limits preserve authorization", func(t *testing.T) {
		var targetCalls atomic.Int32
		tokenBody := jsonDataBodyAtSize(t, token, legacyOasisTokenMaximumResponseBytes)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/token":
				_, _ = io.WriteString(writer, tokenBody)
			case "/v1/sys/version":
				targetCalls.Add(1)
				if got := request.Header.Get("Authorization"); got != token {
					t.Errorf("Authorization = %q, want %q", got, token)
				}
				_, _ = io.CopyN(writer, repeatingByteReader('v'), legacyOasisTargetMaximumResponseBytes)
			default:
				http.NotFound(writer, request)
			}
		}))
		defer server.Close()

		previousServerAPI := config.ServerInfo.ServerApi
		config.ServerInfo.ServerApi = server.URL
		t.Cleanup(func() { config.ServerInfo.ServerApi = previousServerAPI })

		content := OasisGet(server.URL + "/v1/sys/version")
		if int64(len(content)) != legacyOasisTargetMaximumResponseBytes || targetCalls.Load() != 1 {
			t.Fatalf("OasisGet body length = %d, target calls = %d", len(content), targetCalls.Load())
		}
	})

	t.Run("token overflow prevents target request", func(t *testing.T) {
		var targetCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/token":
				_, _ = io.CopyN(writer, repeatingByteReader('t'), legacyOasisTokenMaximumResponseBytes+1)
			case "/v1/sys/version":
				targetCalls.Add(1)
				_, _ = io.WriteString(writer, "unexpected")
			default:
				http.NotFound(writer, request)
			}
		}))
		defer server.Close()

		previousServerAPI := config.ServerInfo.ServerApi
		config.ServerInfo.ServerApi = server.URL
		t.Cleanup(func() { config.ServerInfo.ServerApi = previousServerAPI })

		if content := OasisGet(server.URL + "/v1/sys/version"); content != "" {
			t.Fatalf("OasisGet body length = %d, want 0", len(content))
		}
		if targetCalls.Load() != 0 {
			t.Fatalf("target calls = %d, want 0", targetCalls.Load())
		}
	})

	t.Run("target overflow returns empty body", func(t *testing.T) {
		var targetCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/token":
				_, _ = io.WriteString(writer, `{"data":"`+token+`"}`)
			case "/v1/sys/version":
				targetCalls.Add(1)
				if got := request.Header.Get("Authorization"); got != token {
					t.Errorf("Authorization = %q, want %q", got, token)
				}
				_, _ = io.CopyN(writer, repeatingByteReader('v'), legacyOasisTargetMaximumResponseBytes+1)
			default:
				http.NotFound(writer, request)
			}
		}))
		defer server.Close()

		previousServerAPI := config.ServerInfo.ServerApi
		config.ServerInfo.ServerApi = server.URL
		t.Cleanup(func() { config.ServerInfo.ServerApi = previousServerAPI })

		if content := OasisGet(server.URL + "/v1/sys/version"); content != "" {
			t.Fatalf("OasisGet body length = %d, want 0", len(content))
		}
		if targetCalls.Load() != 1 {
			t.Fatalf("target calls = %d, want 1", targetCalls.Load())
		}
	})
}

func TestConcurrentLegacyResponsesRemainBounded(t *testing.T) {
	server := newLegacyStreamingServer(
		t,
		legacyPersonGetMaximumResponseBytes+1,
		http.StatusOK,
		nil,
	)
	defer server.Close()

	const callers = 32
	start := make(chan struct{})
	errorsChannel := make(chan string, callers)
	var waitGroup sync.WaitGroup
	for index := 0; index < callers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			if content := PersonGet(server.URL); content != "" {
				errorsChannel <- content
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)

	for content := range errorsChannel {
		t.Fatalf("concurrent over-limit body length = %d, want 0", len(content))
	}
}
