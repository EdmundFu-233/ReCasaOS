package publicfiles

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deadlineRecorder struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	deadlines   []time.Time
	deadlineErr error
}

func (r *deadlineRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *deadlineRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *deadlineRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(payload)
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadlines = append(r.deadlines, deadline)
	return r.deadlineErr
}

func TestRateAllowanceRoundsUpAndSaturates(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		rate  int64
		want  time.Duration
	}{
		{name: "empty", bytes: 0, rate: 10, want: 0},
		{name: "invalid rate", bytes: 1, rate: 0, want: 0},
		{name: "half second", bytes: 1, rate: 2, want: 500 * time.Millisecond},
		{name: "one and a half seconds", bytes: 3, rate: 2, want: 1500 * time.Millisecond},
		{name: "nanosecond ceiling", bytes: 1, rate: 3_000_000_000, want: time.Nanosecond},
		{name: "saturated", bytes: int64(^uint64(0) >> 1), rate: 1, want: time.Duration(1<<63 - 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rateAllowance(test.bytes, test.rate); got != test.want {
				t.Fatalf("rateAllowance(%d, %d) = %v, want %v", test.bytes, test.rate, got, test.want)
			}
		})
	}
}

func TestProgressBoundedWriterUsesIdleAndCumulativeRateDeadlines(t *testing.T) {
	start := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	now := start
	recorder := &deadlineRecorder{}
	writer := &progressBoundedWriter{
		ResponseWriter: recorder,
		started:        start,
		now:            func() time.Time { return now },
		idleTimeout:    10 * time.Second,
		minimumGrace:   3 * time.Second,
		minimumRate:    10,
	}

	writer.WriteHeader(http.StatusPartialContent)
	if recorder.status != http.StatusPartialContent || len(recorder.deadlines) != 1 || !recorder.deadlines[0].Equal(start.Add(3*time.Second)) {
		t.Fatalf("initial header status/deadline = %d / %v", recorder.status, recorder.deadlines)
	}

	now = start.Add(time.Second)
	if written, err := writer.Write(bytes.Repeat([]byte{'a'}, 100)); err != nil || written != 100 {
		t.Fatalf("first Write = (%d, %v)", written, err)
	}
	if got := recorder.deadlines[len(recorder.deadlines)-1]; !got.Equal(start.Add(11 * time.Second)) {
		t.Fatalf("idle-bounded deadline = %v, want %v", got, start.Add(11*time.Second))
	}

	now = start.Add(10 * time.Second)
	if written, err := writer.Write(bytes.Repeat([]byte{'b'}, 10)); err != nil || written != 10 {
		t.Fatalf("second Write = (%d, %v)", written, err)
	}
	if got := recorder.deadlines[len(recorder.deadlines)-1]; !got.Equal(start.Add(14 * time.Second)) {
		t.Fatalf("rate-bounded deadline = %v, want %v", got, start.Add(14*time.Second))
	}
	if writer.bodyBytes != 110 {
		t.Fatalf("accounted body bytes = %d, want 110", writer.bodyBytes)
	}
	if _, ok := any(writer).(io.ReaderFrom); ok {
		t.Fatal("progress writer must not expose io.ReaderFrom")
	}
}

func TestProgressBoundedWriterCannotRefreshAnExpiredIdleGap(t *testing.T) {
	start := time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
	now := start
	recorder := &deadlineRecorder{}
	writer := &progressBoundedWriter{
		ResponseWriter: recorder,
		started:        start,
		lastProgress:   start,
		now:            func() time.Time { return now },
		idleTimeout:    10 * time.Second,
		minimumGrace:   time.Minute,
		minimumRate:    1,
	}
	if written, err := writer.Write([]byte("first")); err != nil || written != len("first") {
		t.Fatalf("initial Write = (%d, %v)", written, err)
	}
	deadlinesBefore := len(recorder.deadlines)
	now = start.Add(10 * time.Second)
	if written, err := writer.Write([]byte("must not be sent")); written != 0 || !errors.Is(err, errDownloadWriteIdleExceeded) {
		t.Fatalf("post-idle Write = (%d, %v)", written, err)
	}
	if len(recorder.deadlines) != deadlinesBefore {
		t.Fatal("expired idle gap refreshed the socket deadline")
	}
	if recorder.body.String() != "first" {
		t.Fatalf("post-idle payload reached the response: %q", recorder.body.String())
	}
}

func TestProgressBoundedWriterFailsClosedWithoutDeadlineControl(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("Accept-Ranges", "bytes")
	recorder.Header().Set("Content-Disposition", `attachment; filename="private.bin"`)
	recorder.Header().Set("Content-Length", "1234")
	recorder.Header().Set("Content-Range", "bytes 0-1233/1234")
	recorder.Header().Set("Content-Type", "application/octet-stream")
	writer := &progressBoundedWriter{
		ResponseWriter: recorder,
		started:        time.Now(),
		now:            time.Now,
		idleTimeout:    time.Second,
		minimumGrace:   time.Second,
		minimumRate:    1,
	}
	writer.WriteHeader(http.StatusOK)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("unsupported deadline writer status = %d, want 500", recorder.Code)
	}
	if _, err := writer.Write([]byte("must not be sent")); !errors.Is(err, errDownloadDeadlineUnavailable) {
		t.Fatalf("unsupported deadline Write error = %v", err)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("unsupported writer leaked body %q", recorder.Body.String())
	}
	if recorder.Header().Get("Content-Length") != "0" || recorder.Header().Get("Connection") != "close" {
		t.Fatalf("unsupported writer did not produce a zero-length closing response: %#v", recorder.Header())
	}
	for _, name := range []string{"Accept-Ranges", "Content-Disposition", "Content-Range", "Content-Type"} {
		if got := recorder.Header().Get(name); got != "" {
			t.Errorf("unsupported writer retained %s=%q", name, got)
		}
	}
}

func TestNewHTTPServerUsesDedicatedFiniteLimits(t *testing.T) {
	server := NewHTTPServer(http.NotFoundHandler())
	if server.ReadHeaderTimeout != DefaultReadHeaderTimeout ||
		server.ReadTimeout != DefaultReadTimeout ||
		server.WriteTimeout != DefaultDownloadWriteIdleTimeout ||
		server.IdleTimeout != DefaultConnectionIdleTimeout ||
		server.MaxHeaderBytes != DefaultMaxHeaderBytes || server.Handler == nil {
		t.Fatalf("unexpected public HTTP server limits: %#v", server)
	}
}

func TestProgressingSocketResponseOutlivesBaseWriteTimeout(t *testing.T) {
	handlerDone := make(chan error, 1)
	chunk := bytes.Repeat([]byte{'x'}, 8<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for index := 0; index < 5; index++ {
			if index > 0 {
				time.Sleep(75 * time.Millisecond)
			}
			if _, err := w.Write(chunk); err != nil {
				handlerDone <- err
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				handlerDone <- err
				return
			}
		}
		handlerDone <- nil
	})
	config := testHTTPServerConfig()
	config.baseWriteTimeout = 100 * time.Millisecond
	config.downloadWriteIdleTimeout = 2 * time.Second
	config.downloadMinimumRateGrace = 2 * time.Second
	config.downloadMinimumRate = 1
	server := newHTTPServer(handler, config)
	address := startTestHTTPServer(t, server, nil)

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + address + BasePath + "/api/file?path=progress.bin")
	if err != nil {
		t.Fatal(err)
	}
	payload, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("progress response read/close = (%v, %v)", readErr, closeErr)
	}
	if response.StatusCode != http.StatusOK || len(payload) != len(chunk)*5 {
		t.Fatalf("progress response = status %d, bytes %d", response.StatusCode, len(payload))
	}
	if handlerErr := <-handlerDone; handlerErr != nil {
		t.Fatalf("progress handler failed: %v", handlerErr)
	}
}

func TestStalledSocketResponseHitsIdleDeadline(t *testing.T) {
	handlerDone := make(chan error, 1)
	chunk := bytes.Repeat([]byte{'s'}, 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := w.Write(chunk); err != nil {
				handlerDone <- err
				return
			}
		}
	})
	config := testHTTPServerConfig()
	config.baseWriteTimeout = time.Second
	config.downloadWriteIdleTimeout = 100 * time.Millisecond
	config.downloadMinimumRateGrace = 2 * time.Second
	config.downloadMinimumRate = 1
	server := newHTTPServer(handler, config)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := startTestHTTPServer(t, server, &smallWriteBufferListener{Listener: listener})

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET %s/api/file?path=stalled.bin HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", BasePath); err != nil {
		t.Fatal(err)
	}

	select {
	case handlerErr := <-handlerDone:
		if handlerErr == nil {
			t.Fatal("stalled response unexpectedly completed without an error")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("stalled response did not hit its write deadline")
	}
}

func TestPausedSocketWriterCannotRefreshExpiredIdleDeadline(t *testing.T) {
	handlerDone := make(chan error, 1)
	chunk := bytes.Repeat([]byte{'p'}, 8<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(chunk); err != nil {
			handlerDone <- err
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			handlerDone <- err
			return
		}
		time.Sleep(250 * time.Millisecond)
		_, err := w.Write(chunk)
		handlerDone <- err
	})
	config := testHTTPServerConfig()
	config.baseWriteTimeout = 5 * time.Second
	config.downloadWriteIdleTimeout = 100 * time.Millisecond
	config.downloadMinimumRateGrace = 5 * time.Second
	config.downloadMinimumRate = 1
	server := newHTTPServer(handler, config)
	address := startTestHTTPServer(t, server, nil)

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + address + BasePath + "/api/file?path=pause.bin")
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	select {
	case handlerErr := <-handlerDone:
		if !errors.Is(handlerErr, errDownloadWriteIdleExceeded) {
			t.Fatalf("post-pause Write error = %v, want idle deadline", handlerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("paused handler did not return")
	}
}

func TestTrickleSocketResponseHitsCumulativeRateDeadline(t *testing.T) {
	handlerDone := make(chan error, 1)
	chunk := bytes.Repeat([]byte{'t'}, 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := w.Write(chunk); err != nil {
				handlerDone <- err
				return
			}
		}
	})
	config := testHTTPServerConfig()
	config.baseWriteTimeout = 10 * time.Second
	config.downloadWriteIdleTimeout = 5 * time.Second
	config.downloadMinimumRateGrace = time.Second
	config.downloadMinimumRate = 4 << 20
	server := newHTTPServer(handler, config)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := startTestHTTPServer(t, server, &smallWriteBufferListener{Listener: listener})

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+BasePath+"/api/file?path=trickle.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	if err := request.Write(connection); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	started := time.Now()
	totalRead := 0
	buffer := make([]byte, 32<<10)
	var handlerErr error
	for handlerErr == nil && time.Since(started) < 4*time.Second {
		read, readErr := response.Body.Read(buffer)
		totalRead += read
		select {
		case handlerErr = <-handlerDone:
		default:
		}
		if readErr != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if handlerErr == nil {
		select {
		case handlerErr = <-handlerDone:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("below-budget trickle response was not terminated")
		}
	}
	if handlerErr == nil {
		t.Fatal("below-budget trickle response completed without a write error")
	}
	if totalRead == 0 {
		t.Fatal("trickle client did not read any response body before termination")
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("trickle response lasted %v and may have hit the idle deadline instead of the rate budget", elapsed)
	}
}

func testHTTPServerConfig() httpServerConfig {
	config := defaultHTTPServerConfig()
	config.readHeaderTimeout = time.Second
	config.readTimeout = time.Second
	config.connectionIdleTimeout = time.Second
	return config
}

type smallWriteBufferListener struct {
	net.Listener
}

func (l *smallWriteBufferListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetWriteBuffer(1 << 10); err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	return connection, nil
}

func startTestHTTPServer(t *testing.T, server *http.Server, listener net.Listener) string {
	t.Helper()
	if listener == nil {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("test HTTP server stopped with %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("test HTTP server did not stop")
		}
	})
	return listener.Addr().String()
}
