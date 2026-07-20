//go:build linux

package publicfiles

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRangeErrorsRetainSecurityHeadersAndRejectMultipartWork(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "report.bin"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := BasePath + "/api/file?" + url.Values{"path": []string{"report.bin"}}.Encode()
	tests := []struct {
		name    string
		ranges  []string
		ifRange string
	}{
		{name: "unsatisfiable", ranges: []string{"bytes=99-100"}},
		{name: "multipart", ranges: []string{"bytes=0-0,2-2"}},
		{name: "multipart remains rejected with mismatched If-Range", ranges: []string{"bytes=0-0,2-2"}, ifRange: "Wed, 21 Oct 2015 07:28:00 GMT"},
		{name: "duplicate fields", ranges: []string{"bytes=0-0", "bytes=2-2"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := authorizedRequest(t, http.MethodGet, endpoint)
			for _, value := range test.ranges {
				request.Header.Add("Range", value)
			}
			if test.ifRange != "" {
				request.Header.Set("If-Range", test.ifRange)
			}
			response := serve(fixture.portal, request)
			if response.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("range status = %d, want 416; body=%q", response.Code, response.Body.String())
			}
			for key, want := range map[string]string{
				"Cache-Control":          "no-store",
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "no-referrer",
			} {
				if got := response.Header().Get(key); got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
			if got := response.Header().Get("Content-Range"); got != "bytes */10" {
				t.Errorf("Content-Range = %q, want bytes */10", got)
			}
		})
	}
}

func TestSparseFileHeadAndTailRangeUse64BitOffsets(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	size := (int64(5) << 30) + 7
	filePath := filepath.Join(fixture.root, "large.bin")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{'z'}, size-1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	endpoint := BasePath + "/api/file?" + url.Values{"path": []string{"large.bin"}}.Encode()
	server := NewHTTPServer(fixture.portal)
	address := startTestHTTPServer(t, server, nil)
	client := &http.Client{Timeout: 5 * time.Second}
	requestURL := "http://" + address + endpoint

	headRequest, err := http.NewRequest(http.MethodHead, requestURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	headRequest.Header.Set("Authorization", "Bearer "+testToken)
	head, err := client.Do(headRequest)
	if err != nil {
		t.Fatal(err)
	}
	headBody, readErr := io.ReadAll(head.Body)
	closeErr := head.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("large HEAD read/close = (%v, %v)", readErr, closeErr)
	}
	if head.StatusCode != http.StatusOK || len(headBody) != 0 || head.Header.Get("Content-Length") != strconv.FormatInt(size, 10) {
		t.Fatalf("large HEAD = status %d, length %q, body bytes %d", head.StatusCode, head.Header.Get("Content-Length"), len(headBody))
	}

	rangeRequest, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	rangeRequest.Header.Set("Authorization", "Bearer "+testToken)
	rangeRequest.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", size-1, size-1))
	ranged, err := client.Do(rangeRequest)
	if err != nil {
		t.Fatal(err)
	}
	rangeBody, readErr := io.ReadAll(ranged.Body)
	closeErr = ranged.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("large range read/close = (%v, %v)", readErr, closeErr)
	}
	if ranged.StatusCode != http.StatusPartialContent || string(rangeBody) != "z" {
		t.Fatalf("large tail range = status %d, body %q", ranged.StatusCode, rangeBody)
	}
	wantContentRange := fmt.Sprintf("bytes %d-%d/%d", size-1, size-1, size)
	if got := ranged.Header.Get("Content-Range"); got != wantContentRange {
		t.Fatalf("Content-Range = %q, want %q", got, wantContentRange)
	}

	invalidRequest, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidRequest.Header.Set("Authorization", "Bearer "+testToken)
	invalidRequest.Header.Set("Range", fmt.Sprintf("bytes=%d-", size))
	invalid, err := client.Do(invalidRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, invalid.Body)
	closeErr = invalid.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("invalid range read/close = (%v, %v)", readErr, closeErr)
	}
	if invalid.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("invalid range status = %d, want 416", invalid.StatusCode)
	}
	for key, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Range":          "bytes */" + strconv.FormatInt(size, 10),
	} {
		if got := invalid.Header.Get(key); got != want {
			t.Errorf("socket 416 %s = %q, want %q", key, got, want)
		}
	}
}

func TestErrorResponsesRetainSecurityHeaders(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "report.bin"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	responses := map[string]*httptest.ResponseRecorder{
		"401": serve(fixture.portal, httptest.NewRequest(http.MethodGet, BasePath+"/api/list", nil)),
		"404": serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/file?path=missing.bin")),
	}
	fixture.portal.downloadSlots = make(chan struct{}, 1)
	fixture.portal.downloadSlots <- struct{}{}
	responses["503"] = serve(fixture.portal, authorizedRequest(t, http.MethodGet, BasePath+"/api/file?path=report.bin"))
	<-fixture.portal.downloadSlots

	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			wantStatus, err := strconv.Atoi(name)
			if err != nil {
				t.Fatal(err)
			}
			if response.Code != wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, wantStatus)
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
			if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q", got)
			}
		})
	}
}

func TestStalledPortalDownloadReleasesCapacity(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	fixture.portal.downloadSlots = make(chan struct{}, 1)
	largePath := filepath.Join(fixture.root, "large.bin")
	if err := os.WriteFile(largePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(largePath, 64<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(largePath, 0o600); err != nil {
		t.Fatal(err)
	}

	config := testHTTPServerConfig()
	config.baseWriteTimeout = time.Second
	config.downloadWriteIdleTimeout = 100 * time.Millisecond
	config.downloadMinimumRateGrace = 2 * time.Second
	config.downloadMinimumRate = 1
	server := newHTTPServer(fixture.portal, config)
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
	requestPath := BasePath + "/api/file?" + url.Values{"path": []string{"large.bin"}}.Encode()
	if _, err := fmt.Fprintf(connection, "GET %s HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", requestPath, testToken); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 2*time.Second, func() bool { return len(fixture.portal.downloadSlots) == 1 }, "download slot was not acquired")
	waitForCondition(t, 4*time.Second, func() bool { return len(fixture.portal.downloadSlots) == 0 }, "stalled download did not release capacity")
	_ = connection.Close()

	headRequest, err := http.NewRequest(http.MethodHead, "http://"+address+requestPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	headRequest.Header.Set("Authorization", "Bearer "+testToken)
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(headRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("post-stall HEAD = status %d, read %v, close %v", response.StatusCode, readErr, closeErr)
	}
}

func TestDisconnectedPortalDownloadReleasesCapacity(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	fixture.portal.downloadSlots = make(chan struct{}, 1)
	largePath := filepath.Join(fixture.root, "disconnect.bin")
	if err := os.WriteFile(largePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(largePath, 64<<20); err != nil {
		t.Fatal(err)
	}

	config := testHTTPServerConfig()
	config.baseWriteTimeout = 10 * time.Second
	config.downloadWriteIdleTimeout = 5 * time.Second
	config.downloadMinimumRateGrace = 10 * time.Second
	config.downloadMinimumRate = 1
	server := newHTTPServer(fixture.portal, config)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := startTestHTTPServer(t, server, &smallWriteBufferListener{Listener: listener})
	requestPath := BasePath + "/api/file?" + url.Values{"path": []string{"disconnect.bin"}}.Encode()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+requestPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		t.Fatalf("download status = %d", response.StatusCode)
	}
	waitForCondition(t, time.Second, func() bool { return len(fixture.portal.downloadSlots) == 1 }, "download slot was not acquired")
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, 2*time.Second, func() bool { return len(fixture.portal.downloadSlots) == 0 }, "disconnected download did not promptly release capacity")
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !condition() {
		t.Fatal(message)
	}
}

func TestFileResponsesNeverExposeReaderFromFastPath(t *testing.T) {
	config := testHTTPServerConfig()
	seen := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seen = w.(io.ReaderFrom)
		w.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, BasePath+"/api/file?path=x", nil)
	recorder := &deadlineRecorder{}
	progressBoundedDownloadHandler(handler, config).ServeHTTP(recorder, request)
	if seen {
		t.Fatal("file handler received an io.ReaderFrom fast path")
	}
}

func TestRangeResponseDoesNotLeakHostPaths(t *testing.T) {
	fixture := newPortalFixture(t, 0)
	if err := os.WriteFile(filepath.Join(fixture.root, "report.bin"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := authorizedRequest(t, http.MethodGet, BasePath+"/api/file?path=report.bin")
	request.Header.Set("Range", "bytes=999-")
	response := serve(fixture.portal, request)
	if response.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("range status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), fixture.root) {
		t.Fatal("range error leaked a host path")
	}
}
