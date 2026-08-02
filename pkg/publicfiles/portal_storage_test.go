package publicfiles

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortalDoesNotUseModificationTimeAsRangeValidator(t *testing.T) {
	t.Parallel()

	const (
		oldContent = "old representation"
		newContent = "new representation"
	)
	sharedModTime := time.Unix(1_700_000_000, 0).UTC()
	content := []byte(oldContent)
	backend := &scriptedStorageBackend{
		openFn: func(context.Context, string) (storageFile, fileInfo, error) {
			payload := append([]byte(nil), content...)
			return &memoryStorageFile{Reader: bytes.NewReader(payload)}, testStorageFileInfo{
				name:    "report.txt",
				size:    int64(len(payload)),
				modTime: sharedModTime,
			}, nil
		},
	}
	bearer := testPublicBearer(19)
	portal := testPortalWithStorage(backend, bearer)
	endpoint := "https://files.example.test" + BasePath + "/api/file?path=report.txt"

	prior := httptest.NewRequest(http.MethodGet, endpoint, nil)
	prior.Header.Set("Authorization", "Bearer "+bearer)
	prior.Header.Set("Range", "bytes=0-3")
	priorResponse := httptest.NewRecorder()
	portal.ServeHTTP(priorResponse, prior)
	if priorResponse.Code != http.StatusPartialContent || priorResponse.Body.String() != "old " {
		t.Fatalf(
			"prior range = status %d, body %q; want 206 and old prefix",
			priorResponse.Code,
			priorResponse.Body.String(),
		)
	}

	content = []byte(newContent)
	resume := httptest.NewRequest(http.MethodGet, endpoint, nil)
	resume.Header.Set("Authorization", "Bearer "+bearer)
	resume.Header.Set("Range", "bytes=4-")
	resume.Header.Set("If-Range", sharedModTime.Format(http.TimeFormat))
	resumeResponse := httptest.NewRecorder()
	portal.ServeHTTP(resumeResponse, resume)

	if resumeResponse.Code != http.StatusOK {
		t.Fatalf("date-based If-Range status = %d, want 200", resumeResponse.Code)
	}
	if got := resumeResponse.Body.String(); got != newContent {
		t.Fatalf("date-based If-Range body = %q, want complete new representation", got)
	}
	if got := resumeResponse.Header().Get("Content-Range"); got != "" {
		t.Fatalf("date-based If-Range Content-Range = %q, want empty", got)
	}
	if got := resumeResponse.Header().Get("Last-Modified"); got != "" {
		t.Fatalf("Last-Modified = %q, want no weak range validator", got)
	}

	initial := httptest.NewRequest(http.MethodGet, endpoint, nil)
	initial.Header.Set("Authorization", "Bearer "+bearer)
	initial.Header.Set("Range", "bytes=4-")
	initialResponse := httptest.NewRecorder()
	portal.ServeHTTP(initialResponse, initial)

	if initialResponse.Code != http.StatusPartialContent {
		t.Fatalf("initial range status = %d, want 206", initialResponse.Code)
	}
	if got, want := initialResponse.Body.String(), newContent[4:]; got != want {
		t.Fatalf("initial range body = %q, want %q", got, want)
	}
	if got := initialResponse.Header().Get("Content-Range"); got != "bytes 4-17/18" {
		t.Fatalf("initial range Content-Range = %q, want bytes 4-17/18", got)
	}
}

func TestPortalMapsStorageWorkerPressureToServiceUnavailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		backend  *scriptedStorageBackend
	}{
		{
			name:     "directory list capacity",
			endpoint: BasePath + "/api/list?path=",
			backend: &scriptedStorageBackend{
				listFn: func(context.Context, string, int) ([]Entry, error) {
					return nil, errStorageCapacity
				},
			},
		},
		{
			name:     "file open timeout",
			endpoint: BasePath + "/api/file?path=report.txt",
			backend: &scriptedStorageBackend{
				openFn: func(context.Context, string) (storageFile, fileInfo, error) {
					return nil, nil, errStorageTimeout
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bearer := testPublicBearer(31)
			portal := testPortalWithStorage(test.backend, bearer)
			request := httptest.NewRequest(http.MethodGet, "https://files.example.test"+test.endpoint, nil)
			request.Header.Set("Authorization", "Bearer "+bearer)
			response := httptest.NewRecorder()

			portal.ServeHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
			}
			if got := response.Header().Get("Retry-After"); got != "5" {
				t.Fatalf("Retry-After = %q, want 5", got)
			}
			if body := response.Body.String(); body != `{"error":"storage capacity unavailable"}` {
				t.Fatalf("body = %q, want generic storage-unavailable error", body)
			}
		})
	}
}

func TestPortalAbortsCommittedResponseAfterStorageSourceFailure(t *testing.T) {
	t.Parallel()

	sourceFailure := errors.New("synthetic source read failure")
	file := &failingStorageFile{
		data:         []byte("partial"),
		declaredSize: 32,
		failure:      sourceFailure,
	}
	backend := &scriptedStorageBackend{
		openFn: func(context.Context, string) (storageFile, fileInfo, error) {
			return file, testStorageFileInfo{
				name:    "report.txt",
				size:    file.declaredSize,
				modTime: time.Unix(1, 0),
			}, nil
		},
	}
	bearer := testPublicBearer(47)
	portal := testPortalWithStorage(backend, bearer)
	request := httptest.NewRequest(
		http.MethodGet,
		"https://files.example.test"+BasePath+"/api/file?path=report.txt",
		nil,
	)
	request.Header.Set("Authorization", "Bearer "+bearer)
	response := httptest.NewRecorder()

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		portal.ServeHTTP(response, request)
	}()

	if !errors.Is(asError(recovered), http.ErrAbortHandler) {
		t.Fatalf("panic = %v, want http.ErrAbortHandler", recovered)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Length"); got != "32" {
		t.Fatalf("Content-Length = %q, want 32", got)
	}
	if got := response.Body.String(); got != "partial" {
		t.Fatalf("body = %q, want only the bytes read before failure", got)
	}
	if !errors.Is(file.sourceError(), sourceFailure) {
		t.Fatalf("sourceError() = %v, want synthetic failure", file.sourceError())
	}
	if file.closeCalls.Load() != 1 {
		t.Fatalf("Close() calls = %d, want 1", file.closeCalls.Load())
	}
}

func asError(value any) error {
	err, _ := value.(error)
	return err
}

func testPortalWithStorage(storage storageBackend, bearer string) *Portal {
	return newPortalWithStorage(
		validatedPortalConfig{
			maxEntries:   DefaultMaxDirectoryEntries,
			maxDownloads: 1,
		},
		storage,
		digestPublicBearer(bearer),
	)
}

type scriptedStorageBackend struct {
	listFn  func(context.Context, string, int) ([]Entry, error)
	openFn  func(context.Context, string) (storageFile, fileInfo, error)
	closeFn func() error
}

func (s *scriptedStorageBackend) list(
	ctx context.Context,
	relativePath string,
	maxEntries int,
) ([]Entry, error) {
	if s.listFn == nil {
		return nil, errStorageProtocol
	}
	return s.listFn(ctx, relativePath, maxEntries)
}

func (s *scriptedStorageBackend) openRegular(
	ctx context.Context,
	relativePath string,
) (storageFile, fileInfo, error) {
	if s.openFn == nil {
		return nil, nil, errStorageProtocol
	}
	return s.openFn(ctx, relativePath)
}

func (s *scriptedStorageBackend) close() error {
	if s.closeFn == nil {
		return nil
	}
	return s.closeFn()
}

type failingStorageFile struct {
	data         []byte
	declaredSize int64
	failure      error
	offset       int64
	sourceErr    error
	closeCalls   atomic.Int32
}

func (f *failingStorageFile) Read(buffer []byte) (int, error) {
	if f.offset >= int64(len(f.data)) {
		f.sourceErr = f.failure
		return 0, f.failure
	}
	count := copy(buffer, f.data[f.offset:])
	f.offset += int64(count)
	f.sourceErr = f.failure
	return count, f.failure
}

func (f *failingStorageFile) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = f.offset
	case io.SeekEnd:
		base = f.declaredSize
	default:
		return 0, errStorageProtocol
	}
	next := base + offset
	if next < 0 {
		return 0, errStorageProtocol
	}
	f.offset = next
	return next, nil
}

func (f *failingStorageFile) Close() error {
	f.closeCalls.Add(1)
	return nil
}

func (f *failingStorageFile) sourceError() error {
	return f.sourceErr
}

type memoryStorageFile struct {
	*bytes.Reader
}

func (f *memoryStorageFile) Close() error {
	return nil
}

type testStorageFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (i testStorageFileInfo) Name() string       { return i.name }
func (i testStorageFileInfo) Size() int64        { return i.size }
func (i testStorageFileInfo) Mode() os.FileMode  { return 0o400 }
func (i testStorageFileInfo) ModTime() time.Time { return i.modTime }
func (i testStorageFileInfo) IsDir() bool        { return false }
func (i testStorageFileInfo) Sys() any           { return nil }
