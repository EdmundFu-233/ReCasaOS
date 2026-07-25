package publicfiles

import (
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
