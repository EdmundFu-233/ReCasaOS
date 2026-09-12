package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/service"
	serviceModel "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/labstack/echo/v4"
)

func TestParseManagedDirectoryPagination(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	overflowingInt := strconv.FormatUint(uint64(maxInt)+1, 10)
	tests := []struct {
		name      string
		rawQuery  string
		wantIndex int
		wantSize  int
		wantError bool
	}{
		{name: "both absent", rawQuery: "path=%2FDATA", wantIndex: 1, wantSize: service.ManagedDirectoryLegacyPageSize},
		{name: "valid pair", rawQuery: "path=%2FDATA&index=2&size=128", wantIndex: 2, wantSize: 128},
		{name: "index only", rawQuery: "index=1", wantError: true},
		{name: "size only", rawQuery: "size=1", wantError: true},
		{name: "repeated index", rawQuery: "index=1&index=1&size=1", wantError: true},
		{name: "repeated size", rawQuery: "index=1&size=1&size=1", wantError: true},
		{name: "empty index", rawQuery: "index=&size=1", wantError: true},
		{name: "empty size", rawQuery: "index=1&size=", wantError: true},
		{name: "plus sign", rawQuery: "index=%2B1&size=1", wantError: true},
		{name: "space", rawQuery: "index=%201&size=1", wantError: true},
		{name: "negative", rawQuery: "index=-1&size=1", wantError: true},
		{name: "zero index", rawQuery: "index=0&size=1", wantError: true},
		{name: "zero size", rawQuery: "index=1&size=0", wantError: true},
		{name: "oversized page", rawQuery: "index=1&size=513", wantError: true},
		{name: "maximum integer", rawQuery: "index=" + strconv.Itoa(maxInt) + "&size=1", wantIndex: maxInt, wantSize: 1},
		{name: "integer overflow", rawQuery: "index=" + overflowingInt + "&size=1", wantError: true},
		{name: "offset overflow", rawQuery: "index=" + strconv.Itoa(maxInt) + "&size=2", wantError: true},
		{name: "malformed escape", rawQuery: "index=1&size=1&path=%zz", wantError: true},
		{name: "malformed separator", rawQuery: "index=1;size=1", wantError: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			index, size, err := parseManagedDirectoryPagination(testCase.rawQuery)
			if testCase.wantError {
				if !errors.Is(err, errInvalidManagedDirectoryPagination) {
					t.Fatalf("error = %v, want invalid pagination", err)
				}
				return
			}
			if err != nil || index != testCase.wantIndex || size != testCase.wantSize {
				t.Fatalf("result = %d, %d, %v; want %d, %d", index, size, err, testCase.wantIndex, testCase.wantSize)
			}
		})
	}
}

func TestManagedDirectoryNeedsMountedExtensionsUsesPathBoundaries(t *testing.T) {
	for _, path := range []string{"/mnt", "/mnt/", "/mnt/archive", "/media", "/media/remote"} {
		if !managedDirectoryNeedsMountedExtensions(path) {
			t.Fatalf("managedDirectoryNeedsMountedExtensions(%q) = false", path)
		}
	}
	for _, path := range []string{"", "/DATA", "/mnt-other", "/media-library"} {
		if managedDirectoryNeedsMountedExtensions(path) {
			t.Fatalf("managedDirectoryNeedsMountedExtensions(%q) = true", path)
		}
	}
}

func TestDirPathRejectsInvalidPaginationBeforeServiceAccess(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/folder?index=1", nil)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := DirPath(ctx); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestManagedDirectoryScanLimitHasStableUnprocessableResponse(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/folder?path=%2Fprivate&index=1&size=1", nil)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	secret := "private-path-marker"
	err := errors.Join(fmt.Errorf("%s: %w", secret, service.ErrManagedDirectoryScanLimit), errors.New("close-detail-marker"))
	if responseErr := respondManagedDirectoryListingFailure(ctx, err); responseErr != nil {
		t.Fatal(responseErr)
	}
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "close-detail-marker") {
		t.Fatalf("internal error reflected in response: %s", response.Body.String())
	}
	var result model.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Success != common_err.FILE_READ_ERROR || result.Data != managedDirectoryLimitMessage {
		t.Fatalf("response = %+v", result)
	}
	if strings.Contains(response.Body.String(), "\"content\"") || strings.Contains(response.Body.String(), "\"total\"") {
		t.Fatalf("partial listing fields appeared in limit response: %s", response.Body.String())
	}
}

func TestManagedDirectoryBusyHasStableRetryableResponse(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/folder?path=%2Fprivate&index=1&size=1", nil)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	secret := "busy-private-detail"
	err := fmt.Errorf("%s: %w", secret, service.ErrManagedDirectoryListingBusy)
	if responseErr := respondManagedDirectoryListingFailure(ctx, err); responseErr != nil {
		t.Fatal(responseErr)
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatalf("internal error reflected in response: %s", response.Body.String())
	}
	var result model.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Success != common_err.SERVICE_ERROR || result.Data != managedDirectoryBusyMessage {
		t.Fatalf("response = %+v", result)
	}
	if strings.Contains(response.Body.String(), "\"content\"") || strings.Contains(response.Body.String(), "\"total\"") {
		t.Fatalf("partial listing fields appeared in busy response: %s", response.Body.String())
	}
}

func TestDirPathFifthConcurrentRequestReturnsServiceUnavailable(t *testing.T) {
	releases := make([]func(), 0, 4)
	for index := 0; index < 4; index++ {
		release, err := service.AcquireManagedDirectoryListing(context.Background())
		if err != nil {
			t.Fatalf("reserve slot %d: %v", index+1, err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	request := httptest.NewRequest(http.MethodGet, "/v1/folder?path=%2Fmust-not-be-opened&index=1&size=1", nil)
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := DirPath(ctx); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("status = %d, Retry-After = %q, body = %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestDirPathHoldsAdmissionThroughResponseWrite(t *testing.T) {
	previousService := service.MyService
	service.MyService = managedDirectoryRouteTestRepository{
		system: managedDirectoryRouteTestSystem{},
		shares: managedDirectoryRouteTestShares{},
	}
	t.Cleanup(func() { service.MyService = previousService })

	held := make([]func(), 0, 3)
	for index := 0; index < 3; index++ {
		release, err := service.AcquireManagedDirectoryListing(context.Background())
		if err != nil {
			t.Fatalf("reserve slot %d: %v", index+1, err)
		}
		held = append(held, release)
	}
	t.Cleanup(func() {
		for _, release := range held {
			release()
		}
	})

	writer := &managedDirectoryBlockingResponseWriter{
		header:  make(http.Header),
		started: make(chan struct{}),
		unblock: make(chan struct{}),
	}
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(writer.unblock) }) }
	t.Cleanup(unblock)
	request := httptest.NewRequest(http.MethodGet, "/v1/folder?path=%2FDATA&index=1&size=1", nil)
	ctx := echo.New().NewContext(request, writer)
	done := make(chan error, 1)
	go func() { done <- DirPath(ctx) }()

	select {
	case <-writer.started:
	case err := <-done:
		t.Fatalf("handler returned before response write: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach response write")
	}
	if release, err := service.AcquireManagedDirectoryListing(context.Background()); !errors.Is(err, service.ErrManagedDirectoryListingBusy) {
		if release != nil {
			release()
		}
		t.Fatalf("fifth admission while response blocked error = %v", err)
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handler error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish after response unblocked")
	}

	release, err := service.AcquireManagedDirectoryListing(context.Background())
	if err != nil {
		t.Fatalf("handler did not release admission: %v", err)
	}
	release()
}

type managedDirectoryRouteTestRepository struct {
	service.Repository
	system service.SystemService
	shares service.SharesService
}

func (r managedDirectoryRouteTestRepository) System() service.SystemService { return r.system }
func (r managedDirectoryRouteTestRepository) Shares() service.SharesService { return r.shares }

type managedDirectoryRouteTestSystem struct{ service.SystemService }

func (managedDirectoryRouteTestSystem) GetDirPathPage(context.Context, string, int, int) ([]model.Path, int64, error) {
	return []model.Path{{Name: "visible.txt", Path: "/DATA/visible.txt", Size: 7}}, 1, nil
}

type managedDirectoryRouteTestShares struct{ service.SharesService }

func (managedDirectoryRouteTestShares) GetSharesList() []serviceModel.SharesDBModel { return nil }

type managedDirectoryBlockingResponseWriter struct {
	header  http.Header
	started chan struct{}
	unblock chan struct{}
	once    sync.Once
	status  int
}

func (w *managedDirectoryBlockingResponseWriter) Header() http.Header { return w.header }

func (w *managedDirectoryBlockingResponseWriter) WriteHeader(status int) { w.status = status }

func (w *managedDirectoryBlockingResponseWriter) Write(payload []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.unblock
	return len(payload), nil
}
