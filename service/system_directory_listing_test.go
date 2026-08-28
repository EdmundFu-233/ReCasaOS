package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadManagedDirectoryPageFiltersCountsAndRetainsOnlyPage(t *testing.T) {
	dirEntryInfoCalled := false
	directory := &managedDirectoryTestReader{entries: []fs.DirEntry{
		managedDirectoryTestEntry{name: "a.txt", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "link", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "b", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "pipe", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "gone", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: ".temp", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "active.txt", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "c.txt", infoCalled: &dirEntryInfoCalled},
		managedDirectoryTestEntry{name: "d.txt", infoCalled: &dirEntryInfoCalled},
	}}
	metadata := map[string]managedDirectoryTestInfo{
		"a.txt":      {name: "opaque", size: 1},
		"link":       {name: "opaque", mode: fs.ModeSymlink},
		"b":          {name: "opaque", mode: fs.ModeDir},
		"pipe":       {name: "opaque", mode: fs.ModeNamedPipe},
		".temp":      {name: "opaque", mode: fs.ModeDir},
		"active.txt": {name: "opaque"},
		"c.txt":      {name: "opaque", size: 3},
		"d.txt":      {name: "opaque", size: 4},
	}
	statEntry := func(name string) (fs.FileInfo, error) {
		if name == "gone" {
			return nil, fs.ErrNotExist
		}
		info := metadata[name]
		return info, nil
	}
	hidden := map[string]string{filepath.Join("root", "safe", "active.txt"): "source.txt"}

	page, total, err := readManagedDirectoryPage(context.Background(), directory, filepath.Join("root", "safe"), 2, 2, hidden, pagedDirectoryFilterInternal, statEntry)
	if err != nil {
		t.Fatalf("readManagedDirectoryPage() error = %v", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(page) != 2 || page[0].Name != "c.txt" || page[1].Name != "d.txt" {
		t.Fatalf("page = %+v", page)
	}
	if page[0].Path != filepath.Join("root", "safe", "c.txt") || page[0].Size != 3 {
		t.Fatalf("first page entry = %+v", page[0])
	}
	if cap(page) != 2 {
		t.Fatalf("page capacity = %d, want retention bound 2", cap(page))
	}
	if dirEntryInfoCalled {
		t.Fatal("DirEntry.Info was called instead of descriptor-relative metadata")
	}
	assertManagedDirectoryReadRequests(t, directory.requests)
	if !directory.closed {
		t.Fatal("directory was not closed")
	}
}

func TestLegacyGetDirPathVisibilityPolicyKeepsTempDirectory(t *testing.T) {
	if legacyDirectoryFilterInternal || !pagedDirectoryFilterInternal {
		t.Fatalf("visibility policies legacy=%t paged=%t", legacyDirectoryFilterInternal, pagedDirectoryFilterInternal)
	}
	directory := &managedDirectoryTestReader{entries: []fs.DirEntry{
		managedDirectoryTestEntry{name: ".temp"},
		managedDirectoryTestEntry{name: "visible.txt"},
	}}
	statEntry := func(name string) (fs.FileInfo, error) {
		if name == ".temp" {
			return managedDirectoryTestInfo{name: "opaque", mode: fs.ModeDir}, nil
		}
		return managedDirectoryTestInfo{name: "opaque"}, nil
	}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, 2, nil, legacyDirectoryFilterInternal, statEntry)
	if err != nil {
		t.Fatalf("legacy scan error = %v", err)
	}
	if total != 2 || len(page) != 2 || page[0].Name != ".temp" || !page[0].IsDir || page[1].Name != "visible.txt" {
		t.Fatalf("legacy result = %+v, total=%d", page, total)
	}
}

func TestReadManagedDirectoryPageAcceptsExactRawLimit(t *testing.T) {
	directory := &managedDirectoryCountReader{remaining: ManagedDirectoryRawScanLimit}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", int64(ManagedDirectoryRawScanLimit-2), 2, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if err != nil {
		t.Fatalf("readManagedDirectoryPage() error = %v", err)
	}
	if total != ManagedDirectoryRawScanLimit {
		t.Fatalf("total = %d, want %d", total, ManagedDirectoryRawScanLimit)
	}
	if len(page) != 2 {
		t.Fatalf("page length = %d, want 2", len(page))
	}
	assertManagedDirectoryReadRequests(t, directory.requests)
	if got := directory.requests[len(directory.requests)-1]; got != 1 {
		t.Fatalf("final EOF probe size = %d, want 1", got)
	}
}

func TestReadManagedDirectoryPageRejectsRawLimitWithoutPartialResults(t *testing.T) {
	directory := &managedDirectoryCountReader{remaining: ManagedDirectoryRawScanLimit + 1}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, 2, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if !errors.Is(err, ErrManagedDirectoryScanLimit) {
		t.Fatalf("error = %v, want ErrManagedDirectoryScanLimit", err)
	}
	if page != nil || total != 0 {
		t.Fatalf("partial result returned: page=%+v total=%d", page, total)
	}
	if directory.remaining != 0 {
		t.Fatalf("raw sentinel was not consumed, remaining = %d", directory.remaining)
	}
	assertManagedDirectoryReadRequests(t, directory.requests)
	if !directory.closed {
		t.Fatal("directory was not closed")
	}
}

func TestReadManagedDirectoryLegacyModeRetainsCompleteBoundedList(t *testing.T) {
	directory := &managedDirectoryCountReader{remaining: ManagedDirectoryRawScanLimit}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, ManagedDirectoryRawScanLimit, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if err != nil {
		t.Fatalf("legacy listing error = %v", err)
	}
	if len(page) != ManagedDirectoryRawScanLimit || cap(page) != ManagedDirectoryRawScanLimit || total != ManagedDirectoryRawScanLimit {
		t.Fatalf("legacy result len=%d cap=%d total=%d", len(page), cap(page), total)
	}
	if page[0].Name != "entry-00000" || page[len(page)-1].Name != "entry-09999" {
		t.Fatalf("legacy endpoints = %q, %q", page[0].Name, page[len(page)-1].Name)
	}
}

func TestReadManagedDirectoryLegacyModeRejectsEntryAfterLimit(t *testing.T) {
	directory := &managedDirectoryCountReader{remaining: ManagedDirectoryRawScanLimit + 1}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, ManagedDirectoryRawScanLimit, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if !errors.Is(err, ErrManagedDirectoryScanLimit) || page != nil || total != 0 {
		t.Fatalf("legacy over-limit result = %+v, %d, %v", page, total, err)
	}
}

func TestReadManagedDirectoryPageCloseErrorDiscardsResults(t *testing.T) {
	closeErr := errors.New("injected close failure")
	directory := &managedDirectoryTestReader{
		entries:  []fs.DirEntry{managedDirectoryTestEntry{name: "a.txt"}},
		closeErr: closeErr,
	}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, 1, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want close failure", err)
	}
	if page != nil || total != 0 {
		t.Fatalf("partial result returned after close failure: page=%+v total=%d", page, total)
	}
}

func TestReadManagedDirectoryPagesAreStableAndNonOverlapping(t *testing.T) {
	want := [][]string{{"entry-0", "entry-1"}, {"entry-2", "entry-3"}, {"entry-4"}, {}}
	for pageIndex, wantNames := range want {
		directory := &managedDirectoryTestReader{entries: []fs.DirEntry{
			managedDirectoryTestEntry{name: "entry-0"},
			managedDirectoryTestEntry{name: "entry-1"},
			managedDirectoryTestEntry{name: "entry-2"},
			managedDirectoryTestEntry{name: "entry-3"},
			managedDirectoryTestEntry{name: "entry-4"},
		}}
		page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", int64(pageIndex*2), 2, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
		if err != nil {
			t.Fatalf("page %d error = %v", pageIndex+1, err)
		}
		if total != 5 {
			t.Fatalf("page %d total = %d, want 5", pageIndex+1, total)
		}
		if len(page) != len(wantNames) {
			t.Fatalf("page %d = %+v", pageIndex+1, page)
		}
		for index, name := range wantNames {
			if page[index].Name != name {
				t.Fatalf("page %d entry %d = %q, want %q", pageIndex+1, index, page[index].Name, name)
			}
		}
	}
}

func TestReadManagedDirectoryPageJoinsReadAndCloseErrors(t *testing.T) {
	readErr := errors.New("injected read failure")
	closeErr := errors.New("injected close failure")
	directory := &managedDirectoryTestReader{terminalErr: readErr, closeErr: closeErr}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, 1, nil, pagedDirectoryFilterInternal, regularManagedDirectoryTestStat)
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want joined read and close failures", err)
	}
	if page != nil || total != 0 {
		t.Fatalf("partial result returned: page=%+v total=%d", page, total)
	}
}

func TestReadManagedDirectoryPageToleratesConcurrentDisappearance(t *testing.T) {
	directory := &managedDirectoryTestReader{entries: []fs.DirEntry{managedDirectoryTestEntry{name: "vanished"}}}
	metadata := map[string]fs.FileInfo{"vanished": managedDirectoryTestInfo{name: "opaque"}}
	statEntry := func(name string) (fs.FileInfo, error) {
		delete(metadata, name)
		return nil, fs.ErrNotExist
	}
	page, total, err := readManagedDirectoryPage(context.Background(), directory, "/managed", 0, 1, nil, pagedDirectoryFilterInternal, statEntry)
	if err != nil || len(page) != 0 || total != 0 {
		t.Fatalf("result = %+v, %d, %v", page, total, err)
	}
}

func TestReadManagedDirectoryPageStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var statCalls atomic.Int32
	directory := &managedDirectoryTestReader{
		entries:   []fs.DirEntry{managedDirectoryTestEntry{name: "entry"}},
		afterRead: cancel,
	}
	page, total, err := readManagedDirectoryPage(ctx, directory, "/managed", 0, 1, nil, pagedDirectoryFilterInternal, func(string) (fs.FileInfo, error) {
		statCalls.Add(1)
		return managedDirectoryTestInfo{name: "opaque"}, nil
	})
	if !errors.Is(err, context.Canceled) || page != nil || total != 0 {
		t.Fatalf("result = %+v, %d, %v", page, total, err)
	}
	if statCalls.Load() != 0 {
		t.Fatalf("metadata calls after cancellation = %d", statCalls.Load())
	}
	if !directory.closed {
		t.Fatal("directory was not closed after cancellation")
	}
}

func TestManagedDirectoryListingGateIsNonblockingAndReusable(t *testing.T) {
	gate := newManagedDirectoryListingGate(managedDirectoryListingLimit)
	var openerEntries atomic.Int32
	admit := func() (func(), error) {
		release, err := gate.acquire(context.Background())
		if err == nil {
			openerEntries.Add(1)
		}
		return release, err
	}

	releases := make([]func(), 0, managedDirectoryListingLimit)
	for index := 0; index < managedDirectoryListingLimit; index++ {
		release, err := admit()
		if err != nil {
			t.Fatalf("admission %d error = %v", index+1, err)
		}
		releases = append(releases, release)
	}
	if release, err := admit(); !errors.Is(err, ErrManagedDirectoryListingBusy) || release != nil {
		t.Fatalf("fifth admission release nil = %t, error = %v", release == nil, err)
	}
	if got := openerEntries.Load(); got != managedDirectoryListingLimit {
		t.Fatalf("opener entries after rejection = %d, want %d", got, managedDirectoryListingLimit)
	}

	releases[0]()
	releases[0]() // release is idempotent and cannot overfill the gate.
	replacement, err := admit()
	if err != nil {
		t.Fatalf("admission after release error = %v", err)
	}
	if got := openerEntries.Load(); got != managedDirectoryListingLimit+1 {
		t.Fatalf("opener entries after reuse = %d", got)
	}
	replacement()
	for _, release := range releases[1:] {
		release()
	}
}

func TestManagedDirectoryListingGateHonorsPreCanceledContext(t *testing.T) {
	gate := newManagedDirectoryListingGate(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if release, err := gate.acquire(ctx); !errors.Is(err, context.Canceled) || release != nil {
		t.Fatalf("canceled admission release nil = %t, error = %v", release == nil, err)
	}
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatalf("gate slot leaked after cancellation: %v", err)
	}
	release()
}

func TestLegacyGetDirPathAcquiresAdmissionButPagedCallerDoesNotDoubleAcquire(t *testing.T) {
	previous := managedDirectoryListings
	managedDirectoryListings = newManagedDirectoryListingGate(managedDirectoryListingLimit)
	t.Cleanup(func() { managedDirectoryListings = previous })

	releases := make([]func(), 0, managedDirectoryListingLimit)
	for index := 0; index < managedDirectoryListingLimit; index++ {
		release, err := AcquireManagedDirectoryListing(context.Background())
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

	system := &systemService{}
	if page, err := system.GetDirPath(""); !errors.Is(err, ErrManagedDirectoryListingBusy) || page != nil {
		t.Fatalf("legacy listing while full = %+v, %v", page, err)
	}
	page, total, err := system.GetDirPathPage(context.Background(), "", 1, 1)
	if err != nil || len(page) != 1 || total != 1 {
		t.Fatalf("caller-leased page result = %+v, %d, %v", page, total, err)
	}
}

func TestGetDirPathPageValidatesBoundsBeforeAccess(t *testing.T) {
	system := &systemService{}
	maxInt := int(^uint(0) >> 1)
	for _, testCase := range []struct {
		name  string
		index int
		size  int
	}{
		{name: "zero index", index: 0, size: 1},
		{name: "zero size", index: 1, size: 0},
		{name: "oversized page", index: 1, size: ManagedDirectoryPageLimit + 1},
		{name: "offset overflow", index: maxInt, size: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			page, total, err := system.GetDirPathPage(context.Background(), "/must-not-be-opened", testCase.index, testCase.size)
			if !errors.Is(err, ErrInvalidManagedDirectoryPage) || page != nil || total != 0 {
				t.Fatalf("result = %+v, %d, %v", page, total, err)
			}
		})
	}
}

func TestPlanManagedDirectoryPageWiresBoundedLegacyMode(t *testing.T) {
	legacy, err := planManagedDirectoryPage(1, ManagedDirectoryLegacyPageSize)
	if err != nil {
		t.Fatalf("legacy plan error = %v", err)
	}
	if !legacy.legacy || legacy.offset != 0 || legacy.retainedSize != ManagedDirectoryRawScanLimit {
		t.Fatalf("legacy plan = %+v", legacy)
	}
	explicit, err := planManagedDirectoryPage(2, 128)
	if err != nil {
		t.Fatalf("explicit plan error = %v", err)
	}
	if explicit.legacy || explicit.offset != 128 || explicit.retainedSize != 128 {
		t.Fatalf("explicit plan = %+v", explicit)
	}
	if _, err := planManagedDirectoryPage(2, ManagedDirectoryLegacyPageSize); !errors.Is(err, ErrInvalidManagedDirectoryPage) {
		t.Fatalf("noncanonical legacy plan error = %v", err)
	}
}

func TestGetDirPathPageAllowsOnlyBoundedLegacySentinel(t *testing.T) {
	system := &systemService{}
	page, total, err := system.GetDirPathPage(context.Background(), "", 1, ManagedDirectoryLegacyPageSize)
	if err != nil || len(page) != 1 || total != 1 {
		t.Fatalf("legacy result = %+v, %d, %v", page, total, err)
	}
	page, total, err = system.GetDirPathPage(context.Background(), "/must-not-be-opened", 2, ManagedDirectoryLegacyPageSize)
	if !errors.Is(err, ErrInvalidManagedDirectoryPage) || page != nil || total != 0 {
		t.Fatalf("non-canonical legacy result = %+v, %d, %v", page, total, err)
	}
}

func TestGetDirPathPageKeepsVirtualRootPaginated(t *testing.T) {
	system := &systemService{}
	page, total, err := system.GetDirPathPage(context.Background(), "", 2, ManagedDirectoryPageLimit)
	if err != nil {
		t.Fatalf("GetDirPathPage() error = %v", err)
	}
	if len(page) != 0 || total != 1 {
		t.Fatalf("page = %+v, total = %d", page, total)
	}
}

func assertManagedDirectoryReadRequests(t *testing.T, requests []int) {
	t.Helper()
	if len(requests) == 0 {
		t.Fatal("ReadDir was not called")
	}
	for _, request := range requests {
		if request < 1 || request > managedDirectoryReadBatchSize {
			t.Fatalf("ReadDir request = %d, want 1..%d", request, managedDirectoryReadBatchSize)
		}
	}
}

type managedDirectoryTestReader struct {
	entries     []fs.DirEntry
	position    int
	requests    []int
	terminalErr error
	afterRead   func()
	closeErr    error
	closed      bool
}

func (r *managedDirectoryTestReader) ReadDir(n int) ([]fs.DirEntry, error) {
	r.requests = append(r.requests, n)
	if n < 1 {
		return nil, errors.New("non-positive ReadDir request")
	}
	if r.position >= len(r.entries) {
		if r.terminalErr != nil {
			return nil, r.terminalErr
		}
		return nil, io.EOF
	}
	end := r.position + n
	if end > len(r.entries) {
		end = len(r.entries)
	}
	entries := r.entries[r.position:end]
	r.position = end
	if r.afterRead != nil {
		r.afterRead()
	}
	if r.position == len(r.entries) {
		if r.terminalErr != nil {
			return entries, r.terminalErr
		}
		return entries, io.EOF
	}
	return entries, nil
}

func (r *managedDirectoryTestReader) Stat() (fs.FileInfo, error) {
	return managedDirectoryTestInfo{name: "managed", mode: fs.ModeDir}, nil
}

func (r *managedDirectoryTestReader) Read([]byte) (int, error) { return 0, io.EOF }

func (r *managedDirectoryTestReader) Close() error {
	r.closed = true
	return r.closeErr
}

type managedDirectoryCountReader struct {
	remaining int
	position  int
	requests  []int
	closed    bool
}

func (r *managedDirectoryCountReader) ReadDir(n int) ([]fs.DirEntry, error) {
	r.requests = append(r.requests, n)
	if n < 1 {
		return nil, errors.New("non-positive ReadDir request")
	}
	if r.remaining == 0 {
		return nil, io.EOF
	}
	count := n
	if count > r.remaining {
		count = r.remaining
	}
	entries := make([]fs.DirEntry, count)
	for index := range entries {
		entries[index] = managedDirectoryTestEntry{name: fmt.Sprintf("entry-%05d", r.position+index)}
	}
	r.position += count
	r.remaining -= count
	return entries, nil
}

func (r *managedDirectoryCountReader) Stat() (fs.FileInfo, error) {
	return managedDirectoryTestInfo{name: "managed", mode: fs.ModeDir}, nil
}

func (r *managedDirectoryCountReader) Read([]byte) (int, error) { return 0, io.EOF }

func (r *managedDirectoryCountReader) Close() error {
	r.closed = true
	return nil
}

type managedDirectoryTestEntry struct {
	name       string
	mode       fs.FileMode
	size       int64
	infoErr    error
	infoCalled *bool
}

func (e managedDirectoryTestEntry) Name() string      { return e.name }
func (e managedDirectoryTestEntry) IsDir() bool       { return e.mode.IsDir() }
func (e managedDirectoryTestEntry) Type() fs.FileMode { return e.mode.Type() }
func (e managedDirectoryTestEntry) Info() (fs.FileInfo, error) {
	if e.infoCalled != nil {
		*e.infoCalled = true
	}
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return managedDirectoryTestInfo{name: e.name, mode: e.mode, size: e.size}, nil
}

func regularManagedDirectoryTestStat(string) (fs.FileInfo, error) {
	return managedDirectoryTestInfo{name: "opaque"}, nil
}

type managedDirectoryTestInfo struct {
	name string
	mode fs.FileMode
	size int64
}

func (i managedDirectoryTestInfo) Name() string       { return i.name }
func (i managedDirectoryTestInfo) Size() int64        { return i.size }
func (i managedDirectoryTestInfo) Mode() fs.FileMode  { return i.mode }
func (i managedDirectoryTestInfo) ModTime() time.Time { return time.Unix(1_700_000_000, 0) }
func (i managedDirectoryTestInfo) IsDir() bool        { return i.mode.IsDir() }
func (i managedDirectoryTestInfo) Sys() interface{}   { return nil }
