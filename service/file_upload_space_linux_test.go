//go:build linux

package service

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

// spaceTestPrincipal mirrors the authenticated upload principal that the
// v2 handlers now require before any staging or filesystem work.
const spaceTestPrincipal = 7

func newSpaceTestUpload(t *testing.T) (*FileUploadService, string) {
	t.Helper()
	root := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = roots.Close() })
	upload := NewFileUploadService()
	upload.managementRoots = func() (*filesecurity.ManagedRoots, error) { return roots, nil }
	upload.removeTree = os.RemoveAll
	return upload, root
}

func spaceTestChunk(t *testing.T, content string) *multipart.FileHeader {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "target.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	form, err := multipart.NewReader(&body, writer.Boundary()).ReadForm(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = form.RemoveAll() })
	return form.File["file"][0]
}

func checkSpaceTestChunk(upload *FileUploadService, root string, number int64) error {
	query := url.Values{"path": {root}, "relativePath": {"nested/target.bin"}}
	request := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)
	context := echo.New().NewContext(request, httptest.NewRecorder())
	return upload.TestChunk(context, spaceTestPrincipal, "space-test", number)
}

func sendSpaceTestChunk(t *testing.T, upload *FileUploadService, root string, number int64) error {
	t.Helper()
	content := "data"
	if number == 2 {
		content = "tail"
	}
	return upload.UploadFile(nil, spaceTestPrincipal, root, number, 4, 4, 2, 8, "space-test", "nested/target.bin", "target.bin", spaceTestChunk(t, content))
}

func TestV2UploadSpaceChecksStagingBeforeChunkWrite(t *testing.T) {
	upload, root := newSpaceTestUpload(t)
	target := filepath.Join(root, "nested", "target.bin")
	staging := filepath.Join(root, ".temp", "v2-upload-"+boundUploadIdentifier(spaceTestPrincipal, "space-test", target))
	admission := filesecurity.NewUploadSpaceAdmission(func(_ *filesecurity.ManagedRoots, parent string) (uint64, error) {
		if parent == staging {
			return filesecurity.DefaultUploadReservedFreeBytes, nil
		}
		// The target can be a nested mount with ample space while the
		// filesystem receiving the staging write is full.
		return filesecurity.DefaultUploadReservedFreeBytes + 1024, nil
	})
	upload.reserveSpace = func(roots *filesecurity.ManagedRoots, parent string, size uint64) (func(), error) {
		return admission.Reserve(roots, parent, size, filesecurity.DefaultUploadReservedFreeBytes)
	}
	err := sendSpaceTestChunk(t, upload, root, 1)
	if !errors.Is(err, filesecurity.ErrUploadSpaceInsufficient) || !filesecurity.ManagedMutationChanged(err) {
		t.Fatalf("staging admission error = %v, want insufficient space with created-directory state", err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("denied upload wrote staging content: %v, %v", entries, err)
	}
}

func TestV2UploadSpaceChecksStagingBeforeAssembly(t *testing.T) {
	upload, root := newSpaceTestUpload(t)
	target := filepath.Join(root, "nested", "target.bin")
	staging := filepath.Join(root, ".temp", "v2-upload-"+boundUploadIdentifier(spaceTestPrincipal, "space-test", target))
	upload.reserveSpace = func(_ *filesecurity.ManagedRoots, parent string, size uint64) (func(), error) {
		if size == 8 && parent == staging {
			return nil, filesecurity.ErrUploadSpaceInsufficient
		}
		return func() {}, nil
	}
	if err := sendSpaceTestChunk(t, upload, root, 1); err != nil {
		t.Fatal(err)
	}
	if err := sendSpaceTestChunk(t, upload, root, 2); !errors.Is(err, filesecurity.ErrUploadSpaceInsufficient) {
		t.Fatalf("assembly admission error = %v, want insufficient staging space", err)
	}
	if _, err := os.Stat(filepath.Join(staging, ".complete")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("denied assembly created output: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("denied assembly published target: %v", err)
	}
}

func TestV2UploadSpaceRetryPublishesPendingAssembly(t *testing.T) {
	for _, denied := range []error{filesecurity.ErrUploadSpaceInsufficient, filesecurity.ErrUploadSpaceUnavailable} {
		for _, retryChunk := range []int64{1, 2} {
			t.Run(denied.Error()+"/chunk-"+strconv.FormatInt(retryChunk, 10), func(t *testing.T) {
				upload, root := newSpaceTestUpload(t)
				allowAssembly := false
				active, chunkReservations, assemblyAttempts := 0, 0, 0
				upload.reserveSpace = func(_ *filesecurity.ManagedRoots, _ string, size uint64) (func(), error) {
					if size == 8 {
						assemblyAttempts++
						if !allowAssembly {
							return nil, denied
						}
					} else {
						chunkReservations++
					}
					active++
					return func() { active-- }, nil
				}
				if err := sendSpaceTestChunk(t, upload, root, 1); err != nil {
					t.Fatal(err)
				}
				if err := checkSpaceTestChunk(upload, root, 1); err != nil {
					t.Fatalf("incomplete upload lost its existing chunk: %v", err)
				}
				if err := sendSpaceTestChunk(t, upload, root, 1); err != nil || chunkReservations != 1 || assemblyAttempts != 0 {
					t.Fatalf("incomplete chunk replay rewrote data or assembled early: %v", err)
				}
				if err := sendSpaceTestChunk(t, upload, root, 2); !errors.Is(err, denied) || !filesecurity.ManagedMutationChanged(err) {
					t.Fatalf("first assembly failure = %v", err)
				}
				if err := checkSpaceTestChunk(upload, root, retryChunk); err == nil {
					t.Error("chunk probe lets the client skip an unpublished complete upload")
				}
				if err := sendSpaceTestChunk(t, upload, root, retryChunk); !errors.Is(err, denied) {
					t.Fatalf("retry falsely reported success while assembly was denied: %v", err)
				}
				target := filepath.Join(root, "nested", "target.bin")
				if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("unadmitted target exists: %v", err)
				}
				allowAssembly = true
				if err := sendSpaceTestChunk(t, upload, root, retryChunk); err != nil {
					t.Fatalf("recovered assembly failed: %v", err)
				}
				content, err := os.ReadFile(target)
				if err != nil || string(content) != "datatail" {
					t.Fatalf("published content = %q, %v", content, err)
				}
				session := upload.uploadStatus[boundUploadIdentifier(spaceTestPrincipal, "space-test", target)]
				if session == nil || !session.completed || !session.stagingClean {
					t.Fatal("recovery did not retain a clean completed tombstone")
				}
				if _, err := os.Stat(session.tempDir); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("completed upload retained staging files: %v", err)
				}
				if err := checkSpaceTestChunk(upload, root, retryChunk); err != nil {
					t.Fatalf("completed probe failed: %v", err)
				}
				if err := sendSpaceTestChunk(t, upload, root, retryChunk); err != nil {
					t.Fatalf("completed replay failed: %v", err)
				}
				if active != 0 || chunkReservations != 2 || assemblyAttempts != 3 {
					t.Fatalf("reservation lifecycle: active=%d chunks=%d assemblies=%d", active, chunkReservations, assemblyAttempts)
				}
			})
		}
	}
}

func TestV2UploadSpaceReservationsReleaseOnWriteAndAssemblyErrors(t *testing.T) {
	for _, phase := range []string{"chunk", "assembly"} {
		t.Run(phase, func(t *testing.T) {
			upload, root := newSpaceTestUpload(t)
			active := 0
			upload.reserveSpace = func(*filesecurity.ManagedRoots, string, uint64) (func(), error) {
				active++
				return func() { active-- }, nil
			}
			var err error
			if phase == "chunk" {
				chunk := spaceTestChunk(t, "oversized")
				chunk.Size = 4
				err = upload.UploadFile(nil, spaceTestPrincipal, root, 1, 4, 4, 2, 8, "space-test", "nested/target.bin", "target.bin", chunk)
			} else {
				if err := sendSpaceTestChunk(t, upload, root, 1); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(root, "nested", "target.bin")
				session := upload.uploadStatus[boundUploadIdentifier(spaceTestPrincipal, "space-test", target)]
				injected := errors.New("injected assembly publication failure")
				session.assemblyBeforeCommit = func() error { return injected }
				err = sendSpaceTestChunk(t, upload, root, 2)
				if !errors.Is(err, injected) {
					t.Fatalf("assembly error = %v, want injected failure", err)
				}
			}
			if err == nil || !filesecurity.ManagedMutationChanged(err) || active != 0 {
				t.Fatalf("failed %s write: err=%v, active reservations=%d", phase, err, active)
			}
			if _, err := os.Stat(filepath.Join(root, "nested", "target.bin")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("failed write published target: %v", err)
			}
		})
	}
}

func TestV2UploadSpaceRetryRejectsChangedRecordedChunk(t *testing.T) {
	upload, root := newSpaceTestUpload(t)
	assemblyAttempts := 0
	upload.reserveSpace = func(_ *filesecurity.ManagedRoots, _ string, size uint64) (func(), error) {
		if size == 8 {
			assemblyAttempts++
			return nil, filesecurity.ErrUploadSpaceInsufficient
		}
		return func() {}, nil
	}
	if err := sendSpaceTestChunk(t, upload, root, 1); err != nil {
		t.Fatal(err)
	}
	if err := sendSpaceTestChunk(t, upload, root, 2); !errors.Is(err, filesecurity.ErrUploadSpaceInsufficient) {
		t.Fatalf("assembly error = %v", err)
	}
	target := filepath.Join(root, "nested", "target.bin")
	session := upload.uploadStatus[boundUploadIdentifier(spaceTestPrincipal, "space-test", target)]
	if err := os.WriteFile(filepath.Join(session.tempDir, "2"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sendSpaceTestChunk(t, upload, root, 2); !errors.Is(err, filesecurity.ErrUnsafePath) {
		t.Fatalf("changed recorded chunk was accepted: %v", err)
	}
	if assemblyAttempts != 1 {
		t.Fatalf("changed chunk reached assembly admission %d times", assemblyAttempts)
	}
	if _, err := os.Stat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("changed chunk published target: %v", err)
	}
}
