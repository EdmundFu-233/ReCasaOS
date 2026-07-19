package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestPostSambaSharesCreateRejectsMalformedBody(t *testing.T) {
	e := echo.New()
	request := httptest.NewRequest(http.MethodPost, "/v1/samba/shares", strings.NewReader(`{"path":`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := PostSambaSharesCreate(e.NewContext(request, response)); err != nil {
		t.Fatalf("PostSambaSharesCreate() error = %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestPostSambaSharesCreateRejectsAnonymousShareBeforeFilesystemAccess(t *testing.T) {
	e := echo.New()
	const body = `[{"path":"/DATA/Media","anonymous":true}]`
	request := httptest.NewRequest(http.MethodPost, "/v1/samba/shares", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := PostSambaSharesCreate(e.NewContext(request, response)); err != nil {
		t.Fatalf("PostSambaSharesCreate() error = %v", err)
	}
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Anonymous Samba shares are disabled") {
		t.Fatalf("anonymous response status=%d body=%q", response.Code, response.Body.String())
	}
}

type sambaRollbackValidation struct {
	matches bool
	err     error
}

type sambaRollbackMock struct {
	validations []sambaRollbackValidation
	unmounts    int
}

func (m *sambaRollbackMock) ValidateSambaMount(string, string, string, uint64) (bool, error) {
	if len(m.validations) == 0 {
		return false, errors.New("unexpected validation call")
	}
	validation := m.validations[0]
	m.validations = m.validations[1:]
	return validation.matches, validation.err
}

func (m *sambaRollbackMock) UnmountSmaba(*os.File, string) error {
	m.unmounts++
	return nil
}

type sambaDescriptorMock struct {
	directory string
	mountID   uint64
}

func (m *sambaDescriptorMock) OpenDirectory(string) (*os.File, error) {
	return os.Open(m.directory)
}

func (m *sambaDescriptorMock) MountID(*os.File) (uint64, error) {
	return m.mountID, nil
}

func TestRollbackSambaMountsUnmountsOnlyExactIdentity(t *testing.T) {
	testCases := []struct {
		name        string
		validations []sambaRollbackValidation
		wantUnmount int
		wantError   bool
	}{
		{
			name:        "stacked mount",
			validations: []sambaRollbackValidation{{err: errors.New("multiple mount entries")}},
			wantError:   true,
		},
		{
			name:        "mismatched mount",
			validations: []sambaRollbackValidation{{err: errors.New("unexpected mount identity")}},
			wantError:   true,
		},
		{
			name:        "mount absent or unverifiable",
			validations: []sambaRollbackValidation{{matches: false}},
			wantError:   true,
		},
		{
			name: "exact mount",
			validations: []sambaRollbackValidation{
				{matches: true},
				{matches: true},
				{matches: false},
			},
			wantUnmount: 1,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mock := &sambaRollbackMock{validations: append([]sambaRollbackValidation(nil), testCase.validations...)}
			descriptors := &sambaDescriptorMock{directory: t.TempDir(), mountID: 91}
			_, err := rollbackSambaMounts(descriptors, mock, []sambaMountedPath{{
				path:      "/mnt/nas.local/Media",
				host:      "nas.local",
				directory: "Media",
				mountID:   91,
			}})
			if (err != nil) != testCase.wantError {
				t.Fatalf("error = %v, wantError = %v", err, testCase.wantError)
			}
			if mock.unmounts != testCase.wantUnmount {
				t.Fatalf("unmount calls = %d, want %d", mock.unmounts, testCase.wantUnmount)
			}
		})
	}
}

func TestPostSambaSharesCreateRejectsOversizedBatch(t *testing.T) {
	e := echo.New()
	shares := make([]map[string]string, 65)
	for index := range shares {
		shares[index] = map[string]string{"path": "/DATA/Media"}
	}
	body, err := json.Marshal(shares)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/samba/shares", strings.NewReader(string(body)))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := PostSambaSharesCreate(e.NewContext(request, response)); err != nil {
		t.Fatalf("PostSambaSharesCreate() error = %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestPostSambaSharesCreateRejectsOversizedBody(t *testing.T) {
	e := echo.New()
	body := `[{"path":"/DATA/` + strings.Repeat("x", 70<<10) + `"}]`
	request := httptest.NewRequest(http.MethodPost, "/v1/samba/shares", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()

	if err := PostSambaSharesCreate(e.NewContext(request, response)); err != nil {
		t.Fatalf("PostSambaSharesCreate() error = %v", err)
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestPostSambaConnectionsCreateRejectsMalformedAndOversizedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{"host":`,
		"oversized": `{"username":"alice","host":"nas.local","password":"` + strings.Repeat("x", 70<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := echo.New()
			request := httptest.NewRequest(http.MethodPost, "/v1/samba/connections", strings.NewReader(body))
			request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			response := httptest.NewRecorder()
			if err := PostSambaConnectionsCreate(e.NewContext(request, response)); err != nil {
				t.Fatalf("PostSambaConnectionsCreate() error = %v", err)
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("response status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}
