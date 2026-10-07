package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/service"
	"github.com/labstack/echo/v4"
)

type fakeSystemStateService struct {
	service.SystemService
	rebootErr   error
	shutdownErr error
}

func (f *fakeSystemStateService) SystemReboot() error {
	return f.rebootErr
}

func (f *fakeSystemStateService) SystemShutdown() error {
	return f.shutdownErr
}

type fakeSystemStateRepository struct {
	service.Repository
	system service.SystemService
}

func (f fakeSystemStateRepository) System() service.SystemService {
	return f.system
}

func putSystemState(t *testing.T, state string) (int, model.Result) {
	t.Helper()
	logger.LogInitConsoleOnly()
	e := echo.New()
	request := httptest.NewRequest(http.MethodPut, "/v1/sys/state/"+state, nil)
	recorder := httptest.NewRecorder()
	context := e.NewContext(request, recorder)
	context.SetPath("/v1/sys/state/:state")
	context.SetParamNames("state")
	context.SetParamValues(state)
	if err := PutSystemState(context); err != nil {
		t.Fatalf("PutSystemState() error = %v", err)
	}
	var response model.Result
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return recorder.Code, response
}

// A failed power operation used to be answered with 200 "will be completed
// shortly" while the host kept running.
func TestPutSystemStatePropagatesPowerOperationErrors(t *testing.T) {
	original := service.MyService
	t.Cleanup(func() { service.MyService = original })

	service.MyService = fakeSystemStateRepository{system: &fakeSystemStateService{
		rebootErr:   errors.New("systemctl reboot: exit status 1: secret detail"),
		shutdownErr: errors.New("systemctl poweroff: exit status 1: secret detail"),
	}}

	for _, state := range []string{"off", "restart"} {
		code, response := putSystemState(t, state)
		if code != http.StatusInternalServerError {
			t.Fatalf("%s: status = %d, want %d", state, code, http.StatusInternalServerError)
		}
		if response.Message != "power operation failed" {
			t.Fatalf("%s: message = %q, the command output must stay in the journal", state, response.Message)
		}
	}
}

func TestPutSystemStateSucceeds(t *testing.T) {
	original := service.MyService
	t.Cleanup(func() { service.MyService = original })

	service.MyService = fakeSystemStateRepository{system: &fakeSystemStateService{}}
	for _, state := range []string{"off", "restart"} {
		if code, _ := putSystemState(t, state); code != http.StatusOK {
			t.Fatalf("%s: status = %d, want %d", state, code, http.StatusOK)
		}
	}
}
