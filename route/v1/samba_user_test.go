package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/service"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/labstack/echo/v4"
)

type sambaUserRouteShares struct {
	service.SharesService
	shares []model2.SharesDBModel
}

func (s sambaUserRouteShares) GetSharesList() []model2.SharesDBModel { return s.shares }

type sambaUserRouteRepository struct {
	service.Repository
	shares service.SharesService
}

func (r sambaUserRouteRepository) Shares() service.SharesService { return r.shares }

func TestDeleteSambaUserRefusesAnAccountInUse(t *testing.T) {
	logger.LogInitConsoleOnly()
	previous := service.MyService
	t.Cleanup(func() { service.MyService = previous })
	service.MyService = sambaUserRouteRepository{shares: sambaUserRouteShares{shares: []model2.SharesDBModel{{ID: 1, Name: "Media", Username: "alice"}}}}

	deleted := []string{}
	previousDelete := deleteSambaUser
	deleteSambaUser = func(username string) error { deleted = append(deleted, username); return nil }
	t.Cleanup(func() { deleteSambaUser = previousDelete })

	call := func(username string) (int, string) {
		e := echo.New()
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/v1/samba/users/"+username, nil), recorder)
		ctx.SetParamNames("username")
		ctx.SetParamValues(username)
		if err := DeleteSambaUser(ctx); err != nil {
			t.Fatal(err)
		}
		return recorder.Code, recorder.Body.String()
	}

	if code, body := call("alice"); code == http.StatusOK || !strings.Contains(body, "still used by the share Media") {
		t.Fatalf("deleting an account in use: %d %s", code, body)
	}
	if len(deleted) != 0 {
		t.Fatalf("account deleted although a share names it: %v", deleted)
	}
	if code, _ := call("bob"); code != http.StatusOK || len(deleted) != 1 || deleted[0] != "bob" {
		t.Fatalf("deleting an unused account: %d %v", code, deleted)
	}
}

func TestShareAccountMustBeAShareAccount(t *testing.T) {
	previous := checkShareAccount
	t.Cleanup(func() { checkShareAccount = previous })
	checkShareAccount = func(username string) string {
		if username == "alice" {
			return ""
		}
		return service.ErrSambaUserNotManaged.Error()
	}
	e := echo.New()
	request := httptest.NewRequest(http.MethodPost, "/v1/samba/shares", strings.NewReader(`[{"path":"/DATA/Media","username":"root"}]`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	if err := PostSambaSharesCreate(e.NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	if recorder.Code == http.StatusOK || !strings.Contains(recorder.Body.String(), service.ErrSambaUserNotManaged.Error()) {
		t.Fatalf("a share restricted to a system account was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}
