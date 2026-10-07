package v1

import (
	"net/http"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/service"
	"github.com/labstack/echo/v4"
)

const maxSambaUserBodyBytes = 4 << 10

// Indirection for tests; the real ones run useradd, smbpasswd and userdel.
var (
	listSambaUsers   = service.ListSambaUsers
	createSambaUser  = service.CreateSambaUser
	setSambaPassword = service.SetSambaPassword
	deleteSambaUser  = service.DeleteSambaUser
)

// GetSambaUsersList returns the share accounts. Accounts of the operating
// system are neither listed nor manageable here.
func GetSambaUsersList(ctx echo.Context) error {
	users, err := listSambaUsers()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: users})
}

// PostSambaUserCreate adds a share account: no home directory, no login
// shell, so it cannot be used to reach the host.
func PostSambaUserCreate(ctx echo.Context) error {
	ctx.Request().Body = http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, maxSambaUserBodyBytes)
	request := model.SambaUser{}
	if err := ctx.Bind(&request); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if err := createSambaUser(request.Username, request.Password); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: err.Error()})
	}
	// only the name goes back
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: request.Username})
}

// PutSambaUserPassword replaces the password of a share account.
func PutSambaUserPassword(ctx echo.Context) error {
	username := ctx.Param("username")
	ctx.Request().Body = http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, maxSambaUserBodyBytes)
	request := model.SambaUser{}
	if err := ctx.Bind(&request); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if err := setSambaPassword(username, request.Password); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: username})
}

// DeleteSambaUser removes a share account, refusing while a share still names
// it: smbd treats a "valid users" entry that no longer resolves as nobody
// being allowed in, and the share would stop working without explanation.
func DeleteSambaUser(ctx echo.Context) error {
	username := ctx.Param("username")
	for _, share := range service.MyService.Shares().GetSharesList() {
		if share.Username == username {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: "this account is still used by the share " + share.Name})
		}
	}
	if err := deleteSambaUser(username); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: username})
}
