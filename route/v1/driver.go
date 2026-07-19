package v1

import (
	"github.com/IceWhaleTech/CasaOS-Common/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/labstack/echo/v4"
)

func ListDriverInfo(ctx echo.Context) error {
	// OAuth providers remain hidden until each flow has server-generated state,
	// PKCE, runtime credentials, and a reviewed redirect URI. Advertising the
	// legacy URLs would send users into callbacks that intentionally fail closed.
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: []model.Drive{}})
}
