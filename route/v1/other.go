package v1

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/service"
	"github.com/labstack/echo/v4"
)

const maxSearchRequestBodySize int64 = 8 << 10

func bindSearchRequest(ctx echo.Context) (map[string]string, error) {
	request := ctx.Request()
	request.Body = http.MaxBytesReader(ctx.Response().Writer, request.Body, maxSearchRequestBodySize)

	values := make(map[string]string)
	if err := ctx.Bind(&values); err != nil {
		return nil, err
	}
	return values, nil
}

func GetSearchResult(ctx echo.Context) error {
	values, err := bindSearchRequest(ctx)
	if err != nil {
		status := http.StatusBadRequest
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			status = http.StatusRequestEntityTooLarge
		}
		return ctx.JSON(status, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			Data:    "invalid search request",
		})
	}

	url := values["url"]
	if url == "" {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: "key is empty"})
	}
	// data, err := service.MyService.Other().Search(key)
	data, err := service.MyService.Other().AgentSearch(url)
	if err != nil {
		fmt.Println(err)
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}
