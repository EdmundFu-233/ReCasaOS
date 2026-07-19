package v1

import (
	"errors"
	"net/http"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/labstack/echo/v4"
)

const maxManagedTransferInventoryRequestBodySize int64 = 4 << 10

type managedTransferInventoryRequest struct {
	Parent string `json:"parent"`
}

// PostManagedTransferInventory exposes only a bounded, read-only observation
// of one explicitly selected parent directory. POST keeps the host path out of
// request-target and proxy query logs; the endpoint never performs recovery or
// cleanup and never returns raw syscall errors.
func PostManagedTransferInventory(ctx echo.Context) error {
	var request managedTransferInventoryRequest
	if err := bindBoundedFileJSON(ctx, &request, maxManagedTransferInventoryRequestBodySize); err != nil || !validManagedRequestPath(request.Parent) {
		return ctx.JSON(http.StatusBadRequest, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return managedTransferInventoryUnavailable(ctx, http.StatusServiceUnavailable)
	}
	result, err := roots.InventoryManagedTransferTransactions(request.Parent)
	if err != nil {
		if errors.Is(err, filesecurity.ErrManagedPathOutsideRoots) || errors.Is(err, filesecurity.ErrUnsafePath) {
			return managedTransferInventoryUnavailable(ctx, http.StatusBadRequest)
		}
		return managedTransferInventoryUnavailable(ctx, http.StatusServiceUnavailable)
	}
	return ctx.JSON(http.StatusOK, model.Result{
		Success: common_err.SUCCESS,
		Message: common_err.GetMsg(common_err.SUCCESS),
		Data:    result,
	})
}

func managedTransferInventoryUnavailable(ctx echo.Context, status int) error {
	return ctx.JSON(status, model.Result{
		Success: common_err.SERVICE_ERROR,
		Message: "managed transfer inventory unavailable",
	})
}
