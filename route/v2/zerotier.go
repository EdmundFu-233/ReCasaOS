package v2

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/codegen"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/internal/zerotierapi"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"github.com/labstack/echo/v4"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

const (
	zeroTierUnavailableMessage     = "ZeroTier service unavailable"
	zeroTierInfoTimeout            = 10 * time.Second
	zeroTierMaximumControllerNets  = 256
	zeroTierNetworkIdentifierBytes = 16
)

type zeroTierGetter func(context.Context, string) ([]byte, error)

func (s *CasaOS) SetZerotierNetworkStatus(ctx echo.Context, networkId string) error {

	return ctx.JSON(http.StatusOK, nil)
}
func (s *CasaOS) GetZerotierInfo(ctx echo.Context) error {
	return getZerotierInfo(ctx, httper.ZTGetContext, zeroTierInfoTimeout)
}

func getZerotierInfo(ctx echo.Context, getZeroTier zeroTierGetter, timeout time.Duration) error {
	release, admitted := zerotierapi.TryAcquirePublicRequest()
	if !admitted {
		return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
	}
	defer release()

	boundedContext, cancel := context.WithTimeout(ctx.Request().Context(), timeout)
	defer cancel()
	if err := boundedContext.Err(); err != nil {
		return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
	}

	info := codegen.GetZTInfoOK{}
	respBody, err := getZeroTier(boundedContext, "/controller/network")
	if err != nil {
		logger.Error("get ZeroTier controller networks", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
	}

	var networkIdentifiers []string
	if err := json.Unmarshal(respBody, &networkIdentifiers); err != nil || networkIdentifiers == nil || len(networkIdentifiers) > zeroTierMaximumControllerNets {
		logger.Error("decode ZeroTier controller networks", zap.String("failure_class", "invalid_network_list"))
		return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
	}
	for _, networkIdentifier := range networkIdentifiers {
		if err := boundedContext.Err(); err != nil {
			logger.Error("get ZeroTier controller network", zap.String("failure_class", zerotierapi.FailureClass(err)))
			return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
		}
		if !validZeroTierNetworkIdentifier(networkIdentifier) {
			logger.Error("decode ZeroTier controller network identifier", zap.String("failure_class", "invalid_network_identifier"))
			return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
		}
		res, err := getZeroTier(boundedContext, "/controller/network/"+networkIdentifier)
		if err != nil {
			logger.Error("get ZeroTier controller network", zap.String("failure_class", zerotierapi.FailureClass(err)))
			return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
		}
		network := gjson.ParseBytes(res)
		if !network.IsObject() {
			logger.Error("decode ZeroTier controller network", zap.String("failure_class", "invalid_network_response"))
			return ctx.JSON(http.StatusInternalServerError, codegen.BaseResponse{Message: utils.Ptr(zeroTierUnavailableMessage)})
		}
		name := network.Get("name").Str
		if name == common.RANW_NAME {
			via := network.Get("routes.0.via").Str
			info.Id = utils.Ptr(networkIdentifier)
			info.Name = &name
			if len(via) == 0 {
				info.Status = utils.Ptr("online")
			} else {
				info.Status = utils.Ptr("offline")
			}
			break
		}
	}
	return ctx.JSON(http.StatusOK, info)
}

func validZeroTierNetworkIdentifier(identifier string) bool {
	if len(identifier) != zeroTierNetworkIdentifierBytes {
		return false
	}
	for index := 0; index < len(identifier); index++ {
		character := identifier[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
