package v1

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/internal/zerotierapi"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"github.com/labstack/echo/v4"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

const (
	zeroTierProxyTimeout              = 10 * time.Second
	zeroTierProxyErrorWriteTimeout    = time.Second
	zeroTierProxyMaximumRequestBytes  = 1 << 20
	zeroTierProxyMaximumEndpointBytes = 4096
)

type zeroTierRequester func(context.Context, string, string, []byte) (*zerotierapi.ZeroTierResponse, error)
type zeroTierAdmission func() (release func(), ok bool)

func ZerotierProxy(ctx echo.Context) error {
	return zerotierProxyWithAdmission(
		ctx,
		zerotierapi.Request,
		zeroTierProxyTimeout,
		zerotierapi.TryAcquirePublicRequest,
	)
}

func zerotierProxy(ctx echo.Context, requestZeroTier zeroTierRequester, timeout time.Duration) error {
	return zerotierProxyWithAdmission(
		ctx,
		requestZeroTier,
		timeout,
		zerotierapi.TryAcquirePublicRequest,
	)
}

func zerotierProxyWithAdmission(ctx echo.Context, requestZeroTier zeroTierRequester, timeout time.Duration, tryAcquire zeroTierAdmission) error {
	request := ctx.Request()
	responseController := http.NewResponseController(ctx.Response().Writer)
	ctx.Response().Header().Set("X-Content-Type-Options", "nosniff")
	if !allowedZeroTierProxyMethod(request.Method) {
		abandonZeroTierProxyBody(request, responseController)
		ctx.Response().Header().Set("Allow", "GET, POST, PUT, DELETE")
		return writeZeroTierProxyError(ctx, responseController, http.StatusMethodNotAllowed, "unsupported ZeroTier method\n")
	}
	endpoint, err := sanitizedZeroTierEndpoint(request)
	if err != nil {
		abandonZeroTierProxyBody(request, responseController)
		return writeZeroTierProxyError(ctx, responseController, http.StatusBadRequest, "invalid ZeroTier request\n")
	}
	if requestZeroTier == nil || tryAcquire == nil || timeout <= 0 {
		abandonZeroTierProxyBody(request, responseController)
		return writeZeroTierProxyError(ctx, responseController, http.StatusBadGateway, "ZeroTier service unavailable\n")
	}
	if request.ContentLength > zeroTierProxyMaximumRequestBytes {
		abandonZeroTierProxyBody(request, responseController)
		return writeZeroTierProxyError(ctx, responseController, http.StatusRequestEntityTooLarge, "ZeroTier request body is too large\n")
	}
	release, admitted := tryAcquire()
	if !admitted {
		abandonZeroTierProxyBody(request, responseController)
		return writeZeroTierProxyError(ctx, responseController, http.StatusServiceUnavailable, "ZeroTier service is busy\n")
	}
	defer release()

	boundedContext, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	deadline, _ := boundedContext.Deadline()
	readDeadlineSet := responseController.SetReadDeadline(deadline) == nil
	bodyComplete := false
	defer func() {
		if boundedContext.Err() == nil && readDeadlineSet && bodyComplete {
			_ = responseController.SetReadDeadline(time.Time{})
		}
	}()
	stopBodyClose := context.AfterFunc(boundedContext, func() {
		_ = request.Body.Close()
	})
	defer stopBodyClose()

	body, err := io.ReadAll(io.LimitReader(request.Body, zeroTierProxyMaximumRequestBytes+1))
	if err != nil {
		if errors.Is(boundedContext.Err(), context.DeadlineExceeded) || !time.Now().Before(deadline) {
			return writeZeroTierProxyError(ctx, responseController, http.StatusGatewayTimeout, "ZeroTier request body timed out\n")
		}
		return writeZeroTierProxyError(ctx, responseController, http.StatusBadRequest, "invalid ZeroTier request body\n")
	}
	if len(body) > zeroTierProxyMaximumRequestBytes {
		abandonZeroTierProxyBody(request, responseController)
		return writeZeroTierProxyError(ctx, responseController, http.StatusRequestEntityTooLarge, "ZeroTier request body is too large\n")
	}
	bodyComplete = true
	if readDeadlineSet {
		_ = responseController.SetReadDeadline(time.Time{})
		readDeadlineSet = false
	}
	if (request.Method == http.MethodGet || request.Method == http.MethodDelete) && len(body) != 0 {
		return writeZeroTierProxyError(ctx, responseController, http.StatusBadRequest, "ZeroTier method does not accept a request body\n")
	}
	if request.Method == http.MethodPost || request.Method == http.MethodPut {
		if supplied := request.Header.Get("Content-Type"); supplied != "" {
			mediaType, parameters, err := mime.ParseMediaType(supplied)
			if err != nil || mediaType != "application/json" || !validZeroTierJSONParameters(parameters) {
				return writeZeroTierProxyError(ctx, responseController, http.StatusUnsupportedMediaType, "ZeroTier request must use application/json\n")
			}
		}
	}

	response, err := requestZeroTier(
		boundedContext,
		request.Method,
		endpoint,
		body,
	)
	if err != nil {
		logger.Error("ZeroTier proxy request failed", zap.String("failure_class", zerotierapi.FailureClass(err)))
		switch {
		case errors.Is(err, zerotierapi.ErrZeroTierRequestTooLarge):
			return writeZeroTierProxyError(ctx, responseController, http.StatusRequestEntityTooLarge, "ZeroTier request body is too large\n")
		case errors.Is(err, context.DeadlineExceeded):
			return writeZeroTierProxyError(ctx, responseController, http.StatusGatewayTimeout, "ZeroTier service timed out\n")
		default:
			return writeZeroTierProxyError(ctx, responseController, http.StatusBadGateway, "ZeroTier service unavailable\n")
		}
	}
	if response == nil || response.StatusCode < 200 || response.StatusCode > 599 {
		return writeZeroTierProxyError(ctx, responseController, http.StatusBadGateway, "ZeroTier service unavailable\n")
	}
	if boundedContext.Err() != nil || !time.Now().Before(deadline) {
		return writeZeroTierProxyError(ctx, responseController, http.StatusGatewayTimeout, "ZeroTier service timed out\n")
	}
	writeDeadlineSet := responseController.SetWriteDeadline(deadline) == nil
	defer func() {
		if writeDeadlineSet && boundedContext.Err() == nil {
			_ = responseController.SetWriteDeadline(time.Time{})
		}
	}()
	if response.ContentType != "" {
		ctx.Response().Header().Set("Content-Type", response.ContentType)
	}
	ctx.Response().WriteHeader(response.StatusCode)
	if len(response.Body) == 0 {
		return flushZeroTierProxyResponse(responseController)
	}
	_, err = ctx.Response().Write(response.Body)
	if err != nil {
		return err
	}
	return flushZeroTierProxyResponse(responseController)
}

func validZeroTierJSONParameters(parameters map[string]string) bool {
	for key, value := range parameters {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func writeZeroTierProxyError(ctx echo.Context, responseController *http.ResponseController, status int, message string) error {
	writeDeadlineSet := responseController != nil && responseController.SetWriteDeadline(time.Now().Add(zeroTierProxyErrorWriteTimeout)) == nil
	if writeDeadlineSet {
		defer responseController.SetWriteDeadline(time.Time{}) //nolint:errcheck // best-effort connection cleanup
	}
	if err := ctx.String(status, message); err != nil {
		return err
	}
	return flushZeroTierProxyResponse(responseController)
}

func flushZeroTierProxyResponse(responseController *http.ResponseController) error {
	if responseController == nil {
		return nil
	}
	if err := responseController.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

func abandonZeroTierProxyBody(request *http.Request, responseController *http.ResponseController) {
	if responseController != nil {
		_ = responseController.SetReadDeadline(time.Now())
	}
	if request != nil && request.Body != nil {
		_ = request.Body.Close()
	}
}

func allowedZeroTierProxyMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func sanitizedZeroTierEndpoint(request *http.Request) (string, error) {
	if request == nil || request.URL == nil {
		return "", errors.New("missing request URL")
	}
	rawEndpointBytes := len(request.URL.EscapedPath())
	if request.URL.RawQuery != "" {
		rawEndpointBytes += len(request.URL.RawQuery) + 1
	}
	if rawEndpointBytes > zeroTierProxyMaximumEndpointBytes {
		return "", errors.New("ZeroTier endpoint is too large")
	}
	escapedPath := request.URL.EscapedPath()
	if !strings.HasPrefix(escapedPath, "/v1/zt") {
		return "", errors.New("request is outside ZeroTier route")
	}
	path := strings.TrimPrefix(escapedPath, "/v1/zt")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", errors.New("invalid ZeroTier path")
	}
	decodedPath, err := url.PathUnescape(path)
	if err != nil || strings.HasPrefix(decodedPath, "//") || zeroTierProxyPathContainsUnsafeByte(decodedPath) || zeroTierProxyPathHasDotSegment(decodedPath) {
		return "", errors.New("invalid ZeroTier path")
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return "", errors.New("invalid ZeroTier query")
	}
	filtered := make(url.Values)
	for key, values := range query {
		switch {
		case strings.EqualFold(key, "auth"), strings.EqualFold(key, "token"):
			continue
		case key == "jsonp":
			for _, value := range values {
				filtered.Add(key, value)
			}
		}
	}
	if encoded := filtered.Encode(); encoded != "" {
		endpoint := path + "?" + encoded
		if len(endpoint) > zeroTierProxyMaximumEndpointBytes {
			return "", errors.New("ZeroTier endpoint is too large")
		}
		return endpoint, nil
	}

	return path, nil
}

func zeroTierProxyPathContainsUnsafeByte(path string) bool {
	for index := 0; index < len(path); index++ {
		character := path[index]
		if character < 0x20 || character == 0x7f || character == '\\' || character == '#' {
			return true
		}
	}
	return false
}

func zeroTierProxyPathHasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func CheckNetwork() {
	logger.Info("start check network")
	respBody, err := httper.ZTGet("/controller/network")
	if err != nil {
		logger.Error("get network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return
	}
	networkId := ""
	address := ""
	networkNames := gjson.ParseBytes(respBody).Array()
	routers := ""
	for _, v := range networkNames {
		res, err := httper.ZTGet("/controller/network/" + v.Str)
		if err != nil {
			logger.Error("get network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
			return
		}
		name := gjson.GetBytes(res, "name").Str
		if name == common.RANW_NAME {
			networkId = gjson.GetBytes(res, "id").Str
			routers = gjson.GetBytes(res, "routes.0.target").Str
			break
		}
	}
	ip, s, e, c := getZTIP(routers)
	logger.Info("ip", zap.Any("ip", ip))
	if len(networkId) == 0 {
		if len(address) == 0 {
			address = GetAddress()
		}
		networkId = CreateNet(address, s, e, c)
	}
	res, err := httper.ZTGet("/network")
	if err != nil {
		logger.Error("get network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return
	}
	joined := false
	networks := gjson.GetBytes(res, "#.id").Array()
	for _, v := range networks {
		if v.Str == networkId {
			joined = true
			break
		}
	}
	logger.Info("joined", zap.Any("joined", joined))
	if !joined {
		JoinAndUpdateNet(address, networkId, ip)
	}
}

func GetAddress() string {
	nodeRes, err := httper.ZTGet("/status")
	if err != nil {
		logger.Error("get status error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return ""
	}
	return gjson.GetBytes(nodeRes, "address").String()
}

func JoinAndUpdateNet(address, networkId, ip string) {
	logger.Info("start join network", zap.Any("ip", ip))
	_, err := httper.ZTPost("/network/"+networkId, "")
	if err != nil {
		logger.Error(" get network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return
	}

	if len(address) == 0 {
		address = GetAddress()
	}
	b := `{
		"authorized": true,
		"activeBridge": true,
		"ipAssignments": [
		  "` + ip + `"
		]
	  }`
	_, err = httper.ZTPost("/controller/network/"+networkId+"/member/"+address, b)
	if err != nil {
		logger.Error("join network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return
	}
}

func CreateNet(address, s, e, c string) string {
	body := `{
		"name": "` + common.RANW_NAME + `",
		"private": false,
		"v4AssignMode": {
		"zt": true
		},
		"ipAssignmentPools": [
		{
		"ipRangeStart": "` + s + `",
		"ipRangeEnd": "` + e + `"
		}
		],
		"routes": [
		{
		"target": "` + c + `"
		}
		],
		"rules": [
		{
		"etherType": 2048,
		"not": true,
		"or": false,
		"type": "MATCH_ETHERTYPE"
		},
		{
		"etherType": 2054,
		"not": true,
		"or": false,
		"type": "MATCH_ETHERTYPE"
		},
		{
		"etherType": 34525,
		"not": true,
		"or": false,
		"type": "MATCH_ETHERTYPE"
		},
		{
		"type": "ACTION_DROP"
		},
		{
		"type": "ACTION_ACCEPT"
		}
		],
		"v6AssignMode": {
			"rfc4193": true
		   }
		}`
	createRes, err := httper.ZTPost("/controller/network/"+address+"______", body)
	if err != nil {
		logger.Error("post network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return ""
	}
	return gjson.GetBytes(createRes, "id").Str
}

func GetZTIPs() []gjson.Result {
	res, err := httper.ZTGet("/network")
	if err != nil {
		logger.Error("get network error", zap.String("failure_class", zerotierapi.FailureClass(err)))
		return []gjson.Result{}
	}
	a := gjson.GetBytes(res, "#.routes.0.target")
	return a.Array()
}

func getZTIP(routes string) (ip, start, end, cidr string) {
	excluded := GetZTIPs()
	cidrs := []string{
		"10.147.11.0/24",
		"10.147.12.0/24",
		"10.147.13.0/24",
		"10.147.14.0/24",
		"10.147.15.0/24",
		"10.147.16.0/24",
		"10.147.17.0/24",
		"10.147.18.0/24",
		"10.147.19.0/24",
		"10.147.20.0/24",
		"10.240.0.0/16",
		"10.241.0.0/16",
		"10.242.0.0/16",
		"10.243.0.0/16",
		"10.244.0.0/16",
		"10.245.0.0/16",
		"10.246.0.0/16",
		"10.247.0.0/16",
		"10.248.0.0/16",
		"10.249.0.0/16",
		"172.21.0.0/16",
		"172.22.0.0/16",
		"172.23.0.0/16",
		"172.24.0.0/16",
		"172.25.0.0/16",
		"172.26.0.0/16",
		"172.27.0.0/16",
		"172.28.0.0/16",
		"172.29.0.0/16",
		"172.30.0.0/16",
	}
	filteredCidrs := make([]string, 0)
	if len(routes) > 0 {
		filteredCidrs = append(filteredCidrs, routes)
	} else {
		for _, cidr := range cidrs {
			isExcluded := false
			for _, excludedIP := range excluded {
				if cidr == excludedIP.Str {
					isExcluded = true
					break
				}
			}
			if !isExcluded {
				filteredCidrs = append(filteredCidrs, cidr)
			}
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	ip = ""
	if len(filteredCidrs) > 0 {
		randomIndex := rnd.Intn(len(filteredCidrs))
		selectedCIDR := filteredCidrs[randomIndex]
		_, ipNet, err := net.ParseCIDR(selectedCIDR)
		if err != nil {
			logger.Error("ParseCIDR error", zap.Error(err))
			return
		}
		cidr = selectedCIDR
		startIP := ipNet.IP
		endIP := make(net.IP, len(startIP))
		copy(endIP, startIP)

		for i := range startIP {
			endIP[i] |= ^ipNet.Mask[i]
		}
		startIP[3] = 1
		start = startIP.String()
		endIP[3] = 254
		end = endIP.String()
		ipt := ipNet
		ipt.IP[3] = 1
		ip = ipt.IP.String()
		return
	} else {
		logger.Error("No available CIDR found")
	}
	return
}
