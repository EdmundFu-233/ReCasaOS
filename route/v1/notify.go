package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/service"
	"github.com/labstack/echo/v4"
)

const (
	// LocalStorage's disk/USB snapshots are normally small. 256 KiB leaves
	// substantial compatibility headroom while bounding the two retained raw
	// JSON slots to approximately 512 KiB in total.
	maxNotifyRequestBodySize int64 = 256 << 10
	maxSystemStatusFields          = 2

	notifyInvalidPayloadMessage         = "invalid notification payload"
	notifyPayloadTooLargeMessage        = "notification payload too large"
	notifyUnsupportedMediaTypeMessage   = "notification content type must be application/json"
	notifyIngressDisabledMessage        = "notification event ingress is disabled"
	notifyUnsupportedSystemFieldMessage = "unsupported system status field"
)

type notifyInputError struct {
	status  int
	message string
}

func PostNotifyMessage(ctx echo.Context) error {
	// Official components publish events directly to MessageBus. This legacy
	// wildcard route had no working producer contract and must not turn every
	// registered internal event into an HTTP injection surface. Deliberately do
	// not inspect or drain the request body.
	return respondNotifyInputError(ctx, &notifyInputError{status: http.StatusGone, message: notifyIngressDisabledMessage})
}

func PostSystemStatusNotify(ctx echo.Context) error {
	return postSystemStatusNotify(ctx, func(message map[string]interface{}) {
		service.MyService.Notify().SettingSystemTempData(message)
	})
}

func postSystemStatusNotify(ctx echo.Context, patch func(map[string]interface{})) error {
	message, inputErr := decodeNotifyObject(ctx)
	if inputErr != nil {
		return respondNotifyInputError(ctx, inputErr)
	}
	if len(message) == 0 {
		return respondNotifyInputError(ctx, &notifyInputError{status: http.StatusBadRequest, message: notifyInvalidPayloadMessage})
	}
	if len(message) > maxSystemStatusFields {
		return respondNotifyInputError(ctx, &notifyInputError{status: http.StatusBadRequest, message: notifyUnsupportedSystemFieldMessage})
	}

	// LocalStorage sends sys_disk and sys_usb independently. Validate the whole
	// patch before applying it, then replace only the supplied top-level values;
	// absent fields intentionally retain their previous values.
	for name := range message {
		if !isAllowedSystemStatusField(name) {
			return respondNotifyInputError(ctx, &notifyInputError{status: http.StatusBadRequest, message: notifyUnsupportedSystemFieldMessage})
		}
	}

	patch(message)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

func decodeNotifyObject(ctx echo.Context) (map[string]interface{}, *notifyInputError) {
	request := ctx.Request()
	request.Body = http.MaxBytesReader(ctx.Response().Writer, request.Body, maxNotifyRequestBodySize)
	if request.ContentLength > maxNotifyRequestBodySize {
		return nil, &notifyInputError{status: http.StatusRequestEntityTooLarge, message: notifyPayloadTooLargeMessage}
	}

	contentTypes := request.Header.Values(echo.HeaderContentType)
	if len(contentTypes) != 1 {
		return nil, &notifyInputError{status: http.StatusUnsupportedMediaType, message: notifyUnsupportedMediaTypeMessage}
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != echo.MIMEApplicationJSON {
		return nil, &notifyInputError{status: http.StatusUnsupportedMediaType, message: notifyUnsupportedMediaTypeMessage}
	}

	payload, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, classifyNotifyDecodeError(err)
	}
	if !utf8.Valid(payload) {
		return nil, &notifyInputError{status: http.StatusBadRequest, message: notifyInvalidPayloadMessage}
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	raw := make(map[string]json.RawMessage)
	if err := decoder.Decode(&raw); err != nil {
		return nil, classifyNotifyDecodeError(err)
	}
	if raw == nil {
		return nil, &notifyInputError{status: http.StatusBadRequest, message: notifyInvalidPayloadMessage}
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, &notifyInputError{status: http.StatusBadRequest, message: notifyInvalidPayloadMessage}
		}
		return nil, classifyNotifyDecodeError(err)
	}
	// RawMessage prevents deeply nested JSON from expanding into a much larger
	// retained interface tree. The whole-payload UTF-8 gate above ensures every
	// retained value remains safe to marshal later.
	message := make(map[string]interface{}, len(raw))
	for name, value := range raw {
		message[name] = value
	}
	return message, nil
}

func classifyNotifyDecodeError(err error) *notifyInputError {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return &notifyInputError{status: http.StatusRequestEntityTooLarge, message: notifyPayloadTooLargeMessage}
	}
	return &notifyInputError{status: http.StatusBadRequest, message: notifyInvalidPayloadMessage}
}

func respondNotifyInputError(ctx echo.Context, inputErr *notifyInputError) error {
	return ctx.JSON(inputErr.status, model.Result{Success: common_err.INVALID_PARAMS, Message: inputErr.message})
}

func isAllowedSystemStatusField(name string) bool {
	return name == "sys_disk" || name == "sys_usb"
}
