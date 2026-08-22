package service

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	commonmodel "github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/tidwall/gjson"
)

// GatewayPortClient is the minimal Gateway management surface required to
// recover the legacy HTTP-port migration across process restarts.
type GatewayPortClient interface {
	ChangePort(*commonmodel.ChangePortRequest) error
	GetPort() (error, string)
}

// EnsureGatewayPort changes the Gateway port and makes the operation
// replay-safe. CasaOS-Gateway may apply a change before the client observes a
// failure, and its same-port retry currently fails while binding the already
// occupied port. Confirming the current port after a failed change lets the
// caller durably clear its migration marker once the requested state exists.
func EnsureGatewayPort(gateway GatewayPortClient, desired string) error {
	if gateway == nil {
		return errors.New("Gateway port client is unavailable")
	}
	desiredPort, err := parseGatewayPort(desired)
	if err != nil {
		return fmt.Errorf("invalid desired Gateway port: %w", err)
	}
	normalized := strconv.Itoa(desiredPort)

	changeErr := gateway.ChangePort(&commonmodel.ChangePortRequest{Port: normalized})
	if changeErr == nil {
		return nil
	}

	getErr, response := gateway.GetPort()
	if getErr != nil {
		return errors.Join(
			fmt.Errorf("change Gateway port to %s: %w", normalized, changeErr),
			fmt.Errorf("confirm Gateway port after failed change: %w", getErr),
		)
	}
	currentPort, err := gatewayPortFromResponse(response)
	if err != nil {
		return errors.Join(
			fmt.Errorf("change Gateway port to %s: %w", normalized, changeErr),
			fmt.Errorf("confirm Gateway port after failed change: %w", err),
		)
	}
	if currentPort == desiredPort {
		return nil
	}

	return fmt.Errorf("change Gateway port to %s: %w (Gateway remains on %d)", normalized, changeErr, currentPort)
}

func gatewayPortFromResponse(response string) (int, error) {
	value := gjson.Get(response, "data")
	if !value.Exists() {
		return 0, errors.New("Gateway response is missing data")
	}
	port, err := parseGatewayPort(value.String())
	if err != nil {
		return 0, fmt.Errorf("Gateway response contains an invalid port: %w", err)
	}
	return port, nil
}

func parseGatewayPort(value string) (int, error) {
	trimmed := strings.TrimSpace(value)
	port, err := strconv.Atoi(trimmed)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be an integer from 1 through 65535")
	}
	return port, nil
}
