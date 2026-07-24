package publicfiles

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const DefaultListenAddress = "127.0.0.1:39777"

func ValidateListenAddress(value string) (string, error) {
	host, portValue, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(value) != value {
		return "", errors.New("public file listener must be a literal loopback IP and port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Unmap().IsLoopback() {
		return "", errors.New("public file listener must use a literal loopback IP")
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portValue {
		return "", errors.New("public file listener port must be between 1 and 65535")
	}
	return net.JoinHostPort(address.Unmap().String(), portValue), nil
}
