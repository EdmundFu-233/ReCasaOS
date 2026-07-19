//go:build !linux

package httper

import (
	"context"
	"errors"
	"net"
)

func dialVerifiedRcloneSocket(context.Context) (net.Conn, error) {
	return nil, errors.New("verified rclone Unix sockets require Linux")
}
