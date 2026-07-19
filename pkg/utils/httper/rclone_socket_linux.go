//go:build linux

package httper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const rcloneSocketOwnerUID = uint32(0)

func dialVerifiedRcloneSocket(ctx context.Context) (net.Conn, error) {
	return dialVerifiedUnixSocket(ctx, rcloneUnixSocket, rcloneSocketOwnerUID)
}

// dialVerifiedUnixSocket binds the unauthenticated rclone RC channel to a
// single, non-public Unix socket and its kernel-reported peer credentials.
// Path inspection alone is insufficient because the socket name can be
// replaced between lstat and connect.
func dialVerifiedUnixSocket(ctx context.Context, path string, expectedUID uint32) (net.Conn, error) {
	before, err := inspectVerifiedUnixSocket(path, expectedUID)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect verified rclone socket: %w", err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = connection.Close()
		}
	}()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.New("rclone connection is not a Unix socket")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("inspect rclone socket descriptor: %w", err)
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, fmt.Errorf("inspect rclone socket peer: %w", err)
	}
	if credentialErr != nil {
		return nil, fmt.Errorf("read rclone socket peer credentials: %w", credentialErr)
	}
	if credentials == nil || credentials.Uid != expectedUID || credentials.Pid <= 0 {
		return nil, errors.New("rclone socket peer is not the expected service account")
	}

	after, err := inspectVerifiedUnixSocket(path, expectedUID)
	if err != nil {
		return nil, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
		return nil, errors.New("rclone socket identity changed while connecting")
	}

	succeeded = true
	return connection, nil
}

func inspectVerifiedUnixSocket(path string, expectedUID uint32) (unix.Stat_t, error) {
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); err != nil {
		return unix.Stat_t{}, fmt.Errorf("inspect rclone socket: %w", err)
	}
	if status.Mode&unix.S_IFMT != unix.S_IFSOCK || status.Nlink != 1 {
		return unix.Stat_t{}, errors.New("rclone endpoint is not a single-link Unix socket")
	}
	if status.Uid != expectedUID {
		return unix.Stat_t{}, errors.New("rclone socket has an unexpected owner")
	}
	if status.Mode&0o022 != 0 {
		return unix.Stat_t{}, errors.New("rclone socket is writable by group or other users")
	}
	return status, nil
}
