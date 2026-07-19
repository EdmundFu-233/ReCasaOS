//go:build linux

package httper

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDialVerifiedUnixSocketChecksPathAndPeerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rclone.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := dialVerifiedUnixSocket(ctx, path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestDialVerifiedUnixSocketRejectsUnexpectedOwnerAndNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rclone.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dialVerifiedUnixSocket(context.Background(), path, uint32(os.Geteuid())+1); err == nil {
		t.Fatal("socket with an unexpected owner was accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := dialVerifiedUnixSocket(context.Background(), path, uint32(os.Geteuid())); err == nil {
		t.Fatal("socket writable by group or other users was accepted")
	}

	regular := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dialVerifiedUnixSocket(context.Background(), regular, uint32(os.Geteuid())); err == nil {
		t.Fatal("regular file was accepted as the rclone endpoint")
	}
}
