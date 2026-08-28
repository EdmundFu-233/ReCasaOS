// Package sshsecurity provides a host-key-verified client for the local SSH
// daemon. The CasaOS-Common helper uses InsecureIgnoreHostKey and must not be
// used with passwords.
package sshsecurity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultHostKeyDirectory         = "/etc/ssh"
	localSSHHandshakeTimeout        = 5 * time.Second
	maxConcurrentLocalSSHHandshakes = 16
)

var (
	// ErrLocalSSHBusy reports that the fixed local handshake admission limit is full.
	ErrLocalSSHBusy            = errors.New("too many concurrent local SSH handshakes")
	localSSHHandshakeAdmission = newSSHHandshakeAdmission(maxConcurrentLocalSSHHandshakes)
)

type sshHandshakeAdmission struct {
	slots chan struct{}
}

func newSSHHandshakeAdmission(capacity int) *sshHandshakeAdmission {
	if capacity < 1 {
		panic("SSH handshake admission capacity must be positive")
	}
	return &sshHandshakeAdmission{slots: make(chan struct{}, capacity)}
}

func (a *sshHandshakeAdmission) acquire() (func(), bool) {
	select {
	case a.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-a.slots })
		}, true
	default:
		return nil, false
	}
}

// DialLocal authenticates to the pinned loopback SSH daemon within one bounded
// connect-and-handshake budget. The returned client has no handshake deadline.
func DialLocal(user, password, port string) (*ssh.Client, error) {
	return DialLocalContext(context.Background(), user, password, port)
}

// DialLocalContext is DialLocal with caller cancellation. Cancellation applies
// only while acquiring and authenticating the connection, not its later use.
func DialLocalContext(parent context.Context, user, password, port string) (*ssh.Client, error) {
	if parent == nil {
		return nil, errors.New("local SSH parent context is required")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	address, err := localSSHAddress(port)
	if err != nil {
		return nil, err
	}
	release, admitted := localSSHHandshakeAdmission.acquire()
	if !admitted {
		return nil, ErrLocalSSHBusy
	}
	defer release()

	ctx, cancel := context.WithTimeout(parent, localSSHHandshakeTimeout)
	defer cancel()

	callback, err := LoadHostKeyCallback(defaultHostKeyDirectory)
	if err != nil {
		return nil, fmt.Errorf("load local SSH host keys: %w", err)
	}
	configuration := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: callback,
	}
	return dialSSHContext(ctx, address, configuration)
}

func localSSHAddress(port string) (string, error) {
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65535 || strconv.Itoa(parsed) != port {
		return "", errors.New("local SSH port must be a canonical decimal port")
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func dialSSHContext(ctx context.Context, address string, configuration *ssh.ClientConfig) (*ssh.Client, error) {
	if ctx == nil {
		return nil, errors.New("local SSH handshake context is required")
	}
	if configuration == nil {
		return nil, errors.New("local SSH client configuration is required")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("local SSH handshake deadline is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial local SSH transport: %w", err)
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("set local SSH handshake deadline: %w", err)
	}

	cancellationDone := make(chan struct{})
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
		close(cancellationDone)
	})
	sshConnection, channels, requests, handshakeErr := ssh.NewClientConn(connection, address, configuration)
	var clearDeadlineErr error
	clearedBeforeDeadline := false
	if handshakeErr == nil {
		// NewClientConn starts the mux reader before returning. Remove the
		// handshake deadline immediately so it cannot expire under that reader.
		clearDeadlineErr = connection.SetDeadline(time.Time{})
		clearedBeforeDeadline = clearDeadlineErr == nil && time.Now().Before(deadline)
	}
	cancellationStopped := stopCancellation()
	if !cancellationStopped {
		<-cancellationDone
	}
	if handshakeErr != nil {
		_ = connection.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		var networkError net.Error
		if errors.As(handshakeErr, &networkError) && networkError.Timeout() && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("perform local SSH handshake: %w", handshakeErr)
	}
	if !cancellationStopped {
		_ = sshConnection.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.New("local SSH handshake was canceled")
	}
	if contextErr := ctx.Err(); contextErr != nil {
		_ = sshConnection.Close()
		return nil, contextErr
	}
	if clearDeadlineErr != nil {
		_ = sshConnection.Close()
		return nil, fmt.Errorf("clear local SSH handshake deadline: %w", clearDeadlineErr)
	}
	if !clearedBeforeDeadline {
		_ = sshConnection.Close()
		return nil, context.DeadlineExceeded
	}
	return ssh.NewClient(sshConnection, channels, requests), nil
}

// LoadHostKeyCallback trusts only public host keys already protected by the
// local OS. It does not use ssh-keyscan or trust-on-first-use.
func LoadHostKeyCallback(directory string) (ssh.HostKeyCallback, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("SSH host-key directory must be an absolute clean path")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || !trustedFileMetadata(directoryInfo, false) {
		return nil, errors.New("SSH host-key directory is not trusted")
	}
	paths, err := filepath.Glob(filepath.Join(directory, "ssh_host_*_key.pub"))
	if err != nil {
		return nil, err
	}
	trusted := make([][]byte, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !trustedFileMetadata(info, true) {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 16<<10))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			continue
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey(content)
		if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
			continue
		}
		trusted = append(trusted, append([]byte(nil), key.Marshal()...))
	}
	if len(trusted) == 0 {
		return nil, errors.New("no trusted local SSH host public keys found")
	}

	return func(_ string, _ net.Addr, presented ssh.PublicKey) error {
		if _, certificate := presented.(*ssh.Certificate); certificate {
			return errors.New("SSH host certificates require an explicitly configured CA")
		}
		encoded := presented.Marshal()
		for _, candidate := range trusted {
			if len(encoded) == len(candidate) && subtle.ConstantTimeCompare(encoded, candidate) == 1 {
				return nil
			}
		}
		return errors.New("local SSH host key does not match a protected system key")
	}, nil
}

func trustedFileMetadata(info os.FileInfo, requireSingleLink bool) bool {
	if info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	return !requireSingleLink || stat.Nlink == 1
}
