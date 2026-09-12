package sshsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDialSSHContextBoundsSilentHandshakeAndClosesTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	peerClosed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		accepted <- connection
		_, copyErr := io.Copy(io.Discard, connection)
		peerClosed <- copyErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	configuration := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Test-only listener; production pins protected host keys.
	}
	client, err := dialSSHContext(ctx, listener.Addr().String(), configuration)
	if client != nil {
		client.Close()
		t.Fatal("silent listener produced an SSH client")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent handshake error = %v, want context deadline exceeded", err)
	}

	var peer net.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case <-time.After(time.Second):
		t.Fatal("silent listener did not accept the client connection")
	}
	select {
	case err := <-peerClosed:
		if err != nil {
			t.Fatalf("silent listener read failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client transport remained open after handshake timeout")
	}
}

func TestDialSSHContextCancellationClosesSilentTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	peerClosed := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			peerClosed <- acceptErr
			return
		}
		accepted <- connection
		_, copyErr := io.Copy(io.Discard, connection)
		peerClosed <- copyErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	configuration := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Test-only listener; production pins protected host keys.
	}
	result := make(chan error, 1)
	go func() {
		client, err := dialSSHContext(ctx, listener.Addr().String(), configuration)
		if client != nil {
			_ = client.Close()
		}
		result <- err
	}()

	var peer net.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("silent listener did not accept the client connection")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled handshake error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled SSH handshake did not return")
	}
	select {
	case err := <-peerClosed:
		if err != nil {
			t.Fatalf("canceled handshake peer read failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client transport remained open after handshake cancellation")
	}
}

func TestDialSSHContextClearsDeadlineAfterSuccessfulHandshake(t *testing.T) {
	signer := generateSSHTestSigner(t)
	const authenticationDelay = 300 * time.Millisecond
	serverConfiguration := &ssh.ServerConfig{
		PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			time.Sleep(authenticationDelay)
			if metadata.User() == "test" && string(password) == "test-password" {
				return nil, nil
			}
			return nil, errors.New("authentication rejected")
		},
	}
	serverConfiguration.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go serveSSHTestConnection(listener, serverConfiguration, serverDone)

	configuration := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test-password")},
		HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
	}
	const handshakeBudget = 500 * time.Millisecond
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), handshakeBudget)
	defer cancel()
	client, err := dialSSHContext(ctx, listener.Addr().String(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if wait := time.Until(started.Add(handshakeBudget + 100*time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	accepted, _, err := client.SendRequest("recasaos-test-probe", true, nil)
	if err != nil {
		t.Fatalf("SSH client expired after handshake deadline: %v", err)
	}
	if !accepted {
		t.Fatal("SSH test server rejected post-deadline probe")
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("SSH test server failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH test server did not stop after client close")
	}
}

func TestSSHHandshakeAdmissionIsNonBlockingAndReleaseIsIdempotent(t *testing.T) {
	admission := newSSHHandshakeAdmission(1)
	release, admitted := admission.acquire()
	if !admitted {
		t.Fatal("first handshake was not admitted")
	}
	if secondRelease, admitted := admission.acquire(); admitted || secondRelease != nil {
		t.Fatal("over-capacity handshake was admitted")
	}
	release()
	release()
	thirdRelease, admitted := admission.acquire()
	if !admitted {
		t.Fatal("handshake was not admitted after release")
	}
	thirdRelease()
}

func TestDialLocalRejectsOverloadBeforeHostKeyOrNetworkAccess(t *testing.T) {
	releases := make([]func(), 0, maxConcurrentLocalSSHHandshakes)
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
	})
	for range maxConcurrentLocalSSHHandshakes {
		release, admitted := localSSHHandshakeAdmission.acquire()
		if !admitted {
			t.Fatal("could not fill local SSH handshake admission")
		}
		releases = append(releases, release)
	}

	client, err := DialLocal("test", "secret", "1")
	if client != nil {
		client.Close()
		t.Fatal("over-capacity dial returned a client")
	}
	if !errors.Is(err, ErrLocalSSHBusy) {
		t.Fatalf("over-capacity dial error = %v, want ErrLocalSSHBusy", err)
	}
}

func TestLocalSSHAddressRequiresCanonicalDecimalPort(t *testing.T) {
	for _, port := range []string{"", "0", "01", "+22", "65536", "ssh", "22:23"} {
		if address, err := localSSHAddress(port); err == nil {
			t.Fatalf("localSSHAddress(%q) = %q, want error", port, address)
		}
	}
	if address, err := localSSHAddress("22"); err != nil || address != "127.0.0.1:22" {
		t.Fatalf("localSSHAddress(22) = %q, %v", address, err)
	}
}

func TestLoadHostKeyCallbackAcceptsOnlyProtectedPinnedKey(t *testing.T) {
	directory := protectedTestDirectory(t)
	trusted := generateSSHTestKey(t)
	other := generateSSHTestKey(t)
	path := filepath.Join(directory, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(trusted), 0o600); err != nil {
		t.Fatal(err)
	}
	callback, err := LoadHostKeyCallback(directory)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	if err := callback("127.0.0.1:22", remote, trusted); err != nil {
		t.Fatalf("trusted host key rejected: %v", err)
	}
	if err := callback("127.0.0.1:22", remote, other); err == nil {
		t.Fatal("untrusted host key accepted")
	}
}

func TestLoadHostKeyCallbackRejectsWritableKeyMaterial(t *testing.T) {
	directory := protectedTestDirectory(t)
	path := filepath.Join(directory, "ssh_host_ed25519_key.pub")
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(generateSSHTestKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHostKeyCallback(directory); err == nil {
		t.Fatal("group/world-writable host key was trusted")
	}
}

func protectedTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func generateSSHTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return generateSSHTestSigner(t).PublicKey()
}

func generateSSHTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func serveSSHTestConnection(listener net.Listener, configuration *ssh.ServerConfig, done chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	server, channels, requests, err := ssh.NewServerConn(connection, configuration)
	if err != nil {
		_ = connection.Close()
		done <- err
		return
	}
	go func() {
		for channel := range channels {
			_ = channel.Reject(ssh.Prohibited, "test server does not accept channels")
		}
	}()
	for request := range requests {
		accepted := request.Type == "recasaos-test-probe"
		if request.WantReply {
			_ = request.Reply(accepted, nil)
		}
	}
	done <- server.Wait()
}
