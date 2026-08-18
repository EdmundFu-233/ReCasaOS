package sshsecurity

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
