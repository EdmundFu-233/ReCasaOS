//go:build linux

package sambasecurity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadKeyringRequiresPinnedPrivateRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "samba.keyring")
	content := keyringText("active", strings.Repeat("77", 32))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err != nil {
		t.Fatalf("private keyring rejected: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("group-readable keyring was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "keyring-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(link); err == nil {
		t.Fatal("symlink keyring was accepted")
	}
	hardlink := filepath.Join(root, "keyring-hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("hard-linked keyring was accepted")
	}
}
