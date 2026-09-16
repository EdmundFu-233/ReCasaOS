//go:build linux

package smbcredentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func backupTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	ring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}
	t.Cleanup(ring.Destroy)
	return ring
}

func backupPath(root sourceProvisionTestRoot) string {
	return filepath.Join(root.directory, backupKeyringName)
}

func TestBackupCreatesCanonicalFile(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	ring := backupTestKeyring(t)

	result, err := backupKeyringAt(root.rootFD, root.owner, root.group, ring, ops)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if !result.Created || result.CleanupRequired || result.DurabilityUnknown {
		t.Fatalf("unexpected result: %+v", result)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(backupPath(root), &stat); err != nil {
		t.Fatalf("lstat backup: %v", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o400 ||
		hasSpecialModeBits(stat.Mode) || stat.Uid != root.owner || stat.Gid != root.group ||
		uint64(stat.Nlink) != 1 {
		t.Fatalf("bad backup metadata mode=%v uid=%d links=%d", stat.Mode, stat.Uid, stat.Nlink)
	}
	data, err := os.ReadFile(backupPath(root))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	defer clear(data)
	parsed, err := ParseKeyring(data)
	if err != nil {
		t.Fatalf("parse backup: %v", err)
	}
	defer parsed.Destroy()
	if parsed.ActiveID() != ring.ActiveID() {
		t.Fatalf("backup pins a different active key")
	}
}

func TestBackupNeverOverwrites(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	ring := backupTestKeyring(t)

	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, ring, ops); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	second, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x77}, 64)))
	if err != nil {
		t.Fatalf("second ring: %v", err)
	}
	defer second.Destroy()
	result, err := backupKeyringAt(root.rootFD, root.owner, root.group, second, ops)
	if !errors.Is(err, ErrBackupExists) {
		t.Fatalf("second backup: got %v, want ErrBackupExists", err)
	}
	if result.CleanupRequired {
		t.Fatalf("refused overwrite cleaned its staging: no HOLD expected, got %+v", result)
	}
	if _, err := os.Lstat(filepath.Join(root.directory, backupStagingName)); !os.IsNotExist(err) {
		t.Fatalf("staging must be cleaned after refusal")
	}
	data, err := os.ReadFile(backupPath(root))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	defer clear(data)
	parsed, err := ParseKeyring(data)
	if err != nil {
		t.Fatalf("parse backup: %v", err)
	}
	defer parsed.Destroy()
	if parsed.ActiveID() != ring.ActiveID() {
		t.Fatalf("existing backup was disturbed")
	}
}

func TestBackupStagingConflictIsHold(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	if err := os.WriteFile(filepath.Join(root.directory, backupStagingName), []byte("stale"), 0o600); err != nil {
		t.Fatalf("plant staging: %v", err)
	}
	result, err := backupKeyringAt(root.rootFD, root.owner, root.group, backupTestKeyring(t), ops)
	if !errors.Is(err, ErrSourceCleanupRequired) || !result.CleanupRequired || result.Created {
		t.Fatalf("got %+v, %v; want cleanup HOLD", result, err)
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	ring := backupTestKeyring(t)

	envelope, err := ring.Seal(
		Context{CredentialID: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Username: "user", Host: "file", Port: "445", Directories: "share"},
		[]byte("password"),
	)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, ring, ops); err != nil {
		t.Fatalf("backup: %v", err)
	}
	restored, err := restoreKeyringAt(root.rootFD, root.owner, root.group, ops)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	defer restored.Destroy()
	if restored.ActiveID() != ring.ActiveID() {
		t.Fatalf("restored a different active key")
	}
	opened, err := restored.Open(
		Context{CredentialID: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Username: "user", Host: "file", Port: "445", Directories: "share"},
		envelope,
	)
	if err != nil {
		t.Fatalf("restored key must open sealed envelope: %v", err)
	}
	if string(opened) != "password" {
		t.Fatalf("restored value mismatch")
	}
	clear(opened)
}

func TestRestoreWithoutBackupFails(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	if _, err := restoreKeyringAt(root.rootFD, root.owner, root.group, ops); err == nil {
		t.Fatalf("restore without backup must fail")
	}
}

func TestRestoreRejectsTamperedBackup(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	ring := backupTestKeyring(t)
	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, ring, ops); err != nil {
		t.Fatalf("backup: %v", err)
	}
	data, err := os.ReadFile(backupPath(root))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.Chmod(backupPath(root), 0o600); err != nil {
		clear(data)
		t.Fatalf("chmod writable: %v", err)
	}
	if err := os.WriteFile(backupPath(root), data, 0o600); err != nil {
		clear(data)
		t.Fatalf("rewrite backup: %v", err)
	}
	if err := os.Chmod(backupPath(root), 0o400); err != nil {
		clear(data)
		t.Fatalf("chmod restore: %v", err)
	}
	clear(data)
	if _, err := restoreKeyringAt(root.rootFD, root.owner, root.group, ops); err == nil {
		t.Fatalf("tampered backup must fail restore")
	}
}

func TestRestoreRejectsUnsafePermissions(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	ring := backupTestKeyring(t)
	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, ring, ops); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := os.Chmod(backupPath(root), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := restoreKeyringAt(root.rootFD, root.owner, root.group, ops); !errors.Is(err, ErrUnsafeSourceKeyring) {
		t.Fatalf("got %v, want ErrUnsafeSourceKeyring", err)
	}
}

func TestRemoveBackup(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x11)
	removed, err := removeBackupAt(root.rootFD, root.owner, root.group, ops)
	if err != nil || removed {
		t.Fatalf("absent backup: removed=%v err=%v", removed, err)
	}
	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, backupTestKeyring(t), ops); err != nil {
		t.Fatalf("backup: %v", err)
	}
	removed, err = removeBackupAt(root.rootFD, root.owner, root.group, ops)
	if err != nil || !removed {
		t.Fatalf("present backup: removed=%v err=%v", removed, err)
	}
	// Rotation semantics: after removal a fresh backup succeeds.
	if _, err := backupKeyringAt(root.rootFD, root.owner, root.group, backupTestKeyring(t), ops); err != nil {
		t.Fatalf("backup after removal: %v", err)
	}
}
