//go:build linux

package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSambaConfigCASRejectsSymlinkedDirectory(t *testing.T) {
	realDirectory := t.TempDir()
	target := filepath.Join(realDirectory, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("expected"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := readSambaConfigSnapshot(target, true, "")
	if err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(t.TempDir(), "linked-config")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	expected.path = filepath.Join(linkDirectory, "smb.casa.conf")

	if _, err := publishSambaConfigCAS(expected, []byte("candidate"), 0o600, nil); err == nil {
		t.Fatal("publish through a symlinked directory unexpectedly succeeded")
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "expected" {
		t.Fatalf("target changed through symlinked directory: data=%q err=%v", data, readErr)
	}
	entries, readDirErr := os.ReadDir(realDirectory)
	if readDirErr != nil {
		t.Fatal(readDirErr)
	}
	if len(entries) != 1 || entries[0].Name() != "smb.casa.conf" {
		t.Fatalf("symlinked publish left residue: %#v", entries)
	}
}

func TestRemoveSambaConfigCASRejectsSymlinkedDirectory(t *testing.T) {
	realDirectory := t.TempDir()
	target := filepath.Join(realDirectory, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := readSambaConfigSnapshot(target, true, "")
	if err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(t.TempDir(), "linked-config")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	expected.path = filepath.Join(linkDirectory, "smb.casa.conf")

	if err := removeSambaConfigCAS(expected, nil); err == nil {
		t.Fatal("conditional removal through a symlinked directory unexpectedly succeeded")
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "owned" {
		t.Fatalf("target removed through symlinked directory: data=%q err=%v", data, readErr)
	}
}

func TestReadSambaConfigSnapshotRejectsMultiLinkTarget(t *testing.T) {
	directoryPath := t.TempDir()
	target := filepath.Join(directoryPath, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, target+".hardlink"); err != nil {
		t.Fatal(err)
	}
	directory, err := openSambaConfigDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if _, err := directory.readSnapshot("smb.casa.conf", true, ""); err == nil {
		t.Fatal("multi-link config was accepted")
	}
}

func TestRefuseSambaConfigQuarantineRejectsSymlinkedDirectory(t *testing.T) {
	realDirectory := t.TempDir()
	linkDirectory := filepath.Join(t.TempDir(), "linked-config")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if err := refuseSambaConfigQuarantine(linkDirectory); err == nil {
		t.Fatal("symlinked directory passed the quarantine refusal check")
	}
}
