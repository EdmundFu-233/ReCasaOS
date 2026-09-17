//go:build linux

package filesecurity

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReplaceRegularFileRoundTrip(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "smb.conf")
	if err := ReplaceRegularFile(destination, []byte("v1"), 0o600); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := ReplaceRegularFile(destination, []byte("v2-longer-content"), 0o600); err != nil {
		t.Fatalf("re-replace: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "v2-longer-content" {
		t.Fatalf("content = %q", data)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o", got)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("not a regular file: %v", info.Mode())
	}
}

func TestReplaceRegularFileRejectsUnsafe(t *testing.T) {
	for name, path := range map[string]string{
		"relative":  "relative.conf",
		"unclean":   "/tmp/../tmp/x.conf",
		"dot":       "/tmp/.",
		"empty":     "",
		"with null": "/tmp/x\x00.conf",
	} {
		if err := ReplaceRegularFile(path, []byte("x"), 0o600); err == nil {
			t.Fatalf("%s: %q must be rejected", name, path)
		}
	}
	destination := filepath.Join(t.TempDir(), "x.conf")
	if err := ReplaceRegularFile(destination, []byte("x"), 0); err == nil {
		t.Fatalf("zero permission must be rejected")
	}
	if err := ReplaceRegularFile(destination, make([]byte, maxReplaceDataBytes+1), 0o600); err == nil {
		t.Fatalf("oversize payload must be rejected")
	}
}

func TestReplaceRegularFileReplacesSymlinkNotTarget(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "smb.conf")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceRegularFile(link, []byte("new"), 0o600); err != nil {
		t.Fatalf("replace over symlink: %v", err)
	}
	victim, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "victim" {
		t.Fatalf("symlink target was modified: %q", victim)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("destination is still a symlink: %v", info.Mode())
	}
}

func TestReplaceRegularFileConcurrentHammer(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "smb.conf")
	versions := make([][]byte, 8)
	for i := range versions {
		versions[i] = bytes.Repeat([]byte{byte('a' + i)}, 1024)
	}
	var wg sync.WaitGroup
	for i := range versions {
		wg.Add(1)
		go func(version []byte) {
			defer wg.Done()
			for range 25 {
				if err := ReplaceRegularFile(destination, version, 0o600); err != nil {
					t.Errorf("replace: %v", err)
					return
				}
			}
		}(versions[i])
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		swap := filepath.Join(directory, "swap")
		for range 200 {
			_ = os.Symlink(destination, swap)
			_ = os.Remove(swap)
			_ = os.Mkdir(swap, 0o700)
			_ = os.Remove(swap)
		}
	}()
	wg.Wait()
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	whole := false
	for _, version := range versions {
		if bytes.Equal(data, version) {
			whole = true
		}
	}
	if !whole {
		t.Fatalf("torn write observed (%d bytes)", len(data))
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "smb.conf" && name != "swap" {
			t.Fatalf("staging residue leaked: %q", name)
		}
	}
}

func TestReplaceRegularFileMissingParent(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "no-such-dir", "x.conf")
	if err := ReplaceRegularFile(destination, []byte("x"), 0o600); err == nil {
		t.Fatalf("missing parent must fail")
	}
}
