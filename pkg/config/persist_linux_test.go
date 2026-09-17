//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-ini/ini"
)

func TestPersistHTTPPortFailsClosedOnSymlinkedParent(t *testing.T) {
	preserveConfigGlobals(t)

	realDirectory := t.TempDir()
	path := filepath.Join(realDirectory, "casaos.conf")
	InitSetup(path, "[server]\nHttpPort = 80\n")

	linkDirectory := filepath.Join(t.TempDir(), "linked-config")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	ConfigFilePath = filepath.Join(linkDirectory, "casaos.conf")

	if err := PersistHTTPPort("49152"); err == nil {
		t.Fatal("PersistHTTPPort unexpectedly wrote through a symlinked parent")
	}
	if ServerInfo.HttpPort != "80" {
		t.Fatalf("ServerInfo.HttpPort = %q after failure, want 80", ServerInfo.HttpPort)
	}
	if got := Cfg.Section("server").Key("HttpPort").String(); got != "80" {
		t.Fatalf("in-memory HttpPort = %q after failure, want 80", got)
	}
	persisted, err := ini.Load(path)
	if err != nil {
		t.Fatalf("load original configuration after failure: %v", err)
	}
	if got := persisted.Section("server").Key("HttpPort").String(); got != "80" {
		t.Fatalf("on-disk HttpPort = %q after failure, want 80", got)
	}
}
