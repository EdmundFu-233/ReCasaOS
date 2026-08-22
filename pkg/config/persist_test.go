package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-ini/ini"
)

func preserveConfigGlobals(t *testing.T) {
	t.Helper()

	oldSysInfo := *SysInfo
	oldAppInfo := *AppInfo
	oldCommonInfo := *CommonInfo
	oldServerInfo := *ServerInfo
	oldSystemConfigInfo := *SystemConfigInfo
	oldFileSettingInfo := *FileSettingInfo
	oldCfg := Cfg
	oldConfigFilePath := ConfigFilePath

	t.Cleanup(func() {
		*SysInfo = oldSysInfo
		*AppInfo = oldAppInfo
		*CommonInfo = oldCommonInfo
		*ServerInfo = oldServerInfo
		*SystemConfigInfo = oldSystemConfigInfo
		*FileSettingInfo = oldFileSettingInfo
		Cfg = oldCfg
		ConfigFilePath = oldConfigFilePath
	})
}

func TestMigrateLegacyHTTPPortRetriesBeforeClearing(t *testing.T) {
	preserveConfigGlobals(t)

	path := filepath.Join(t.TempDir(), "custom.conf")
	InitSetup(path, "[server]\nHttpPort = 8080\n")
	attempts := 0
	if err := MigrateLegacyHTTPPort("8080", 3, 0, func(port string) error {
		attempts++
		if port != "8080" {
			t.Fatalf("change port = %q, want 8080", port)
		}
		if attempts < 3 {
			return errors.New("Gateway unavailable")
		}
		return nil
	}); err != nil {
		t.Fatalf("MigrateLegacyHTTPPort: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("Gateway attempts = %d, want 3", attempts)
	}
	if ServerInfo.HttpPort != "" {
		t.Fatalf("ServerInfo.HttpPort = %q after migration, want empty", ServerInfo.HttpPort)
	}
	persisted, err := ini.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := persisted.Section("server").Key("HttpPort").String(); got != "" {
		t.Fatalf("persisted HttpPort = %q after migration, want empty", got)
	}
}

func TestMigrateLegacyHTTPPortFailsClosedWithoutClearing(t *testing.T) {
	preserveConfigGlobals(t)

	path := filepath.Join(t.TempDir(), "custom.conf")
	InitSetup(path, "[server]\nHttpPort = 8080\n")
	attempts := 0
	err := MigrateLegacyHTTPPort("8080", 2, 0, func(string) error {
		attempts++
		return errors.New("Gateway unavailable")
	})
	if err == nil {
		t.Fatal("MigrateLegacyHTTPPort unexpectedly succeeded")
	}
	if attempts != 2 {
		t.Fatalf("Gateway attempts = %d, want 2", attempts)
	}
	if ServerInfo.HttpPort != "8080" {
		t.Fatalf("ServerInfo.HttpPort = %q after failure, want 8080", ServerInfo.HttpPort)
	}
	persisted, loadErr := ini.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got := persisted.Section("server").Key("HttpPort").String(); got != "8080" {
		t.Fatalf("persisted HttpPort = %q after failure, want 8080", got)
	}
}

func TestMigrateLegacyHTTPPortSkipsEmptyValue(t *testing.T) {
	called := false
	if err := MigrateLegacyHTTPPort("", 0, -1, func(string) error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("empty legacy value returned error: %v", err)
	}
	if called {
		t.Fatal("empty legacy value called Gateway")
	}
}

func TestInitSetupBindsActualConfigPathAndCreatesPrivateFile(t *testing.T) {
	preserveConfigGlobals(t)

	path := filepath.Join(t.TempDir(), "custom.conf")
	InitSetup(path, "[server]\nHttpPort = 8080\n[system]\nConfigPath = /tmp/redirected.conf\n")

	if ConfigFilePath != path {
		t.Fatalf("ConfigFilePath = %q, want %q", ConfigFilePath, path)
	}
	if SystemConfigInfo.ConfigPath != path {
		t.Fatalf("SystemConfigInfo.ConfigPath = %q, want actual loaded path %q", SystemConfigInfo.ConfigPath, path)
	}
	if ServerInfo.HttpPort != "8080" {
		t.Fatalf("ServerInfo.HttpPort = %q, want 8080", ServerInfo.HttpPort)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat created configuration: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("created configuration mode = %#o, want 0600", got)
	}
}

func TestPersistHTTPPortUsesActualPathAndAtomicPrivateReplacement(t *testing.T) {
	preserveConfigGlobals(t)

	directory := t.TempDir()
	path := filepath.Join(directory, "custom.conf")
	decoy := filepath.Join(directory, "redirected.conf")
	InitSetup(path, "[server]\nHttpPort = 80\n")
	SystemConfigInfo.ConfigPath = decoy
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("loosen test configuration permissions: %v", err)
	}

	if err := PersistHTTPPort("49152"); err != nil {
		t.Fatalf("PersistHTTPPort: %v", err)
	}
	if ServerInfo.HttpPort != "49152" {
		t.Fatalf("ServerInfo.HttpPort = %q, want 49152", ServerInfo.HttpPort)
	}

	persisted, err := ini.Load(path)
	if err != nil {
		t.Fatalf("load persisted configuration: %v", err)
	}
	if got := persisted.Section("server").Key("HttpPort").String(); got != "49152" {
		t.Fatalf("persisted HttpPort = %q, want 49152", got)
	}
	if _, err := os.Stat(decoy); !os.IsNotExist(err) {
		t.Fatalf("config-controlled decoy path was used: err=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted configuration: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("persisted configuration mode = %#o, want 0600", got)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".custom.conf.tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary configurations: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary configuration files remain after success: %v", matches)
	}
}

func TestPersistHTTPPortRollsBackBeforeReplacementFailure(t *testing.T) {
	for _, test := range []struct {
		name       string
		sample     string
		serverPort string
		hadKey     bool
		keyValue   string
	}{
		{name: "existing key", sample: "[server]\nHttpPort = 80\n", serverPort: "80", hadKey: true, keyValue: "80"},
		{name: "absent key", sample: "[server]\nRunMode = release\n", serverPort: "", hadKey: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			preserveConfigGlobals(t)

			directory := t.TempDir()
			path := filepath.Join(directory, "custom.conf")
			InitSetup(path, test.sample)
			blockedPath := filepath.Join(directory, "blocked.conf")
			if err := os.Mkdir(blockedPath, 0o700); err != nil {
				t.Fatalf("create replacement blocker: %v", err)
			}
			ConfigFilePath = blockedPath

			if err := PersistHTTPPort("49152"); err == nil {
				t.Fatal("PersistHTTPPort unexpectedly replaced a directory")
			}
			if ServerInfo.HttpPort != test.serverPort {
				t.Fatalf("ServerInfo.HttpPort = %q after failure, want %q", ServerInfo.HttpPort, test.serverPort)
			}
			section := Cfg.Section("server")
			if got := section.HasKey("HttpPort"); got != test.hadKey {
				t.Fatalf("in-memory HttpPort presence = %v after failure, want %v", got, test.hadKey)
			}
			if test.hadKey {
				if got := section.Key("HttpPort").String(); got != test.keyValue {
					t.Fatalf("in-memory HttpPort = %q after failure, want %q", got, test.keyValue)
				}
			}

			persisted, err := ini.Load(path)
			if err != nil {
				t.Fatalf("load original configuration after failure: %v", err)
			}
			if got := persisted.Section("server").HasKey("HttpPort"); got != test.hadKey {
				t.Fatalf("on-disk HttpPort presence = %v after failure, want %v", got, test.hadKey)
			}
			if test.hadKey {
				if got := persisted.Section("server").Key("HttpPort").String(); got != test.keyValue {
					t.Fatalf("on-disk HttpPort = %q after failure, want %q", got, test.keyValue)
				}
			}
			matches, err := filepath.Glob(filepath.Join(directory, ".blocked.conf.tmp-*"))
			if err != nil {
				t.Fatalf("glob temporary configurations: %v", err)
			}
			if len(matches) != 0 {
				t.Fatalf("temporary configuration files remain after failure: %v", matches)
			}
		})
	}
}
