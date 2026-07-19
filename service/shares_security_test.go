package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	model2 "github.com/IceWhaleTech/CasaOS/service/model"
)

func TestValidateSambaShareFieldsRejectsConfigInjection(t *testing.T) {
	if err := validateSambaShareFields("/DATA/Media Library", "Media Library"); err != nil {
		t.Fatalf("validateSambaShareFields() rejected safe share: %v", err)
	}
	for _, testCase := range []struct {
		path string
		name string
	}{
		{path: "/DATA/global", name: "global"},
		{path: "/DATA/IPC$", name: "IPC$"},
		{path: "/DATA/ADMIN$", name: "ADMIN$"},
		{path: "/DATA/C$", name: "C$"},
		{path: "/DATA/print$", name: "print$"},
		{path: "/DATA/Media  Share", name: "Media  Share"},
		{path: "/DATA/Media\tShare", name: "Media\tShare"},
		{path: "/DATA/bad]name", name: "bad]name"},
		{path: "/DATA/bad\n[global]", name: "bad\n[global]"},
		{path: `/DATA/bad\name`, name: `bad\name`},
		{path: `/DATA/bad"name`, name: `bad"name`},
		{path: "/DATA/bad%U", name: "bad%U"},
		{path: "/DATA/.hidden", name: ".hidden"},
		{path: "/DATA/trailing.", name: "trailing."},
		{path: "/DATA/café", name: "café"},
		{path: "/DATA/é", name: "é"},
		{path: "/DATA/bad:name", name: "bad:name"},
		{path: "/DATA/bad#name", name: "bad#name"},
		{path: "/DATA/bad;name", name: "bad;name"},
		{path: "/DATA/Media", name: "Other"},
	} {
		if err := validateSambaShareFields(testCase.path, testCase.name); err == nil {
			t.Errorf("validateSambaShareFields(%q, %q) unexpectedly succeeded", testCase.path, testCase.name)
		}
	}
}

func TestRenderedSambaMainRequiresSMB2Signing(t *testing.T) {
	config, err := renderSambaMainConfig("/etc/samba/smb.casa.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "server signing = mandatory") {
		t.Fatalf("rendered main config does not require SMB signing:\n%s", config)
	}
}

func TestCurrentSambaAPIsRejectAnonymousShares(t *testing.T) {
	share := model2.SharesDBModel{ID: 1, Anonymous: true, Path: "/DATA/Media", Name: "Media"}
	if _, err := renderSambaSharesConfig(nil, []model2.SharesDBModel{share}); err == nil {
		t.Fatal("renderer accepted an anonymous Samba row")
	}
	if err := (&sharesStruct{}).CreateShares([]model2.SharesDBModel{share}); err == nil {
		t.Fatal("share service accepted an anonymous Samba request")
	}
}

func TestWriteFileAtomicReplacesContentAndPermissions(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "smb.casa.conf")
	if err := os.WriteFile(destination, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(destination, []byte("new"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic() error = %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("config content = %q, want new", data)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
}

func TestInitSambaConfigDoesNotOverwriteExistingBackup(t *testing.T) {
	configDirectory := t.TempDir()
	configPath := filepath.Join(configDirectory, "smb.conf")
	backupPath := configPath + ".bak"
	if err := os.WriteFile(configPath, []byte("operator config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("precious backup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	if err := os.WriteFile(sharesPath, []byte(sambaSharesConfigMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	shareService := &sharesStruct{
		sambaConfigPath:       configPath,
		sambaSharesConfigPath: sharesPath,
		validateCandidate:     func([]byte) error { return nil },
		restartSMBD:           func() error { return nil },
	}
	if err := shareService.InitSambaConfig(); err == nil {
		t.Fatal("InitSambaConfig() unexpectedly overwrote an existing backup")
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(configData) != "operator config\n" || string(backupData) != "precious backup\n" {
		t.Fatalf("config or backup changed: config=%q backup=%q", configData, backupData)
	}
}

func TestInitSambaConfigRejectsSymlinkAndHardlinkedMainConfig(t *testing.T) {
	configDirectory := t.TempDir()
	targetPath := filepath.Join(configDirectory, "target.conf")
	if err := os.WriteFile(targetPath, []byte("operator config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(configDirectory, "symlink.conf")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := (&sharesStruct{sambaConfigPath: symlinkPath}).InitSambaConfig(); err == nil {
		t.Fatal("InitSambaConfig() unexpectedly accepted a symlink")
	}

	hardlinkPath := filepath.Join(configDirectory, "hardlink.conf")
	if err := os.Link(targetPath, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := (&sharesStruct{sambaConfigPath: targetPath}).InitSambaConfig(); err == nil {
		t.Fatal("InitSambaConfig() unexpectedly accepted a multiply linked file")
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "operator config\n" {
		t.Fatalf("operator config changed to %q", data)
	}
	if _, err := os.Stat(targetPath + ".bak"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unexpected backup after rejected config: %v", err)
	}
}

func TestMissingMainConfigCannotCreateOrphanSharesConfig(t *testing.T) {
	configDirectory := t.TempDir()
	mainConfigPath := filepath.Join(configDirectory, "missing-smb.conf")
	sharesConfigPath := filepath.Join(configDirectory, "smb.casa.conf")
	shareService := &sharesStruct{
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: sharesConfigPath,
	}
	if err := shareService.InitSambaConfig(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("InitSambaConfig() error = %v, want fs.ErrNotExist", err)
	}
	if err := shareService.UpdateConfigFile(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("UpdateConfigFile() error = %v, want fs.ErrNotExist", err)
	}
	if _, err := os.Stat(sharesConfigPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("orphan shares config exists or stat failed unexpectedly: %v", err)
	}
}

func TestExistingUnmanagedSharesConfigIsNeverOverwritten(t *testing.T) {
	configDirectory := t.TempDir()
	mainConfigPath := filepath.Join(configDirectory, "smb.conf")
	sharesConfigPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainConfig, err := renderSambaMainConfig(sharesConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainConfigPath, mainConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorData := []byte("[operator-owned]\npath = /srv/operator\n")
	if err := os.WriteFile(sharesConfigPath, operatorData, 0o600); err != nil {
		t.Fatal(err)
	}
	shareService := &sharesStruct{sambaConfigPath: mainConfigPath, sambaSharesConfigPath: sharesConfigPath}
	if err := shareService.UpdateConfigFile(); err == nil {
		t.Fatal("UpdateConfigFile() unexpectedly overwrote an unmanaged shares config")
	}
	after, err := os.ReadFile(sharesConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(operatorData) {
		t.Fatalf("operator shares config changed to %q", after)
	}
}
