//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
)

// writeExternalSambaMain lays out an externally owned main config the way a
// configuration-managed host does: smb.conf is a symlink to a read-only file
// elsewhere that includes the shares fragment.
func writeExternalSambaMain(t *testing.T, configDirectory, sharesPath string, include bool) (string, []byte) {
	t.Helper()
	store := t.TempDir()
	content := "[global]\n   workgroup = OPERATOR\n   server signing = mandatory\n"
	if include {
		content += "   include = " + sharesPath + "\n"
	}
	target := filepath.Join(store, "smb.conf")
	if err := os.WriteFile(target, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(configDirectory, "smb.conf")
	if err := os.Symlink(target, mainPath); err != nil {
		t.Fatal(err)
	}
	return mainPath, []byte(content)
}

func assertExternalMainUntouched(t *testing.T, mainPath string, content []byte) {
	t.Helper()
	info, err := os.Lstat(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s was replaced; the external main config must stay a symlink", mainPath)
	}
	data, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Fatalf("external main config changed: %q", data)
	}
	if _, err := os.Stat(mainPath + legacySambaBackupSuffix); err == nil {
		t.Fatalf("a backup of the external main config was written")
	}
}

func TestExternalMainConfigManagesOnlyTheFragment(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath, mainContent := writeExternalSambaMain(t, configDirectory, sharesPath, true)
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
		externalMainConfig:    true,
	}

	if err := shareService.CreateShares([]model2.SharesDBModel{{Path: sharePath, Name: "Media"}}); err != nil {
		t.Fatalf("CreateShares() error = %v", err)
	}
	if restarts != 1 {
		t.Fatalf("restart calls = %d, want 1", restarts)
	}
	fragment, err := os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(fragment), sambaSharesConfigMarker) || !strings.Contains(string(fragment), "[Media]") {
		t.Fatalf("fragment does not carry the share: %q", fragment)
	}
	assertExternalMainUntouched(t, mainPath, mainContent)

	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatalf("ReconcileSambaConfig() error = %v", err)
	}
	if err := shareService.InitSambaConfig(); err != nil {
		t.Fatalf("InitSambaConfig() error = %v", err)
	}
	assertExternalMainUntouched(t, mainPath, mainContent)

	var shares []model2.SharesDBModel
	if err := database.Find(&shares).Error; err != nil {
		t.Fatal(err)
	}
	if err := shareService.DeleteShare(strconv.FormatUint(uint64(shares[0].ID), 10)); err != nil {
		t.Fatalf("DeleteShare() error = %v", err)
	}
	fragment, err = os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fragment), "[Media]") {
		t.Fatalf("deleted share still in the fragment: %q", fragment)
	}
	assertExternalMainUntouched(t, mainPath, mainContent)
}

// The managed mode refuses the same symlinked main config: that is why a host
// that owns smb.conf needs the external mode at all.
func TestManagedMainConfigRefusesSymlinkedMain(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath, mainContent := writeExternalSambaMain(t, configDirectory, sharesPath, true)
	shareService := &sharesStruct{
		db:                    openSambaTestDB(t),
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return nil },
	}
	if err := shareService.CreateShares([]model2.SharesDBModel{{Path: sharePath, Name: "Media"}}); err == nil {
		t.Fatal("managed mode accepted a symlinked main config")
	}
	assertExternalMainUntouched(t, mainPath, mainContent)
}

func TestExternalMainConfigMustIncludeTheFragment(t *testing.T) {
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath, _ := writeExternalSambaMain(t, configDirectory, sharesPath, false)
	shareService := &sharesStruct{
		db:                    openSambaTestDB(t),
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { t.Fatal("restarted Samba"); return nil },
		externalMainConfig:    true,
	}
	for name, run := range map[string]func() error{
		"ReconcileSambaConfig": shareService.ReconcileSambaConfig,
		"InitSambaConfig":      shareService.InitSambaConfig,
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "does not include") {
			t.Fatalf("%s() error = %v, want a missing include", name, err)
		}
	}
	if _, err := os.Stat(sharesPath); err == nil {
		t.Fatal("a fragment was written although the main config does not include it")
	}
}

func TestCheckExternalSambaMainIncludes(t *testing.T) {
	sharesPath := "/etc/samba/smb.casa.conf"
	for _, tc := range []struct {
		content string
		ok      bool
	}{
		{"[global]\ninclude = /etc/samba/smb.casa.conf\n", true},
		{"[global]\n\tInclude=/etc/samba/smb.casa.conf  \n", true},
		{"[global]\n# include = /etc/samba/smb.casa.conf\n", false},
		{"[global]\n; include = /etc/samba/smb.casa.conf\n", false},
		{"[global]\ninclude = /etc/samba/smb.casa.conf.d\n", false},
		{"[global]\n", false},
	} {
		mainPath := filepath.Join(t.TempDir(), "smb.conf")
		if err := os.WriteFile(mainPath, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkExternalSambaMainIncludes(mainPath, sharesPath); (err == nil) != tc.ok {
			t.Errorf("%q: err = %v, want ok=%v", tc.content, err, tc.ok)
		}
	}
}

func TestNewSharesServiceReadsSambaMainConfig(t *testing.T) {
	previous := *config.ServerInfo
	t.Cleanup(func() { *config.ServerInfo = previous })
	for value, want := range map[string]bool{"": false, "managed": false, "external": true, " External ": true, "bogus": false} {
		*config.ServerInfo = model.ServerModel{SambaMainConfig: value}
		if got := NewSharesService(nil).(*sharesStruct).externalMainConfig; got != want {
			t.Errorf("SambaMainConfig %q: external = %v, want %v", value, got, want)
		}
	}
}
