//go:build linux

package service

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

func TestManagedSambaMainConfigRefusesGuestFallback(t *testing.T) {
	config, err := renderSambaMainConfig("/etc/samba/smb.casa.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("\n   map to guest = never\n")) || bytes.Contains(config, []byte("bad user")) {
		t.Fatalf("managed main config allows a guest fallback:\n%s", config)
	}
}

func TestPreviousManagedSambaMainConfigIsUpgradedOnReconcile(t *testing.T) {
	roots, _ := openSambaTestRoots(t)
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	previous, err := renderPreviousSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	overwriteSambaTestFile(t, mainPath, previous, 0o600)
	restarts := 0
	service := &sharesStruct{
		db:                    openSambaTestDB(t),
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
	}
	if err := service.ReconcileSambaConfig(); err != nil {
		t.Fatalf("reconcile error = %v", err)
	}
	current, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	assertFileDataAndMode(t, mainPath, current, 0o600)
	if restarts == 0 {
		t.Fatal("upgraded main config was not loaded: no Samba restart")
	}
	if !IsManagedSambaMainConfigLine(string(bytes.SplitN(previous, []byte("\n"), 2)[0])) {
		t.Fatal("v1 marker line no longer recognised as managed")
	}
}

func TestEditedPreviousManagedSambaMainConfigIsNotUpgraded(t *testing.T) {
	roots, _ := openSambaTestRoots(t)
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	previous, err := renderPreviousSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte{}, previous...), []byte("   # local edit\n")...)
	overwriteSambaTestFile(t, mainPath, edited, 0o600)
	service := &sharesStruct{
		db:                    openSambaTestDB(t),
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { t.Fatal("edited config restarted Samba"); return nil },
	}
	if err := service.ReconcileSambaConfig(); err == nil {
		t.Fatal("edited v1 main config was accepted")
	}
	assertFileDataAndMode(t, mainPath, edited, 0o600)
}
