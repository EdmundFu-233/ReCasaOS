//go:build linux

package service

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
)

const timeMachineLines = "vfs objects = catia fruit streams_xattr\nfruit:time machine = yes\n"

func TestTimeMachineLinesOnlyOnTheFlaggedShare(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	for _, name := range []string{"Backups", "Media"} {
		if err := os.Mkdir(filepath.Join(rootPath, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	fragment, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{
		{ID: 1, Path: filepath.Join(rootPath, "Backups"), Name: "Backups", Username: "alice", TimeMachine: true},
		{ID: 2, Path: filepath.Join(rootPath, "Media"), Name: "Media"},
	})
	if err != nil {
		t.Fatal(err)
	}
	backups, media, _ := strings.Cut(string(fragment), "[Media]")
	if !strings.Contains(backups, "force user = alice\n"+timeMachineLines) {
		t.Fatalf("Backups section = %q", backups)
	}
	if strings.Contains(media, "fruit") {
		t.Fatalf("Media section got Time Machine lines: %q", media)
	}
}

func TestSetShareTimeMachineFlag(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Backups")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath := writeSambaTestMainConfig(t, configDirectory, sharesPath)
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return nil },
		setShareOwner: func(*filesecurity.ManagedRoots, string, string) (func() error, error) {
			return func() error { return nil }, nil
		},
	}
	if err := shareService.CreateShares([]model2.SharesDBModel{{Path: sharePath, Name: "Backups", TimeMachine: true}}); err != nil {
		t.Fatal(err)
	}
	fragment, _ := os.ReadFile(sharesPath)
	if !strings.Contains(string(fragment), timeMachineLines) {
		t.Fatalf("created share without Time Machine lines: %q", fragment)
	}
	listed := shareService.GetSharesList()
	if len(listed) != 1 || !listed[0].TimeMachine {
		t.Fatalf("GetSharesList() = %+v, want the flag", listed)
	}
	id := strconv.FormatUint(uint64(listed[0].ID), 10)

	// nil: flag unchanged (account-only clients)
	if err := shareService.SetShare(id, "", nil); err != nil {
		t.Fatal(err)
	}
	if fragment, _ = os.ReadFile(sharesPath); !strings.Contains(string(fragment), timeMachineLines) {
		t.Fatalf("flag lost by an account-only update: %q", fragment)
	}
	off := false
	if err := shareService.SetShare(id, "", &off); err != nil {
		t.Fatal(err)
	}
	if fragment, _ = os.ReadFile(sharesPath); strings.Contains(string(fragment), "fruit") {
		t.Fatalf("flag not cleared: %q", fragment)
	}
	if listed = shareService.GetSharesList(); listed[0].TimeMachine {
		t.Fatal("row still flagged")
	}
}

func TestValidateTimeMachineSupport(t *testing.T) {
	original := smbdBuildOptions
	t.Cleanup(func() { smbdBuildOptions = original })
	modules := t.TempDir()
	smbdBuildOptions = func() ([]byte, error) {
		return []byte("Paths:\n   SBINDIR: /usr/sbin\n   MODULESDIR: " + modules + "\n"), nil
	}
	if err := ValidateTimeMachineSupport(); !errors.Is(err, ErrTimeMachineUnsupported) {
		t.Fatalf("missing fruit.so: err = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(modules, "vfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "vfs", "fruit.so"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTimeMachineSupport(); err != nil {
		t.Fatalf("fruit.so present: err = %v", err)
	}
	// no smbd / no MODULESDIR: no false refusal
	smbdBuildOptions = func() ([]byte, error) { return nil, errors.New("exec: smbd not found") }
	if err := ValidateTimeMachineSupport(); err != nil {
		t.Fatalf("no smbd: err = %v", err)
	}
	smbdBuildOptions = func() ([]byte, error) { return []byte("Paths:\n"), nil }
	if err := ValidateTimeMachineSupport(); err != nil {
		t.Fatalf("no MODULESDIR: err = %v", err)
	}
}
