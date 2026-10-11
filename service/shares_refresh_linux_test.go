//go:build linux

package service

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
)

func TestChangedSambaShares(t *testing.T) {
	before := []byte(sambaSharesConfigMarker + "\n[Media]\npath = \"/DATA/Media\"\nvalid users = bob\n\n[Docs]\npath = \"/DATA/Docs\"\n\n[Old]\npath = \"/DATA/Old\"\n")
	after := []byte(sambaSharesConfigMarker + "\n[Media]\npath = \"/DATA/Media\"\nvalid users = alice\n\n[docs]\npath = \"/DATA/Docs\"\n\n[New]\npath = \"/DATA/New\"\n")
	// Media: account changed; Docs: case-only rename (header differs); Old: gone; New: added
	if got, want := changedSambaShares(before, after), []string{"Docs", "Media", "Old"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changedSambaShares() = %v, want %v", got, want)
	}
	if got := changedSambaShares(before, before); len(got) != 0 {
		t.Fatalf("unchanged fragment: %v", got)
	}
	if got := changedSambaShares(nil, after); len(got) != 0 {
		t.Fatalf("first fragment: %v", got)
	}
}

func TestTimeMachineSharesChanged(t *testing.T) {
	plain := []byte(sambaSharesConfigMarker + "\n[Media]\npath = \"/DATA/Media\"\n")
	backups := []byte(sambaSharesConfigMarker + "\n[Media]\npath = \"/DATA/Media\"\n\n[Backups]\npath = \"/DATA/Backups\"\n" + timeMachineLines)
	edited := []byte(sambaSharesConfigMarker + "\n[Media]\npath = \"/DATA/Media\"\nvalid users = bob\n\n[Backups]\npath = \"/DATA/Backups\"\nvalid users = bob\n" + timeMachineLines)
	for _, c := range []struct {
		name          string
		before, after []byte
		want          bool
	}{
		{"added", plain, backups, true},
		{"removed", backups, plain, true},
		{"other edits", backups, edited, false},
		{"none", plain, plain, false},
	} {
		if got := timeMachineSharesChanged(c.before, c.after); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// share edits reload smbd and close only the touched shares; no restart
func TestShareEditsReloadInsteadOfRestart(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	for _, name := range []string{"Media", "Docs"} {
		if err := os.Mkdir(filepath.Join(rootPath, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath := writeSambaTestMainConfig(t, configDirectory, sharesPath)
	restarts := 0
	var reloads [][]string
	var reloadErr error
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
		reloadSMBD: func(closeShares []string) error {
			reloads = append(reloads, closeShares)
			return reloadErr
		},
		setShareOwner: func(*filesecurity.ManagedRoots, string, string) (func() error, error) {
			return func() error { return nil }, nil
		},
	}
	if err := shareService.CreateShares([]model2.SharesDBModel{
		{Path: filepath.Join(rootPath, "Media"), Name: "Media"},
		{Path: filepath.Join(rootPath, "Docs"), Name: "Docs"},
	}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, share := range shareService.GetSharesList() {
		ids[share.Name] = strconv.FormatUint(uint64(share.ID), 10)
	}
	if err := shareService.SetShare(ids["Media"], "bob", nil); err != nil {
		t.Fatal(err)
	}
	if err := shareService.DeleteShare(ids["Docs"]); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{}, {"Media"}, {"Docs"}}
	if restarts != 0 || !reflect.DeepEqual(reloads, want) {
		t.Fatalf("restarts = %d, reloads = %v; want 0, %v", restarts, reloads, want)
	}

	// Time Machine flag: restart (mDNS registration)
	on := true
	if err := shareService.SetShare(ids["Media"], "bob", &on); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 || len(reloads) != 3 {
		t.Fatalf("Time Machine toggle: restarts = %d, reloads = %d; want 1, 3", restarts, len(reloads))
	}

	// reload fails (smbd down): restart instead, the edit still lands
	reloadErr = errors.New("smbd not running")
	if err := shareService.SetShare(ids["Media"], "", nil); err != nil {
		t.Fatal(err)
	}
	if restarts != 2 {
		t.Fatalf("reload failure: restarts = %d, want 2", restarts)
	}
	if listed := shareService.GetSharesList(); len(listed) != 1 || listed[0].Username != "" {
		t.Fatalf("edit lost: %+v", listed)
	}
}
