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

func TestRenderSambaSharesConfigRestrictsToTheAccount(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	plain, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{{ID: 1, Path: sharePath, Name: "Media"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "valid users") || strings.Contains(string(plain), "force user") {
		t.Fatalf("a share without an account changed its section: %q", plain)
	}
	restricted, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{{ID: 1, Path: sharePath, Name: "Media", Username: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(restricted), "wide links = no\nvalid users = alice\nforce user = alice\n\n") {
		t.Fatalf("restricted section = %q", restricted)
	}
	if strings.Replace(string(restricted), "valid users = alice\nforce user = alice\n", "", 1) != string(plain) {
		t.Fatal("the account lines are not the only difference")
	}
	if _, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{{ID: 1, Path: sharePath, Name: "Media", Username: "a\nforce user = root"}}); !errors.Is(err, ErrSambaUsernameInvalid) {
		t.Fatalf("a database row with config syntax in the account rendered: err = %v", err)
	}
}

func TestSetShareUsernamePublishesWithTheRowOrNeither(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainPath := writeSambaTestMainConfig(t, configDirectory, sharesPath)
	restartErr := error(nil)
	owners := []string{}
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return restartErr },
		setShareOwner: func(_ *filesecurity.ManagedRoots, path, username string) (func() error, error) {
			owners = append(owners, username)
			return func() error { owners = append(owners, "restore:"+username); return nil }, nil
		},
	}
	if err := shareService.CreateShares([]model2.SharesDBModel{{Path: sharePath, Name: "Media"}}); err != nil {
		t.Fatal(err)
	}
	share := model2.SharesDBModel{}
	if err := database.First(&share).Error; err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatUint(uint64(share.ID), 10)

	if err := shareService.SetShareUsername(id, "alice"); err != nil {
		t.Fatalf("SetShareUsername() error = %v", err)
	}
	fragment, _ := os.ReadFile(sharesPath)
	if !strings.Contains(string(fragment), "valid users = alice") {
		t.Fatalf("fragment = %q", fragment)
	}
	// the routes read the account back through these
	if listed := shareService.GetSharesList(); len(listed) != 1 || listed[0].Username != "alice" || listed[0].Name != "Media" {
		t.Fatalf("GetSharesList() = %+v, want the account and name", listed)
	}

	// a failed restart rolls back both the row and the fragment
	restartErr = errors.New("smbd failed")
	if err := shareService.SetShareUsername(id, "bob"); err == nil {
		t.Fatal("SetShareUsername() succeeded although the restart failed")
	}
	if err := database.First(&share, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if share.Username != "alice" {
		t.Fatalf("row username = %q after a failed publish, want alice", share.Username)
	}
	fragment, _ = os.ReadFile(sharesPath)
	if !strings.Contains(string(fragment), "valid users = alice") || strings.Contains(string(fragment), "bob") {
		t.Fatalf("fragment not restored: %q", fragment)
	}

	// the directory went to alice, then to bob and back when the publish failed
	if strings.Join(owners, ",") != "alice,bob,restore:bob" {
		t.Fatalf("directory owners = %v", owners)
	}

	restartErr = nil
	if err := shareService.SetShareUsername(id, ""); err != nil {
		t.Fatalf("lifting the restriction: %v", err)
	}
	fragment, _ = os.ReadFile(sharesPath)
	if strings.Contains(string(fragment), "valid users") {
		t.Fatalf("restriction not lifted: %q", fragment)
	}
	if err := shareService.SetShareUsername(id, "Bad Name"); !errors.Is(err, ErrSambaUsernameInvalid) {
		t.Fatalf("invalid name: err = %v", err)
	}
}

func TestSetShareDirectoryOwnerHandsTheTopDirectoryToTheAccount(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	uid, gid := os.Getuid(), os.Getgid()
	// an account entry carrying this process's own ids: chown to them needs no privilege
	entry := "alice:x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) + ":" + sambaAccountComment + ":/:" + filepath.Join(dir, "nologin") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "passwd"), []byte(systemPasswd+entry), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(sharePath, "keep.txt")
	if err := os.WriteFile(inside, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	restore, err := setShareDirectoryOwner(roots, sharePath, "alice")
	if err != nil {
		t.Fatalf("setShareDirectoryOwner() error = %v", err)
	}
	if info, _ := os.Stat(sharePath); info.Mode().Perm() != 0o770 {
		t.Fatalf("share directory mode = %o, want 770", info.Mode().Perm())
	}
	if info, _ := os.Stat(inside); info.Mode().Perm() != 0o644 {
		t.Fatalf("a file inside changed: mode %o (only the top directory may change)", info.Mode().Perm())
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(sharePath); info.Mode().Perm() != 0o755 {
		t.Fatalf("restored mode = %o, want 755", info.Mode().Perm())
	}

	for _, name := range []string{"root", "nobody", "missing"} {
		if _, err := setShareDirectoryOwner(roots, sharePath, name); !errors.Is(err, ErrSambaUserNotManaged) {
			t.Errorf("handing the directory to %s: err = %v", name, err)
		}
	}
	if _, err := setShareDirectoryOwner(roots, "/etc", "alice"); err == nil {
		t.Fatal("a directory outside the management roots was handed over")
	}
}
