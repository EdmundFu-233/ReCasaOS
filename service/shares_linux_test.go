//go:build linux

package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestPublishSambaConfigCASPreservesReplacementDuringRollbackCleanup(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("expected"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := readSambaConfigSnapshot(target, true, "")
	if err != nil {
		t.Fatal(err)
	}
	// Force the first exchange to displace a different inode so CAS must roll
	// back. The cleanup hook then swaps the candidate path with external data.
	if err := os.Rename(target, target+".expected-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("concurrent-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookCalls := 0
	cleanupHook := func(path string) {
		hookCalls++
		if hookCalls != 1 {
			return
		}
		if err := os.Rename(path, path+".candidate-moved"); err != nil {
			t.Errorf("move candidate in cleanup hook: %v", err)
			return
		}
		if err := os.WriteFile(path, []byte("external-cleanup-replacement"), 0o600); err != nil {
			t.Errorf("write cleanup replacement: %v", err)
		}
	}
	owned, err := publishSambaConfigCAS(expected, []byte("candidate"), 0o600, cleanupHook)
	if err == nil || owned.exists {
		t.Fatalf("conflicting publish = owned %+v, err %v", owned, err)
	}
	targetData, readErr := os.ReadFile(target)
	if readErr != nil || string(targetData) != "concurrent-target" {
		t.Fatalf("concurrent target was not restored: data=%q err=%v", targetData, readErr)
	}
	if !directoryContainsFileData(t, directory, []byte("external-cleanup-replacement")) {
		t.Fatal("external cleanup replacement was deleted")
	}
	if err := refuseSambaConfigQuarantine(directory); err == nil {
		t.Fatal("detected unknown temporary file did not block future publications")
	}
}

func TestRemoveSambaConfigCASPreservesCleanupReplacement(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := readSambaConfigSnapshot(target, true, "")
	if err != nil {
		t.Fatal(err)
	}
	cleanupHook := func(path string) {
		if err := os.Rename(path, path+".owned-moved"); err != nil {
			t.Errorf("move owned file: %v", err)
			return
		}
		if err := os.WriteFile(path, []byte("external"), 0o600); err != nil {
			t.Errorf("write external replacement: %v", err)
		}
	}
	if err := removeSambaConfigCAS(expected, cleanupHook); err == nil {
		t.Fatal("conditional removal unexpectedly accepted a replacement")
	}
	if !directoryContainsFileData(t, directory, []byte("external")) {
		t.Fatal("external replacement was deleted")
	}
}

func directoryContainsFileData(t *testing.T, directory string, expected []byte) bool {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err == nil && bytes.Equal(data, expected) {
			return true
		}
	}
	return false
}

func TestPublishSambaConfigCASNormalUpdatesDoNotAccumulateTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "smb.casa.conf")
	if err := os.WriteFile(target, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		expected, err := readSambaConfigSnapshot(target, true, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publishSambaConfigCAS(expected, []byte(fmt.Sprintf("candidate-%d", index)), 0o600, nil); err != nil {
			t.Fatalf("publish %d: %v", index, err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		t.Fatalf("normal CAS updates accumulated files: %#v", entries)
	}
}

func TestOrphanedSambaCASStagingFileBlocksPublication(t *testing.T) {
	directory := t.TempDir()
	orphan := filepath.Join(directory, ".smb.conf.cas-crash-remnant")
	if err := os.WriteFile(orphan, []byte("unknown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := refuseSambaConfigQuarantine(directory); err == nil {
		t.Fatal("orphaned CAS staging file did not fail closed")
	}
	data, err := os.ReadFile(orphan)
	if err != nil || string(data) != "unknown" {
		t.Fatalf("orphaned staging file was changed: data=%q err=%v", data, err)
	}
}

func TestCompleteBackupDoesNotHideDirectorySyncFailure(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "smb.conf")
	backupPath := sourcePath + legacySambaBackupSuffix
	if err := os.WriteFile(sourcePath, []byte("legacy"), 0o640); err != nil {
		t.Fatal(err)
	}
	source, err := readSambaConfigSnapshot(sourcePath, true, "")
	if err != nil {
		t.Fatal(err)
	}
	previousSync := syncSambaConfigDirectory
	t.Cleanup(func() { syncSambaConfigDirectory = previousSync })
	syncSambaConfigDirectory = func(string) error { return errors.New("injected directory sync failure") }
	if _, _, err := ensureSambaConfigBackup(source, backupPath); err == nil {
		t.Fatal("backup publication hid a directory sync failure")
	}
	syncSambaConfigDirectory = previousSync
	backup, created, err := ensureSambaConfigBackup(source, backupPath)
	if err != nil || created || string(backup.data) != "legacy" {
		t.Fatalf("complete backup did not converge on retry: created=%v data=%q err=%v", created, backup.data, err)
	}
}

func TestPartialExistingLegacyBackupIsPreservedAndRejected(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "smb.conf")
	backupPath := sourcePath + legacySambaBackupSuffix
	if err := os.WriteFile(sourcePath, []byte("complete legacy config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := readSambaConfigSnapshot(sourcePath, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureSambaConfigBackup(source, backupPath); err == nil {
		t.Fatal("partial final backup unexpectedly accepted")
	}
	after, err := os.ReadFile(backupPath)
	if err != nil || string(after) != "partial" {
		t.Fatalf("partial external backup was changed: data=%q err=%v", after, err)
	}
}

func TestReconcileMigratesExactLegacyConfigAndEmptyNamesWithoutTouchingCasaOSBackup(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: false, Path: sharePath, Name: ""}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	legacyMain, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	oldCasaOSBackup := []byte("pre-existing CasaOS backup must remain untouched")
	if err := os.WriteFile(mainPath+".bak", oldCasaOSBackup, 0o600); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
	}
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 {
		t.Fatalf("restart count = %d, want 1", restarts)
	}
	assertFileDataAndMode(t, mainPath+".bak", oldCasaOSBackup, 0o600)
	assertFileDataAndMode(t, mainPath+legacySambaBackupSuffix, legacyMain, 0o600)
	assertFileDataAndMode(t, sharesPath+legacySambaBackupSuffix, legacyFragment, 0o600)
	mainData, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	fragmentData, err := os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"force user", "mask = 0777", "guest ok = Yes", "public = Yes"} {
		if bytes.Contains(mainData, []byte(unsafe)) || bytes.Contains(fragmentData, []byte(unsafe)) {
			t.Fatalf("migrated config retained %q", unsafe)
		}
	}
	if !bytes.Contains(mainData, []byte("server signing = mandatory")) || !bytes.Contains(fragmentData, []byte(sambaSharesConfigMarker)) {
		t.Fatalf("migrated config missing managed markers/signing: main=%q fragment=%q", mainData, fragmentData)
	}
	assertSambaMode(t, mainPath, 0o600)
	assertSambaMode(t, sharesPath, 0o600)
	var migrated model2.SharesDBModel
	if err := database.First(&migrated, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if migrated.Name != "Media" || migrated.Anonymous {
		t.Fatalf("migrated row = %+v", migrated)
	}
}

func TestLegacyMigrationRestartFailureRollsBackDatabaseAndConfigThenConverges(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Path: sharePath}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	legacyMain, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	restartFailure := errors.New("injected restart failure")
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD: func() error {
			restarts++
			if restarts == 1 {
				return restartFailure
			}
			return nil
		},
	}
	if err := shareService.ReconcileSambaConfig(); !errors.Is(err, restartFailure) {
		t.Fatalf("ReconcileSambaConfig() error = %v", err)
	}
	assertFileDataAndMode(t, mainPath, legacyMain, 0o644)
	assertFileDataAndMode(t, sharesPath, legacyFragment, 0o777)
	var rolledBack model2.SharesDBModel
	if err := database.First(&rolledBack, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if rolledBack.Name != "" {
		t.Fatalf("legacy name update committed after restart failure: %+v", rolledBack)
	}
	shareService.restartSMBD = func() error { return nil }
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatalf("retry did not converge: %v", err)
	}
}

func TestLegacyMigrationCommitFailureRollsBackAndRetries(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: true, Path: sharePath}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	legacyMain, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	commitFailure := errors.New("injected legacy migration commit failure")
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
		commitLegacyMigration: func(*gorm.DB) error { return commitFailure },
	}
	if err := shareService.ReconcileSambaConfig(); !errors.Is(err, commitFailure) {
		t.Fatalf("commit failure error = %v", err)
	}
	assertFileDataAndMode(t, mainPath, legacyMain, 0o644)
	assertFileDataAndMode(t, sharesPath, legacyFragment, 0o777)
	assertFileDataAndMode(t, mainPath+legacySambaBackupSuffix, legacyMain, 0o600)
	assertFileDataAndMode(t, sharesPath+legacySambaBackupSuffix, legacyFragment, 0o600)
	var rolledBack model2.SharesDBModel
	if err := database.First(&rolledBack, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !rolledBack.Anonymous || rolledBack.Name != "" {
		t.Fatalf("commit failure changed DB row: %+v", rolledBack)
	}
	if restarts != 2 {
		t.Fatalf("restart count after rollback = %d, want 2", restarts)
	}
	shareService.commitLegacyMigration = nil
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatalf("retry did not converge: %v", err)
	}
	var migrated model2.SharesDBModel
	if err := database.First(&migrated, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if migrated.Anonymous || migrated.Name != "Media" {
		t.Fatalf("retry did not commit private row: %+v", migrated)
	}
}

func TestLegacyMigrationRejectsModifiedOrUnbackedTransitionalConfigWithoutMutation(t *testing.T) {
	for _, mode := range []string{"modified-main", "modified-fragment", "transition-missing-backup"} {
		t.Run(mode, func(t *testing.T) {
			roots, rootPath := openSambaTestRoots(t)
			sharePath := filepath.Join(rootPath, "Media")
			if err := os.Mkdir(sharePath, 0o750); err != nil {
				t.Fatal(err)
			}
			database := openSambaTestDB(t)
			share := model2.SharesDBModel{Path: sharePath}
			if err := database.Create(&share).Error; err != nil {
				t.Fatal(err)
			}
			configDirectory := t.TempDir()
			mainPath := filepath.Join(configDirectory, "smb.conf")
			sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
			legacyMain, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
			switch mode {
			case "modified-main":
				legacyMain = append(append([]byte{}, legacyMain...), []byte("\n# operator change")...)
				if err := os.WriteFile(mainPath, legacyMain, 0o644); err != nil {
					t.Fatal(err)
				}
			case "modified-fragment":
				legacyFragment = append(append([]byte{}, legacyFragment...), []byte("# operator change\n")...)
				if err := os.WriteFile(sharesPath, legacyFragment, 0o777); err != nil {
					t.Fatal(err)
				}
			case "transition-missing-backup":
				managedMain, err := renderSambaMainConfig(sharesPath)
				if err != nil {
					t.Fatal(err)
				}
				legacyMain = managedMain
				overwriteSambaTestFile(t, mainPath, managedMain, 0o600)
			}
			shareService := &sharesStruct{
				db:                    database,
				sambaConfigPath:       mainPath,
				sambaSharesConfigPath: sharesPath,
				managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
				validateCandidate:     acceptSambaCandidate,
				restartSMBD:           func() error { t.Fatal("restart ran for rejected legacy config"); return nil },
			}
			if err := shareService.ReconcileSambaConfig(); err == nil {
				t.Fatalf("%s unexpectedly migrated", mode)
			}
			assertFileDataAndMode(t, mainPath, legacyMain, map[string]os.FileMode{"transition-missing-backup": 0o600}[mode])
			if mode != "transition-missing-backup" {
				assertSambaMode(t, mainPath, 0o644)
			}
			assertFileDataAndMode(t, sharesPath, legacyFragment, 0o777)
			var after model2.SharesDBModel
			if err := database.First(&after, share.ID).Error; err != nil {
				t.Fatal(err)
			}
			if after.Name != "" {
				t.Fatalf("rejected legacy config updated DB row: %+v", after)
			}
		})
	}
}

func TestLegacyAnonymousShareIsTransactionallyConvertedToPrivate(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: true, Path: sharePath}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	legacyMain, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return nil },
	}
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatalf("ReconcileSambaConfig() error = %v", err)
	}
	assertFileDataAndMode(t, mainPath+legacySambaBackupSuffix, legacyMain, 0o600)
	assertFileDataAndMode(t, sharesPath+legacySambaBackupSuffix, legacyFragment, 0o600)
	fragment, err := os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fragment, []byte("[Media]")) || !bytes.Contains(fragment, []byte("guest ok = No")) || bytes.Contains(fragment, []byte("guest ok = Yes")) {
		t.Fatalf("legacy anonymous share was not converted to a private stanza: %q", fragment)
	}
	var after model2.SharesDBModel
	if err := database.First(&after, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Anonymous || after.Name != "Media" {
		t.Fatalf("legacy row was not committed as private: %+v", after)
	}
}

func TestLegacyMigrationUsesExactStanzaMultisetAndQuarantinesUnsafeRows(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	safePath := filepath.Join(rootPath, "Media")
	unsafePath := filepath.Join(rootPath, "café")
	for _, path := range []string{safePath, unsafePath} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	database := openSambaTestDB(t)
	safe := model2.SharesDBModel{Anonymous: true, Path: safePath}
	unsafe := model2.SharesDBModel{Anonymous: true, Path: unsafePath}
	if err := database.Create(&safe).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&unsafe).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	// Reverse the DB insertion order: the old renderer did not promise query
	// order, so only an exact stanza multiset is a safe compatibility check.
	_, legacyFragment := writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{
		{ID: unsafe.ID, Path: unsafePath, Name: "café"},
		{ID: safe.ID, Path: safePath, Name: "Media"},
	})
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
	}
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatal(err)
	}
	fragment, err := os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fragment, []byte("[Media]")) || bytes.Contains(fragment, []byte("café")) || bytes.Contains(fragment, []byte("guest ok = Yes")) {
		t.Fatalf("selective private migration produced %q", fragment)
	}
	assertFileDataAndMode(t, sharesPath+legacySambaBackupSuffix, legacyFragment, 0o600)
	var safeAfter, unsafeAfter model2.SharesDBModel
	if err := database.First(&safeAfter, safe.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.First(&unsafeAfter, unsafe.ID).Error; err != nil {
		t.Fatal(err)
	}
	if safeAfter.Anonymous || safeAfter.Name != "Media" {
		t.Fatalf("safe row was not privatized: %+v", safeAfter)
	}
	if !unsafeAfter.Anonymous || unsafeAfter.Name != "" {
		t.Fatalf("unsafe evidence row was changed: %+v", unsafeAfter)
	}
	if err := shareService.ReconcileSambaConfig(); err != nil {
		t.Fatalf("second reconciliation did not converge: %v", err)
	}
	if restarts != 1 {
		t.Fatalf("restart count = %d, want 1", restarts)
	}
}

func TestLegacyMigrationWithOnlyUnsafeEvidenceDoesNotRestartRepeatedly(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	unsafePath := filepath.Join(rootPath, "café")
	if err := os.Mkdir(unsafePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	unsafe := model2.SharesDBModel{Anonymous: true, Path: unsafePath}
	if err := database.Create(&unsafe).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: unsafe.ID, Path: unsafePath, Name: "café"}})
	restarts := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restarts++; return nil },
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := shareService.ReconcileSambaConfig(); err != nil {
			t.Fatalf("reconcile %d: %v", attempt, err)
		}
	}
	if restarts != 1 {
		t.Fatalf("restart count = %d, want 1", restarts)
	}
	fragment, err := os.ReadFile(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(fragment) != sambaSharesConfigMarker {
		t.Fatalf("unsafe-only candidate = %q", fragment)
	}
	var after model2.SharesDBModel
	if err := database.First(&after, unsafe.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !after.Anonymous || after.Name != "" {
		t.Fatalf("unsafe evidence row changed: %+v", after)
	}
}

func TestLegacyMigrationResumesManagedCandidateBeforeDatabaseCommit(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: true, Path: sharePath}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	legacyState := captureSambaTestState(t, mainPath, sharesPath)
	service := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return nil },
	}
	if err := service.ensureLegacyMigrationBackups(legacyState); err != nil {
		t.Fatal(err)
	}
	managedMain, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	privateCandidate, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	if err != nil {
		t.Fatal(err)
	}
	overwriteSambaTestFile(t, mainPath, managedMain, 0o600)
	overwriteSambaTestFile(t, sharesPath, privateCandidate, 0o600)
	if err := service.ReconcileSambaConfig(); err != nil {
		t.Fatalf("resume error = %v", err)
	}
	var after model2.SharesDBModel
	if err := database.First(&after, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.Anonymous || after.Name != "Media" {
		t.Fatalf("resumed migration did not commit row: %+v", after)
	}
}

func TestLegacyMigrationRejectsForgedManagedResumeCandidate(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: true, Path: sharePath}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	configDirectory := t.TempDir()
	mainPath := filepath.Join(configDirectory, "smb.conf")
	sharesPath := filepath.Join(configDirectory, "smb.casa.conf")
	writeExactLegacySambaConfig(t, mainPath, sharesPath, []model2.SharesDBModel{{ID: share.ID, Path: sharePath, Name: "Media"}})
	legacyState := captureSambaTestState(t, mainPath, sharesPath)
	service := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainPath,
		sambaSharesConfigPath: sharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { t.Fatal("forged candidate restarted"); return nil },
	}
	if err := service.ensureLegacyMigrationBackups(legacyState); err != nil {
		t.Fatal(err)
	}
	managedMain, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	overwriteSambaTestFile(t, mainPath, managedMain, 0o600)
	forged := []byte(sambaSharesConfigMarker + "# forged\n")
	overwriteSambaTestFile(t, sharesPath, forged, 0o600)
	if err := service.ReconcileSambaConfig(); err == nil {
		t.Fatal("forged managed resume candidate was accepted")
	}
	assertFileDataAndMode(t, sharesPath, forged, 0o600)
	var after model2.SharesDBModel
	if err := database.First(&after, share.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !after.Anonymous || after.Name != "" {
		t.Fatalf("forged resume changed DB evidence: %+v", after)
	}
}

func captureSambaTestState(t *testing.T, mainPath, sharesPath string) sambaConfigState {
	t.Helper()
	main, err := readSambaConfigSnapshot(mainPath, true, "")
	if err != nil {
		t.Fatal(err)
	}
	shares, err := readSambaConfigSnapshot(sharesPath, false, "")
	if err != nil {
		t.Fatal(err)
	}
	return sambaConfigState{main: main, shares: shares}
}

func writeExactLegacySambaConfig(t *testing.T, mainPath, sharesPath string, shares []model2.SharesDBModel) ([]byte, []byte) {
	t.Helper()
	mainData, err := exactLegacySambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	var fragment strings.Builder
	for _, share := range shares {
		fragment.WriteString(legacySambaShareStanza(share.Name, share.Path))
	}
	fragmentData := []byte(fragment.String())
	if err := os.WriteFile(mainPath, mainData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mainPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharesPath, fragmentData, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sharesPath, 0o777); err != nil {
		t.Fatal(err)
	}
	return mainData, fragmentData
}

func assertFileDataAndMode(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expected) {
		t.Fatalf("%s data changed: got %q want %q", path, data, expected)
	}
	if mode != 0 {
		assertSambaMode(t, path, mode)
	}
}

func overwriteSambaTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	// os.WriteFile preserves an existing inode's mode. The migration fixtures
	// start as upstream 0644/0777 files, while a successful CAS publication is
	// always 0600, so model both content and permissions explicitly.
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertSambaMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("%s mode = %o, want %o", path, actual, expected)
	}
}

func openSambaTestRoots(t *testing.T) (*filesecurity.ManagedRoots, string) {
	t.Helper()
	rootPath := t.TempDir()
	roots, err := filesecurity.OpenManagementFileRoots([]string{rootPath})
	if err != nil {
		t.Fatalf("OpenManagementFileRoots() error = %v", err)
	}
	t.Cleanup(func() {
		if err := roots.Close(); err != nil {
			t.Errorf("ManagedRoots.Close() error = %v", err)
		}
	})
	return roots, rootPath
}

func openSambaTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "shares.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := database.AutoMigrate(&model2.SharesDBModel{}); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return database
}

func writeSambaTestMainConfig(t *testing.T, directory, sharesPath string) string {
	t.Helper()
	configPath := filepath.Join(directory, "smb.conf")
	mainConfig, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, mainConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func acceptSambaCandidate([]byte) error { return nil }

func TestCanonicalSambaSharePathCanonicalizesWithoutChangingPermissions(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}

	canonicalPath, name, err := CanonicalSambaSharePath(roots, sharePath+string(filepath.Separator))
	if err != nil {
		t.Fatalf("CanonicalSambaSharePath() error = %v", err)
	}
	if canonicalPath != sharePath || name != "Media" {
		t.Fatalf("CanonicalSambaSharePath() = (%q, %q), want (%q, %q)", canonicalPath, name, sharePath, "Media")
	}
	info, err := os.Stat(sharePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("share mode = %o, want 750", got)
	}
}

func TestCanonicalSambaSharePathRejectsConfigSyntax(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	for _, name := range []string{"global", "IPC$", "Media  Share", "Media\tShare", "bad]name", "bad\n[global]", `bad\name`, `bad"name`, "bad%U"} {
		name := name
		t.Run(name, func(t *testing.T) {
			sharePath := filepath.Join(rootPath, name)
			if err := os.Mkdir(sharePath, 0o750); err != nil {
				t.Fatal(err)
			}
			if _, _, err := CanonicalSambaSharePath(roots, sharePath); err == nil {
				t.Fatalf("CanonicalSambaSharePath(%q) unexpectedly succeeded", sharePath)
			}
		})
	}
}

func TestRenderSambaSharesConfigRevalidatesDatabaseRecords(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media Library")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}

	configData, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{{
		ID:        1,
		Anonymous: false,
		Path:      sharePath,
		Name:      "Media Library",
	}})
	if err != nil {
		t.Fatalf("renderSambaSharesConfig() error = %v", err)
	}
	configText := string(configData)
	if !strings.Contains(configText, "[Media Library]") || !strings.Contains(configText, `path = "`+sharePath+`"`) {
		t.Fatalf("rendered config missing validated share:\n%s", configText)
	}
	if strings.Contains(configText, "mask = 0777") || !strings.Contains(configText, "create mask = 0660") || !strings.Contains(configText, "directory mask = 0770") {
		t.Fatalf("rendered config has unsafe masks:\n%s", configText)
	}
	for _, required := range []string{"public = No", "read only = No", "guest ok = No", "follow symlinks = no", "wide links = no"} {
		if !strings.Contains(configText, required) {
			t.Fatalf("rendered anonymous config missing %q:\n%s", required, configText)
		}
	}
	if strings.Contains(configText, "force user") {
		t.Fatalf("rendered config still forces a privileged user:\n%s", configText)
	}

	invalidRecords := []model2.SharesDBModel{
		{ID: 2, Anonymous: false, Path: sharePath + string(filepath.Separator), Name: "Media Library"},
		{ID: 3, Anonymous: false, Path: sharePath, Name: "Other"},
	}
	for _, record := range invalidRecords {
		if _, err := renderSambaSharesConfig(roots, []model2.SharesDBModel{record}); err == nil {
			t.Fatalf("renderSambaSharesConfig(%+v) unexpectedly succeeded", record)
		}
	}
}

func TestUpdateConfigFileReturnsWriteRestartAndDatabaseErrors(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	if err := database.Create(&model2.SharesDBModel{Anonymous: false, Path: sharePath, Name: "Media"}).Error; err != nil {
		t.Fatal(err)
	}

	configDirectory := t.TempDir()
	writeFailureSharesPath := filepath.Join(t.TempDir(), "missing", "smb.casa.conf")
	mainConfigPath := writeSambaTestMainConfig(t, configDirectory, writeFailureSharesPath)
	restartCalled := false
	writeFailureService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: writeFailureSharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD: func() error {
			restartCalled = true
			return nil
		},
	}
	if err := writeFailureService.UpdateConfigFile(); err == nil {
		t.Fatal("UpdateConfigFile() unexpectedly ignored config write failure")
	}
	if restartCalled {
		t.Fatal("Samba restarted even though CAS proved no config was published")
	}

	restartFailure := errors.New("restart failed")
	restartSharesPath := filepath.Join(t.TempDir(), "smb.casa.conf")
	restartMainPath := writeSambaTestMainConfig(t, t.TempDir(), restartSharesPath)
	restartFailureService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       restartMainPath,
		sambaSharesConfigPath: restartSharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return restartFailure },
	}
	if err := restartFailureService.UpdateConfigFile(); !errors.Is(err, restartFailure) {
		t.Fatalf("UpdateConfigFile() error = %v, want wrapped restart failure", err)
	}

	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	databaseFailureService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       restartMainPath,
		sambaSharesConfigPath: restartSharesPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { t.Fatal("restart ran after database failure"); return nil },
	}
	if err := databaseFailureService.UpdateConfigFile(); err == nil {
		t.Fatal("UpdateConfigFile() unexpectedly ignored database failure")
	}
}

func TestCreateShareRollsBackDatabaseWhenRestartFails(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesConfigPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainConfigPath := writeSambaTestMainConfig(t, configDirectory, sharesConfigPath)
	restartFailure := errors.New("restart failed")
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: sharesConfigPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { return restartFailure },
	}
	if err := shareService.CreateShare(model2.SharesDBModel{Anonymous: false, Path: sharePath, Name: "Media"}); !errors.Is(err, restartFailure) {
		t.Fatalf("CreateShare() error = %v, want wrapped restart failure", err)
	}
	var count int64
	if err := database.Model(&model2.SharesDBModel{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("share row count = %d, want rollback to zero", count)
	}
}

func TestDeleteShareRestoresDatabaseAndConfigWhenRestartFails(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	share := model2.SharesDBModel{Anonymous: false, Path: sharePath, Name: "Media"}
	if err := database.Create(&share).Error; err != nil {
		t.Fatal(err)
	}
	restartFailure := errors.New("restart failed")
	restartCalls := 0
	configPath := filepath.Join(t.TempDir(), "smb.casa.conf")
	mainConfigPath := writeSambaTestMainConfig(t, t.TempDir(), configPath)
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: configPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD: func() error {
			restartCalls++
			if restartCalls == 1 {
				return restartFailure
			}
			return nil
		},
	}
	if err := shareService.DeleteShare(fmt.Sprint(share.ID)); !errors.Is(err, restartFailure) {
		t.Fatalf("DeleteShare() error = %v, want wrapped restart failure", err)
	}
	var restored model2.SharesDBModel
	if err := database.First(&restored, share.ID).Error; err != nil {
		t.Fatalf("restored database row error = %v", err)
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shares config snapshot was not restored to absent state: %v", err)
	}
}

func TestCreateSharesPublishesOnceAndCommitsBatch(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	firstPath := filepath.Join(rootPath, "Media")
	secondPath := filepath.Join(rootPath, "Backups")
	for _, path := range []string{firstPath, secondPath} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	sharesConfigPath := filepath.Join(configDirectory, "smb.casa.conf")
	mainConfigPath := writeSambaTestMainConfig(t, configDirectory, sharesConfigPath)
	restartCalls := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: sharesConfigPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD:           func() error { restartCalls++; return nil },
	}
	err := shareService.CreateShares([]model2.SharesDBModel{
		{Path: firstPath, Name: "Media"},
		{Path: secondPath, Name: "Backups"},
	})
	if err != nil {
		t.Fatalf("CreateShares() error = %v", err)
	}
	if restartCalls != 1 {
		t.Fatalf("restart calls = %d, want one", restartCalls)
	}
	var count int64
	if err := database.Model(&model2.SharesDBModel{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("share row count = %d, want 2", count)
	}
}

func TestCreateSharesRefusesCustomizedOperatorMainWithoutPublishing(t *testing.T) {
	roots, rootPath := openSambaTestRoots(t)
	sharePath := filepath.Join(rootPath, "Media")
	if err := os.Mkdir(sharePath, 0o750); err != nil {
		t.Fatal(err)
	}
	database := openSambaTestDB(t)
	configDirectory := t.TempDir()
	mainConfigPath := filepath.Join(configDirectory, "smb.conf")
	sharesConfigPath := filepath.Join(configDirectory, "smb.casa.conf")
	operatorMain := []byte("[global]\nworkgroup = OPERATOR\n")
	if err := os.WriteFile(mainConfigPath, operatorMain, 0o640); err != nil {
		t.Fatal(err)
	}
	restartCalls := 0
	shareService := &sharesStruct{
		db:                    database,
		sambaConfigPath:       mainConfigPath,
		sambaSharesConfigPath: sharesConfigPath,
		managementRoots:       func() (*filesecurity.ManagedRoots, error) { return roots, nil },
		validateCandidate:     acceptSambaCandidate,
		restartSMBD: func() error {
			restartCalls++
			return nil
		},
	}
	if err := shareService.CreateShares([]model2.SharesDBModel{{Path: sharePath, Name: "Media"}}); err == nil {
		t.Fatal("CreateShares() unexpectedly replaced a customized main config")
	}
	mainAfter, err := os.ReadFile(mainConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(mainAfter) != string(operatorMain) {
		t.Fatalf("operator main config was not restored: %q", mainAfter)
	}
	info, err := os.Stat(mainConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("restored main config mode = %o, want 640", info.Mode().Perm())
	}
	for _, path := range []string{sharesConfigPath, mainConfigPath + ".bak", mainConfigPath + legacySambaBackupSuffix} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failure left %s behind: %v", path, err)
		}
	}
	var count int64
	if err := database.Model(&model2.SharesDBModel{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 || restartCalls != 0 {
		t.Fatalf("row count=%d restart calls=%d, want 0 and 0", count, restartCalls)
	}
}
