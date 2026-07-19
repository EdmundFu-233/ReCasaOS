package service

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
)

// This fixture is the byte-for-byte static main template emitted by the last
// upstream CasaOS implementation. The source raw string had no final newline.
//
//go:embed testdata/casaos_smb_conf_v1.conf
var legacyCasaOSMainFixture []byte

const legacySambaBackupSuffix = ".recasaos-legacy.bak"

func exactLegacySambaMainConfig(sharesPath string) ([]byte, error) {
	if !filepath.IsAbs(sharesPath) || strings.ContainsAny(sharesPath, "\r\n\"%") {
		return nil, errors.New("unsafe legacy Samba shares path")
	}
	fixture := bytes.TrimSuffix(legacyCasaOSMainFixture, []byte("\n"))
	const legacyInclude = "/etc/samba/smb.casa.conf"
	if bytes.Count(fixture, []byte(legacyInclude)) != 1 {
		return nil, errors.New("invalid embedded CasaOS Samba fixture")
	}
	return bytes.Replace(fixture, []byte(legacyInclude), []byte(sharesPath), 1), nil
}

func isExactLegacySambaMainConfig(data []byte, sharesPath string) (bool, error) {
	expected, err := exactLegacySambaMainConfig(sharesPath)
	if err != nil {
		return false, err
	}
	return bytes.Equal(data, expected), nil
}

func validateLegacySambaSharesConfig(shares []model2.SharesDBModel, data []byte) error {
	if len(shares) > maxManagedSambaShares {
		return fmt.Errorf("legacy Samba share count exceeds %d", maxManagedSambaShares)
	}
	if len(data) > maxSambaConfigBytes {
		return fmt.Errorf("legacy Samba fragment exceeds %d bytes", maxSambaConfigBytes)
	}
	stanzaCounts := make(map[string]int, len(shares))
	expectedLength := 0
	for _, share := range shares {
		if share.Path == "" || len(share.Path) > 4096 || !utf8.ValidString(share.Path) {
			return fmt.Errorf("validate legacy Samba share %d: invalid persisted path", share.ID)
		}
		stanza := legacySambaShareStanza(filepath.Base(share.Path), share.Path)
		stanzaCounts[stanza]++
		expectedLength += len(stanza)
	}
	if len(data) != expectedLength {
		return errors.New("legacy Samba fragment does not byte-match database paths")
	}
	// Upstream did not declare an ORDER BY when rendering. Consume an exact
	// multiset of complete generated stanzas so harmless query-order drift does
	// not leave the old guest/force-root config active. Duplicate stanza counts
	// are preserved, and every byte must belong to one raw DB row.
	for offset := 0; offset < len(data); {
		matched := ""
		for stanza, remaining := range stanzaCounts {
			if remaining == 0 || !bytes.HasPrefix(data[offset:], []byte(stanza)) {
				continue
			}
			if matched != "" && matched != stanza {
				return errors.New("legacy Samba fragment has an ambiguous stanza boundary")
			}
			matched = stanza
		}
		if matched == "" {
			return errors.New("legacy Samba fragment contains an unknown or modified stanza")
		}
		stanzaCounts[matched]--
		offset += len(matched)
	}
	for _, remaining := range stanzaCounts {
		if remaining != 0 {
			return errors.New("legacy Samba fragment is missing a database stanza")
		}
	}
	return nil
}

type legacySambaMigrationPlan struct {
	safeShares       []model2.SharesDBModel
	databaseMutation bool
}

func planLegacySambaSharesMigration(managementRoots *filesecurity.ManagedRoots, shares []model2.SharesDBModel) (legacySambaMigrationPlan, error) {
	type candidate struct {
		index int
		path  string
		name  string
		key   string
	}
	candidates := make([]candidate, 0, len(shares))
	pathCounts := make(map[string]int, len(shares))
	nameCounts := make(map[string]int, len(shares))
	for index, share := range shares {
		canonicalPath, canonicalName, err := CanonicalSambaSharePath(managementRoots, share.Path)
		if err != nil || canonicalPath != share.Path {
			continue // Retain the DB row as quarantined evidence; never render it.
		}
		nameKey, err := sambaShareNameKey(canonicalName)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{index: index, path: canonicalPath, name: canonicalName, key: nameKey})
		pathCounts[canonicalPath]++
		nameCounts[nameKey]++
	}
	plan := legacySambaMigrationPlan{safeShares: make([]model2.SharesDBModel, 0, len(candidates))}
	for _, candidate := range candidates {
		if pathCounts[candidate.path] != 1 || nameCounts[candidate.key] != 1 {
			continue
		}
		share := shares[candidate.index]
		share.Path = candidate.path
		share.Name = candidate.name
		if shares[candidate.index].Name != candidate.name || shares[candidate.index].Anonymous {
			plan.databaseMutation = true
		}
		share.Anonymous = false
		plan.safeShares = append(plan.safeShares, share)
	}
	return plan, nil
}

func applyLegacySambaSharesMigration(database *gorm.DB, plan legacySambaMigrationPlan) error {
	for _, share := range plan.safeShares {
		if err := database.Model(&model2.SharesDBModel{}).Where("id = ?", share.ID).Updates(map[string]any{"name": share.Name, "anonymous": false}).Error; err != nil {
			return fmt.Errorf("secure legacy Samba share %d: %w", share.ID, err)
		}
	}
	return nil
}

func legacySambaShareStanza(name, path string) string {
	return "\n[" + name + `]
comment = CasaOS share ` + name + `
public = Yes
path = ` + path + `
browseable = Yes
read only = No
guest ok = Yes
create mask = 0777
directory mask = 0777
force user = root

`
}

func (s *sharesStruct) migrateLegacySambaConfigLocked(state sambaConfigState, mainAlreadyManaged bool) error {
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	transaction := s.db.Begin()
	if transaction.Error != nil {
		return fmt.Errorf("begin legacy Samba migration transaction: %w", transaction.Error)
	}
	shares, err := loadSambaShares(transaction)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	legacyShares := state.shares
	currentSharesManaged := state.shares.exists && bytes.HasPrefix(state.shares.data, []byte(sambaSharesConfigMarker))
	if currentSharesManaged {
		legacyShares, err = readSambaConfigSnapshot(state.shares.path+legacySambaBackupSuffix, false, "")
		if err != nil {
			return errors.Join(fmt.Errorf("read legacy Samba fragment backup: %w", err), transaction.Rollback().Error)
		}
	}
	if !legacyShares.exists {
		if len(shares) != 0 {
			return errors.Join(errors.New("legacy Samba fragment is missing while database shares remain"), transaction.Rollback().Error)
		}
	} else if err := validateLegacySambaSharesConfig(shares, legacyShares.data); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	plan, err := planLegacySambaSharesMigration(managementRoots, shares)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	if err := applyLegacySambaSharesMigration(transaction, plan); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	candidate, err := renderSambaSharesConfig(managementRoots, plan.safeShares)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	validator := s.validateCandidate
	if validator == nil {
		validator = validateSambaCandidateWithTestparm
	}
	if err := validator(candidate); err != nil {
		return errors.Join(fmt.Errorf("validate migrated Samba candidate: %w", err), transaction.Rollback().Error)
	}
	if err := verifySambaConfigState(state); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}

	if mainAlreadyManaged {
		if err := s.verifyLegacyMigrationBackups(state, legacyShares); err != nil {
			return errors.Join(err, transaction.Rollback().Error)
		}
	} else if err := s.ensureLegacyMigrationBackups(state); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}

	mutation := sambaConfigMutation{}
	if !mainAlreadyManaged {
		mainConfig, err := renderSambaMainConfig(state.shares.path)
		if err != nil {
			return errors.Join(err, transaction.Rollback().Error)
		}
		mutation.mainWritten, err = s.writeTrackedSambaConfig(state.main, mainConfig, 0o600)
		if err != nil {
			return errors.Join(fmt.Errorf("publish migrated Samba main config: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
		}
	}
	if currentSharesManaged {
		if state.shares.permission != 0o600 || !bytes.Equal(state.shares.data, candidate) {
			return errors.Join(errors.New("managed Samba fragment does not match the resumable legacy migration candidate"), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
		}
	} else {
		mutation.sharesWritten, err = s.writeTrackedSambaConfig(state.shares, candidate, 0o600)
		if err != nil {
			return errors.Join(fmt.Errorf("publish migrated Samba shares config: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
		}
	}
	if err := s.restartSamba(); err != nil {
		return errors.Join(fmt.Errorf("restart migrated Samba config: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
	}
	commit := s.commitLegacyMigration
	if commit == nil {
		commit = func(transaction *gorm.DB) error { return transaction.Commit().Error }
	}
	if err := commit(transaction); err != nil {
		return errors.Join(fmt.Errorf("commit legacy Samba migration: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
	}
	return nil
}

func (s *sharesStruct) ensureLegacyMigrationBackups(state sambaConfigState) error {
	_, _, err := ensureSambaConfigBackup(state.main, state.main.path+legacySambaBackupSuffix)
	if err != nil {
		return fmt.Errorf("back up legacy Samba main config: %w", err)
	}
	if !state.shares.exists {
		return nil
	}
	_, _, sharesErr := ensureSambaConfigBackup(state.shares, state.shares.path+legacySambaBackupSuffix)
	if sharesErr == nil {
		return nil
	}
	return fmt.Errorf("back up legacy Samba shares config: %w", sharesErr)
}

func (s *sharesStruct) verifyLegacyMigrationBackups(state sambaConfigState, legacyShares sambaConfigSnapshot) error {
	legacyMain, err := exactLegacySambaMainConfig(state.shares.path)
	if err != nil {
		return err
	}
	mainBackup, err := readSambaConfigSnapshot(state.main.path+legacySambaBackupSuffix, true, "")
	if err != nil || mainBackup.permission != 0o600 || !bytes.Equal(mainBackup.data, legacyMain) {
		return errors.Join(errors.New("managed main with legacy fragment lacks a valid ReCasaOS migration backup"), err)
	}
	if legacyShares.exists {
		sharesBackup, err := readSambaConfigSnapshot(state.shares.path+legacySambaBackupSuffix, true, "")
		if err != nil || sharesBackup.permission != 0o600 || sharesBackup.digest != legacyShares.digest {
			return errors.Join(errors.New("legacy Samba fragment lacks a valid ReCasaOS migration backup"), err)
		}
	} else if _, err := os.Lstat(state.shares.path + legacySambaBackupSuffix); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("unexpected legacy Samba fragment backup exists"), err)
	}
	return nil
}

type legacySambaReconcileState uint8

const (
	legacySambaNotPresent legacySambaReconcileState = iota
	legacySambaResume
	legacySambaCompleted
)

// inspectLegacySambaReconcileState recognizes both the narrow
// post-publication/pre-commit crash state and a completed selective migration.
// Backup mismatches fall through to normal managed reconciliation, which still
// validates every current database row.
func (s *sharesStruct) inspectLegacySambaReconcileState(state sambaConfigState, managementRoots *filesecurity.ManagedRoots) (legacySambaReconcileState, error) {
	mainBackup, err := readSambaConfigSnapshot(state.main.path+legacySambaBackupSuffix, false, "")
	if err != nil || !mainBackup.exists {
		return legacySambaNotPresent, err
	}
	legacyMain, err := exactLegacySambaMainConfig(state.shares.path)
	if err != nil || mainBackup.permission != 0o600 || !bytes.Equal(mainBackup.data, legacyMain) {
		return legacySambaNotPresent, err
	}
	shares, err := loadSambaShares(s.db)
	if err != nil {
		return legacySambaNotPresent, err
	}
	sharesBackup, err := readSambaConfigSnapshot(state.shares.path+legacySambaBackupSuffix, false, "")
	if err != nil {
		return legacySambaNotPresent, err
	}
	if !sharesBackup.exists {
		if len(shares) != 0 {
			return legacySambaNotPresent, nil
		}
	} else if sharesBackup.permission != 0o600 || validateLegacySambaSharesConfig(shares, sharesBackup.data) != nil {
		return legacySambaNotPresent, nil
	}
	plan, err := planLegacySambaSharesMigration(managementRoots, shares)
	if err != nil {
		return legacySambaNotPresent, err
	}
	candidate, err := renderSambaSharesConfig(managementRoots, plan.safeShares)
	if err != nil {
		return legacySambaNotPresent, err
	}
	if !state.shares.exists {
		return legacySambaResume, nil
	}
	if state.shares.permission != 0o600 || !bytes.Equal(state.shares.data, candidate) {
		return legacySambaNotPresent, errors.New("managed Samba fragment does not match the exact legacy migration candidate")
	}
	if plan.databaseMutation {
		return legacySambaResume, nil
	}
	return legacySambaCompleted, nil
}
