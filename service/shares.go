/*
 * @Author: LinkLeong link@icewhale.org
 * @Date: 2022-07-26 11:21:14
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-08-18 11:16:25
 * @FilePath: /CasaOS/service/shares.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/service/model"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
)

type SharesService interface {
	GetSharesList() (shares []model2.SharesDBModel)
	GetSharesByPath(path string) (shares []model2.SharesDBModel)
	GetSharesByName(name string) (shares []model2.SharesDBModel)
	CreateShare(share model2.SharesDBModel) error
	CreateShares(shares []model2.SharesDBModel) error
	DeleteShare(id string) error
	SetShareUsername(id string, username string) error
	UpdateConfigFile() error
	InitSambaConfig() error
	ReconcileSambaConfig() error
}

type sharesStruct struct {
	mu                    sync.Mutex
	db                    *gorm.DB
	sambaConfigPath       string
	sambaSharesConfigPath string
	sambaLockPath         string
	managementRoots       func() (*filesecurity.ManagedRoots, error)
	validateCandidate     func([]byte) error
	restartSMBD           func() error
	// setShareOwner hands a share directory to its account (or to root);
	// tests replace it, the default is setShareDirectoryOwner.
	setShareOwner         func(roots *filesecurity.ManagedRoots, path, username string) (func() error, error)
	beforeConfigPublish   func(string)
	beforeConfigCleanup   func(string)
	commitLegacyMigration func(*gorm.DB) error
	// externalMainConfig: the host owns smb.conf and includes the shares
	// fragment. The main config is then never read, written, verified or
	// backed up here; only the fragment is managed.
	externalMainConfig bool
}

const (
	defaultSambaConfigPath       = "/etc/samba/smb.conf"
	defaultSambaSharesConfigPath = "/etc/samba/smb.casa.conf"
	defaultSambaLockPath         = "/run/lock/recasaos-samba.lock"
	sambaMainConfigMarker        = "# ReCasaOS managed Samba main config v2\n"
	// v1: same template with `map to guest = bad user`; upgraded in place.
	previousSambaMainConfigMarker = "# ReCasaOS managed Samba main config v1\n"
	// SambaMainConfigExternal is the [server] SambaMainConfig value for a
	// main config owned by the host (see model.ServerModel).
	SambaMainConfigExternal = "external"
	sambaSharesConfigMarker = "# ReCasaOS managed Samba shares v1\n"
	maxSambaConfigBytes     = 4 << 20
	maxManagedSambaShares   = 256
)

func IsManagedSambaMainConfigLine(line string) bool {
	return line == strings.TrimSuffix(sambaMainConfigMarker, "\n") ||
		line == strings.TrimSuffix(previousSambaMainConfigMarker, "\n")
}

func (s *sharesStruct) GetSharesByName(name string) (shares []model2.SharesDBModel) {
	s.db.Select("anonymous,path,name,id").Where("LOWER(name) = LOWER(?)", name).Find(&shares)

	return
}

func (s *sharesStruct) GetSharesByPath(path string) (shares []model2.SharesDBModel) {
	s.db.Select("anonymous,path,id").Where("path = ?", path).Find(&shares)
	return
}

func (s *sharesStruct) GetSharesList() (shares []model2.SharesDBModel) {
	s.db.Select("anonymous,path,name,username,id").Find(&shares)
	return
}

func (s *sharesStruct) CreateShare(share model2.SharesDBModel) error {
	return s.CreateShares([]model2.SharesDBModel{share})
}

func (s *sharesStruct) managementFileRoots() (*filesecurity.ManagedRoots, error) {
	rootsProvider := s.managementRoots
	if rootsProvider == nil {
		rootsProvider = filesecurity.ManagementFileRoots
	}
	managementRoots, err := rootsProvider()
	if err != nil {
		return nil, fmt.Errorf("load managed roots: %w", err)
	}
	return managementRoots, nil
}

type sambaConfigSnapshot struct {
	path       string
	exists     bool
	data       []byte
	permission fs.FileMode
	identity   fs.FileInfo
	digest     [sha256.Size]byte
}

type sambaConfigState struct {
	main   sambaConfigSnapshot
	shares sambaConfigSnapshot
	// mainExternal: main is not tracked (externalMainConfig).
	mainExternal bool
}

type sambaConfigMutation struct {
	backupCreated bool
	backupWritten *sambaConfigSnapshot
	mainWritten   *sambaConfigSnapshot
	sharesWritten *sambaConfigSnapshot
}

var errSambaConfigConflict = errors.New("Samba config changed concurrently")

func (s *sharesStruct) CreateShares(shares []model2.SharesDBModel) error {
	if len(shares) == 0 {
		return errors.New("no Samba shares requested")
	}
	for _, share := range shares {
		if share.Anonymous {
			return errors.New("anonymous Samba shares are disabled because mandatory SMB signing is required; use the tokenized public-files portal")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()

	state, err := s.captureConfigStateLocked()
	if err != nil {
		return err
	}
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	for _, share := range shares {
		canonicalPath, canonicalName, validateErr := CanonicalSambaSharePath(managementRoots, share.Path)
		if validateErr != nil {
			return fmt.Errorf("validate share before create: %w", validateErr)
		}
		if canonicalPath != share.Path || canonicalName != share.Name {
			return errors.New("validate share before create: path/name is not canonical")
		}
	}

	transaction := s.db.Begin()
	if transaction.Error != nil {
		return fmt.Errorf("begin share transaction: %w", transaction.Error)
	}
	var existingShareCount int64
	if err := transaction.Model(&model2.SharesDBModel{}).Count(&existingShareCount).Error; err != nil {
		return errors.Join(fmt.Errorf("count existing Samba shares: %w", err), transaction.Rollback().Error)
	}
	if existingShareCount+int64(len(shares)) > maxManagedSambaShares {
		return errors.Join(fmt.Errorf("Samba share count exceeds %d", maxManagedSambaShares), transaction.Rollback().Error)
	}
	if err := transaction.Create(&shares).Error; err != nil {
		return errors.Join(fmt.Errorf("create shares: %w", err), transaction.Rollback().Error)
	}
	restoreOwners, err := s.applyShareOwners(managementRoots, shares, false)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	candidate, err := s.renderConfigFromDB(transaction, managementRoots)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, restoreOwners())
	}
	mutation, err := s.publishCandidateLocked(candidate, state)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwners())
	}
	if err := transaction.Commit().Error; err != nil {
		return errors.Join(fmt.Errorf("commit share transaction: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwners())
	}
	return nil
}

// SetShareUsername restricts a share to one share account, or lifts the
// restriction with an empty username, and republishes the config in the same
// transaction as the row: either both change or neither.
func (s *sharesStruct) SetShareUsername(id string, username string) error {
	if username != "" {
		if err := ValidateSambaUsername(username); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()
	state, err := s.captureConfigStateLocked()
	if err != nil {
		return err
	}
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	transaction := s.db.Begin()
	if transaction.Error != nil {
		return fmt.Errorf("begin share transaction: %w", transaction.Error)
	}
	share := model2.SharesDBModel{}
	if err := transaction.Where("id = ?", id).First(&share).Error; err != nil {
		return errors.Join(fmt.Errorf("load share: %w", err), transaction.Rollback().Error)
	}
	if err := transaction.Model(&share).Update("username", username).Error; err != nil {
		return errors.Join(fmt.Errorf("update share account: %w", err), transaction.Rollback().Error)
	}
	restoreOwner, err := s.shareOwner()(managementRoots, share.Path, username)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	candidate, err := s.renderConfigFromDB(transaction, managementRoots)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, restoreOwner())
	}
	mutation, err := s.publishCandidateLocked(candidate, state)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwner())
	}
	if err := transaction.Commit().Error; err != nil {
		return errors.Join(fmt.Errorf("commit share transaction: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwner())
	}
	return nil
}

func (s *sharesStruct) shareOwner() func(*filesecurity.ManagedRoots, string, string) (func() error, error) {
	if s.setShareOwner != nil {
		return s.setShareOwner
	}
	return setShareDirectoryOwner
}

// applyShareOwners hands each share's directory to its account; the returned
// function undoes all of it.
func (s *sharesStruct) applyShareOwners(roots *filesecurity.ManagedRoots, shares []model2.SharesDBModel, release bool) (func() error, error) {
	restores := []func() error{}
	restoreAll := func() error {
		var err error
		for i := len(restores) - 1; i >= 0; i-- {
			err = errors.Join(err, restores[i]())
		}
		return err
	}
	for _, share := range shares {
		if share.Username == "" {
			continue
		}
		username := share.Username
		if release {
			username = ""
		}
		restore, err := s.shareOwner()(roots, share.Path, username)
		if err != nil {
			return nil, errors.Join(err, restoreAll())
		}
		restores = append(restores, restore)
	}
	return restoreAll, nil
}

func (s *sharesStruct) DeleteShare(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()
	state, err := s.captureConfigStateLocked()
	if err != nil {
		return err
	}
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	transaction := s.db.Begin()
	if transaction.Error != nil {
		return fmt.Errorf("begin share transaction: %w", transaction.Error)
	}
	share := model.SharesDBModel{}
	if err := transaction.Where("id = ?", id).First(&share).Error; err != nil {
		return errors.Join(fmt.Errorf("load share before delete: %w", err), transaction.Rollback().Error)
	}
	if err := transaction.Delete(&share).Error; err != nil {
		return errors.Join(fmt.Errorf("delete share: %w", err), transaction.Rollback().Error)
	}
	// a share account must not keep the folder after its share is gone
	restoreOwners, err := s.applyShareOwners(managementRoots, []model.SharesDBModel{share}, true)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	candidate, err := s.renderConfigFromDB(transaction, managementRoots)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, restoreOwners())
	}
	mutation, err := s.publishCandidateLocked(candidate, state)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwners())
	}
	if err := transaction.Commit().Error; err != nil {
		return errors.Join(fmt.Errorf("commit share transaction: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation), restoreOwners())
	}
	return nil
}

func (s *sharesStruct) UpdateConfigFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()
	state, err := s.captureConfigStateLocked()
	if err != nil {
		return err
	}
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	candidate, err := s.renderConfigFromDB(s.db, managementRoots)
	if err != nil {
		return err
	}
	mutation, err := s.publishCandidateLocked(candidate, state)
	if err != nil {
		return errors.Join(err, s.restoreConfigStateLocked(state, mutation))
	}
	return nil
}

func (s *sharesStruct) InitSambaConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.externalMainConfig {
		mainPath, sharesPath := s.configPaths()
		return checkExternalSambaMainIncludes(mainPath, sharesPath)
	}
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()
	state, err := s.captureConfigStateLocked()
	if err != nil {
		return err
	}
	if !state.shares.exists {
		return errors.New("refusing to initialize Samba main config without a managed shares config")
	}
	validator := s.validateCandidate
	if validator == nil {
		validator = validateSambaCandidateWithTestparm
	}
	if err := validator(state.shares.data); err != nil {
		return fmt.Errorf("validate existing Samba shares config: %w", err)
	}
	if err := verifySambaConfigState(state); err != nil {
		return err
	}
	mutation, err := s.initSambaConfigLocked(state.main)
	if err != nil {
		return errors.Join(err, s.restoreConfigStateLocked(state, mutation))
	}
	if mutation.mainWritten != nil {
		if err := s.restartSamba(); err != nil {
			return errors.Join(err, s.restoreConfigStateLocked(state, mutation))
		}
	}
	return nil
}

// ReconcileSambaConfig treats committed database rows as the source of truth
// after a crash between config publication and database commit. It only
// operates on an already fully managed main/fragment pair.
func (s *sharesStruct) ReconcileSambaConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	releaseConfigLock, err := s.acquireConfigProcessLock()
	if err != nil {
		return err
	}
	defer releaseConfigLock()

	state, err := s.captureRawConfigStateLocked()
	if err != nil {
		return err
	}
	if s.externalMainConfig {
		// No legacy migration: that converts a main config this service
		// owned. Only the fragment is reconciled, and only into an existing
		// managed one or a new file.
		if err := checkExternalSambaMainIncludes(state.main.path, state.shares.path); err != nil {
			return err
		}
		if state.shares.exists && !bytes.HasPrefix(state.shares.data, []byte(sambaSharesConfigMarker)) {
			return fmt.Errorf("refusing to overwrite unmanaged Samba config %s", state.shares.path)
		}
	} else {
		before := state
		upgraded, err := s.upgradePreviousSambaMainConfigLocked(state.main)
		if err != nil {
			return errors.Join(err, s.restoreConfigStateLocked(before, sambaConfigMutation{mainWritten: upgraded}))
		}
		if upgraded != nil {
			state.main = *upgraded
			if err := s.restartSamba(); err != nil {
				return errors.Join(err, s.restoreConfigStateLocked(before, sambaConfigMutation{mainWritten: upgraded}))
			}
		}
		expectedMain, err := renderSambaMainConfig(state.shares.path)
		if err != nil {
			return err
		}
		managedMain := bytes.HasPrefix(state.main.data, []byte(sambaMainConfigMarker)) && bytes.Equal(state.main.data, expectedMain)
		managedShares := !state.shares.exists || bytes.HasPrefix(state.shares.data, []byte(sambaSharesConfigMarker))
		if !managedMain || !managedShares {
			legacyMain, legacyErr := isExactLegacySambaMainConfig(state.main.data, state.shares.path)
			if legacyErr != nil {
				return legacyErr
			}
			if !legacyMain && !(managedMain && state.shares.exists && !managedShares) {
				return errors.New("refusing to reconcile an unmanaged or unexpected Samba main config")
			}
			return s.migrateLegacySambaConfigLocked(state, managedMain)
		}
	}
	managementRoots, err := s.managementFileRoots()
	if err != nil {
		return err
	}
	if !s.externalMainConfig {
		legacyState, err := s.inspectLegacySambaReconcileState(state, managementRoots)
		if err != nil {
			return fmt.Errorf("inspect resumable legacy Samba migration: %w", err)
		}
		if legacyState == legacySambaResume {
			return s.migrateLegacySambaConfigLocked(state, true)
		}
		if legacyState == legacySambaCompleted {
			return nil
		}
	}
	transaction := s.db.Begin()
	if transaction.Error != nil {
		return fmt.Errorf("begin Samba reconciliation transaction: %w", transaction.Error)
	}
	shares, err := loadAndNormalizeLegacySambaShareNames(transaction, managementRoots)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	candidate, err := renderSambaSharesConfig(managementRoots, shares)
	if err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	if err := validateSambaCandidateSize(candidate); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	validator := s.validateCandidate
	if validator == nil {
		validator = validateSambaCandidateWithTestparm
	}
	if err := validator(candidate); err != nil {
		return errors.Join(fmt.Errorf("validate reconciled Samba candidate: %w", err), transaction.Rollback().Error)
	}
	if err := verifySambaConfigState(state); err != nil {
		return errors.Join(err, transaction.Rollback().Error)
	}
	mutation := sambaConfigMutation{}
	if !state.shares.exists || !bytes.Equal(candidate, state.shares.data) {
		written, err := s.writeTrackedSambaConfig(state.shares, candidate, 0o600)
		mutation.sharesWritten = written
		if err != nil {
			return errors.Join(fmt.Errorf("publish reconciled Samba config: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
		}
	}
	if err := s.restartSamba(); err != nil {
		if mutation.sharesWritten != nil {
			return errors.Join(fmt.Errorf("restart reconciled Samba config: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
		}
		return errors.Join(fmt.Errorf("restart reconciled Samba config: %w", err), transaction.Rollback().Error)
	}
	if err := transaction.Commit().Error; err != nil {
		return errors.Join(fmt.Errorf("commit Samba reconciliation: %w", err), transaction.Rollback().Error, s.restoreConfigStateLocked(state, mutation))
	}
	return nil
}

func (s *sharesStruct) renderConfigFromDB(database *gorm.DB, managementRoots *filesecurity.ManagedRoots) ([]byte, error) {
	shares, err := loadSambaShares(database)
	if err != nil {
		return nil, err
	}
	return renderSambaSharesConfig(managementRoots, shares)
}

func loadSambaShares(database *gorm.DB) ([]model2.SharesDBModel, error) {
	shares := []model2.SharesDBModel{}
	if err := database.Select("id,anonymous,path,name,username").Order("id ASC").Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("load Samba shares: %w", err)
	}
	if len(shares) > maxManagedSambaShares {
		return nil, fmt.Errorf("Samba share count exceeds %d", maxManagedSambaShares)
	}
	return shares, nil
}

func loadAndNormalizeLegacySambaShareNames(database *gorm.DB, managementRoots *filesecurity.ManagedRoots) ([]model2.SharesDBModel, error) {
	shares, err := loadSambaShares(database)
	if err != nil {
		return nil, err
	}
	seenPaths := make(map[string]struct{}, len(shares))
	seenNames := make(map[string]struct{}, len(shares))
	for index := range shares {
		share := &shares[index]
		canonicalPath, canonicalName, err := CanonicalSambaSharePath(managementRoots, share.Path)
		if err != nil {
			return nil, fmt.Errorf("normalize legacy Samba share %d: %w", share.ID, err)
		}
		if canonicalPath != share.Path || share.Name != "" && share.Name != canonicalName {
			return nil, fmt.Errorf("normalize legacy Samba share %d: database path/name is not canonical", share.ID)
		}
		nameKey, err := sambaShareNameKey(canonicalName)
		if err != nil {
			return nil, fmt.Errorf("normalize legacy Samba share %d: %w", share.ID, err)
		}
		if _, duplicate := seenPaths[canonicalPath]; duplicate {
			return nil, fmt.Errorf("normalize legacy Samba share %d: duplicate path", share.ID)
		}
		if _, duplicate := seenNames[nameKey]; duplicate {
			return nil, fmt.Errorf("normalize legacy Samba share %d: duplicate name", share.ID)
		}
		seenPaths[canonicalPath] = struct{}{}
		seenNames[nameKey] = struct{}{}
		if share.Name == "" {
			if err := database.Model(&model2.SharesDBModel{}).Where("id = ? AND name = ?", share.ID, "").Update("name", canonicalName).Error; err != nil {
				return nil, fmt.Errorf("persist normalized legacy Samba share %d: %w", share.ID, err)
			}
			share.Name = canonicalName
		}
	}
	return shares, nil
}

func (s *sharesStruct) configPaths() (string, string) {
	mainPath := s.sambaConfigPath
	if mainPath == "" {
		mainPath = defaultSambaConfigPath
	}
	sharesPath := s.sambaSharesConfigPath
	if sharesPath == "" {
		sharesPath = defaultSambaSharesConfigPath
	}
	return mainPath, sharesPath
}

func (s *sharesStruct) configProcessLockPath() string {
	if s.sambaLockPath != "" {
		return s.sambaLockPath
	}
	mainPath, _ := s.configPaths()
	if mainPath == defaultSambaConfigPath {
		return defaultSambaLockPath
	}
	return filepath.Join(filepath.Dir(mainPath), ".recasaos-samba.lock")
}

func (s *sharesStruct) acquireConfigProcessLock() (func(), error) {
	lockPath := s.configProcessLockPath()
	if !filepath.IsAbs(lockPath) {
		return nil, errors.New("Samba config lock path must be absolute")
	}
	locked, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Samba config lock: %w", err)
	}
	cleanup := func() {
		_ = syscall.Flock(int(locked.Fd()), syscall.LOCK_UN)
		_ = locked.Close()
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("inspect Samba config lock: %w", err)
	}
	openedInfo, err := locked.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("inspect opened Samba config lock: %w", err)
		}
		return nil, errors.New("Samba config lock changed while opening")
	}
	if err := validateSingleLinkRegularConfig(openedInfo); err != nil {
		cleanup()
		return nil, fmt.Errorf("validate Samba config lock: %w", err)
	}
	if err := locked.Chmod(0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("secure Samba config lock: %w", err)
	}
	if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX); err != nil {
		cleanup()
		return nil, fmt.Errorf("lock Samba config: %w", err)
	}
	currentPathInfo, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(openedInfo, currentPathInfo) {
		cleanup()
		if err != nil {
			return nil, fmt.Errorf("reinspect Samba config lock: %w", err)
		}
		return nil, errors.New("Samba config lock changed while waiting")
	}
	return cleanup, nil
}

func (s *sharesStruct) captureConfigStateLocked() (sambaConfigState, error) {
	state, err := s.captureRawConfigStateLocked()
	if err != nil {
		return sambaConfigState{}, err
	}
	if state.shares.exists && !bytes.HasPrefix(state.shares.data, []byte(sambaSharesConfigMarker)) {
		return sambaConfigState{}, fmt.Errorf("refusing to overwrite unmanaged Samba config %s", state.shares.path)
	}
	return state, nil
}

func (s *sharesStruct) captureRawConfigStateLocked() (sambaConfigState, error) {
	mainPath, sharesPath := s.configPaths()
	sharesSnapshot, err := readSambaConfigSnapshot(sharesPath, false, "")
	if err != nil {
		return sambaConfigState{}, err
	}
	if s.externalMainConfig {
		// Not read: an externally owned main config may legitimately be a
		// symlink (e.g. into a read-only store), which the tracked reader
		// refuses.
		return sambaConfigState{main: sambaConfigSnapshot{path: mainPath}, shares: sharesSnapshot, mainExternal: true}, nil
	}
	mainSnapshot, err := readSambaConfigSnapshot(mainPath, true, "")
	if err != nil {
		return sambaConfigState{}, err
	}
	return sambaConfigState{main: mainSnapshot, shares: sharesSnapshot}, nil
}

func readSambaConfigSnapshot(path string, required bool, requiredMarker string) (sambaConfigSnapshot, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return sambaConfigSnapshot{path: path}, nil
	}
	if err != nil {
		return sambaConfigSnapshot{}, fmt.Errorf("inspect Samba config %s: %w", path, err)
	}
	if err := validateSingleLinkRegularConfig(pathInfo); err != nil {
		return sambaConfigSnapshot{}, fmt.Errorf("inspect Samba config %s: %w", path, err)
	}
	opened, err := os.Open(path)
	if err != nil {
		return sambaConfigSnapshot{}, fmt.Errorf("open Samba config %s: %w", path, err)
	}
	openedInfo, statErr := opened.Stat()
	if statErr != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = opened.Close()
		if statErr != nil {
			return sambaConfigSnapshot{}, fmt.Errorf("inspect opened Samba config %s: %w", path, statErr)
		}
		return sambaConfigSnapshot{}, fmt.Errorf("Samba config %s changed while opening", path)
	}
	if err := validateSingleLinkRegularConfig(openedInfo); err != nil {
		_ = opened.Close()
		return sambaConfigSnapshot{}, fmt.Errorf("inspect opened Samba config %s: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(opened, maxSambaConfigBytes+1))
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil {
		return sambaConfigSnapshot{}, errors.Join(readErr, closeErr)
	}
	if len(data) > maxSambaConfigBytes {
		return sambaConfigSnapshot{}, fmt.Errorf("Samba config %s exceeds %d bytes", path, maxSambaConfigBytes)
	}
	if requiredMarker != "" && !bytes.HasPrefix(data, []byte(requiredMarker)) {
		return sambaConfigSnapshot{}, fmt.Errorf("refusing to overwrite unmanaged Samba config %s", path)
	}
	return sambaConfigSnapshot{
		path:       path,
		exists:     true,
		data:       data,
		permission: openedInfo.Mode().Perm(),
		identity:   openedInfo,
		digest:     sha256.Sum256(data),
	}, nil
}

func verifySambaConfigSnapshot(snapshot sambaConfigSnapshot) error {
	current, err := readSambaConfigSnapshot(snapshot.path, false, "")
	if err != nil {
		return fmt.Errorf("%w: verify %s: %v", errSambaConfigConflict, snapshot.path, err)
	}
	if current.exists != snapshot.exists {
		return fmt.Errorf("%w: existence changed for %s", errSambaConfigConflict, snapshot.path)
	}
	if !snapshot.exists {
		return nil
	}
	if !os.SameFile(snapshot.identity, current.identity) || current.permission != snapshot.permission || current.digest != snapshot.digest {
		return fmt.Errorf("%w: identity, permissions, or content changed for %s", errSambaConfigConflict, snapshot.path)
	}
	return nil
}

func verifySambaConfigState(state sambaConfigState) error {
	if state.mainExternal {
		return verifySambaConfigSnapshot(state.shares)
	}
	return errors.Join(verifySambaConfigSnapshot(state.main), verifySambaConfigSnapshot(state.shares))
}

func sambaConfigSnapshotsEqual(expected, actual sambaConfigSnapshot) bool {
	if expected.exists != actual.exists {
		return false
	}
	if !expected.exists {
		return true
	}
	return os.SameFile(expected.identity, actual.identity) && expected.permission == actual.permission && expected.digest == actual.digest
}

func (s *sharesStruct) writeTrackedSambaConfig(expected sambaConfigSnapshot, data []byte, permission fs.FileMode) (*sambaConfigSnapshot, error) {
	if s.beforeConfigPublish != nil {
		s.beforeConfigPublish(expected.path)
	}
	ownedCandidate, writeErr := publishSambaConfigCAS(expected, data, permission, s.beforeConfigCleanup)
	if !ownedCandidate.exists {
		return nil, writeErr
	}
	written, inspectErr := readSambaConfigSnapshot(expected.path, false, "")
	if inspectErr != nil {
		return nil, errors.Join(writeErr, fmt.Errorf("verify written Samba config %s: %w", expected.path, inspectErr))
	}
	if !sambaConfigSnapshotsEqual(ownedCandidate, written) || written.permission != permission.Perm() || written.digest != sha256.Sum256(data) {
		return nil, errors.Join(writeErr, fmt.Errorf("verify written Samba config %s: content or permissions mismatch", expected.path))
	}
	return &written, writeErr
}

func (s *sharesStruct) initSambaConfigLocked(snapshot sambaConfigSnapshot) (sambaConfigMutation, error) {
	if s.externalMainConfig {
		return sambaConfigMutation{}, nil
	}
	_, sharesPath := s.configPaths()
	mainConfig, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		return sambaConfigMutation{}, err
	}
	if upgraded, err := s.upgradePreviousSambaMainConfigLocked(snapshot); upgraded != nil || err != nil {
		return sambaConfigMutation{mainWritten: upgraded}, err
	}
	if bytes.HasPrefix(snapshot.data, []byte(sambaMainConfigMarker)) {
		if !bytes.Equal(snapshot.data, mainConfig) {
			return sambaConfigMutation{}, errors.New("managed Samba main config does not match the expected template")
		}
		return sambaConfigMutation{}, nil
	}
	legacyMain, err := isExactLegacySambaMainConfig(snapshot.data, sharesPath)
	if err != nil {
		return sambaConfigMutation{}, err
	}
	if !legacyMain {
		return sambaConfigMutation{}, errors.New("refusing to replace a customized or unknown Samba main config")
	}
	backupPath := snapshot.path + legacySambaBackupSuffix
	backupWritten, backupCreated, err := ensureSambaConfigBackup(snapshot, backupPath)
	if err != nil {
		return sambaConfigMutation{}, fmt.Errorf("back up Samba config: %w", err)
	}
	mutation := sambaConfigMutation{backupCreated: backupCreated}
	if backupCreated {
		mutation.backupWritten = &backupWritten
	}
	mainWritten, err := s.writeTrackedSambaConfig(snapshot, mainConfig, 0o600)
	mutation.mainWritten = mainWritten
	if err != nil {
		return mutation, fmt.Errorf("write Samba main config: %w", err)
	}
	return mutation, nil
}

func ensureSambaConfigBackup(snapshot sambaConfigSnapshot, backupPath string) (sambaConfigSnapshot, bool, error) {
	if err := copyValidatedConfigExclusive(snapshot, backupPath); err == nil {
		backup, readErr := readSambaConfigSnapshot(backupPath, true, "")
		return backup, true, readErr
	} else if !errors.Is(err, fs.ErrExist) {
		return sambaConfigSnapshot{}, false, err
	}
	existing, err := readSambaConfigSnapshot(backupPath, true, "")
	if err != nil {
		return sambaConfigSnapshot{}, false, err
	}
	if existing.permission != 0o600 || existing.digest != snapshot.digest || len(existing.data) != len(snapshot.data) {
		return sambaConfigSnapshot{}, false, errors.New("existing Samba backup does not match the current unmanaged main config")
	}
	if err := syncSambaConfigDirectory(filepath.Dir(backupPath)); err != nil {
		return sambaConfigSnapshot{}, false, fmt.Errorf("sync existing Samba backup directory: %w", err)
	}
	return existing, false, nil
}

// Anonymous shares are refused, so no login may fall back to guest: a wrong
// password is answered with "access denied" and the client asks again, instead
// of a guest session that then sees no share.
func renderSambaMainConfig(sharesPath string) ([]byte, error) {
	return renderSambaMainConfigVersion(sharesPath, sambaMainConfigMarker, "never")
}

func renderPreviousSambaMainConfig(sharesPath string) ([]byte, error) {
	return renderSambaMainConfigVersion(sharesPath, previousSambaMainConfigMarker, "bad user")
}

func renderSambaMainConfigVersion(sharesPath, marker, mapToGuest string) ([]byte, error) {
	if !filepath.IsAbs(sharesPath) || strings.ContainsAny(sharesPath, "\r\n\\\"%") {
		return nil, errors.New("unsafe Samba shares config path")
	}
	return []byte(marker + `[global]
   min protocol = SMB2
   server signing = mandatory
   ea support = yes
   map to guest = ` + mapToGuest + `
   follow symlinks = no
   wide links = no
   include = ` + sharesPath + "\n"), nil
}

// upgradePreviousSambaMainConfigLocked replaces a byte-exact v1 managed main
// config with the current template. Anything else is left alone (nil, nil).
func (s *sharesStruct) upgradePreviousSambaMainConfigLocked(main sambaConfigSnapshot) (*sambaConfigSnapshot, error) {
	_, sharesPath := s.configPaths()
	previous, err := renderPreviousSambaMainConfig(sharesPath)
	if err != nil || !bytes.Equal(main.data, previous) {
		return nil, err
	}
	current, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		return nil, err
	}
	written, err := s.writeTrackedSambaConfig(main, current, 0o600)
	if err != nil {
		return written, fmt.Errorf("upgrade Samba main config: %w", err)
	}
	return written, nil
}

func (s *sharesStruct) publishCandidateLocked(candidate []byte, state sambaConfigState) (sambaConfigMutation, error) {
	if err := validateSambaCandidateSize(candidate); err != nil {
		return sambaConfigMutation{}, err
	}
	validator := s.validateCandidate
	if validator == nil {
		validator = validateSambaCandidateWithTestparm
	}
	if err := validator(candidate); err != nil {
		return sambaConfigMutation{}, fmt.Errorf("validate Samba candidate: %w", err)
	}
	if err := verifySambaConfigState(state); err != nil {
		return sambaConfigMutation{}, err
	}
	mutation, err := s.initSambaConfigLocked(state.main)
	if err != nil {
		return mutation, err
	}
	sharesWritten, err := s.writeTrackedSambaConfig(state.shares, candidate, 0o600)
	mutation.sharesWritten = sharesWritten
	if err != nil {
		return mutation, fmt.Errorf("publish Samba shares config: %w", err)
	}
	if err := s.restartSamba(); err != nil {
		return mutation, fmt.Errorf("restart Samba: %w", err)
	}
	return mutation, nil
}

func validateSambaCandidateSize(candidate []byte) error {
	if len(candidate) > maxSambaConfigBytes {
		return fmt.Errorf("Samba candidate exceeds %d bytes", maxSambaConfigBytes)
	}
	return nil
}

func (s *sharesStruct) restoreConfigStateLocked(state sambaConfigState, mutation sambaConfigMutation) error {
	if mutation.mainWritten == nil && mutation.sharesWritten == nil && !mutation.backupCreated {
		return nil
	}
	var restoreErr error
	mainRestored, mainRestoreErr := s.restoreSambaConfigSnapshotIfOwned(state.main, mutation.mainWritten)
	sharesRestored, sharesRestoreErr := s.restoreSambaConfigSnapshotIfOwned(state.shares, mutation.sharesWritten)
	restoreErr = errors.Join(restoreErr, mainRestoreErr, sharesRestoreErr)
	if mutation.backupCreated {
		mainSafe := mainRestored
		if mutation.mainWritten == nil {
			mainSafe = verifySambaConfigSnapshot(state.main) == nil
		}
		if mainSafe && mutation.backupWritten != nil {
			if err := removeSambaConfigCAS(*mutation.backupWritten, s.beforeConfigCleanup); err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("preserving Samba backup after conflict: %w", err))
			}
		} else if !mainSafe {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("%w: preserving Samba backup because main config ownership was lost", errSambaConfigConflict))
		}
	}
	if mainRestored || sharesRestored {
		restoreErr = errors.Join(restoreErr, s.restartSamba())
	}
	return restoreErr
}

func (s *sharesStruct) restoreSambaConfigSnapshotIfOwned(original sambaConfigSnapshot, written *sambaConfigSnapshot) (bool, error) {
	if written == nil {
		return false, nil
	}
	if original.exists {
		if _, err := publishSambaConfigCAS(*written, original.data, original.permission, s.beforeConfigCleanup); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := removeSambaConfigCAS(*written, s.beforeConfigCleanup); err != nil {
		return false, err
	}
	return true, nil
}

func (s *sharesStruct) restartSamba() error {
	restart := s.restartSMBD
	if restart == nil {
		restart = restartSambaService
	}
	return restart()
}

func validateSingleLinkRegularConfig(info fs.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return errors.New("Samba config must be a regular non-symlink file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("Samba config must have exactly one hard link")
	}
	return nil
}

// CanonicalSambaSharePath validates a client-selected share directory through
// the pinned management roots and returns the only path/name pair that may be
// stored in the database or rendered into smb.conf.
func CanonicalSambaSharePath(managementRoots *filesecurity.ManagedRoots, requestedPath string) (string, string, error) {
	if managementRoots == nil {
		return "", "", errors.New("managed roots are nil")
	}
	location, err := managementRoots.Match(requestedPath)
	if err != nil {
		return "", "", fmt.Errorf("match Samba share path: %w", err)
	}
	name := filepath.Base(location.Canonical)
	if err := validateSambaShareFields(location.Canonical, name); err != nil {
		return "", "", err
	}
	directory, err := managementRoots.OpenDirectory(location.Canonical)
	if err != nil {
		return "", "", fmt.Errorf("open Samba share directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return "", "", fmt.Errorf("close Samba share directory: %w", err)
	}
	return location.Canonical, name, nil
}

func renderSambaSharesConfig(managementRoots *filesecurity.ManagedRoots, shares []model2.SharesDBModel) ([]byte, error) {
	if len(shares) > maxManagedSambaShares {
		return nil, fmt.Errorf("Samba share count exceeds %d", maxManagedSambaShares)
	}
	seenPaths := make(map[string]struct{}, len(shares))
	seenNames := make(map[string]struct{}, len(shares))
	var configBuilder strings.Builder
	configBuilder.WriteString(sambaSharesConfigMarker)
	for _, share := range shares {
		if share.Anonymous {
			return nil, fmt.Errorf("validate Samba share %d: anonymous Samba is incompatible with mandatory signing; use the tokenized public-files portal", share.ID)
		}
		canonicalPath, canonicalName, err := CanonicalSambaSharePath(managementRoots, share.Path)
		if err != nil {
			return nil, fmt.Errorf("validate Samba share %d: %w", share.ID, err)
		}
		if canonicalPath != share.Path || canonicalName != share.Name {
			return nil, fmt.Errorf("validate Samba share %d: database path/name is not canonical", share.ID)
		}
		if _, exists := seenPaths[canonicalPath]; exists {
			return nil, fmt.Errorf("validate Samba share %d: duplicate path", share.ID)
		}
		nameKey, err := sambaShareNameKey(canonicalName)
		if err != nil {
			return nil, fmt.Errorf("validate Samba share %d: %w", share.ID, err)
		}
		if _, exists := seenNames[nameKey]; exists {
			return nil, fmt.Errorf("validate Samba share %d: duplicate name", share.ID)
		}
		seenPaths[canonicalPath] = struct{}{}
		seenNames[nameKey] = struct{}{}
		// Re-validated here, not only at the API: the name is written into the
		// config. A share without an account renders exactly as before.
		account := ""
		if share.Username != "" {
			if err := ValidateSambaUsername(share.Username); err != nil {
				return nil, fmt.Errorf("validate Samba share %d: %w", share.ID, err)
			}
			// valid users and force user together: one without the other
			// either leaves the share open to every Samba account or hands
			// the files to whoever connected
			account = fmt.Sprintf("valid users = %s\nforce user = %s\n", share.Username, share.Username)
		}

		_, _ = fmt.Fprintf(&configBuilder, `
[%s]
comment = ReCasaOS managed share
public = No
path = "%s"
browseable = Yes
read only = No
guest ok = No
create mask = 0660
directory mask = 0770
follow symlinks = no
wide links = no
%s
`, canonicalName, canonicalPath, account)
	}
	candidate := []byte(configBuilder.String())
	if err := validateSambaCandidateSize(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func validateSambaShareFields(path, name string) error {
	if err := filesecurity.ValidatePathComponent(name); err != nil {
		return fmt.Errorf("invalid Samba share name: %w", err)
	}
	if filepath.Base(path) != name {
		return errors.New("Samba share name does not match canonical path")
	}
	if err := validateASCIIShareName(name); err != nil {
		return err
	}
	if strings.TrimSpace(name) != name || strings.ContainsAny(name, "[]\\\"%") {
		return errors.New("Samba share name contains configuration syntax")
	}
	if strings.HasSuffix(name, "$") {
		return errors.New("hidden or administrative Samba share name")
	}
	switch strings.ToLower(name) {
	case "global", "homes", "printers", "ipc$":
		return errors.New("reserved Samba share name")
	}
	if _, err := sambaShareNameKey(name); err != nil {
		return err
	}
	if err := validateSambaConfigValue(name); err != nil {
		return fmt.Errorf("invalid Samba share name: %w", err)
	}
	if strings.ContainsAny(path, "\\\"%") {
		return errors.New("Samba share path contains configuration escape syntax")
	}
	if err := validateSambaConfigValue(path); err != nil {
		return fmt.Errorf("invalid Samba share path: %w", err)
	}
	return nil
}

func validateASCIIShareName(name string) error {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return errors.New("Samba share name has an unsafe leading or trailing character")
	}
	for index, character := range name {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if character > unicode.MaxASCII || !(alphaNumeric || index > 0 && strings.ContainsRune("._- ", character)) {
			return errors.New("Samba share name must use the unambiguous ASCII set [A-Za-z0-9._ -]")
		}
	}
	return nil
}

func sambaShareNameKey(name string) (string, error) {
	previousSpace := false
	for _, character := range name {
		if unicode.IsSpace(character) {
			if character != ' ' || previousSpace {
				return "", errors.New("Samba share name contains ambiguous whitespace")
			}
			previousSpace = true
			continue
		}
		previousSpace = false
	}
	return strings.ToLower(name), nil
}

func validateSambaConfigValue(value string) error {
	if value == "" || !utf8.ValidString(value) {
		return errors.New("empty or invalid UTF-8 value")
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return errors.New("control or line-separator character")
		}
	}
	return nil
}

func copyValidatedConfigExclusive(snapshot sambaConfigSnapshot, destination string) error {
	if err := verifySambaConfigSnapshot(snapshot); err != nil {
		return fmt.Errorf("Samba config changed before backup: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	expectedDestination := sambaConfigSnapshot{path: destination}
	owned, err := publishSambaConfigCAS(expectedDestination, snapshot.data, 0o600, nil)
	if err != nil {
		if owned.exists {
			return fmt.Errorf("Samba backup was published but is not confirmed durable: %w", err)
		}
		if _, statErr := os.Lstat(destination); statErr == nil {
			return errors.Join(fs.ErrExist, err)
		}
		return err
	}
	written, err := readSambaConfigSnapshot(destination, true, "")
	if err != nil || !sambaConfigSnapshotsEqual(owned, written) || written.digest != snapshot.digest || written.permission != 0o600 {
		return errors.Join(errors.New("Samba backup verification failed"), err)
	}
	if err := verifySambaConfigSnapshot(snapshot); err != nil {
		return fmt.Errorf("Samba source changed after publishing its complete backup: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

var syncSambaConfigDirectory = syncDirectory

type boundedCommandOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (w *boundedCommandOutput) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := w.limit - w.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = w.buffer.Write(data)
	}
	return originalLength, nil
}

func validateSambaCandidateWithTestparm(candidate []byte) error {
	validationDirectory, err := os.MkdirTemp("", "recasaos-samba-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(validationDirectory)
	sharesPath := filepath.Join(validationDirectory, "smb.casa.conf")
	mainPath := filepath.Join(validationDirectory, "smb.conf")
	if err := os.WriteFile(sharesPath, candidate, 0o600); err != nil {
		return err
	}
	mainConfig, err := renderSambaMainConfig(sharesPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(mainPath, mainConfig, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output := &boundedCommandOutput{limit: 8 << 10}
	command := exec.CommandContext(ctx, "testparm", "-s", mainPath)
	command.Stdout = io.Discard
	command.Stderr = output
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("testparm timed out")
		}
		return fmt.Errorf("testparm failed: %w: %s", err, strings.TrimSpace(output.buffer.String()))
	}
	return nil
}

func writeFileAtomic(destination string, data []byte, permission fs.FileMode) error {
	return filesecurity.ReplaceRegularFile(destination, data, permission)
}

func restartSambaService() error {
	helperPath := filepath.Join(config.AppInfo.ShellPath, "helper.sh")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output := &boundedCommandOutput{limit: 8 << 10}
	restart := exec.CommandContext(ctx, "bash", "-c", `source "$1"; RestartSMBD`, "recasaos-samba", helperPath)
	restart.Stdout = output
	restart.Stderr = output
	err := restart.Run()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("Samba restart timed out")
		}
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(output.buffer.String()))
	}
	return nil
}

func NewSharesService(db *gorm.DB) SharesService {
	external := config.ServerInfo != nil && strings.EqualFold(strings.TrimSpace(config.ServerInfo.SambaMainConfig), SambaMainConfigExternal)
	return &sharesStruct{
		externalMainConfig:    external,
		db:                    db,
		sambaConfigPath:       defaultSambaConfigPath,
		sambaSharesConfigPath: defaultSambaSharesConfigPath,
		managementRoots:       filesecurity.ManagementFileRoots,
		validateCandidate:     validateSambaCandidateWithTestparm,
		restartSMBD:           restartSambaService,
	}
}

// checkExternalSambaMainIncludes verifies, read-only, that an externally owned
// main config includes the shares fragment: otherwise every share published
// here would silently never be served. The main config is resolved like smbd
// does, symlinks included; this file is never written.
func checkExternalSambaMainIncludes(mainPath, sharesPath string) error {
	file, err := os.Open(mainPath)
	if err != nil {
		return fmt.Errorf("read external Samba main config: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSambaConfigBytes+1))
	if err != nil {
		return fmt.Errorf("read external Samba main config: %w", err)
	}
	if len(data) > maxSambaConfigBytes {
		return fmt.Errorf("external Samba main config %s exceeds %d bytes", mainPath, maxSambaConfigBytes)
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || strings.HasPrefix(key, "#") || strings.HasPrefix(key, ";") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "include") && strings.TrimSpace(value) == sharesPath {
			return nil
		}
	}
	return fmt.Errorf("external Samba main config %s does not include %s", mainPath, sharesPath)
}
