/*
 * @Author: LinkLeong link@icewhale.org
 * @Date: 2022-11-15 15:51:44
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-11-15 15:55:16
 * @FilePath: /CasaOS/route/init.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package route

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/encryption"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/file"
	v1 "github.com/IceWhaleTech/CasaOS/route/v1"
	"github.com/IceWhaleTech/CasaOS/service"
	serviceModel "github.com/IceWhaleTech/CasaOS/service/model"
	"go.uber.org/zap"
)

func InitFunction() {
	if err := service.MyService.Shares().ReconcileSambaConfig(); err != nil {
		logger.Error("reconcile samba config", zap.Error(err))
	}
	go InitNetworkMount()
	go InitInfo()
	//go InitZerotier()
}

func InitInfo() {
	mb := model.BaseInfo{}
	if file.Exists(config.AppInfo.DBPath + "/baseinfo.conf") {
		err := json.Unmarshal(file.ReadFullFile(config.AppInfo.DBPath+"/baseinfo.conf"), &mb)
		if err != nil {
			logger.Error("baseinfo.conf", zap.String("error", err.Error()))
		}
	}
	if file.Exists("/etc/CHANNEL") {
		channel := file.ReadFullFile("/etc/CHANNEL")
		mb.Channel = string(channel)
	}
	mac, err := service.MyService.System().GetMacAddress()
	if err != nil {
		logger.Error("GetMacAddress", zap.String("error", err.Error()))
	}
	mb.Hash = encryption.GetMD5ByStr(mac)
	mb.Version = common.VERSION
	osRelease, _ := file.ReadOSRelease()

	mb.DriveModel = osRelease["MODEL"]
	if len(mb.DriveModel) == 0 {
		mb.DriveModel = "Casa"
	}
	os.Remove(config.AppInfo.DBPath + "/baseinfo.conf")
	by, err := json.Marshal(mb)
	if err != nil {
		logger.Error("init info err", zap.Any("err", err))
		return
	}
	if err := file.WriteToFullPath(by, config.AppInfo.DBPath+"/baseinfo.conf", 0o600); err != nil {
		logger.Error("write baseinfo.conf", zap.Error(err))
	}
}

func InitNetworkMount() {
	time.Sleep(time.Second * 10)
	managementRoots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		logger.Error("management file roots unavailable", zap.Error(err))
		return
	}
	func() {
		releaseLifecycle := service.AcquireSambaConnectionLifecycle()
		defer releaseLifecycle()

		connections, err := service.MyService.Connections().GetConnectionsList()
		if err != nil {
			logger.Error("load samba connections", zap.Error(err))
			return
		}
		currentBootID, err := service.CurrentBootID()
		if err != nil {
			logger.Error("load Linux boot ID", zap.Error(err))
			return
		}
		for _, v := range connections {
			connection, err := service.MyService.Connections().GetConnectionByID(fmt.Sprint(v.ID))
			if err != nil {
				logger.Error("load samba connection", zap.Error(err), zap.Uint("connection_id", v.ID))
				continue
			}
			if err := restoreSambaConnectionMounts(managementRoots, &connection, currentBootID); err != nil {
				logger.Error("restore samba connection", zap.Error(err), zap.Uint("connection_id", connection.ID))
			}
		}
	}()
	err = service.MyService.Storage().CheckAndMountAll()
	if err != nil {
		logger.Error("mount storage err", zap.Any("err", err))
	}
}

type sambaRestoreMount struct {
	path      string
	host      string
	directory string
	mountID   uint64
}

func restoreSambaConnectionMounts(managementRoots *filesecurity.ManagedRoots, connection *serviceModel.ConnectionsDBModel, currentBootID string) error {
	const maxConnectionShares = 64
	directories, persistedDirectories, normalizedPort, legacy, err := service.ParsePersistedSambaConnection(connection.Directories, connection.Port, connection.BootID, connection.MountIDs, maxConnectionShares)
	if err != nil {
		return err
	}
	connection.Port = normalizedPort
	if err := service.ValidateSambaConnectionFields(connection.Username, connection.Password, connection.Host, connection.Port); err != nil {
		return err
	}
	persistedMountIDs := map[string]uint64{}
	if !legacy {
		persistedMountIDs, err = service.ParseSambaMountIDs(connection.MountIDs, maxConnectionShares)
		if err != nil {
			return err
		}
	}
	baseLocation, err := managementRoots.Match(filepath.Join("/mnt", connection.Host))
	if err != nil {
		return err
	}
	baseHostPath := baseLocation.Canonical
	if connection.MountPoint != baseHostPath {
		return errors.New("persisted Samba mount point mismatch")
	}
	if legacy {
		if len(directories) == 0 {
			return errors.New("legacy Samba connection has no mountable shares; delete it after confirming no old mounts remain")
		}
		if err := prepareLegacySambaConnectionMigration(managementRoots, baseHostPath, persistedDirectories); err != nil {
			return err
		}
	}
	_, err = ensureSambaRestoreDirectory(managementRoots, baseHostPath)
	if err != nil {
		return err
	}
	plans := make([]sambaRestoreMount, 0, len(directories))
	for _, directory := range directories {
		location, err := managementRoots.MatchChild(baseHostPath, directory)
		if err != nil {
			return err
		}
		_, err = ensureSambaRestoreDirectory(managementRoots, location.Canonical)
		if err != nil {
			return err
		}
		plans = append(plans, sambaRestoreMount{path: location.Canonical, host: connection.Host, directory: directory})
	}

	releaseMutation, err := managementRoots.AcquireMutation()
	if err != nil {
		return err
	}
	defer releaseMutation()
	newMounts := make([]sambaRestoreMount, 0, len(plans))
	fail := func(cause error) error {
		_, rollbackErr := rollbackRestoredSambaMounts(managementRoots, newMounts)
		releaseMutation()
		return errors.Join(cause, rollbackErr)
	}
	if legacy {
		if _, err := v1.PreflightLegacySambaMountBoundaries(managementRoots, baseHostPath, persistedDirectories); err != nil {
			return fail(err)
		}
	}
	if err := v1.ValidateSambaBaseMountDirectory(managementRoots, baseHostPath, directories); err != nil {
		return fail(err)
	}
	if baseMounted, err := managementRoots.IsMountPoint(baseHostPath); err != nil || baseMounted {
		if err == nil {
			err = errors.New("unexpected Samba base mount boundary")
		}
		return fail(err)
	}

	updatedMountIDs := make(map[string]uint64, len(plans))
	for _, plan := range plans {
		expectedMountID := persistedMountIDs[plan.directory]
		if connection.BootID == currentBootID && expectedMountID != 0 {
			matches, err := service.MyService.Connections().ValidateSambaMount(plan.path, connection.Host, plan.directory, expectedMountID)
			if err != nil {
				return fail(err)
			}
			if matches {
				mountedDirectory, err := managementRoots.OpenDirectory(plan.path)
				if err != nil {
					return fail(err)
				}
				descriptorMountID, mountIDErr := managementRoots.MountID(mountedDirectory)
				closeErr := mountedDirectory.Close()
				if mountIDErr != nil || descriptorMountID != expectedMountID || closeErr != nil {
					if mountIDErr == nil && descriptorMountID != expectedMountID {
						mountIDErr = fmt.Errorf("descriptor mount ID %d does not match persisted mount ID %d", descriptorMountID, expectedMountID)
					}
					return fail(errors.Join(mountIDErr, closeErr))
				}
				updatedMountIDs[plan.directory] = expectedMountID
				continue
			}
		} else {
			_, mounted, err := service.MyService.Connections().InspectSambaMount(plan.path, connection.Host, plan.directory)
			if err != nil {
				return fail(err)
			}
			if mounted {
				return fail(errors.New("refusing to adopt an unowned Samba mount after reboot"))
			}
		}

		mountDirectory, err := v1.OpenEmptySambaMountDirectory(managementRoots, plan.path)
		if err != nil {
			return fail(err)
		}
		if err := service.MyService.Connections().MountSmaba(connection.Username, connection.Host, plan.directory, connection.Port, mountDirectory, connection.Password); err != nil {
			return fail(errors.Join(err, mountDirectory.Close()))
		}
		newMounts = append(newMounts, sambaRestoreMount{path: plan.path, host: connection.Host, directory: plan.directory})
		identity, mounted, inspectErr := service.MyService.Connections().InspectSambaMount(plan.path, connection.Host, plan.directory)
		if inspectErr == nil && mounted {
			newMounts[len(newMounts)-1].mountID = identity.MountID
		}
		var descriptorErr error
		if inspectErr == nil && mounted {
			mountedView, openErr := managementRoots.OpenDirectory(plan.path)
			if openErr != nil {
				descriptorErr = openErr
			} else {
				descriptorMountID, mountIDErr := managementRoots.MountID(mountedView)
				if mountIDErr == nil && descriptorMountID != identity.MountID {
					mountIDErr = fmt.Errorf("mounted descriptor ID %d does not match mountinfo ID %d", descriptorMountID, identity.MountID)
				}
				descriptorErr = errors.Join(mountIDErr, mountedView.Close())
			}
		}
		closeErr := mountDirectory.Close()
		if inspectErr != nil || !mounted || descriptorErr != nil || closeErr != nil {
			if inspectErr == nil && !mounted {
				inspectErr = errors.New("mounted Samba identity did not appear")
			}
			return fail(errors.Join(inspectErr, descriptorErr, closeErr))
		}
		updatedMountIDs[plan.directory] = identity.MountID
	}
	encodedMountIDs, err := service.EncodeSambaMountIDs(updatedMountIDs, maxConnectionShares)
	if err != nil {
		return fail(err)
	}
	connection.BootID = currentBootID
	connection.MountIDs = encodedMountIDs
	connection.Directories = strings.Join(directories, ",")
	if err := service.MyService.Connections().UpdateConnectionMountState(
		connection.ID,
		connection.Port,
		connection.Directories,
		connection.BootID,
		connection.MountIDs,
	); err != nil {
		return fail(err)
	}
	releaseMutation()
	return nil
}

func prepareLegacySambaConnectionMigration(managementRoots *filesecurity.ManagedRoots, baseHostPath string, persistedDirectories []string) error {
	releaseMutation, err := managementRoots.AcquireMutation()
	if err != nil {
		return err
	}
	legacyPaths, err := v1.PreflightLegacySambaMountBoundaries(managementRoots, baseHostPath, persistedDirectories)
	if err != nil {
		releaseMutation()
		return err
	}
	for index, directory := range persistedDirectories {
		if !strings.HasSuffix(directory, "$") {
			continue
		}
		path := legacyPaths[index]
		opened, openErr := v1.OpenEmptySambaMountDirectory(managementRoots, path)
		if errors.Is(openErr, fs.ErrNotExist) {
			continue
		}
		if openErr != nil {
			releaseMutation()
			return fmt.Errorf("legacy administrative share directory requires administrator cleanup: %w", openErr)
		}
		if closeErr := opened.Close(); closeErr != nil {
			releaseMutation()
			return closeErr
		}
	}
	releaseMutation()
	return nil
}

func ensureSambaRestoreDirectory(managementRoots *filesecurity.ManagedRoots, path string) (bool, error) {
	directory, err := managementRoots.OpenDirectory(path)
	if err == nil {
		return false, directory.Close()
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err := managementRoots.MkdirAll(path, 0o750); err != nil {
		return false, err
	}
	return true, nil
}

func rollbackRestoredSambaMounts(managementRoots *filesecurity.ManagedRoots, mounted []sambaRestoreMount) (map[string]struct{}, error) {
	protected := make(map[string]struct{}, len(mounted))
	var result error
	for index := len(mounted) - 1; index >= 0; index-- {
		candidate := mounted[index]
		if candidate.mountID == 0 {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, errors.New("refusing to rollback a Samba mount without a captured mount ID"))
			continue
		}
		parentDirectory, err := managementRoots.OpenDirectory(filepath.Dir(candidate.path))
		if err != nil {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, err)
			continue
		}
		mountDirectory, err := managementRoots.OpenDirectory(candidate.path)
		if err != nil {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		descriptorMountID, err := managementRoots.MountID(mountDirectory)
		if err != nil || descriptorMountID != candidate.mountID {
			protected[candidate.path] = struct{}{}
			if err == nil {
				err = fmt.Errorf("descriptor mount ID %d does not match captured mount ID %d", descriptorMountID, candidate.mountID)
			}
			result = errors.Join(result, err, mountDirectory.Close(), parentDirectory.Close())
			continue
		}
		matches, err := service.MyService.Connections().ValidateSambaMount(candidate.path, candidate.host, candidate.directory, candidate.mountID)
		if err != nil || !matches {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, errors.New("cannot validate restored Samba mount ownership"), err, mountDirectory.Close(), parentDirectory.Close())
			continue
		}
		if err := mountDirectory.Close(); err != nil {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		matches, err = service.MyService.Connections().ValidateSambaMount(candidate.path, candidate.host, candidate.directory, candidate.mountID)
		if err != nil || !matches {
			protected[candidate.path] = struct{}{}
			if err == nil {
				err = errors.New("restored Samba mount identity changed before rollback")
			}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		if err := service.MyService.Connections().UnmountSmaba(parentDirectory, filepath.Base(candidate.path)); err != nil {
			protected[candidate.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		stillMounted, verifyErr := service.MyService.Connections().ValidateSambaMount(candidate.path, candidate.host, candidate.directory, candidate.mountID)
		if verifyErr != nil || stillMounted {
			protected[candidate.path] = struct{}{}
			if verifyErr == nil {
				verifyErr = errors.New("restored Samba mount remained after rollback")
			}
		}
		result = errors.Join(result, verifyErr, parentDirectory.Close())
	}
	return protected, result
}
func InitZerotier() {
	v1.CheckNetwork()
}
