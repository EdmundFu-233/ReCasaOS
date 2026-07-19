/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-07-26 11:08:48
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-08-17 18:25:42
 * @FilePath: /CasaOS/route/v1/samba.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package v1

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/IceWhaleTech/CasaOS-Common/utils/systemctl"
	"github.com/labstack/echo/v4"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/samba"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/file"
	"github.com/IceWhaleTech/CasaOS/service"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
)

// service

func GetSambaStatus(ctx echo.Context) error {
	if status, err := systemctl.IsServiceRunning("smbd"); err != nil || !status {
		return ctx.JSON(http.StatusInternalServerError, model.Result{
			Success: common_err.SERVICE_NOT_RUNNING,
			Message: common_err.GetMsg(common_err.SERVICE_NOT_RUNNING),
		})
	}

	needInit := true
	if file.Exists("/etc/samba/smb.conf") {
		str := file.ReadLine(1, "/etc/samba/smb.conf")
		if service.IsManagedSambaMainConfigLine(str) {
			needInit = false
		}
	}
	data := make(map[string]string, 1)
	data["need_init"] = fmt.Sprintf("%v", needInit)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: data})
}

func GetSambaSharesList(ctx echo.Context) error {
	shares := service.MyService.Shares().GetSharesList()
	shareList := []model.Shares{}
	for _, v := range shares {
		shareList = append(shareList, model.Shares{
			Anonymous: v.Anonymous,
			Path:      v.Path,
			ID:        v.ID,
		})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: shareList})
}

func PostSambaSharesCreate(ctx echo.Context) error {
	const (
		maxSharesBodyBytes  = 64 << 10
		maxSharesPerRequest = 64
	)

	ctx.Request().Body = http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, maxSharesBodyBytes)
	shares := []model.Shares{}
	if err := ctx.Bind(&shares); err != nil || len(shares) == 0 || len(shares) > maxSharesPerRequest {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	for _, share := range shares {
		if share.Anonymous {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: "Anonymous Samba shares are disabled because mandatory SMB signing is required; use the tokenized public-files portal."})
		}
		if share.Path == "" {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
		}
	}
	managementRoots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	canonicalShares := make([]model.Shares, 0, len(shares))
	shareNames := make([]string, 0, len(shares))
	seenPaths := make(map[string]struct{}, len(shares))
	seenNames := make(map[string]struct{}, len(shares))
	for _, v := range shares {
		canonicalPath, shareName, validationErr := service.CanonicalSambaSharePath(managementRoots, v.Path)
		if validationErr != nil {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		caseFoldedName := strings.ToLower(shareName)
		if _, exists := seenPaths[canonicalPath]; exists {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_ALREADY_EXISTS)})
		}
		if _, exists := seenNames[caseFoldedName]; exists {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_NAME_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_NAME_ALREADY_EXISTS)})
		}
		if len(service.MyService.Shares().GetSharesByPath(canonicalPath)) > 0 {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_ALREADY_EXISTS)})
		}
		if len(service.MyService.Shares().GetSharesByName(shareName)) > 0 {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.SHARE_NAME_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.SHARE_NAME_ALREADY_EXISTS)})
		}
		seenPaths[canonicalPath] = struct{}{}
		seenNames[caseFoldedName] = struct{}{}
		canonicalShares = append(canonicalShares, model.Shares{Anonymous: v.Anonymous, Path: canonicalPath})
		shareNames = append(shareNames, shareName)
	}
	shareDBModels := make([]model2.SharesDBModel, 0, len(canonicalShares))
	for index, v := range canonicalShares {
		shareDBModels = append(shareDBModels, model2.SharesDBModel{
			Anonymous: v.Anonymous,
			Path:      v.Path,
			Name:      shareNames[index],
		})
	}
	if err := service.MyService.Shares().CreateShares(shareDBModels); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: canonicalShares})
}

func DeleteSambaShares(ctx echo.Context) error {
	id := ctx.Param("id")
	if id == "" {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INSUFFICIENT_PERMISSIONS, Message: common_err.GetMsg(common_err.INSUFFICIENT_PERMISSIONS)})
	}
	if err := service.MyService.Shares().DeleteShare(id); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
}

// client
func GetSambaConnectionsList(ctx echo.Context) error {
	connections, err := service.MyService.Connections().GetConnectionsList()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	connectionList := []model.Connections{}
	for _, v := range connections {
		connectionList = append(connectionList, model.Connections{
			ID:         v.ID,
			Username:   v.Username,
			Port:       v.Port,
			Host:       v.Host,
			MountPoint: v.MountPoint,
		})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: connectionList})
}

func PostSambaConnectionsCreate(ctx echo.Context) error {
	const (
		maxConnectionBodyBytes = 64 << 10
		maxConnectionShares    = 64
	)
	ctx.Request().Body = http.MaxBytesReader(ctx.Response().Writer, ctx.Request().Body, maxConnectionBodyBytes)
	connection := model.Connections{}
	if err := ctx.Bind(&connection); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if connection.Port == "" {
		connection.Port = "445"
	}
	if err := service.ValidateSambaConnectionFields(connection.Username, connection.Password, connection.Host, connection.Port); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	releaseLifecycle := service.AcquireSambaConnectionLifecycle()
	defer releaseLifecycle()
	connections, err := service.MyService.Connections().GetConnectionByHost(connection.Host)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if len(connections) > 0 {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.Record_ALREADY_EXIST, Message: common_err.GetMsg(common_err.Record_ALREADY_EXIST), Data: common_err.GetMsg(common_err.Record_ALREADY_EXIST)})
	}
	directories, err := samba.GetSambaSharesList(connection.Host, connection.Port, connection.Username, connection.Password)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	directories, err = service.FilterSambaMountableShares(directories, maxConnectionShares)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	managementRoots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}

	bootID, err := service.CurrentBootID()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	connectionDBModel := model2.ConnectionsDBModel{
		Username:    connection.Username,
		Password:    connection.Password,
		Host:        connection.Host,
		Port:        connection.Port,
		Directories: strings.Join(directories, ","),
		BootID:      bootID,
	}
	baseLocation, err := managementRoots.Match(filepath.Join("/mnt", connection.Host))
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	baseHostPath := baseLocation.Canonical
	connectionDBModel.MountPoint = baseHostPath
	connection.MountPoint = baseHostPath
	_, err = ensureSambaHostDirectory(managementRoots, baseHostPath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	baseMounted, err := managementRoots.IsMountPoint(baseHostPath)
	if err != nil || baseMounted {
		if baseMounted && err == nil {
			err = errors.New("Samba host directory is already a mount point")
		}
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	plans := make([]sambaMountPlan, 0, len(directories))
	for _, v := range directories {
		mountLocation, matchErr := managementRoots.MatchChild(baseHostPath, v)
		if matchErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: matchErr.Error()})
		}
		mountPoint := mountLocation.Canonical
		_, createErr := ensureSambaMountDirectory(managementRoots, mountPoint)
		if createErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: createErr.Error()})
		}
		plans = append(plans, sambaMountPlan{directory: v, path: mountPoint})
	}

	releaseMutation, err := managementRoots.AcquireMutation()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	defer releaseMutation()
	mounted := make([]sambaMountedPath, 0, len(plans))
	failWithRollback := func(cause error) error {
		_, rollbackErr := rollbackSambaMounts(managementRoots, service.MyService.Connections(), mounted)
		releaseMutation()
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			Data:    errors.Join(cause, rollbackErr).Error(),
		})
	}
	if err := ValidateSambaBaseMountDirectory(managementRoots, baseHostPath, directories); err != nil {
		return failWithRollback(err)
	}
	if mountedBase, err := managementRoots.IsMountPoint(baseHostPath); err != nil || mountedBase {
		if err == nil {
			err = errors.New("Samba host directory became a mount point")
		}
		return failWithRollback(err)
	}
	mountIDs := make(map[string]uint64, len(plans))
	for _, plan := range plans {
		mountDirectory, err := OpenEmptySambaMountDirectory(managementRoots, plan.path)
		if err != nil {
			return failWithRollback(err)
		}
		_, alreadyMounted, inspectErr := service.MyService.Connections().InspectSambaMount(plan.path, connection.Host, plan.directory)
		if inspectErr != nil || alreadyMounted {
			closeErr := mountDirectory.Close()
			if inspectErr == nil {
				inspectErr = errors.New("Samba mount point already has an unowned mount")
			}
			return failWithRollback(errors.Join(inspectErr, closeErr))
		}
		if err := service.MyService.Connections().MountSmaba(connectionDBModel.Username, connectionDBModel.Host, plan.directory, connectionDBModel.Port, mountDirectory, connectionDBModel.Password); err != nil {
			closeErr := mountDirectory.Close()
			return failWithRollback(errors.Join(err, closeErr))
		}
		mounted = append(mounted, sambaMountedPath{path: plan.path, host: connection.Host, directory: plan.directory})
		identity, matches, verifyErr := service.MyService.Connections().InspectSambaMount(plan.path, connection.Host, plan.directory)
		if verifyErr == nil && matches {
			mounted[len(mounted)-1].mountID = identity.MountID
		}
		var descriptorErr error
		if verifyErr == nil && matches {
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
		if verifyErr != nil || !matches || descriptorErr != nil || closeErr != nil {
			if verifyErr == nil && !matches {
				verifyErr = errors.New("mounted Samba identity did not appear")
			}
			return failWithRollback(errors.Join(verifyErr, descriptorErr, closeErr))
		}
		mountIDs[plan.directory] = identity.MountID
	}
	connectionDBModel.MountIDs, err = service.EncodeSambaMountIDs(mountIDs, maxConnectionShares)
	if err != nil {
		return failWithRollback(err)
	}
	if err := service.MyService.Connections().CreateConnection(&connectionDBModel); err != nil {
		return failWithRollback(err)
	}
	releaseMutation()

	connection.ID = connectionDBModel.ID
	connection.Password = ""
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: connection})
}

func DeleteSambaConnections(ctx echo.Context) error {
	const maxConnectionShares = 64
	id := ctx.Param("id")
	releaseLifecycle := service.AcquireSambaConnectionLifecycle()
	defer releaseLifecycle()
	connection, err := service.MyService.Connections().GetConnectionByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.Record_NOT_EXIST, Message: common_err.GetMsg(common_err.Record_NOT_EXIST)})
	}
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	directories, persistedDirectories, normalizedPort, legacy, err := service.ParsePersistedSambaConnection(connection.Directories, connection.Port, connection.BootID, connection.MountIDs, maxConnectionShares)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	connection.Port = normalizedPort
	if !legacy {
		if err := service.ValidateSambaConnectionFields(connection.Username, connection.Password, connection.Host, connection.Port); err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
	} else if err := service.ValidateLegacySambaHost(connection.Host); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	managementRoots, rootsErr := filesecurity.ManagementFileRoots()
	if rootsErr != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	baseLocation, matchErr := managementRoots.Match(filepath.Join("/mnt", connection.Host))
	if matchErr != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	baseHostPath := baseLocation.Canonical
	if connection.MountPoint != baseHostPath {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if legacy {
		releaseMutation, acquireErr := managementRoots.AcquireMutation()
		if acquireErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: acquireErr.Error()})
		}
		legacyPaths, preflightErr := PreflightLegacySambaMountBoundaries(managementRoots, baseHostPath, persistedDirectories)
		if preflightErr == nil {
			preflightErr = service.MyService.Connections().DeleteConnection(id)
		}
		releaseMutation()
		if preflightErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: preflightErr.Error()})
		}
		_ = legacyPaths // Proven inert directories are deliberately retained.
		return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
	}
	currentBootID, err := service.CurrentBootID()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	mountIDs, err := service.ParseSambaMountIDs(connection.MountIDs, maxConnectionShares)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	releaseMutation, err := managementRoots.AcquireMutation()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	defer releaseMutation()
	baseMounted, baseMountErr := managementRoots.IsMountPoint(baseHostPath)
	if baseMountErr != nil && !errors.Is(baseMountErr, fs.ErrNotExist) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: baseMountErr.Error()})
	}
	if baseMounted {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: "Samba host directory is an unexpected mount point"})
	}
	mountPoints := make([]string, 0, len(directories))
	ownedMounts := make([]sambaMountedPath, 0, len(directories))
	for _, v := range directories {
		mountLocation, err := managementRoots.MatchChild(baseHostPath, v)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		mountPoint := mountLocation.Canonical
		mountPoints = append(mountPoints, mountPoint)
		expectedMountID := mountIDs[v]
		if connection.BootID != currentBootID || expectedMountID == 0 {
			_, mounted, inspectErr := service.MyService.Connections().InspectSambaMount(mountPoint, connection.Host, v)
			if inspectErr != nil {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: inspectErr.Error()})
			}
			if mounted {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: "refusing to unmount a Samba mount not owned in this boot"})
			}
			continue
		}
		matches, verifyErr := service.MyService.Connections().ValidateSambaMount(mountPoint, connection.Host, v, expectedMountID)
		if verifyErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: verifyErr.Error()})
		}
		if matches {
			mountDirectory, openErr := managementRoots.OpenDirectory(mountPoint)
			if openErr != nil {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: openErr.Error()})
			}
			descriptorMountID, descriptorErr := managementRoots.MountID(mountDirectory)
			if descriptorErr != nil || descriptorMountID != expectedMountID {
				if descriptorErr == nil {
					descriptorErr = fmt.Errorf("descriptor mount ID %d does not match persisted mount ID %d", descriptorMountID, expectedMountID)
				}
				descriptorErr = errors.Join(descriptorErr, mountDirectory.Close())
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: descriptorErr.Error()})
			}
			if closeErr := mountDirectory.Close(); closeErr != nil {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: closeErr.Error()})
			}
			ownedMounts = append(ownedMounts, sambaMountedPath{path: mountPoint, host: connection.Host, directory: v, mountID: expectedMountID})
		}
	}
	// Preflight above proves every persisted path before any destructive step.
	for _, ownedMount := range ownedMounts {
		parentDirectory, parentOpenErr := managementRoots.OpenDirectory(filepath.Dir(ownedMount.path))
		if parentOpenErr != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: parentOpenErr.Error()})
		}
		mountDirectory, openErr := managementRoots.OpenDirectory(ownedMount.path)
		if openErr != nil {
			openErr = errors.Join(openErr, parentDirectory.Close())
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: openErr.Error()})
		}
		descriptorMountID, descriptorErr := managementRoots.MountID(mountDirectory)
		if descriptorErr != nil || descriptorMountID != ownedMount.mountID {
			if descriptorErr == nil {
				descriptorErr = fmt.Errorf("descriptor mount ID %d does not match persisted mount ID %d", descriptorMountID, ownedMount.mountID)
			}
			descriptorErr = errors.Join(descriptorErr, mountDirectory.Close(), parentDirectory.Close())
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: descriptorErr.Error()})
		}
		if closeErr := mountDirectory.Close(); closeErr != nil {
			closeErr = errors.Join(closeErr, parentDirectory.Close())
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: closeErr.Error()})
		}
		matches, verifyErr := service.MyService.Connections().ValidateSambaMount(ownedMount.path, ownedMount.host, ownedMount.directory, ownedMount.mountID)
		if verifyErr != nil || !matches {
			if verifyErr == nil {
				verifyErr = errors.New("Samba mount identity changed before unmount")
			}
			verifyErr = errors.Join(verifyErr, parentDirectory.Close())
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: verifyErr.Error()})
		}
		if err := service.MyService.Connections().UnmountSmaba(parentDirectory, filepath.Base(ownedMount.path)); err != nil {
			err = errors.Join(err, parentDirectory.Close())
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
		}
		stillMounted, verifyErr := service.MyService.Connections().ValidateSambaMount(ownedMount.path, ownedMount.host, ownedMount.directory, ownedMount.mountID)
		verifyErr = errors.Join(verifyErr, parentDirectory.Close())
		if verifyErr != nil || stillMounted {
			if verifyErr == nil {
				verifyErr = errors.New("Samba mount remained after unmount")
			}
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: verifyErr.Error()})
		}
	}
	if err := service.MyService.Connections().DeleteConnection(id); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	releaseMutation()
	_ = mountPoints // Mount directories are retained to avoid pathname deletion races.
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: id})
}

type sambaMountedPath struct {
	path      string
	host      string
	directory string
	mountID   uint64
}

type sambaMountPlan struct {
	directory string
	path      string
}

func ensureSambaMountDirectory(managementRoots *filesecurity.ManagedRoots, path string) (bool, error) {
	created := false
	directory, err := OpenEmptySambaMountDirectory(managementRoots, path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := managementRoots.MkdirAll(path, 0o750); err != nil {
			return false, err
		}
		created = true
		directory, err = OpenEmptySambaMountDirectory(managementRoots, path)
	}
	if err != nil {
		return false, err
	}
	return created, directory.Close()
}

func ensureSambaHostDirectory(managementRoots *filesecurity.ManagedRoots, path string) (bool, error) {
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

type sambaMountRollbackService interface {
	UnmountSmaba(parentDirectory *os.File, child string) error
	ValidateSambaMount(mountPoint, host, directory string, expectedMountID uint64) (bool, error)
}

type sambaMountDescriptorProvider interface {
	OpenDirectory(path string) (*os.File, error)
	MountID(opened *os.File) (uint64, error)
}

func rollbackSambaMounts(descriptors sambaMountDescriptorProvider, connections sambaMountRollbackService, mounted []sambaMountedPath) (map[string]struct{}, error) {
	var result error
	protectedPaths := make(map[string]struct{}, len(mounted))
	for index := len(mounted) - 1; index >= 0; index-- {
		mountedPath := mounted[index]
		if mountedPath.mountID == 0 {
			protectedPaths[mountedPath.path] = struct{}{}
			result = errors.Join(result, fmt.Errorf("refusing to unmount %s without a captured mount ID", mountedPath.path))
			continue
		}
		parentDirectory, err := descriptors.OpenDirectory(filepath.Dir(mountedPath.path))
		if err != nil {
			protectedPaths[mountedPath.path] = struct{}{}
			result = errors.Join(result, err)
			continue
		}
		mountDirectory, err := descriptors.OpenDirectory(mountedPath.path)
		if err != nil {
			protectedPaths[mountedPath.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		descriptorMountID, err := descriptors.MountID(mountDirectory)
		if err != nil || descriptorMountID != mountedPath.mountID {
			protectedPaths[mountedPath.path] = struct{}{}
			if err == nil {
				err = fmt.Errorf("descriptor mount ID %d does not match captured mount ID %d", descriptorMountID, mountedPath.mountID)
			}
			result = errors.Join(result, err, mountDirectory.Close(), parentDirectory.Close())
			continue
		}
		matches, err := connections.ValidateSambaMount(mountedPath.path, mountedPath.host, mountedPath.directory, mountedPath.mountID)
		if err != nil || !matches {
			protectedPaths[mountedPath.path] = struct{}{}
			if err == nil {
				err = errors.New("Samba mount identity is absent or mismatched")
			}
			result = errors.Join(result, fmt.Errorf("refusing to unmount %s during rollback: %w", mountedPath.path, err), mountDirectory.Close(), parentDirectory.Close())
			continue
		}
		if err := mountDirectory.Close(); err != nil {
			protectedPaths[mountedPath.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		matches, err = connections.ValidateSambaMount(mountedPath.path, mountedPath.host, mountedPath.directory, mountedPath.mountID)
		if err != nil || !matches {
			protectedPaths[mountedPath.path] = struct{}{}
			if err == nil {
				err = errors.New("Samba mount identity changed before rollback unmount")
			}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		if err := connections.UnmountSmaba(parentDirectory, filepath.Base(mountedPath.path)); err != nil {
			protectedPaths[mountedPath.path] = struct{}{}
			result = errors.Join(result, err, parentDirectory.Close())
			continue
		}
		stillMounted, err := connections.ValidateSambaMount(mountedPath.path, mountedPath.host, mountedPath.directory, mountedPath.mountID)
		if err != nil || stillMounted {
			protectedPaths[mountedPath.path] = struct{}{}
			if err == nil {
				err = errors.New("Samba mount remained after rollback")
			}
			result = errors.Join(result, err)
		}
		result = errors.Join(result, parentDirectory.Close())
	}
	return protectedPaths, result
}

func OpenEmptySambaMountDirectory(managementRoots *filesecurity.ManagedRoots, path string) (*os.File, error) {
	directory, err := managementRoots.OpenDirectory(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(1)
	if len(entries) != 0 || !errors.Is(readErr, io.EOF) {
		if readErr == nil && len(entries) != 0 {
			readErr = errors.New("refusing to mount over a non-empty directory")
		}
		return nil, errors.Join(readErr, directory.Close())
	}
	return directory, nil
}

func ValidateSambaBaseMountDirectory(managementRoots *filesecurity.ManagedRoots, path string, expectedChildren []string) error {
	const maxSambaBaseEntries = 128
	directory, err := managementRoots.OpenDirectory(path)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(maxSambaBaseEntries + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > maxSambaBaseEntries || len(entries) < len(expectedChildren) {
		return errors.New("Samba host directory contains unexpected entries")
	}
	expected := make(map[string]struct{}, len(expectedChildren))
	for _, child := range expectedChildren {
		expected[child] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; ok {
			if !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
				return errors.New("Samba host directory contains an unexpected entry")
			}
			delete(expected, entry.Name())
			continue
		}
		if !strings.HasSuffix(entry.Name(), "$") || service.ValidateLegacySambaDirectory(entry.Name()) != nil || !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("Samba host directory contains an unexpected entry")
		}
		location, err := managementRoots.MatchChild(path, entry.Name())
		if err != nil {
			return err
		}
		mounted, err := managementRoots.IsMountPoint(location.Canonical)
		if err != nil || mounted {
			if err == nil {
				err = errors.New("legacy Samba administrative directory is a mount point")
			}
			return err
		}
		opened, err := OpenEmptySambaMountDirectory(managementRoots, location.Canonical)
		if err != nil {
			return err
		}
		if err := opened.Close(); err != nil {
			return err
		}
	}
	if len(expected) != 0 {
		return errors.New("Samba host directory is missing an expected entry")
	}
	return nil
}

// PreflightLegacySambaMountBoundaries is deliberately mount-type agnostic. A
// legacy row has no boot/mount identity, so no existing boundary can be safely
// adopted or unmounted even when it looks like the expected CIFS source.
func PreflightLegacySambaMountBoundaries(managementRoots *filesecurity.ManagedRoots, baseHostPath string, directories []string) ([]string, error) {
	baseMounted, err := managementRoots.IsMountPoint(baseHostPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if baseMounted {
		return nil, errors.New("legacy Samba mount boundary detected; reboot or perform administrator cleanup before retrying")
	}
	paths := make([]string, 0, len(directories))
	for _, directory := range directories {
		location, err := managementRoots.MatchChild(baseHostPath, directory)
		if err != nil {
			return nil, err
		}
		paths = append(paths, location.Canonical)
		mounted, err := managementRoots.IsMountPoint(location.Canonical)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if mounted {
			return nil, errors.New("legacy Samba mount boundary detected; reboot or perform administrator cleanup before retrying")
		}
	}
	return paths, nil
}
