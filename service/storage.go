package service

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const cloudMountRoot = "/mnt"

var ErrStorageUnmountCleanup = errors.New("cloud storage unmounted but mount directory cleanup failed")

type StorageService interface {
	MountStorage(mountPoint, fs string) error
	UnmountStorage(mountPoint string) error
	GetStorages() (httper.MountList, error)
	CreateConfig(data map[string]string, name string, t string) error
	CheckAndMountByName(name string) error
	CheckAndMountAll() error
	GetConfigByName(name string) (map[string]string, error)
	DeleteConfigByName(name string) error
	GetConfig() (httper.RemotesResult, error)
}

type storageStruct struct{}

// CloudMountPointForRemote binds each rclone remote to exactly one mount path.
// The restricted ASCII alphabet is valid for both rclone remote names and a
// single ordinary filesystem component.
func CloudMountPointForRemote(remote string) (string, error) {
	if !isSafeCloudRemote(remote) {
		return "", fmt.Errorf("unsafe cloud storage remote name %q", remote)
	}
	return cloudMountRoot + "/" + remote, nil
}

// CloudRemoteFromMountPoint accepts only /mnt/<safe-single-component>.
func CloudRemoteFromMountPoint(mountPoint string) (string, error) {
	const prefix = cloudMountRoot + "/"
	if !strings.HasPrefix(mountPoint, prefix) {
		return "", fmt.Errorf("cloud mount point must be below %s", cloudMountRoot)
	}
	remote := strings.TrimPrefix(mountPoint, prefix)
	expected, err := CloudMountPointForRemote(remote)
	if err != nil || expected != mountPoint {
		return "", fmt.Errorf("cloud mount point must be %s/<safe-remote-name>", cloudMountRoot)
	}
	return remote, nil
}

func isSafeCloudRemote(remote string) bool {
	if len(remote) == 0 || len(remote) > 128 || !isASCIIAlphaNumeric(remote[0]) {
		return false
	}
	for index := 1; index < len(remote); index++ {
		character := remote[index]
		if !isASCIIAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func cloudRemoteFromFS(remoteFS string) (string, error) {
	if !strings.HasSuffix(remoteFS, ":") || strings.Count(remoteFS, ":") != 1 {
		return "", fmt.Errorf("invalid rclone filesystem %q", remoteFS)
	}
	remote := strings.TrimSuffix(remoteFS, ":")
	if !isSafeCloudRemote(remote) {
		return "", fmt.Errorf("unsafe rclone remote name %q", remote)
	}
	return remote, nil
}

func validateCloudMountForRemote(mountPoint, remote string) error {
	expected, err := CloudMountPointForRemote(remote)
	if err != nil {
		return err
	}
	if mountPoint != expected {
		return fmt.Errorf("rclone remote %q must mount at %q", remote, expected)
	}
	return nil
}

func managementRootsForCloudMount(mountPoint string) (*filesecurity.ManagedRoots, error) {
	if _, err := CloudRemoteFromMountPoint(mountPoint); err != nil {
		return nil, err
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return nil, err
	}
	if _, err := roots.Match(mountPoint); err != nil {
		return nil, fmt.Errorf("authorize cloud mount point: %w", err)
	}
	return roots, nil
}

func managedMountState(roots *filesecurity.ManagedRoots, mountPoint string) (bool, error) {
	mounted, err := roots.IsMountPoint(mountPoint)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return mounted, err
}

func mountListContains(list httper.MountList, mountPoint, remote string) (bool, error) {
	for _, mounted := range list.MountPoints {
		if mounted.MountPoint != mountPoint {
			continue
		}
		if mounted.Fs != remote {
			return false, fmt.Errorf("mount point %q belongs to unexpected rclone remote %q", mountPoint, mounted.Fs)
		}
		return true, nil
	}
	return false, nil
}

func (s *storageStruct) MountStorage(mountPoint, remoteFS string) error {
	remote, err := cloudRemoteFromFS(remoteFS)
	if err != nil {
		return err
	}
	if err := validateCloudMountForRemote(mountPoint, remote); err != nil {
		return err
	}
	roots, err := managementRootsForCloudMount(mountPoint)
	if err != nil {
		return err
	}
	if err := roots.MkdirAll(mountPoint, 0o750); err != nil {
		return fmt.Errorf("create managed cloud mount directory: %w", err)
	}
	alreadyMounted, err := managedMountState(roots, mountPoint)
	if err != nil {
		return fmt.Errorf("inspect cloud mount directory: %w", err)
	}
	if alreadyMounted {
		return fmt.Errorf("refusing to mount over occupied mount point %q", mountPoint)
	}
	if err := httper.Mount(mountPoint, remoteFS); err != nil {
		return err
	}
	mounted, verifyErr := managedMountState(roots, mountPoint)
	if verifyErr == nil && mounted {
		return nil
	}
	rollbackErr := httper.Unmount(mountPoint)
	if verifyErr != nil {
		return errors.Join(fmt.Errorf("verify mounted cloud storage: %w", verifyErr), rollbackErr)
	}
	return errors.Join(errors.New("rclone reported success without creating a mount boundary"), rollbackErr)
}

func (s *storageStruct) UnmountStorage(mountPoint string) error {
	remote, err := CloudRemoteFromMountPoint(mountPoint)
	if err != nil {
		return err
	}
	roots, err := managementRootsForCloudMount(mountPoint)
	if err != nil {
		return err
	}
	listedMounts, err := httper.GetMountList()
	if err != nil {
		return fmt.Errorf("list rclone mounts before unmount: %w", err)
	}
	listed, err := mountListContains(listedMounts, mountPoint, remote)
	if err != nil {
		return err
	}
	mounted, err := managedMountState(roots, mountPoint)
	if err != nil {
		return fmt.Errorf("inspect cloud mount before unmount: %w", err)
	}
	if listed != mounted {
		return fmt.Errorf("refusing inconsistent cloud unmount state (rclone=%t, mount-boundary=%t)", listed, mounted)
	}
	if listed {
		if err := httper.Unmount(mountPoint); err != nil {
			return err
		}
		mounted, err = managedMountState(roots, mountPoint)
		if err != nil {
			return fmt.Errorf("verify cloud unmount: %w", err)
		}
		refreshed, err := httper.GetMountList()
		if err != nil {
			return fmt.Errorf("verify rclone mount list after unmount: %w", err)
		}
		stillListed, err := mountListContains(refreshed, mountPoint, remote)
		if err != nil {
			return err
		}
		if mounted || stillListed {
			return fmt.Errorf("cloud storage remained mounted after rclone unmount (rclone=%t, mount-boundary=%t)", stillListed, mounted)
		}
	}
	if err := roots.RemoveEmptyDirectory(mountPoint); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTEMPTY) {
		return fmt.Errorf("%w: %v", ErrStorageUnmountCleanup, err)
	}
	return nil
}

func (s *storageStruct) GetStorages() (httper.MountList, error) {
	list, err := httper.GetMountList()
	if err != nil {
		return list, err
	}
	filtered := httper.MountList{MountPoints: make([]httper.MountPoints, 0, len(list.MountPoints))}
	for _, mounted := range list.MountPoints {
		remote, err := CloudRemoteFromMountPoint(mounted.MountPoint)
		if err != nil || mounted.Fs != remote {
			continue
		}
		roots, err := managementRootsForCloudMount(mounted.MountPoint)
		if err != nil {
			return httper.MountList{}, err
		}
		reallyMounted, err := managedMountState(roots, mounted.MountPoint)
		if err != nil {
			return httper.MountList{}, fmt.Errorf("verify listed cloud mount %q: %w", mounted.MountPoint, err)
		}
		if reallyMounted {
			filtered.MountPoints = append(filtered.MountPoints, mounted)
		}
	}
	return filtered, nil
}

func (s *storageStruct) CreateConfig(data map[string]string, name string, storageType string) error {
	mountPoint, err := CloudMountPointForRemote(name)
	if err != nil {
		return err
	}
	if configured := data["mount_point"]; configured != "" && configured != mountPoint {
		return fmt.Errorf("rclone config mount_point must be %q", mountPoint)
	}
	if _, err := managementRootsForCloudMount(mountPoint); err != nil {
		return err
	}
	validated := make(map[string]string, len(data)+1)
	for key, value := range data {
		validated[key] = value
	}
	validated["mount_point"] = mountPoint
	return httper.CreateConfig(validated, name, storageType)
}

func (s *storageStruct) CheckAndMountByName(name string) error {
	if _, err := CloudMountPointForRemote(name); err != nil {
		return err
	}
	currentRemote, err := s.GetConfigByName(name)
	if err != nil {
		return err
	}
	mountPoint := currentRemote["mount_point"]
	storages, err := s.GetStorages()
	if err != nil {
		return err
	}
	listed, err := mountListContains(storages, mountPoint, name)
	if err != nil {
		return err
	}
	if listed {
		roots, err := managementRootsForCloudMount(mountPoint)
		if err != nil {
			return err
		}
		mounted, err := managedMountState(roots, mountPoint)
		if err != nil || !mounted {
			return errors.Join(errors.New("rclone lists storage without a real mount boundary"), err)
		}
		return nil
	}
	return s.MountStorage(mountPoint, name+":")
}

func (s *storageStruct) CheckAndMountAll() error {
	section, err := httper.GetAllConfigName()
	if err != nil {
		return err
	}
	var result error
	for _, remote := range section.Remotes {
		if err := s.CheckAndMountByName(remote); err != nil {
			logger.Error("check and mount cloud storage", zap.String("remote", remote), zap.Error(err))
			result = errors.Join(result, fmt.Errorf("mount cloud remote %q: %w", remote, err))
		}
	}
	return result
}

func (s *storageStruct) GetConfigByName(name string) (map[string]string, error) {
	expected, err := CloudMountPointForRemote(name)
	if err != nil {
		return nil, err
	}
	config, err := httper.GetConfigByName(name)
	if err != nil {
		return nil, err
	}
	if config["mount_point"] != expected {
		return nil, fmt.Errorf("persisted rclone mount_point for %q must be %q", name, expected)
	}
	if _, err := managementRootsForCloudMount(expected); err != nil {
		return nil, err
	}
	return config, nil
}

func (s *storageStruct) DeleteConfigByName(name string) error {
	if _, err := CloudMountPointForRemote(name); err != nil {
		return err
	}
	return httper.DeleteConfigByName(name)
}

func (s *storageStruct) GetConfig() (httper.RemotesResult, error) {
	section, err := httper.GetAllConfigName()
	if err != nil {
		return httper.RemotesResult{}, err
	}
	for _, remote := range section.Remotes {
		if _, err := CloudMountPointForRemote(remote); err != nil {
			return httper.RemotesResult{}, err
		}
	}
	return section, nil
}

func NewStorageService() StorageService {
	return &storageStruct{}
}
