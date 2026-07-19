package service

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const cloudMountRoot = "/mnt"

const maxCloudConfigsPerScan = 256

type StorageService interface {
	MountStorage(mountPoint, fs string) error
	RemoveStorage(mountPoint string) error
	GetStorages() (httper.MountList, error)
	CreateConfig(data map[string]string, name string, t string) error
	CheckAndMountByName(name string) error
	CheckAndMountAll() error
	GetConfigByName(name string) (map[string]string, error)
	GetConfig() (httper.RemotesResult, error)
}

type storageStruct struct {
	// rclone's config and mount endpoints are separate operations. Keep every
	// state-changing sequence serialized so a concurrent request cannot remount
	// a remote between the final unmount check and config deletion.
	mu     sync.Mutex
	rclone cloudRcloneClient
	roots  func(string) (cloudManagedRoots, error)
}

type cloudRcloneClient interface {
	GetMountList() (httper.MountList, error)
	Mount(string, string) error
	Unmount(string) error
	CreateConfig(map[string]string, string, string) error
	GetConfigByName(string) (map[string]string, error)
	GetAllConfigName() (httper.RemotesResult, error)
	DeleteConfigByName(string) error
}

type cloudManagedRoots interface {
	AcquireMutation() (func(), error)
	MkdirAll(string, fs.FileMode) error
	IsMountPoint(string) (bool, error)
	OpenDirectory(string) (*os.File, error)
}

type defaultCloudRcloneClient struct{}

func (defaultCloudRcloneClient) GetMountList() (httper.MountList, error) {
	return httper.GetMountList()
}
func (defaultCloudRcloneClient) Mount(mountPoint, filesystem string) error {
	return httper.Mount(mountPoint, filesystem)
}
func (defaultCloudRcloneClient) Unmount(mountPoint string) error {
	return httper.Unmount(mountPoint)
}
func (defaultCloudRcloneClient) CreateConfig(data map[string]string, name, storageType string) error {
	return httper.CreateConfig(data, name, storageType)
}
func (defaultCloudRcloneClient) GetConfigByName(name string) (map[string]string, error) {
	return httper.GetConfigByName(name)
}
func (defaultCloudRcloneClient) GetAllConfigName() (httper.RemotesResult, error) {
	return httper.GetAllConfigName()
}
func (defaultCloudRcloneClient) DeleteConfigByName(name string) error {
	return httper.DeleteConfigByName(name)
}

func (s *storageStruct) rcloneClient() cloudRcloneClient {
	if s.rclone != nil {
		return s.rclone
	}
	return defaultCloudRcloneClient{}
}

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
		// Older CasaOS releases derived remote names from email addresses.
		// Preserve '+' aliases and '@' while continuing to exclude separators,
		// rclone's ':' delimiter, whitespace, controls and shell syntax.
		if !isASCIIAlphaNumeric(character) && character != '-' && character != '_' && character != '.' && character != '+' && character != '@' {
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

func managementRootsForCloudMount(mountPoint string) (cloudManagedRoots, error) {
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

func (s *storageStruct) managedRootsForMount(mountPoint string) (cloudManagedRoots, error) {
	if s.roots != nil {
		return s.roots(mountPoint)
	}
	return managementRootsForCloudMount(mountPoint)
}

func managedMountState(roots cloudManagedRoots, mountPoint string) (bool, error) {
	mounted, err := roots.IsMountPoint(mountPoint)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return mounted, err
}

func acquireCloudMutation(roots cloudManagedRoots) (func(), error) {
	if roots == nil {
		return nil, errors.New("managed roots are unavailable")
	}
	release, err := roots.AcquireMutation()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(release)
	}, nil
}

func mountListContains(list httper.MountList, mountPoint, remote string) (bool, error) {
	found := false
	for _, mounted := range list.MountPoints {
		if mounted.MountPoint == mountPoint && mounted.Fs != remote {
			return false, fmt.Errorf("mount point %q belongs to unexpected rclone remote %q", mountPoint, mounted.Fs)
		}
		if mounted.Fs != remote {
			continue
		}
		if mounted.FsPath != "" {
			return false, fmt.Errorf("rclone remote %q is mounted from unexpected subpath %q", remote, mounted.FsPath)
		}
		if mounted.MountPoint != mountPoint {
			return false, fmt.Errorf("rclone remote %q is mounted at unexpected path %q", remote, mounted.MountPoint)
		}
		if found {
			return false, fmt.Errorf("rclone remote %q has duplicate mount records", remote)
		}
		found = true
	}
	return found, nil
}

func (s *storageStruct) MountStorage(mountPoint, remoteFS string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mountStorageLocked(mountPoint, remoteFS)
}

func (s *storageStruct) mountStorageLocked(mountPoint, remoteFS string) error {
	remote, err := cloudRemoteFromFS(remoteFS)
	if err != nil {
		return err
	}
	if err := validateCloudMountForRemote(mountPoint, remote); err != nil {
		return err
	}
	config, err := s.getConfigByNameLocked(remote)
	if err != nil {
		return fmt.Errorf("validate cloud config before mount: %w", err)
	}
	if config["mount_point"] != mountPoint || !isSupportedCloudStorageType(config["type"]) {
		return fmt.Errorf("cloud config %q is not a supported managed mapping", remote)
	}
	roots, err := s.managedRootsForMount(mountPoint)
	if err != nil {
		return err
	}
	if err := roots.MkdirAll(mountPoint, 0o750); err != nil {
		return fmt.Errorf("create managed cloud mount directory: %w", err)
	}
	releaseMutation, err := acquireCloudMutation(roots)
	if err != nil {
		return fmt.Errorf("acquire managed cloud mount transaction: %w", err)
	}
	defer releaseMutation()

	// Re-read every external state input after acquiring the filesystem
	// mutation lease. The empty-directory check, mount request and both
	// independent postconditions must form one namespace transaction.
	config, err = s.rcloneClient().GetConfigByName(remote)
	if err != nil {
		return fmt.Errorf("revalidate cloud config before mount: %w", err)
	}
	if config["mount_point"] != mountPoint || !isSupportedCloudStorageType(config["type"]) {
		return fmt.Errorf("cloud config %q changed before mount", remote)
	}
	listedMounts, err := s.rcloneClient().GetMountList()
	if err != nil {
		return fmt.Errorf("list rclone mounts before mount: %w", err)
	}
	listed, err := mountListContains(listedMounts, mountPoint, remote)
	if err != nil {
		return err
	}
	alreadyMounted, err := managedMountState(roots, mountPoint)
	if err != nil {
		return fmt.Errorf("inspect cloud mount directory: %w", err)
	}
	if listed != alreadyMounted {
		return fmt.Errorf("refusing inconsistent cloud mount state (rclone=%t, mount-boundary=%t)", listed, alreadyMounted)
	}
	if listed {
		return fmt.Errorf("refusing to mount over occupied mount point %q", mountPoint)
	}
	if err := requireEmptyManagedDirectory(roots, mountPoint); err != nil {
		return err
	}
	mountErr := s.rcloneClient().Mount(mountPoint, remoteFS)
	mounted, verifyErr := managedMountState(roots, mountPoint)
	refreshed, listErr := s.rcloneClient().GetMountList()
	listed = false
	if listErr == nil {
		listed, listErr = mountListContains(refreshed, mountPoint, remote)
	}
	if verifyErr == nil && listErr == nil && mounted && listed {
		// A lost RC response is ambiguous, but the independently verified final
		// state is authoritative and exactly matches the requested operation.
		return nil
	}
	if verifyErr == nil && listErr == nil && !mounted && !listed && mountErr != nil {
		return mountErr
	}
	rollbackErr := s.rcloneClient().Unmount(mountPoint)
	if verifyErr != nil {
		return errors.Join(mountErr, fmt.Errorf("verify mounted cloud storage: %w", verifyErr), listErr, rollbackErr)
	}
	if listErr != nil {
		return errors.Join(mountErr, fmt.Errorf("verify rclone mount list after mount: %w", listErr), rollbackErr)
	}
	return errors.Join(mountErr, fmt.Errorf("rclone mount did not reach a consistent state (rclone=%t, mount-boundary=%t)", listed, mounted), rollbackErr)
}

func requireEmptyManagedDirectory(roots cloudManagedRoots, mountPoint string) error {
	directory, err := roots.OpenDirectory(mountPoint)
	if err != nil {
		return fmt.Errorf("open cloud mount directory: %w", err)
	}
	_, readErr := directory.ReadDir(1)
	closeErr := directory.Close()
	if readErr == nil {
		return errors.Join(errors.New("refusing to mount over a non-empty directory"), closeErr)
	}
	if !errors.Is(readErr, io.EOF) {
		return errors.Join(fmt.Errorf("inspect cloud mount directory: %w", readErr), closeErr)
	}
	return closeErr
}

func (s *storageStruct) UnmountStorage(mountPoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unmountStorageLocked(mountPoint)
}

func (s *storageStruct) unmountStorageLocked(mountPoint string) error {
	remote, err := CloudRemoteFromMountPoint(mountPoint)
	if err != nil {
		return err
	}
	config, err := s.getConfigByNameLocked(remote)
	if err != nil {
		return fmt.Errorf("validate cloud config before unmount: %w", err)
	}
	if config["mount_point"] != mountPoint {
		return fmt.Errorf("persisted rclone mount_point for %q changed", remote)
	}
	roots, err := s.managedRootsForMount(mountPoint)
	if err != nil {
		return err
	}
	releaseMutation, err := acquireCloudMutation(roots)
	if err != nil {
		return fmt.Errorf("acquire managed cloud unmount transaction: %w", err)
	}
	defer releaseMutation()

	config, err = s.rcloneClient().GetConfigByName(remote)
	if err != nil {
		return fmt.Errorf("revalidate cloud config before unmount: %w", err)
	}
	if config["mount_point"] != mountPoint {
		return fmt.Errorf("persisted rclone mount_point for %q changed", remote)
	}
	listedMounts, err := s.rcloneClient().GetMountList()
	if err != nil {
		return fmt.Errorf("list rclone mounts before unmount: %w", err)
	}
	listed, err := mountListContains(listedMounts, mountPoint, remote)
	if err != nil {
		return err
	}
	mounted, stateErr := managedMountState(roots, mountPoint)
	if stateErr != nil && !(listed && isRecoverableStaleMountError(stateErr)) {
		return fmt.Errorf("inspect cloud mount before unmount: %w", stateErr)
	}
	if !listed && mounted {
		return fmt.Errorf("refusing inconsistent cloud unmount state (rclone=%t, mount-boundary=%t)", listed, mounted)
	}
	if listed {
		unmountErr := s.rcloneClient().Unmount(mountPoint)
		mounted, stateErr = managedMountState(roots, mountPoint)
		if stateErr != nil {
			return errors.Join(unmountErr, fmt.Errorf("verify cloud unmount: %w", stateErr))
		}
		refreshed, err := s.rcloneClient().GetMountList()
		if err != nil {
			return errors.Join(unmountErr, fmt.Errorf("verify rclone mount list after unmount: %w", err))
		}
		stillListed, err := mountListContains(refreshed, mountPoint, remote)
		if err != nil {
			return errors.Join(unmountErr, err)
		}
		if mounted || stillListed {
			return errors.Join(unmountErr, fmt.Errorf("cloud storage remained mounted after rclone unmount (rclone=%t, mount-boundary=%t)", stillListed, mounted))
		}
	}
	// Keep the mountpoint directory. Releasing this transaction and then
	// reacquiring the ManagedRoots mutation lock to remove an empty directory
	// would leave a TOCTOU window in which another file operation could replace
	// it with a new, meaningful empty directory. The retained directory does not
	// widen permissions, is revalidated before every mount, and can be safely
	// reused by a later configuration with the same name.
	return nil
}

func isRecoverableStaleMountError(err error) bool {
	return errors.Is(err, unix.ENOTCONN) || errors.Is(err, unix.ESTALE) || errors.Is(err, unix.EIO)
}

// RemoveStorage is the only route-facing removal operation. It validates the
// persisted mapping, proves that the remote has no unexpected mount, unmounts
// and rechecks it, then deletes the config without releasing the operation
// lock. The verified-unmounted mountpoint directory is deliberately retained
// to avoid deleting a concurrently replaced empty directory.
func (s *storageStruct) RemoveStorage(mountPoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	remote, err := CloudRemoteFromMountPoint(mountPoint)
	if err != nil {
		return err
	}
	config, err := s.getConfigByNameLocked(remote)
	if err != nil {
		return fmt.Errorf("validate cloud config before removal: %w", err)
	}
	if config["mount_point"] != mountPoint {
		return fmt.Errorf("persisted rclone mount_point for %q changed", remote)
	}
	unmountErr := s.unmountStorageLocked(mountPoint)
	if unmountErr != nil {
		return unmountErr
	}
	// Re-read external rclone state immediately before deletion. The in-process
	// lock prevents our own requests from changing it; this second read also
	// fails closed if another privileged actor changed the config meanwhile.
	config, err = s.getConfigByNameLocked(remote)
	if err != nil {
		return fmt.Errorf("revalidate cloud config before deletion: %w", err)
	}
	if config["mount_point"] != mountPoint {
		return fmt.Errorf("persisted rclone mount_point for %q changed", remote)
	}
	deleteErr := s.deleteConfigByNameLocked(remote)
	return deleteErr
}

func (s *storageStruct) GetStorages() (httper.MountList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getStoragesLocked()
}

func (s *storageStruct) getStoragesLocked() (httper.MountList, error) {
	list, err := s.rcloneClient().GetMountList()
	if err != nil {
		return list, err
	}
	filtered := httper.MountList{MountPoints: make([]httper.MountPoints, 0, len(list.MountPoints))}
	for _, mounted := range list.MountPoints {
		remote, err := CloudRemoteFromMountPoint(mounted.MountPoint)
		if err != nil || mounted.Fs != remote || mounted.FsPath != "" {
			continue
		}
		roots, err := s.managedRootsForMount(mounted.MountPoint)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createConfigLocked(data, name, storageType)
}

func (s *storageStruct) createConfigLocked(data map[string]string, name string, storageType string) error {
	if !isSupportedCloudStorageType(storageType) {
		return fmt.Errorf("unsupported cloud storage type %q", storageType)
	}
	mountPoint, err := CloudMountPointForRemote(name)
	if err != nil {
		return err
	}
	if configured := data["mount_point"]; configured != "" && configured != mountPoint {
		return fmt.Errorf("rclone config mount_point must be %q", mountPoint)
	}
	if _, err := s.managedRootsForMount(mountPoint); err != nil {
		return err
	}
	validated := make(map[string]string, len(data)+1)
	for key, value := range data {
		validated[key] = value
	}
	validated["mount_point"] = mountPoint
	remotes, err := s.rcloneClient().GetAllConfigName()
	if err != nil {
		return fmt.Errorf("list rclone configs before create: %w", err)
	}
	if remoteListContains(remotes, name) {
		return fmt.Errorf("rclone config %q already exists", name)
	}
	createErr := s.rcloneClient().CreateConfig(validated, name, storageType)
	if createErr == nil {
		return nil
	}
	// Reconcile an ambiguous one-shot RC failure. The name was absent before
	// the request, so an exact persisted mapping afterwards proves creation.
	remotes, listErr := s.rcloneClient().GetAllConfigName()
	if listErr != nil || !remoteListContains(remotes, name) {
		return errors.Join(createErr, listErr)
	}
	config, configErr := s.rcloneClient().GetConfigByName(name)
	if configErr == nil && config["mount_point"] == mountPoint && config["type"] == storageType {
		return nil
	}
	return errors.Join(createErr, configErr, errors.New("rclone config creation reached an unexpected state"))
}

func isSupportedCloudStorageType(storageType string) bool {
	switch storageType {
	case "drive", "dropbox", "onedrive":
		return true
	default:
		return false
	}
}

func remoteListContains(remotes httper.RemotesResult, name string) bool {
	for _, remote := range remotes.Remotes {
		if remote == name {
			return true
		}
	}
	return false
}

func (s *storageStruct) CheckAndMountByName(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkAndMountByNameLocked(name)
}

func (s *storageStruct) checkAndMountByNameLocked(name string) error {
	if _, err := CloudMountPointForRemote(name); err != nil {
		return err
	}
	currentRemote, err := s.getConfigByNameLocked(name)
	if err != nil {
		return err
	}
	mountPoint := currentRemote["mount_point"]
	storages, err := s.getStoragesLocked()
	if err != nil {
		return err
	}
	listed, err := mountListContains(storages, mountPoint, name)
	if err != nil {
		return err
	}
	if listed {
		roots, err := s.managedRootsForMount(mountPoint)
		if err != nil {
			return err
		}
		mounted, err := managedMountState(roots, mountPoint)
		if err != nil || !mounted {
			return errors.Join(errors.New("rclone lists storage without a real mount boundary"), err)
		}
		return nil
	}
	return s.mountStorageLocked(mountPoint, name+":")
}

func (s *storageStruct) CheckAndMountAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	section, err := s.rcloneClient().GetAllConfigName()
	if err != nil {
		return err
	}
	if len(section.Remotes) > maxCloudConfigsPerScan {
		return fmt.Errorf("rclone config scan exceeds %d remotes", maxCloudConfigsPerScan)
	}
	listedMounts, err := s.rcloneClient().GetMountList()
	if err != nil {
		return err
	}
	var result error
	for _, remote := range section.Remotes {
		config, configErr := s.rcloneClient().GetConfigByName(remote)
		if configErr != nil {
			logger.Error("read cloud storage config", zap.String("remote", remote), zap.Error(configErr))
			result = errors.Join(result, fmt.Errorf("read cloud remote %q: %w", remote, configErr))
			continue
		}
		// rclone's config file may contain operator-managed remotes unrelated to
		// CasaOS. Only configs explicitly carrying our mount_point participate in
		// startup mounting.
		if config["mount_point"] == "" {
			continue
		}
		mountPoint, validationErr := CloudMountPointForRemote(remote)
		if validationErr == nil && config["mount_point"] != mountPoint {
			validationErr = fmt.Errorf("persisted rclone mount_point for %q must be %q", remote, mountPoint)
		}
		if validationErr == nil {
			var listed bool
			listed, validationErr = mountListContains(listedMounts, mountPoint, remote)
			if validationErr == nil && listed {
				var roots cloudManagedRoots
				roots, validationErr = s.managedRootsForMount(mountPoint)
				if validationErr == nil {
					var mounted bool
					mounted, validationErr = managedMountState(roots, mountPoint)
					if validationErr == nil && !mounted {
						validationErr = errors.New("rclone lists storage without a real mount boundary")
					}
				}
			} else if validationErr == nil {
				validationErr = s.mountStorageLocked(mountPoint, remote+":")
				if validationErr == nil {
					listedMounts, validationErr = s.rcloneClient().GetMountList()
				}
			}
		}
		if validationErr != nil {
			logger.Error("check and mount cloud storage", zap.String("remote", remote), zap.Error(validationErr))
			result = errors.Join(result, fmt.Errorf("mount cloud remote %q: %w", remote, validationErr))
		}
	}
	return result
}

func (s *storageStruct) GetConfigByName(name string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getConfigByNameLocked(name)
}

func (s *storageStruct) getConfigByNameLocked(name string) (map[string]string, error) {
	expected, err := CloudMountPointForRemote(name)
	if err != nil {
		return nil, err
	}
	config, err := s.rcloneClient().GetConfigByName(name)
	if err != nil {
		return nil, err
	}
	if config["mount_point"] != expected {
		return nil, fmt.Errorf("persisted rclone mount_point for %q must be %q", name, expected)
	}
	if _, err := s.managedRootsForMount(expected); err != nil {
		return nil, err
	}
	return config, nil
}

func (s *storageStruct) DeleteConfigByName(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteConfigByNameLocked(name)
}

func (s *storageStruct) deleteConfigByNameLocked(name string) error {
	mountPoint, err := CloudMountPointForRemote(name)
	if err != nil {
		return err
	}
	if _, err := s.getConfigByNameLocked(name); err != nil {
		return err
	}
	listedMounts, err := s.rcloneClient().GetMountList()
	if err != nil {
		return fmt.Errorf("list rclone mounts before config deletion: %w", err)
	}
	listed, err := mountListContains(listedMounts, mountPoint, name)
	if err != nil {
		return err
	}
	roots, err := s.managedRootsForMount(mountPoint)
	if err != nil {
		return err
	}
	mounted, err := managedMountState(roots, mountPoint)
	if err != nil {
		return fmt.Errorf("inspect cloud mount before config deletion: %w", err)
	}
	if listed || mounted {
		return fmt.Errorf("refusing to delete config for mounted remote %q", name)
	}
	deleteErr := s.rcloneClient().DeleteConfigByName(name)
	if deleteErr == nil {
		return nil
	}
	// The delete endpoint is called once. If its response was lost, prove the
	// final state with the independent list endpoint instead of retrying a
	// non-idempotent operation.
	remotes, listErr := s.rcloneClient().GetAllConfigName()
	if listErr == nil && !remoteListContains(remotes, name) {
		return nil
	}
	return errors.Join(deleteErr, listErr)
}

func (s *storageStruct) GetConfig() (httper.RemotesResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	section, err := s.rcloneClient().GetAllConfigName()
	if err != nil {
		return httper.RemotesResult{}, err
	}
	if len(section.Remotes) > maxCloudConfigsPerScan {
		return httper.RemotesResult{}, fmt.Errorf("rclone config scan exceeds %d remotes", maxCloudConfigsPerScan)
	}
	managed := httper.RemotesResult{Remotes: make([]string, 0, len(section.Remotes))}
	for _, remote := range section.Remotes {
		config, err := s.rcloneClient().GetConfigByName(remote)
		if err != nil {
			return httper.RemotesResult{}, err
		}
		if config["mount_point"] == "" {
			continue
		}
		expected, err := CloudMountPointForRemote(remote)
		if err != nil {
			return httper.RemotesResult{}, err
		}
		if config["mount_point"] != expected {
			return httper.RemotesResult{}, fmt.Errorf("persisted rclone mount_point for %q must be %q", remote, expected)
		}
		managed.Remotes = append(managed.Remotes, remote)
	}
	return managed, nil
}

func NewStorageService() StorageService {
	return &storageStruct{}
}
