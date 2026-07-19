package service

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"golang.org/x/sys/unix"
)

type fakeCloudRoots struct {
	directory       string
	mounted         bool
	stateErr        error
	removeCalls     int
	mkdirCalls      int
	mutationMu      sync.Mutex
	mutationHeld    bool
	mutationAcquire int
	mutationRelease int
}

func (roots *fakeCloudRoots) AcquireMutation() (func(), error) {
	roots.mutationMu.Lock()
	defer roots.mutationMu.Unlock()
	if roots.mutationHeld {
		return nil, errors.New("fake managed mutation already held")
	}
	roots.mutationHeld = true
	roots.mutationAcquire++
	var once sync.Once
	return func() {
		once.Do(func() {
			roots.mutationMu.Lock()
			roots.mutationHeld = false
			roots.mutationRelease++
			roots.mutationMu.Unlock()
		})
	}, nil
}

func (roots *fakeCloudRoots) mutationIsHeld() bool {
	roots.mutationMu.Lock()
	defer roots.mutationMu.Unlock()
	return roots.mutationHeld
}

func (roots *fakeCloudRoots) MkdirAll(string, fs.FileMode) error {
	roots.mkdirCalls++
	return nil
}
func (roots *fakeCloudRoots) IsMountPoint(string) (bool, error) {
	return roots.mounted, roots.stateErr
}
func (roots *fakeCloudRoots) RemoveEmptyDirectory(string) error {
	roots.removeCalls++
	return nil
}
func (roots *fakeCloudRoots) OpenDirectory(string) (*os.File, error) {
	return os.Open(roots.directory)
}

type fakeCloudRclone struct {
	configs         map[string]map[string]string
	mounts          httper.MountList
	roots           *fakeCloudRoots
	mountErr        error
	unmountErr      error
	deleteErr       error
	mountApplies    bool
	unmountApplies  bool
	deleteApplies   bool
	mountCalls      int
	unmountCalls    int
	deleteCalls     int
	mountUnleased   bool
	unmountUnleased bool
}

type blockingCloudRclone struct {
	*fakeCloudRclone
	mu            sync.Mutex
	getCalls      int
	firstEntered  chan struct{}
	secondEntered chan struct{}
	releaseFirst  chan struct{}
}

func (client *blockingCloudRclone) GetConfigByName(name string) (map[string]string, error) {
	client.mu.Lock()
	client.getCalls++
	call := client.getCalls
	client.mu.Unlock()
	if call == 1 {
		close(client.firstEntered)
		<-client.releaseFirst
	} else if call == 2 {
		close(client.secondEntered)
	}
	return client.fakeCloudRclone.GetConfigByName(name)
}

func (client *fakeCloudRclone) GetMountList() (httper.MountList, error) {
	result := httper.MountList{MountPoints: append([]httper.MountPoints(nil), client.mounts.MountPoints...)}
	return result, nil
}
func (client *fakeCloudRclone) Mount(mountPoint, filesystem string) error {
	client.mountCalls++
	if !client.roots.mutationIsHeld() {
		client.mountUnleased = true
	}
	if client.mountApplies {
		client.mounts.MountPoints = []httper.MountPoints{{MountPoint: mountPoint, Fs: strings.TrimSuffix(filesystem, ":")}}
		client.roots.mounted = true
	}
	return client.mountErr
}
func (client *fakeCloudRclone) Unmount(string) error {
	client.unmountCalls++
	if !client.roots.mutationIsHeld() {
		client.unmountUnleased = true
	}
	if client.unmountApplies {
		client.mounts.MountPoints = nil
		client.roots.mounted = false
		client.roots.stateErr = nil
	}
	return client.unmountErr
}
func (client *fakeCloudRclone) CreateConfig(data map[string]string, name, storageType string) error {
	config := make(map[string]string, len(data)+1)
	for key, value := range data {
		config[key] = value
	}
	config["type"] = storageType
	client.configs[name] = config
	return nil
}
func (client *fakeCloudRclone) GetConfigByName(name string) (map[string]string, error) {
	config, exists := client.configs[name]
	if !exists {
		return nil, fs.ErrNotExist
	}
	result := make(map[string]string, len(config))
	for key, value := range config {
		result[key] = value
	}
	return result, nil
}
func (client *fakeCloudRclone) GetAllConfigName() (httper.RemotesResult, error) {
	result := httper.RemotesResult{Remotes: make([]string, 0, len(client.configs))}
	for name := range client.configs {
		result.Remotes = append(result.Remotes, name)
	}
	return result, nil
}
func (client *fakeCloudRclone) DeleteConfigByName(name string) error {
	client.deleteCalls++
	if client.deleteApplies {
		delete(client.configs, name)
	}
	return client.deleteErr
}

func newFakeCloudStorage(t *testing.T) (*storageStruct, *fakeCloudRclone, *fakeCloudRoots) {
	t.Helper()
	roots := &fakeCloudRoots{directory: t.TempDir()}
	client := &fakeCloudRclone{
		configs: map[string]map[string]string{
			"cloud": {"mount_point": "/mnt/cloud", "type": "drive"},
		},
		roots:         roots,
		deleteApplies: true,
	}
	storage := &storageStruct{
		rclone: client,
		roots: func(string) (cloudManagedRoots, error) {
			return roots, nil
		},
	}
	return storage, client, roots
}

func TestCloudMountPointRequiresSafeSingleComponent(t *testing.T) {
	valid := []string{"drive1", "alice_google-drive.2", "john+home@gmail.com_google_drive", "A"}
	for _, remote := range valid {
		mountPoint, err := CloudMountPointForRemote(remote)
		if err != nil {
			t.Fatalf("valid remote %q rejected: %v", remote, err)
		}
		if mountPoint != "/mnt/"+remote {
			t.Fatalf("mount point = %q", mountPoint)
		}
		roundTrip, err := CloudRemoteFromMountPoint(mountPoint)
		if err != nil || roundTrip != remote {
			t.Fatalf("round trip for %q = %q, %v", remote, roundTrip, err)
		}
	}

	invalidRemotes := []string{"", ".hidden", "../escape", "a/b", "a:b", "name with space", "é", "-leading"}
	for _, remote := range invalidRemotes {
		if _, err := CloudMountPointForRemote(remote); err == nil {
			t.Fatalf("unsafe remote %q accepted", remote)
		}
	}
	invalidPaths := []string{"/mnt", "/mnt/", "/mnt/../etc", "/mnt/a/b", "/mnt/.hidden", "/media/drive", "/mnt/drive/", "/mnt//drive"}
	for _, mountPoint := range invalidPaths {
		if _, err := CloudRemoteFromMountPoint(mountPoint); err == nil {
			t.Fatalf("unsafe mount point %q accepted", mountPoint)
		}
	}
}

func TestMountListContainsRequiresExpectedRemote(t *testing.T) {
	list := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	found, err := mountListContains(list, "/mnt/cloud", "cloud")
	if err != nil || !found {
		t.Fatalf("expected mount not found: %t, %v", found, err)
	}
	if _, err := mountListContains(list, "/mnt/cloud", "other"); err == nil {
		t.Fatal("mount owned by another remote was accepted")
	}
	found, err = mountListContains(list, "/mnt/missing", "missing")
	if err != nil || found {
		t.Fatalf("missing mount = %t, %v", found, err)
	}

	for name, invalid := range map[string]httper.MountList{
		"expected path owned by another remote": {MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "other"}}},
		"same remote at another path":           {MountPoints: []httper.MountPoints{{MountPoint: "/mnt/legacy", Fs: "cloud"}}},
		"same remote from a subdirectory":       {MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud", FsPath: "subdir"}}},
		"duplicate remote records": {MountPoints: []httper.MountPoints{
			{MountPoint: "/mnt/cloud", Fs: "cloud"},
			{MountPoint: "/mnt/cloud", Fs: "cloud"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mountListContains(invalid, "/mnt/cloud", "cloud"); err == nil {
				t.Fatal("inconsistent mount topology was accepted")
			}
		})
	}
}

func TestCloudRemoteFromFSRejectsInjectedOrUnqualifiedNames(t *testing.T) {
	if remote, err := cloudRemoteFromFS("cloud:"); err != nil || remote != "cloud" {
		t.Fatalf("valid rclone fs = %q, %v", remote, err)
	}
	for _, remoteFS := range []string{"cloud", "cloud::", "../cloud:", "a/b:", ":"} {
		if _, err := cloudRemoteFromFS(remoteFS); err == nil {
			t.Fatalf("unsafe rclone fs %q accepted", remoteFS)
		}
	}
}

func TestSupportedCloudStorageTypesAreExplicit(t *testing.T) {
	for _, storageType := range []string{"drive", "dropbox", "onedrive"} {
		if !isSupportedCloudStorageType(storageType) {
			t.Fatalf("supported cloud type %q was rejected", storageType)
		}
	}
	for _, storageType := range []string{"", "local", "sftp", "../drive", "Drive"} {
		if isSupportedCloudStorageType(storageType) {
			t.Fatalf("unsupported cloud type %q was accepted", storageType)
		}
	}
}

func TestRemoteListContainsUsesExactNames(t *testing.T) {
	remotes := httper.RemotesResult{Remotes: []string{"cloud", "cloud-backup"}}
	if !remoteListContains(remotes, "cloud") {
		t.Fatal("exact remote was not found")
	}
	if remoteListContains(remotes, "clou") || remoteListContains(remotes, "Cloud") {
		t.Fatal("non-exact remote name was accepted")
	}
}

func TestRemoveStorageRejectsPersistedPathMismatchBeforeUnmount(t *testing.T) {
	storage, client, _ := newFakeCloudStorage(t)
	client.configs["cloud"]["mount_point"] = "/mnt/legacy"

	if err := storage.RemoveStorage("/mnt/cloud"); err == nil {
		t.Fatal("RemoveStorage() accepted a mismatched persisted mount point")
	}
	if client.unmountCalls != 0 || client.deleteCalls != 0 {
		t.Fatalf("state changed after rejected config: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
}

func TestRemoveStorageRejectsSameRemoteMountedElsewhere(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mounts.MountPoints = []httper.MountPoints{{MountPoint: "/mnt/legacy", Fs: "cloud"}}
	roots.mounted = false

	if err := storage.RemoveStorage("/mnt/cloud"); err == nil {
		t.Fatal("RemoveStorage() accepted the same remote at another path")
	}
	if client.unmountCalls != 0 || client.deleteCalls != 0 {
		t.Fatalf("state changed after topology rejection: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
}

func TestRemoveStorageReconcilesAmbiguousUnmountBeforeDeletingConfig(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mounts.MountPoints = []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}
	roots.mounted = true
	client.unmountApplies = true
	client.unmountErr = errors.New("response lost after unmount")

	if err := storage.RemoveStorage("/mnt/cloud"); err != nil {
		t.Fatalf("RemoveStorage() error = %v", err)
	}
	if client.unmountCalls != 1 || client.deleteCalls != 1 {
		t.Fatalf("calls: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
	if client.unmountUnleased || roots.mutationAcquire != 1 || roots.mutationRelease != 1 {
		t.Fatalf("unmount lease: unleased=%t acquire=%d release=%d", client.unmountUnleased, roots.mutationAcquire, roots.mutationRelease)
	}
	if _, exists := client.configs["cloud"]; exists {
		t.Fatal("verified-unmounted config remains")
	}
}

func TestRemoveStoragePreservesUnmountedMountDirectory(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	if err := storage.RemoveStorage("/mnt/cloud"); err != nil {
		t.Fatalf("RemoveStorage() error = %v", err)
	}
	if client.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", client.deleteCalls)
	}
	if roots.removeCalls != 0 {
		t.Fatalf("unmounted directory cleanup calls = %d, want 0", roots.removeCalls)
	}
	if info, err := os.Stat(roots.directory); err != nil || !info.IsDir() {
		t.Fatalf("retained mount directory = (%v, %v)", info, err)
	}
}

func TestRemoveStorageReconcilesAmbiguousConfigDeletion(t *testing.T) {
	storage, client, _ := newFakeCloudStorage(t)
	client.deleteErr = errors.New("response lost after config deletion")
	client.deleteApplies = true

	if err := storage.RemoveStorage("/mnt/cloud"); err != nil {
		t.Fatalf("RemoveStorage() error = %v", err)
	}
	if client.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want exactly one", client.deleteCalls)
	}
}

func TestMountStorageReconcilesAmbiguousSuccessfulMount(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mountApplies = true
	client.mountErr = errors.New("response lost after mount")

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err != nil {
		t.Fatalf("MountStorage() error = %v", err)
	}
	if client.mountCalls != 1 {
		t.Fatalf("mount calls = %d, want exactly one", client.mountCalls)
	}
	if client.mountUnleased || roots.mutationAcquire != 1 || roots.mutationRelease != 1 {
		t.Fatalf("mount lease: unleased=%t acquire=%d release=%d", client.mountUnleased, roots.mutationAcquire, roots.mutationRelease)
	}
}

func TestMountStorageRejectsUnsupportedPersistedType(t *testing.T) {
	storage, client, _ := newFakeCloudStorage(t)
	client.configs["cloud"]["type"] = "sftp"

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err == nil {
		t.Fatal("MountStorage() accepted an unsupported persisted backend")
	}
	if client.mountCalls != 0 {
		t.Fatal("mount RC was called after rejecting the backend")
	}
}

func TestMountStorageRejectsNonEmptyDirectory(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	if err := os.WriteFile(roots.directory+string(os.PathSeparator)+"keep", []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err == nil {
		t.Fatal("MountStorage() accepted a non-empty directory")
	}
	if client.mountCalls != 0 {
		t.Fatal("mount RC was called for a non-empty directory")
	}
}

func TestRemoveStorageCanRecoverListedStaleMount(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mounts.MountPoints = []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}
	roots.stateErr = unix.ENOTCONN
	client.unmountApplies = true

	if err := storage.RemoveStorage("/mnt/cloud"); err != nil {
		t.Fatalf("RemoveStorage() stale-mount recovery error = %v", err)
	}
	if client.unmountCalls != 1 || client.deleteCalls != 1 {
		t.Fatalf("calls: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
}

func TestRemoveStorageKeepsConfigWhenStaleUnmountCannotBeVerified(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mounts.MountPoints = []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}
	roots.stateErr = unix.ESTALE
	client.unmountErr = errors.New("unmount failed")

	if err := storage.RemoveStorage("/mnt/cloud"); err == nil {
		t.Fatal("RemoveStorage() accepted an unverifiable stale unmount")
	}
	if client.unmountCalls != 1 || client.deleteCalls != 0 {
		t.Fatalf("calls: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
	if _, exists := client.configs["cloud"]; !exists {
		t.Fatal("config was deleted after stale unmount verification failed")
	}
}

func TestStorageOperationsAreSerialized(t *testing.T) {
	storage, baseClient, roots := newFakeCloudStorage(t)
	client := &blockingCloudRclone{
		fakeCloudRclone: baseClient,
		firstEntered:    make(chan struct{}),
		secondEntered:   make(chan struct{}),
		releaseFirst:    make(chan struct{}),
	}
	storage.rclone = client
	storage.roots = func(string) (cloudManagedRoots, error) { return roots, nil }

	results := make(chan error, 2)
	go func() {
		_, err := storage.GetConfigByName("cloud")
		results <- err
	}()
	select {
	case <-client.firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first storage operation did not enter fake rclone client")
	}
	go func() {
		_, err := storage.GetConfigByName("cloud")
		results <- err
	}()
	select {
	case <-client.secondEntered:
		t.Fatal("second storage operation entered before the first released the service lock")
	case <-time.After(100 * time.Millisecond):
	}
	close(client.releaseFirst)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatalf("GetConfigByName() error = %v", err)
		}
	}
}
