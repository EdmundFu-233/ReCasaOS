package service

import (
	"context"
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
	stateSequence   []fakeCloudMountState
	stateCalls      int
}

type fakeCloudMountState struct {
	mounted bool
	err     error
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
	if len(roots.stateSequence) != 0 {
		index := roots.stateCalls
		if index >= len(roots.stateSequence) {
			index = len(roots.stateSequence) - 1
		}
		roots.stateCalls++
		state := roots.stateSequence[index]
		return state.mounted, state.err
	}
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
	settleResponses []fakeCloudMountListResponse
	settleCalls     int
}

type fakeCloudMountListResponse struct {
	list         httper.MountList
	err          error
	apply        bool
	applyMounted bool
}

type fakeCloudSettleClock struct {
	now   time.Time
	waits []time.Duration
}

func (clock *fakeCloudSettleClock) Now() time.Time {
	return clock.now
}

func (clock *fakeCloudSettleClock) Wait(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.waits = append(clock.waits, delay)
	clock.now = clock.now.Add(delay)
	return nil
}

type blockingCloudRclone struct {
	*fakeCloudRclone
	mu            sync.Mutex
	getCalls      int
	firstEntered  chan struct{}
	secondEntered chan struct{}
	releaseFirst  chan struct{}
}

type deadlineCloudRclone struct {
	*fakeCloudRclone
	contextCalls int
}

func (client *deadlineCloudRclone) GetMountListContext(ctx context.Context) (httper.MountList, error) {
	client.contextCalls++
	<-ctx.Done()
	return httper.MountList{}, ctx.Err()
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
func (client *fakeCloudRclone) GetMountListContext(ctx context.Context) (httper.MountList, error) {
	if err := ctx.Err(); err != nil {
		return httper.MountList{}, err
	}
	client.settleCalls++
	if len(client.settleResponses) == 0 {
		return client.GetMountList()
	}
	index := client.settleCalls - 1
	if index >= len(client.settleResponses) {
		index = len(client.settleResponses) - 1
	}
	response := client.settleResponses[index]
	result := httper.MountList{MountPoints: append([]httper.MountPoints(nil), response.list.MountPoints...)}
	if response.apply {
		client.mounts = result
		client.roots.mounted = response.applyMounted
		client.roots.stateErr = nil
	}
	return result, response.err
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
		settleTimeout:  3 * time.Second,
		settleInterval: time.Second,
		settleClock:    &fakeCloudSettleClock{now: time.Unix(1, 0)},
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
	if client.unmountCalls != 0 || client.deleteCalls != 1 || client.settleCalls != 8 {
		t.Fatalf("healthy unmounted calls: unmount=%d delete=%d list=%d", client.unmountCalls, client.deleteCalls, client.settleCalls)
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

func TestMountStorageSettlesDelayedCompletionOnSecondAndThirdFramesOnce(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mountErr = errors.New("mount response timed out")
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	client.settleResponses = []fakeCloudMountListResponse{
		{}, {},
		{list: mountedList, apply: true, applyMounted: true}, {list: mountedList},
		{list: mountedList}, {list: mountedList},
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: false},
		{mounted: false},
		{mounted: true},
		{mounted: true},
	}

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err != nil {
		t.Fatalf("MountStorage() delayed completion error = %v", err)
	}
	if client.mountCalls != 1 || client.unmountCalls != 0 {
		t.Fatalf("mutation calls: mount=%d unmount=%d", client.mountCalls, client.unmountCalls)
	}
	if client.settleCalls != 6 {
		t.Fatalf("settle list probes = %d, want 6 across three frames", client.settleCalls)
	}
	if roots.mutationAcquire != 1 || roots.mutationRelease != 1 {
		t.Fatalf("mutation lease: acquire=%d release=%d", roots.mutationAcquire, roots.mutationRelease)
	}
}

func TestMountStorageRejectsTornFrameUntilTwoStableFramesFollow(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mountErr = errors.New("mount response timed out")
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	client.settleResponses = []fakeCloudMountListResponse{
		{}, {list: mountedList, apply: true, applyMounted: true},
		{list: mountedList}, {list: mountedList},
		{list: mountedList}, {list: mountedList},
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: false},
		{mounted: true},
		{mounted: true},
		{mounted: true},
	}

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err != nil {
		t.Fatalf("MountStorage() after torn frame = %v", err)
	}
	if client.mountCalls != 1 || client.unmountCalls != 0 {
		t.Fatalf("mutation calls: mount=%d unmount=%d", client.mountCalls, client.unmountCalls)
	}
	if client.settleCalls != 6 {
		t.Fatalf("torn frame was incorrectly counted toward confirmation: probes=%d", client.settleCalls)
	}
}

func TestMountStorageRetriesTransientListErrorWithinSettleWindow(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mountApplies = true
	client.mountErr = errors.New("ambiguous mount transport failure")
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	client.settleResponses = []fakeCloudMountListResponse{
		{err: errors.New("transient list failure")}, {list: mountedList},
		{list: mountedList}, {list: mountedList},
		{list: mountedList}, {list: mountedList},
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: false},
		{mounted: true},
		{mounted: true},
		{mounted: true},
	}

	if err := storage.MountStorage("/mnt/cloud", "cloud:"); err != nil {
		t.Fatalf("MountStorage() transient list error = %v", err)
	}
	if client.mountCalls != 1 || client.unmountCalls != 0 || client.settleCalls != 6 {
		t.Fatalf("calls: mount=%d unmount=%d list=%d", client.mountCalls, client.unmountCalls, client.settleCalls)
	}
}

func TestMountStorageRejectsTopologyConflictsWithoutRollback(t *testing.T) {
	conflicts := map[string]struct {
		list     httper.MountList
		expected string
	}{
		"foreign remote at target": {
			list:     httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "other"}}},
			expected: "unexpected rclone remote",
		},
		"same remote elsewhere": {
			list:     httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/legacy", Fs: "cloud"}}},
			expected: "unexpected path",
		},
		"same remote subpath": {
			list:     httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud", FsPath: "subdir"}}},
			expected: "unexpected subpath",
		},
		"duplicate remote": {
			list: httper.MountList{MountPoints: []httper.MountPoints{
				{MountPoint: "/mnt/cloud", Fs: "cloud"},
				{MountPoint: "/mnt/cloud", Fs: "cloud"},
			}},
			expected: "duplicate mount records",
		},
	}
	for name, conflict := range conflicts {
		t.Run(name, func(t *testing.T) {
			storage, client, roots := newFakeCloudStorage(t)
			client.mountErr = errors.New("ambiguous mount failure")
			// Only the before snapshot conflicts. The after snapshot is valid,
			// proving that a one-sided conflict is still fail-closed.
			client.settleResponses = []fakeCloudMountListResponse{{list: conflict.list}, {}}

			err := storage.MountStorage("/mnt/cloud", "cloud:")
			if err == nil {
				t.Fatal("MountStorage() accepted a conflicting rclone topology")
			}
			if !strings.Contains(err.Error(), conflict.expected) || strings.Contains(err.Error(), "%!w") {
				t.Fatalf("conflict error is not readable: %v", err)
			}
			if client.mountCalls != 1 || client.unmountCalls != 0 || client.settleCalls != 2 {
				t.Fatalf("calls after conflict: mount=%d unmount=%d list=%d", client.mountCalls, client.unmountCalls, client.settleCalls)
			}
			if roots.mutationAcquire != 1 || roots.mutationRelease != 1 {
				t.Fatalf("mutation lease after conflict: acquire=%d release=%d", roots.mutationAcquire, roots.mutationRelease)
			}
		})
	}
}

func TestMountStorageAlwaysWithholdsAutomaticRollback(t *testing.T) {
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	listError := fakeCloudMountListResponse{err: errors.New("listmounts unavailable")}
	tests := map[string][]fakeCloudMountListResponse{
		"all topology unknown": {
			listError, listError, listError, listError, listError, listError,
		},
		"stable empty through deadline": {
			{}, {}, {}, {}, {}, {},
		},
		"stable empty then unknown": {
			{}, {}, listError, listError, listError, listError,
		},
		"historical exact target then unknown": {
			{list: mountedList}, {list: mountedList}, listError, listError, listError, listError,
		},
		"exact target through deadline": {
			{list: mountedList}, {list: mountedList},
			{list: mountedList}, {list: mountedList},
			{list: mountedList}, {list: mountedList},
		},
	}
	for name, responses := range tests {
		t.Run(name, func(t *testing.T) {
			storage, client, roots := newFakeCloudStorage(t)
			client.mountErr = errors.New("mount response timed out")
			client.settleResponses = responses

			err := storage.MountStorage("/mnt/cloud", "cloud:")
			if err == nil || !strings.Contains(err.Error(), "automatic rollback withheld until operation identity/cancellation exists") {
				t.Fatalf("MountStorage() attribution error = %v", err)
			}
			if client.mountCalls != 1 || client.unmountCalls != 0 || client.settleCalls != 6 {
				t.Fatalf("calls without final ownership: mount=%d unmount=%d list=%d", client.mountCalls, client.unmountCalls, client.settleCalls)
			}
			if roots.mutationAcquire != 1 || roots.mutationRelease != 1 || roots.mutationIsHeld() {
				t.Fatalf("mutation lease without final ownership: acquire=%d release=%d held=%t", roots.mutationAcquire, roots.mutationRelease, roots.mutationIsHeld())
			}
		})
	}
}

func TestCloudMountSettleUsesOneTotalDeadline(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	clock := storage.settleClock.(*fakeCloudSettleClock)
	started := clock.Now()

	settlement := storage.settleCloudMountState(roots, "/mnt/cloud", "cloud", true)
	if settlement.converged {
		t.Fatal("non-mounted storage unexpectedly converged to mounted")
	}
	if settlement.samples != 3 || client.settleCalls != 6 {
		t.Fatalf("deadline sampling: frames=%d list-probes=%d", settlement.samples, client.settleCalls)
	}
	if elapsed := clock.Now().Sub(started); elapsed != storage.settleTimeout {
		t.Fatalf("virtual elapsed = %s, want one total deadline %s", elapsed, storage.settleTimeout)
	}
	if len(clock.waits) != 3 {
		t.Fatalf("wait calls = %d, want 3", len(clock.waits))
	}
	if err := settlement.unresolvedError("test settle", true); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("deadline error = %v", err)
	}
}

func TestCloudMountSettleBoundsBlockingListByWallClock(t *testing.T) {
	storage, baseClient, roots := newFakeCloudStorage(t)
	client := &deadlineCloudRclone{fakeCloudRclone: baseClient}
	storage.rclone = client
	storage.settleTimeout = 50 * time.Millisecond
	storage.settleInterval = 10 * time.Millisecond
	storage.settleClock = realCloudSettleClock{}

	started := time.Now()
	settlement := storage.settleCloudMountState(roots, "/mnt/cloud", "cloud", true)
	elapsed := time.Since(started)
	if settlement.converged || settlement.samples != 1 {
		t.Fatalf("blocking list settlement = converged:%t samples:%d", settlement.converged, settlement.samples)
	}
	if client.contextCalls != 2 {
		t.Fatalf("sandwich list probes = %d, want 2 sharing the deadline", client.contextCalls)
	}
	if elapsed < storage.settleTimeout || elapsed > time.Second {
		t.Fatalf("bounded settle elapsed = %s, timeout = %s", elapsed, storage.settleTimeout)
	}
}

func TestMountStorageWithholdsAutomaticRollbackAndReleasesLocks(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mountErr = errors.New("original mount error")
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	for index := 0; index < 6; index++ {
		client.settleResponses = append(client.settleResponses, fakeCloudMountListResponse{list: mountedList})
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: false},
		{mounted: false}, {mounted: false}, {mounted: false},
	}

	err := storage.MountStorage("/mnt/cloud", "cloud:")
	if err == nil || !strings.Contains(err.Error(), "cloud mount reconciliation unresolved") || !strings.Contains(err.Error(), "automatic rollback withheld until operation identity/cancellation exists") {
		t.Fatalf("MountStorage() withheld rollback = %v", err)
	}
	if !strings.Contains(err.Error(), "original mount error") {
		t.Fatalf("MountStorage() lost original mutation error: %v", err)
	}
	if client.mountCalls != 1 || client.unmountCalls != 0 || client.settleCalls != 6 {
		t.Fatalf("mutation calls: mount=%d unmount=%d list=%d", client.mountCalls, client.unmountCalls, client.settleCalls)
	}
	if roots.mutationAcquire != 1 || roots.mutationRelease != 1 || roots.mutationIsHeld() {
		t.Fatalf("mutation lease remained held: acquire=%d release=%d held=%t", roots.mutationAcquire, roots.mutationRelease, roots.mutationIsHeld())
	}

	result := make(chan error, 1)
	go func() {
		_, getErr := storage.GetConfigByName("cloud")
		result <- getErr
	}()
	select {
	case getErr := <-result:
		if getErr != nil {
			t.Fatalf("storage lock released but follow-up failed: %v", getErr)
		}
	case <-time.After(time.Second):
		t.Fatal("storage operation lock remained held after withholding rollback")
	}
}

func TestRemoveStorageDeletesOnlyAfterDelayedDualEvidence(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	client.mounts = mountedList
	roots.mounted = true
	client.unmountErr = errors.New("unmount response timed out")
	client.settleResponses = []fakeCloudMountListResponse{
		{list: mountedList}, {list: mountedList},
		{apply: true, applyMounted: false}, {},
		{}, {},
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: true},
		{mounted: true},
		{mounted: false},
		{mounted: false},
		{mounted: false},
	}

	if err := storage.RemoveStorage("/mnt/cloud"); err != nil {
		t.Fatalf("RemoveStorage() delayed unmount = %v", err)
	}
	if client.unmountCalls != 1 || client.deleteCalls != 1 || client.settleCalls != 10 {
		t.Fatalf("calls: unmount=%d delete=%d list=%d", client.unmountCalls, client.deleteCalls, client.settleCalls)
	}
	if _, exists := client.configs["cloud"]; exists {
		t.Fatal("config remained after dual unmount evidence converged")
	}
}

func TestRemoveStorageKeepsConfigOnPersistentSettleListErrors(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	client.mounts = httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	roots.mounted = true
	client.unmountErr = errors.New("unmount response timed out")
	for index := 0; index < 6; index++ {
		client.settleResponses = append(client.settleResponses, fakeCloudMountListResponse{err: errors.New("listmounts unavailable")})
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: true},
		{mounted: false}, {mounted: false}, {mounted: false},
	}

	err := storage.RemoveStorage("/mnt/cloud")
	if err == nil || !strings.Contains(err.Error(), "cloud unmount reconciliation unresolved") || !strings.Contains(err.Error(), "listmounts unavailable") {
		t.Fatalf("RemoveStorage() persistent list failure = %v", err)
	}
	if client.unmountCalls != 1 || client.deleteCalls != 0 || client.settleCalls != 6 {
		t.Fatalf("calls: unmount=%d delete=%d list=%d", client.unmountCalls, client.deleteCalls, client.settleCalls)
	}
	if _, exists := client.configs["cloud"]; !exists {
		t.Fatal("config was deleted without converged dual evidence")
	}
	if info, statErr := os.Stat(roots.directory); statErr != nil || !info.IsDir() {
		t.Fatalf("mount directory was not retained: info=%v err=%v", info, statErr)
	}
	if roots.mutationAcquire != 1 || roots.mutationRelease != 1 || roots.mutationIsHeld() {
		t.Fatalf("mutation lease after list failure: acquire=%d release=%d held=%t", roots.mutationAcquire, roots.mutationRelease, roots.mutationIsHeld())
	}
}

func TestRemoveStorageKeepsConfigWhenInitiallyAbsentMountReappearsDuringSettle(t *testing.T) {
	storage, client, roots := newFakeCloudStorage(t)
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	client.settleResponses = []fakeCloudMountListResponse{
		{}, {},
		{list: mountedList, apply: true, applyMounted: true}, {list: mountedList},
		{list: mountedList}, {list: mountedList},
	}
	roots.stateSequence = []fakeCloudMountState{
		{mounted: false},
		{mounted: false},
		{mounted: true},
		{mounted: true},
	}

	err := storage.RemoveStorage("/mnt/cloud")
	if err == nil || !strings.Contains(err.Error(), "cloud unmount reconciliation unresolved") {
		t.Fatalf("RemoveStorage() delayed remount = %v", err)
	}
	if client.unmountCalls != 0 || client.deleteCalls != 0 || client.settleCalls != 6 {
		t.Fatalf("calls after delayed remount: unmount=%d delete=%d list=%d", client.unmountCalls, client.deleteCalls, client.settleCalls)
	}
	if _, exists := client.configs["cloud"]; !exists {
		t.Fatal("config was deleted after an initially absent mount reappeared")
	}
	if roots.mutationAcquire != 1 || roots.mutationRelease != 1 {
		t.Fatalf("mutation lease after delayed remount: acquire=%d release=%d", roots.mutationAcquire, roots.mutationRelease)
	}
}

func TestRemoveStorageFreshDeleteSettleFailsClosed(t *testing.T) {
	mountedList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "cloud"}}}
	foreignList := httper.MountList{MountPoints: []httper.MountPoints{{MountPoint: "/mnt/cloud", Fs: "other"}}}
	listError := fakeCloudMountListResponse{err: errors.New("listmounts unavailable before config deletion")}
	tests := map[string][]fakeCloudMountListResponse{
		"target reappears": {
			{list: mountedList, apply: true, applyMounted: true}, {list: mountedList},
			{list: mountedList}, {list: mountedList},
			{list: mountedList}, {list: mountedList},
		},
		"foreign mount appears": {
			{list: foreignList}, {list: foreignList},
		},
		"topology becomes unknown": {
			listError, listError, listError, listError, listError, listError,
		},
	}
	for name, deletionResponses := range tests {
		t.Run(name, func(t *testing.T) {
			storage, client, roots := newFakeCloudStorage(t)
			client.mounts = httper.MountList{MountPoints: append([]httper.MountPoints(nil), mountedList.MountPoints...)}
			roots.mounted = true
			client.unmountApplies = true
			client.settleResponses = append([]fakeCloudMountListResponse{{}, {}, {}, {}}, deletionResponses...)

			err := storage.RemoveStorage("/mnt/cloud")
			if err == nil || !strings.Contains(err.Error(), "cloud config deletion precondition unresolved") {
				t.Fatalf("RemoveStorage() final delete gate = %v", err)
			}
			if client.unmountCalls != 1 || client.deleteCalls != 0 {
				t.Fatalf("mutations after failed delete gate: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
			}
			if _, exists := client.configs["cloud"]; !exists {
				t.Fatal("config was deleted after the fresh deletion gate failed")
			}
			if info, statErr := os.Stat(roots.directory); statErr != nil || !info.IsDir() {
				t.Fatalf("mount directory was not retained: info=%v err=%v", info, statErr)
			}
			if roots.mutationAcquire != 1 || roots.mutationRelease != 1 || roots.mutationIsHeld() {
				t.Fatalf("mutation lease after failed delete gate: acquire=%d release=%d held=%t", roots.mutationAcquire, roots.mutationRelease, roots.mutationIsHeld())
			}
		})
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

	err := storage.RemoveStorage("/mnt/cloud")
	if err == nil {
		t.Fatal("RemoveStorage() accepted an unverifiable stale unmount")
	}
	if !strings.Contains(err.Error(), "cloud unmount reconciliation unresolved") || !strings.Contains(err.Error(), "unmount failed") {
		t.Fatalf("RemoveStorage() unresolved error lost evidence: %v", err)
	}
	if client.unmountCalls != 1 || client.deleteCalls != 0 {
		t.Fatalf("calls: unmount=%d delete=%d", client.unmountCalls, client.deleteCalls)
	}
	if _, exists := client.configs["cloud"]; !exists {
		t.Fatal("config was deleted after stale unmount verification failed")
	}
	if info, statErr := os.Stat(roots.directory); statErr != nil || !info.IsDir() {
		t.Fatalf("mount directory was not retained: info=%v err=%v", info, statErr)
	}
	if roots.mutationAcquire != 1 || roots.mutationRelease != 1 || roots.mutationIsHeld() {
		t.Fatalf("mutation lease after unresolved unmount: acquire=%d release=%d held=%t", roots.mutationAcquire, roots.mutationRelease, roots.mutationIsHeld())
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
