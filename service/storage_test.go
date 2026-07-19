package service

import (
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
)

func TestCloudMountPointRequiresSafeSingleComponent(t *testing.T) {
	valid := []string{"drive1", "alice_google-drive.2", "A"}
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
