package service

import (
	"testing"

	serviceModel "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/moby/sys/mountinfo"
)

func TestDirectoryListingMountedPathSetUnionsExactPaths(t *testing.T) {
	mounts := []*mountinfo.Info{
		{Mountpoint: "/mnt/archive"},
		{Mountpoint: "/mnt/shared"},
		nil,
		{Mountpoint: ""},
	}
	connections := []serviceModel.ConnectionsDBModel{
		{MountPoint: "/media/remote"},
		{MountPoint: "/mnt/shared"},
		{MountPoint: ""},
	}
	paths := directoryListingMountedPathSet(mounts, connections)
	for _, path := range []string{"/mnt/archive", "/mnt/shared", "/media/remote"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("mounted path %q missing from %+v", path, paths)
		}
	}
	if len(paths) != 3 {
		t.Fatalf("mounted path count = %d, want 3", len(paths))
	}
	for _, path := range []string{"", "/mnt", "/mnt/archive/child", "/mnt/Archive", "/media/remote/"} {
		if _, ok := paths[path]; ok {
			t.Fatalf("non-exact path %q unexpectedly matched", path)
		}
	}
}
