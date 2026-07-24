//go:build linux

package filesecurity

import (
	"bytes"
	"os"
	"testing"
)

func requireIsolatedPrivilegedMountTest(t *testing.T) {
	t.Helper()
	if os.Getenv("RECASAOS_PRIVILEGED_MOUNT_TEST") != "1" {
		t.Skip("privileged mount mutation requires the isolated CI opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicitly requested privileged mount test is not running as root")
	}
	selfNamespace, err := os.Stat("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("cannot prove isolated mount namespace before privileged test: %v", err)
	}
	initNamespace, err := os.Stat("/proc/1/ns/mnt")
	if err != nil {
		t.Fatalf("cannot inspect PID 1 mount namespace before privileged test: %v", err)
	}
	if os.SameFile(selfNamespace, initNamespace) {
		t.Fatal("refusing privileged mount mutation in PID 1's mount namespace")
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("cannot verify private mount propagation before privileged test: %v", err)
	}
	if bytes.Contains(mountInfo, []byte(" shared:")) {
		t.Fatal("refusing privileged mount mutation while shared mount propagation remains enabled")
	}
}
