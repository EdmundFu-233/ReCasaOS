//go:build linux

package publicfiles

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const publicFilesystemImageSize = int64(512 << 20)

// This test changes the mount namespace and must run only in the explicitly
// privileged, ephemeral CI step. Ordinary unprivileged test runs skip before
// making a mount change.
func requireIsolatedPublicMountTest(t *testing.T) {
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

func requirePublicFilesystemTool(t *testing.T, name string) string {
	t.Helper()
	absolutePath, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("required privileged filesystem test tool %q is unavailable: %v", name, err)
	}
	return absolutePath
}

func runPublicFilesystemTool(t *testing.T, executable string, arguments ...string) {
	t.Helper()
	output, err := exec.Command(executable, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf(
			"privileged filesystem test command %s failed: %v\n%s",
			executable,
			err,
			strings.TrimSpace(string(output)),
		)
	}
}

func validateLoopDeviceOutput(output []byte) (string, error) {
	device := strings.TrimSpace(string(output))
	if device == "" || strings.ContainsAny(device, " \t\r\n") {
		return "", fmt.Errorf("losetup returned an invalid device name %q", output)
	}
	if filepath.Dir(device) != "/dev" {
		return "", fmt.Errorf("losetup returned a device outside /dev: %q", device)
	}
	name := filepath.Base(device)
	index := strings.TrimPrefix(name, "loop")
	if index == name || index == "" {
		return "", fmt.Errorf("losetup returned a non-loop device: %q", device)
	}
	for _, character := range index {
		if character < '0' || character > '9' {
			return "", fmt.Errorf("losetup returned a malformed loop device: %q", device)
		}
	}
	var stat unix.Stat_t
	if err := unix.Stat(device, &stat); err != nil {
		return "", fmt.Errorf("inspect losetup device %q: %w", device, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFBLK {
		return "", fmt.Errorf("losetup output is not a block device: %q", device)
	}
	return device, nil
}

func detachLoopDevicesForImage(t *testing.T, losetupTool, imagePath string) {
	t.Helper()
	output, err := exec.Command(losetupTool, "--associated", imagePath).CombinedOutput()
	if err != nil {
		t.Errorf("inspect loop devices associated with %q: %v: %s", imagePath, err, strings.TrimSpace(string(output)))
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		device, _, found := strings.Cut(line, ":")
		if !found {
			t.Errorf("cannot identify associated loop device from %q", line)
			continue
		}
		validated, validationErr := validateLoopDeviceOutput([]byte(device))
		if validationErr != nil {
			t.Errorf("refuse to detach malformed associated loop device from %q: %v", line, validationErr)
			continue
		}
		detachOutput, detachErr := exec.Command(losetupTool, "--detach", validated).CombinedOutput()
		if detachErr != nil {
			t.Errorf("detach associated loop device %q: %v: %s", validated, detachErr, strings.TrimSpace(string(detachOutput)))
		}
	}
}

func cleanupLoopMountedFilesystem(t *testing.T, losetupTool, imagePath, mountPoint, loopDevice string, mounted bool) {
	t.Helper()
	if mounted {
		if err := unix.Unmount(mountPoint, 0); err != nil {
			if detachErr := unix.Unmount(mountPoint, unix.MNT_DETACH); detachErr != nil {
				t.Errorf("unmount loop filesystem normally (%v) or detached (%v)", err, detachErr)
			} else {
				t.Errorf("loop filesystem required a detached unmount after normal unmount failed: %v", err)
			}
		}
	}

	if loopDevice == "" {
		detachLoopDevicesForImage(t, losetupTool, imagePath)
		return
	}

	detachOutput, detachErr := exec.Command(losetupTool, "--detach", loopDevice).CombinedOutput()
	if detachErr != nil {
		t.Errorf("detach exact loop device %q: %v: %s", loopDevice, detachErr, strings.TrimSpace(string(detachOutput)))
		return
	}
	remaining, listErr := exec.Command(losetupTool, "--associated", imagePath).CombinedOutput()
	if listErr != nil {
		t.Errorf("verify loop cleanup for %q: %v: %s", imagePath, listErr, strings.TrimSpace(string(remaining)))
	} else if strings.TrimSpace(string(remaining)) != "" {
		t.Errorf("loop device remained associated after detaching %q: %s", loopDevice, strings.TrimSpace(string(remaining)))
	}
}

func TestPinnedPublicRootSurvivesBindMountReplacement(t *testing.T) {
	requireIsolatedPublicMountTest(t)
	base := t.TempDir()
	original := filepath.Join(base, "original")
	replacement := filepath.Join(base, "replacement")
	mountPoint := filepath.Join(base, "public-root")
	for _, directory := range []string{original, replacement, mountPoint} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(original, "original.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "replacement.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	mounted := false
	if err := unix.Mount(original, mountPoint, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested bind-mount regression cannot mount: %v", err)
	}
	mounted = true
	t.Cleanup(func() {
		if mounted {
			if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
				t.Errorf("unmount public root replacement: %v", err)
			}
		}
	})

	root, err := openSecureRoot(mountPoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.close(); err != nil {
			t.Errorf("close pinned public root: %v", err)
		}
	})
	originalMountID := root.mountID

	if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	mounted = false
	if err := unix.Mount(replacement, mountPoint, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	mounted = true

	current, err := os.Open(mountPoint)
	if err != nil {
		t.Fatal(err)
	}
	currentMountID, mountErr := publicRootMountID(int(current.Fd()))
	closeErr := current.Close()
	if mountErr != nil || closeErr != nil {
		t.Fatal(errors.Join(mountErr, closeErr))
	}
	if currentMountID == originalMountID {
		t.Fatalf("replacement bind mount reused live pinned mount ID %d", currentMountID)
	}

	entries, err := root.list("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "original.txt" || entries[0].Type != "file" {
		t.Fatalf("pinned root followed replacement mount: %#v", entries)
	}
}

func TestPublicRootRejectsNestedBindMount(t *testing.T) {
	requireIsolatedPublicMountTest(t)
	rootPath := t.TempDir()
	nested := filepath.Join(rootPath, "nested")
	backing := t.TempDir()
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "visible.txt"), []byte("visible"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backing, "must-not-cross.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(backing, nested, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("explicitly requested nested-bind regression cannot mount: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(nested, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount nested public root: %v", err)
		}
	})

	root, err := openSecureRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	entries, err := root.list("", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "visible.txt" || entries[0].Type != "file" {
		t.Fatalf("nested mount was exposed by public root: %#v", entries)
	}
}

func TestPublicRootAcceptsTmpfsInIsolatedNamespace(t *testing.T) {
	requireIsolatedPublicMountTest(t)
	mountPoint := t.TempDir()
	if err := unix.Mount("none", mountPoint, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4m,mode=0700"); err != nil {
		t.Fatalf("explicitly requested tmpfs regression cannot mount: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mountPoint, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount tmpfs public root: %v", err)
		}
	})

	content := []byte("ReCasaOS tmpfs compatibility\n")
	if err := os.WriteFile(filepath.Join(mountPoint, "visible.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openSecureRoot(mountPoint)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if root.filesystemType != uint32(unix.TMPFS_MAGIC) {
		t.Fatalf("tmpfs root type = %#x, want %#x", root.filesystemType, uint32(unix.TMPFS_MAGIC))
	}
	entries, err := root.list("", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "visible.txt" || entries[0].Type != "file" || entries[0].Size != int64(len(content)) {
		t.Fatalf("tmpfs listing did not contain the expected regular file: %#v", entries)
	}
	opened, info, err := root.openRegular("visible.txt")
	if err != nil {
		t.Fatal(err)
	}
	read, readErr := io.ReadAll(opened)
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	if info.Size() != int64(len(content)) || !bytes.Equal(read, content) {
		t.Fatalf("tmpfs regular file result = size %d content %q", info.Size(), read)
	}
}

func TestPublicRootAllowlistedFilesystemCompatibilityMatrix(t *testing.T) {
	requireIsolatedPublicMountTest(t)

	losetupTool := requirePublicFilesystemTool(t, "losetup")
	testContent := []byte("ReCasaOS allowlisted filesystem compatibility\n")
	tests := []struct {
		name       string
		mkfsTool   string
		mkfsArgs   []string
		mountType  string
		superMagic uint32
	}{
		{
			name:       "ext4",
			mkfsTool:   "mkfs.ext4",
			mkfsArgs:   []string{"-F", "-q"},
			mountType:  "ext4",
			superMagic: uint32(unix.EXT4_SUPER_MAGIC),
		},
		{
			name:       "xfs",
			mkfsTool:   "mkfs.xfs",
			mkfsArgs:   []string{"-f", "-q"},
			mountType:  "xfs",
			superMagic: uint32(unix.XFS_SUPER_MAGIC),
		},
		{
			name:       "btrfs",
			mkfsTool:   "mkfs.btrfs",
			mkfsArgs:   []string{"-f", "-q"},
			mountType:  "btrfs",
			superMagic: uint32(unix.BTRFS_SUPER_MAGIC),
		},
		{
			name:       "f2fs",
			mkfsTool:   "mkfs.f2fs",
			mkfsArgs:   []string{"-f"},
			mountType:  "f2fs",
			superMagic: uint32(unix.F2FS_SUPER_MAGIC),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mkfsTool := requirePublicFilesystemTool(t, test.mkfsTool)
			base := t.TempDir()
			imagePath := filepath.Join(base, test.name+".img")
			image, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr := image.Truncate(publicFilesystemImageSize)
			closeErr := image.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatalf("create sparse %s image: %v", test.name, errors.Join(truncateErr, closeErr))
			}

			mkfsArgs := append(append([]string(nil), test.mkfsArgs...), imagePath)
			runPublicFilesystemTool(t, mkfsTool, mkfsArgs...)

			mountPoint := filepath.Join(base, "public-root")
			if err := os.Mkdir(mountPoint, 0o700); err != nil {
				t.Fatal(err)
			}
			loopDevice := ""
			mounted := false
			t.Cleanup(func() {
				cleanupLoopMountedFilesystem(t, losetupTool, imagePath, mountPoint, loopDevice, mounted)
			})
			loopOutput, loopErr := exec.Command(losetupTool, "--find", "--show", imagePath).CombinedOutput()
			if loopErr != nil {
				t.Fatalf("attach loop device for %s: %v: %s", test.name, loopErr, strings.TrimSpace(string(loopOutput)))
			}
			loopDevice, err = validateLoopDeviceOutput(loopOutput)
			if err != nil {
				t.Fatalf("validate loop device for %s: %v", test.name, err)
			}
			verifiedOutput, verifyErr := exec.Command(
				losetupTool,
				"--list",
				"--noheadings",
				"--output",
				"NAME",
				loopDevice,
			).CombinedOutput()
			if verifyErr != nil || strings.TrimSpace(string(verifiedOutput)) != loopDevice {
				t.Fatalf(
					"verify exact loop device for %s: %v: %q",
					test.name,
					verifyErr,
					strings.TrimSpace(string(verifiedOutput)),
				)
			}
			if err := unix.Mount(
				loopDevice,
				mountPoint,
				test.mountType,
				unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC,
				"",
			); err != nil {
				t.Fatalf("mount %s loop device %q: %v", test.name, loopDevice, err)
			}
			mounted = true

			visiblePath := filepath.Join(mountPoint, "visible.txt")
			if err := os.WriteFile(visiblePath, testContent, 0o600); err != nil {
				t.Fatalf("write %s compatibility fixture: %v", test.name, err)
			}
			root, err := openSecureRoot(mountPoint)
			if err != nil {
				t.Fatalf("open %s public root: %v", test.name, err)
			}
			t.Cleanup(func() {
				if err := root.close(); err != nil {
					t.Errorf("close %s public root: %v", test.name, err)
				}
			})
			if root.filesystemType != test.superMagic {
				t.Fatalf(
					"%s public root type = %#x, want %#x",
					test.name,
					root.filesystemType,
					test.superMagic,
				)
			}

			entries, err := root.list("", 16)
			if err != nil {
				t.Fatalf("list %s public root: %v", test.name, err)
			}
			foundVisible := false
			for _, entry := range entries {
				if entry.Name == "visible.txt" {
					foundVisible = entry.Type == "file" && entry.Size == int64(len(testContent))
				}
			}
			if !foundVisible {
				t.Fatalf("%s public root listing did not contain the expected regular file: %#v", test.name, entries)
			}

			opened, info, err := root.openRegular("visible.txt")
			if err != nil {
				t.Fatalf("open regular file from %s public root: %v", test.name, err)
			}
			content, readErr := io.ReadAll(opened)
			closeErr = opened.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read regular file from %s public root: %v", test.name, errors.Join(readErr, closeErr))
			}
			if info.Size() != int64(len(testContent)) || !bytes.Equal(content, testContent) {
				t.Fatalf(
					"%s regular file result = size %d content %q",
					test.name,
					info.Size(),
					content,
				)
			}
		})
	}
}
