//go:build linux

package publicfiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

const safeOpenTestToken = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

const zfsSuperMagic = 0x2fc12fc1 // OpenZFS Linux statfs magic; intentionally not allowlisted.

func signExtendedFilesystemMagic(magic uint32) int64 {
	return int64(int32(magic))
}

func newSecureRootFixture(t *testing.T) (*secureRoot, string) {
	t.Helper()
	rootPath := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := openSecureRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.close() })
	return root, rootPath
}

func TestPublicRootFilesystemPolicyIsExplicitAndFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		magic   int64
		allowed bool
	}{
		{name: "ext2-ext4", magic: int64(unix.EXT4_SUPER_MAGIC), allowed: true},
		{name: "xfs", magic: int64(unix.XFS_SUPER_MAGIC), allowed: true},
		{name: "btrfs", magic: int64(unix.BTRFS_SUPER_MAGIC), allowed: true},
		{name: "tmpfs", magic: int64(unix.TMPFS_MAGIC), allowed: true},
		{name: "f2fs", magic: int64(unix.F2FS_SUPER_MAGIC), allowed: true},
		{name: "btrfs-sign-extended-on-32-bit", magic: signExtendedFilesystemMagic(uint32(unix.BTRFS_SUPER_MAGIC)), allowed: true},
		{name: "f2fs-sign-extended-on-32-bit", magic: signExtendedFilesystemMagic(uint32(unix.F2FS_SUPER_MAGIC)), allowed: true},
		{name: "fuse", magic: int64(unix.FUSE_SUPER_MAGIC)},
		{name: "nfs", magic: int64(unix.NFS_SUPER_MAGIC)},
		{name: "cifs", magic: int64(unix.CIFS_SUPER_MAGIC)},
		{name: "cifs-sign-extended-on-32-bit", magic: signExtendedFilesystemMagic(uint32(unix.CIFS_SUPER_MAGIC))},
		{name: "smb", magic: int64(unix.SMB_SUPER_MAGIC)},
		{name: "smb2", magic: int64(unix.SMB2_SUPER_MAGIC)},
		{name: "ceph", magic: int64(unix.CEPH_SUPER_MAGIC)},
		{name: "9p", magic: int64(unix.V9FS_MAGIC)},
		{name: "overlay", magic: int64(unix.OVERLAYFS_SUPER_MAGIC)},
		{name: "bcachefs-unverified", magic: int64(unix.BCACHEFS_SUPER_MAGIC)},
		{name: "erofs-unverified", magic: int64(unix.EROFS_SUPER_MAGIC_V1)},
		{name: "ramfs-unverified", magic: int64(unix.RAMFS_MAGIC)},
		{name: "xenfs", magic: int64(unix.XENFS_SUPER_MAGIC)},
		{name: "zfs-unverified", magic: zfsSuperMagic},
		{name: "unknown", magic: 0x12345678},
		{name: "noncanonical-high-bits", magic: 1<<32 | int64(uint32(unix.EXT4_SUPER_MAGIC))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, allowed := publicRootFilesystemName(test.magic)
			if allowed != test.allowed {
				t.Fatalf("filesystem %#x allowed = %v, want %v", uint32(test.magic), allowed, test.allowed)
			}
			if allowed && name == "" {
				t.Fatal("allowlisted filesystem has no documented name")
			}
			if !allowed && name != "" {
				t.Fatalf("rejected filesystem unexpectedly has policy name %q", name)
			}
		})
	}
}

func TestOpenSecureRootRejectsUnsupportedFilesystemAndClosesDescriptor(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	capturedFD := -1
	root, err := openSecureRootWith(rootPath, func(fd int) (rootFilesystemIdentity, error) {
		capturedFD = fd
		return rootFilesystemIdentity{mountID: 42, magic: int64(unix.FUSE_SUPER_MAGIC)}, nil
	})
	if root != nil {
		_ = root.close()
		t.Fatal("FUSE policy unexpectedly returned a root")
	}
	if !errors.Is(err, errPublicRootFilesystemNotAllowed) || !strings.Contains(err.Error(), "supported local filesystems") {
		t.Fatalf("FUSE policy error = %v", err)
	}
	if capturedFD < 0 {
		t.Fatal("filesystem inspector did not receive the root descriptor")
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(capturedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("rejected root descriptor was not closed: %v", statErr)
	}
}

func TestOpenSecureRootInspectionFailureRollsBackDescriptor(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	probeErr := errors.New("injected root filesystem inspection failure")
	capturedFD := -1
	root, err := openSecureRootWith(rootPath, func(fd int) (rootFilesystemIdentity, error) {
		capturedFD = fd
		return rootFilesystemIdentity{}, probeErr
	})
	if root != nil {
		_ = root.close()
		t.Fatal("failed inspection unexpectedly returned a root")
	}
	if !errors.Is(err, probeErr) {
		t.Fatalf("inspection error = %v, want injected error", err)
	}
	if capturedFD < 0 {
		t.Fatal("filesystem inspector did not receive the root descriptor")
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(capturedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("root descriptor survived failed startup: %v", statErr)
	}
}

func TestOpenSecureRootRejectsZeroMountIDAndClosesDescriptor(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	capturedFD := -1
	root, err := openSecureRootWith(rootPath, func(fd int) (rootFilesystemIdentity, error) {
		capturedFD = fd
		return rootFilesystemIdentity{magic: int64(unix.EXT4_SUPER_MAGIC)}, nil
	})
	if root != nil {
		_ = root.close()
		t.Fatal("zero mount identifier unexpectedly returned a root")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("zero mount identifier error = %v, want ErrUnsupported", err)
	}
	if capturedFD < 0 {
		t.Fatal("filesystem inspector did not receive the root descriptor")
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(capturedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("root descriptor survived invalid mount identity: %v", statErr)
	}
}

func TestOpenSecureRootReadabilityProbeUsesPinnedDescriptorAndRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory read-permission boundary")
	}

	base := t.TempDir()
	rootPath := filepath.Join(base, "shared")
	movedPath := filepath.Join(base, "shared-pinned")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(movedPath, 0o700) })

	capturedFD := -1
	root, err := openSecureRootWith(rootPath, func(fd int) (rootFilesystemIdentity, error) {
		capturedFD = fd
		mountID, mountErr := publicRootMountID(fd)
		if mountErr != nil {
			return rootFilesystemIdentity{}, mountErr
		}
		if renameErr := os.Rename(rootPath, movedPath); renameErr != nil {
			return rootFilesystemIdentity{}, renameErr
		}
		if chmodErr := os.Chmod(movedPath, 0o111); chmodErr != nil {
			return rootFilesystemIdentity{}, chmodErr
		}
		if mkdirErr := os.Mkdir(rootPath, 0o700); mkdirErr != nil {
			return rootFilesystemIdentity{}, mkdirErr
		}
		return rootFilesystemIdentity{mountID: mountID, magic: int64(unix.EXT4_SUPER_MAGIC)}, nil
	})
	if root != nil {
		_ = root.close()
		t.Fatal("unreadable pinned root unexpectedly passed the startup probe")
	}
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("unreadable pinned root error = %v, want EACCES or EPERM", err)
	}
	if !strings.Contains(err.Error(), "not readable by the service user") {
		t.Fatalf("unreadable pinned root returned an unhelpful error: %v", err)
	}
	if capturedFD < 0 {
		t.Fatal("filesystem inspector did not receive the root descriptor")
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(capturedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("root descriptor survived failed readability probe: %v", statErr)
	}
}

func TestSecureRootRecordsAndRevalidatesPinnedMountIdentity(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var expectedMountID uint64
	root, err := openSecureRootWith(rootPath, func(fd int) (rootFilesystemIdentity, error) {
		mountID, mountErr := publicRootMountID(fd)
		expectedMountID = mountID
		return rootFilesystemIdentity{mountID: mountID, magic: int64(unix.EXT4_SUPER_MAGIC)}, mountErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	if root.mountID != expectedMountID || root.filesystemType != uint32(unix.EXT4_SUPER_MAGIC) {
		t.Fatalf("stored root identity = (mount=%d, fs=%#x), want (mount=%d, fs=%#x)", root.mountID, root.filesystemType, expectedMountID, uint32(unix.EXT4_SUPER_MAGIC))
	}

	root.mountID ^= 1
	fd, err := root.open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if !errors.Is(err, unix.EXDEV) {
		t.Fatalf("changed mount identity returned fd=%d err=%v, want EXDEV", fd, err)
	}
}

func TestSecureRootOpenAndCloseAreSynchronizedAndIdempotent(t *testing.T) {
	root, _ := newSecureRootFixture(t)
	const openers = 64
	start := make(chan struct{})
	errorsSeen := make(chan error, openers)
	var wait sync.WaitGroup
	wait.Add(openers)
	for range openers {
		go func() {
			defer wait.Done()
			<-start
			fd, err := root.open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW)
			if fd >= 0 {
				if closeErr := unix.Close(fd); closeErr != nil {
					errorsSeen <- closeErr
				}
				return
			}
			if !errors.Is(err, unix.EBADF) {
				errorsSeen <- err
			}
		}()
	}
	close(start)
	if err := root.close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent open/close error: %v", err)
	}
	if err := root.close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	if fd, err := root.open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW); fd >= 0 || !errors.Is(err, unix.EBADF) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("open after close returned fd=%d err=%v", fd, err)
	}
}

func TestOpenSecureRootRejectsKnownNonDataFilesystem(t *testing.T) {
	if _, err := os.Stat("/proc"); err != nil {
		t.Skipf("/proc is unavailable: %v", err)
	}
	root, err := openSecureRoot("/proc")
	if root != nil {
		_ = root.close()
		t.Fatal("procfs unexpectedly returned a public root")
	}
	if !errors.Is(err, errPublicRootFilesystemNotAllowed) {
		t.Fatalf("procfs error = %v, want filesystem policy rejection", err)
	}
}

func TestOpenRegularRejectsUnsafeObjectsBeforeDataOpen(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	if err := os.Mkdir(filepath.Join(rootPath, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(rootPath, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "linked"), []byte("linked"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(rootPath, "linked"), filepath.Join(rootPath, "linked-again")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(rootPath), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootPath, "symlink")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"directory", "pipe", "linked", "symlink"} {
		t.Run(name, func(t *testing.T) {
			dataOpenCalls := 0
			file, info, err := root.openRegularWith(name, func(int) (int, error) {
				dataOpenCalls++
				return -1, errors.New("data open must not run")
			})
			if file != nil {
				_ = file.Close()
			}
			if err == nil || info != nil {
				t.Fatalf("unsafe %s open returned file=%v info=%v err=%v", name, file, info, err)
			}
			if dataOpenCalls != 0 {
				t.Fatalf("unsafe %s reached the data opener %d times", name, dataOpenCalls)
			}
		})
	}
}

func TestOpenRegularUsesPinnedProcDescriptor(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	content := "pinned content"
	if err := os.WriteFile(filepath.Join(rootPath, "report"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	file, info, err := root.openRegular("report")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != content || info.Size() != int64(len(content)) || !info.Mode().IsRegular() {
		t.Fatalf("reopened file = (%q, size=%d, mode=%v)", payload, info.Size(), info.Mode())
	}
}

func TestOpenRegularReopensPinnedObjectAfterPathReplacement(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	target := filepath.Join(rootPath, "report")
	moved := filepath.Join(rootPath, "report-original")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, _, err := root.openRegularWith("report", func(pinnedFD int) (int, error) {
		if err := os.Rename(target, moved); err != nil {
			return -1, err
		}
		if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
			return -1, err
		}
		return reopenPinnedRegular(pinnedFD)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "original" {
		t.Fatalf("reopened content = %q, want pinned original", payload)
	}
}

func TestOpenRegularFailsClosedWhenProcReopenIsUnavailable(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	if err := os.WriteFile(filepath.Join(rootPath, "report"), []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	file, info, err := root.openRegularWith("report", func(int) (int, error) {
		calls++
		return -1, unix.ENOENT
	})
	if file != nil {
		_ = file.Close()
	}
	if err == nil || !errors.Is(err, unix.ENOENT) || file != nil || info != nil {
		t.Fatalf("unavailable proc reopen returned file=%v info=%v err=%v", file, info, err)
	}
	if calls != 1 {
		t.Fatalf("proc reopener called %d times, want exactly once and no fallback", calls)
	}
}

func TestOpenPinnedRegularClosesPinnedFDWhenReopenFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(target, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}

	pinnedFD := -1
	dataFD, _, err := openPinnedRegular(func() (int, error) {
		fd, openErr := unix.Open(target, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		pinnedFD = fd
		return fd, openErr
	}, func(int) (int, error) {
		return -1, unix.ENOENT
	})
	if err == nil || dataFD != -1 {
		t.Fatalf("failed reopen returned dataFD=%d err=%v", dataFD, err)
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(pinnedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("pinned descriptor was not closed after reopen failure: %v", statErr)
	}
}

func TestOpenRegularRejectsReopenedIdentityMismatchAndClosesFD(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	if err := os.WriteFile(filepath.Join(rootPath, "expected"), []byte("expected"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(rootPath, "other")
	if err := os.WriteFile(otherPath, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	reopenedFD := -1
	file, info, err := root.openRegularWith("expected", func(int) (int, error) {
		fd, duplicateErr := unix.Dup(int(other.Fd()))
		reopenedFD = fd
		return fd, duplicateErr
	})
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, unix.EPERM) || file != nil || info != nil {
		t.Fatalf("identity mismatch returned file=%v info=%v err=%v", file, info, err)
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(reopenedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("rejected reopened descriptor was not closed: %v", statErr)
	}
}

func TestOpenRegularRevalidatesLinkCountAfterReopen(t *testing.T) {
	root, rootPath := newSecureRootFixture(t)
	target := filepath.Join(rootPath, "report")
	if err := os.WriteFile(target, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, info, err := root.openRegularWith("report", func(pinnedFD int) (int, error) {
		if err := os.Link(target, filepath.Join(rootPath, "second-name")); err != nil {
			return -1, err
		}
		return reopenPinnedRegular(pinnedFD)
	})
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, unix.EPERM) || file != nil || info != nil {
		t.Fatalf("changed link count returned file=%v info=%v err=%v", file, info, err)
	}
}

func TestTokenRejectsUnsafeObjectBeforeDataOpen(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(base, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(base, "linked")
	if err := os.WriteFile(linked, []byte(safeOpenTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, filepath.Join(base, "linked-again")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linked, filepath.Join(base, "symlink")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"directory", "pipe", "linked", "symlink"} {
		t.Run(name, func(t *testing.T) {
			dataOpenCalls := 0
			token, err := readTokenFileSecureWith(filepath.Join(base, name), func(int) (int, error) {
				dataOpenCalls++
				return -1, errors.New("data open must not run")
			})
			if err == nil || token != nil {
				t.Fatalf("unsafe token %s returned token=%q err=%v", name, token, err)
			}
			if dataOpenCalls != 0 {
				t.Fatalf("unsafe token %s reached the data opener %d times", name, dataOpenCalls)
			}
		})
	}
}

func TestTokenFailsClosedWhenProcReopenIsUnavailable(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(safeOpenTestToken), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	token, err := readTokenFileSecureWith(tokenPath, func(int) (int, error) {
		calls++
		return -1, unix.ENOENT
	})
	if err == nil || token != nil {
		t.Fatalf("unavailable proc reopen returned token=%q err=%v", token, err)
	}
	if calls != 1 {
		t.Fatalf("proc reopener called %d times, want exactly once and no fallback", calls)
	}
}

func TestTokenRejectsReopenedIdentityMismatch(t *testing.T) {
	base := t.TempDir()
	expectedPath := filepath.Join(base, "expected-token")
	otherPath := filepath.Join(base, "other-token")
	if err := os.WriteFile(expectedPath, []byte(safeOpenTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte(strings.Repeat("A1", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	reopenedFD := -1
	token, err := readTokenFileSecureWith(expectedPath, func(int) (int, error) {
		fd, duplicateErr := unix.Dup(int(other.Fd()))
		reopenedFD = fd
		return fd, duplicateErr
	})
	if err == nil || token != nil || !strings.Contains(err.Error(), "stable single-link regular file") {
		t.Fatalf("identity mismatch returned token=%q err=%v", token, err)
	}
	var stat unix.Stat_t
	if statErr := unix.Fstat(reopenedFD, &stat); !errors.Is(statErr, unix.EBADF) {
		t.Fatalf("rejected token descriptor was not closed: %v", statErr)
	}
}

func TestTokenValidatesPermissionsOnReopenedDescriptor(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(safeOpenTestToken), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := readTokenFileSecureWith(tokenPath, func(pinnedFD int) (int, error) {
		if err := os.Chmod(tokenPath, 0o640); err != nil {
			return -1, err
		}
		return reopenPinnedRegular(pinnedFD)
	})
	if err == nil || token != nil || !strings.Contains(err.Error(), "inaccessible by group") {
		t.Fatalf("changed token permissions returned token=%q err=%v", token, err)
	}
}
