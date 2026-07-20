//go:build linux

package publicfiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const safeOpenTestToken = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

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
