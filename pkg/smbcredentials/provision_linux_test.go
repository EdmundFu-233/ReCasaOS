//go:build linux

package smbcredentials

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

type sourceProvisionTestRoot struct {
	root      string
	directory string
	rootFD    int
	owner     uint32
	group     uint32
}

type countingSourceReader struct {
	reads atomic.Int64
}

func (r *countingSourceReader) Read(buffer []byte) (int, error) {
	r.reads.Add(1)
	for index := range buffer {
		buffer[index] = 0x7f
	}
	return len(buffer), nil
}

func newSourceProvisionTestRoot(t *testing.T) sourceProvisionTestRoot {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(root, "etc")
	directory := filepath.Join(etc, "recasaos")
	if err := os.Mkdir(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(
		root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		_ = unix.Close(rootFD)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(rootFD); err != nil {
			t.Errorf("close test root: %v", err)
		}
	})
	return sourceProvisionTestRoot{
		root:      root,
		directory: directory,
		rootFD:    rootFD,
		owner:     rootStat.Uid,
		group:     rootStat.Gid,
	}
}

func sourceProvisionTestOps(fill byte) sourceProvisionOps {
	ops := defaultSourceProvisionOps()
	ops.random = bytes.NewReader(bytes.Repeat([]byte{fill}, 4096))
	return ops
}

func forceNamedSourceProvision(ops *sourceProvisionOps) {
	openat := ops.openat
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		if name == "." && flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return -1, unix.EOPNOTSUPP
		}
		return openat(directoryFD, name, flags, mode)
	}
}

// emulateAnonymousSourceOpen supplies an unlinked regular file with nlink=0 so
// state-machine tests do not depend on the test filesystem supporting O_TMPFILE.
// Publication itself remains modeled by the individual test's linkat/fstatat
// hooks; the real-syscall integration test below covers AT_EMPTY_PATH.
func emulateAnonymousSourceOpen(ops *sourceProvisionOps) *int {
	openat := ops.openat
	unlinkat := ops.unlinkat
	closeFD := ops.close
	candidateFD := -1
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		if name != "." || flags&unix.O_TMPFILE != unix.O_TMPFILE {
			return openat(directoryFD, name, flags, mode)
		}
		fd, err := openat(
			directoryFD,
			".anonymous-candidate-test",
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if err != nil {
			return -1, err
		}
		if err := unlinkat(directoryFD, ".anonymous-candidate-test", 0); err != nil {
			_ = closeFD(fd)
			return -1, err
		}
		candidateFD = fd
		return fd, nil
	}
	return &candidateFD
}

func provisionSourceForTest(
	t *testing.T,
	root sourceProvisionTestRoot,
	ops sourceProvisionOps,
) (ProvisionResult, error) {
	t.Helper()
	return provisionSystemKeyringSourceAt(
		root.rootFD,
		root.owner,
		root.group,
		ops,
	)
}

func sourceTarget(root sourceProvisionTestRoot) string {
	return filepath.Join(root.directory, CredentialName)
}

func sourceStaging(root sourceProvisionTestRoot) string {
	return filepath.Join(root.directory, sourceKeyringStagingName)
}

func readAndValidateProvisionedSource(t *testing.T, root sourceProvisionTestRoot) []byte {
	t.Helper()
	path := sourceTarget(root)
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	wantSize := len(keyringMagic) + 1 + 1 + keyIDSize + keyIDSize + keySize
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o400 ||
		hasSpecialModeBits(stat.Mode) ||
		stat.Uid != root.owner || stat.Gid != root.group ||
		uint64(stat.Nlink) != 1 || stat.Size != int64(wantSize) {
		t.Fatalf(
			"source metadata mode=%v uid=%d gid=%d links=%d size=%d",
			stat.Mode,
			stat.Uid,
			stat.Gid,
			stat.Nlink,
			stat.Size,
		)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyring(data)
	if err != nil {
		clear(data)
		t.Fatal(err)
	}
	if len(parsed.KeyIDs()) != 1 || parsed.ActiveID() == "" {
		parsed.Destroy()
		clear(data)
		t.Fatal("provisioned source did not contain exactly one active key")
	}
	parsed.Destroy()
	return data
}

func TestProvisionSystemKeyringSourceUsesFixedPath(t *testing.T) {
	if SourceKeyringPath != "/etc/recasaos/"+CredentialName {
		t.Fatalf("SourceKeyringPath=%q", SourceKeyringPath)
	}
	if sourceKeyringStagingName != "."+CredentialName+".provisioning" {
		t.Fatalf("sourceKeyringStagingName=%q", sourceKeyringStagingName)
	}
}

func TestNamedSourceProvisionCreatesCanonicalKeyringAndNeverReplaces(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x41)
	forceNamedSourceProvision(&ops)
	result, err := provisionSourceForTest(t, root, ops)
	if err != nil || result != (ProvisionResult{Created: true}) {
		t.Fatalf("first provision result=%+v err=%v", result, err)
	}
	first := readAndValidateProvisionedSource(t, root)
	defer clear(first)
	if _, err := os.Lstat(sourceStaging(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging survived successful publish: %v", err)
	}

	secondOps := sourceProvisionTestOps(0x42)
	forceNamedSourceProvision(&secondOps)
	second, secondErr := provisionSourceForTest(t, root, secondOps)
	if second != (ProvisionResult{}) || !errors.Is(secondErr, ErrSourceKeyringExists) {
		t.Fatalf("second provision result=%+v err=%v", second, secondErr)
	}
	after, err := os.ReadFile(sourceTarget(root))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(first, after) {
		t.Fatal("second provision replaced the original source keyring")
	}
}

func TestSourceProvisionRejectsEveryExistingTargetObjectWithoutOpeningIt(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"regular": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("existing-secret-sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink("/does/not/matter", path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "other")
			if err := os.WriteFile(other, []byte("hardlink-sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(other, path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			path := sourceTarget(root)
			create(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			reader := &countingSourceReader{}
			ops := sourceProvisionTestOps(0x43)
			ops.random = reader
			openat := ops.openat
			unexpectedOpenErr := errors.New("test sentinel: existing target was opened")
			var targetOpenCount atomic.Int32
			ops.openat = func(directoryFD int, candidate string, flags int, mode uint32) (int, error) {
				if candidate == CredentialName {
					targetOpenCount.Add(1)
					return -1, unexpectedOpenErr
				}
				return openat(directoryFD, candidate, flags, mode)
			}
			var regularBefore []byte
			if name == "regular" || name == "hardlink" {
				regularBefore, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(regularBefore)
			}
			result, provisionErr := provisionSourceForTest(t, root, ops)
			if result != (ProvisionResult{}) || !errors.Is(provisionErr, ErrSourceKeyringExists) {
				t.Fatalf("result=%+v err=%v", result, provisionErr)
			}
			if errors.Is(provisionErr, unexpectedOpenErr) {
				t.Fatalf("existing target open sentinel reached error chain: %v", provisionErr)
			}
			if reader.reads.Load() != 0 {
				t.Fatalf("existing target consumed random key bytes %d times", reader.reads.Load())
			}
			if got := targetOpenCount.Load(); got != 0 {
				t.Fatalf("existing target was opened %d times", got)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("existing object changed: before=%v after=%v err=%v", before, after, err)
			}
			if regularBefore != nil {
				regularAfter, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatal(readErr)
				}
				defer clear(regularAfter)
				if !bytes.Equal(regularBefore, regularAfter) {
					t.Fatal("existing regular object contents changed")
				}
			}
		})
	}
}

func TestSourceProvisionTreatsEveryStagingObjectAsRecoveryMarker(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"regular": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("staged-secret"), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink("unknown", path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			path := sourceStaging(root)
			create(t, path)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			reader := &countingSourceReader{}
			ops := sourceProvisionTestOps(0x44)
			ops.random = reader
			result, provisionErr := provisionSourceForTest(t, root, ops)
			if result != (ProvisionResult{CleanupRequired: true}) ||
				!errors.Is(provisionErr, ErrSourceCleanupRequired) {
				t.Fatalf("result=%+v err=%v", result, provisionErr)
			}
			if reader.reads.Load() != 0 {
				t.Fatalf("existing marker consumed random key bytes %d times", reader.reads.Load())
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("marker changed: before=%v after=%v err=%v", before, after, err)
			}
			if _, err := os.Lstat(sourceTarget(root)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target appeared beside recovery marker: %v", err)
			}
		})
	}
}

func TestSourceProvisionReportsExistingTargetAndMarkerTogether(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	if err := os.WriteFile(sourceTarget(root), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourceStaging(root), []byte("staging"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := provisionSourceForTest(t, root, sourceProvisionTestOps(0x45))
	if result != (ProvisionResult{CleanupRequired: true}) ||
		!errors.Is(err, ErrSourceKeyringExists) ||
		!errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSourceProvisionNamespaceInspectionFailureIsRecoveryHold(t *testing.T) {
	for _, name := range []string{CredentialName, sourceKeyringStagingName} {
		for _, errno := range []error{unix.EIO, unix.EACCES} {
			t.Run(name+"/"+errno.Error(), func(t *testing.T) {
				root := newSourceProvisionTestRoot(t)
				reader := &countingSourceReader{}
				ops := sourceProvisionTestOps(0x46)
				ops.random = reader
				fstatat := ops.fstatat
				ops.fstatat = func(directoryFD int, candidate string, stat *unix.Stat_t, flags int) error {
					if candidate == name {
						return errno
					}
					return fstatat(directoryFD, candidate, stat, flags)
				}
				result, err := provisionSourceForTest(t, root, ops)
				if result != (ProvisionResult{CleanupRequired: true}) ||
					!errors.Is(err, ErrSourceCleanupRequired) ||
					!errors.Is(err, errno) {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if reader.reads.Load() != 0 {
					t.Fatalf("namespace inspection failure generated a key")
				}
				for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
					if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("inspection failure created %s: %v", path, statErr)
					}
				}
			})
		}
	}
	t.Run("known target plus unknown staging", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		target := []byte("known existing target")
		if err := os.WriteFile(sourceTarget(root), target, 0o600); err != nil {
			t.Fatal(err)
		}
		reader := &countingSourceReader{}
		ops := sourceProvisionTestOps(0x46)
		ops.random = reader
		fstatat := ops.fstatat
		ops.fstatat = func(directoryFD int, candidate string, stat *unix.Stat_t, flags int) error {
			if candidate == sourceKeyringStagingName {
				return unix.EIO
			}
			return fstatat(directoryFD, candidate, stat, flags)
		}
		result, err := provisionSourceForTest(t, root, ops)
		if result != (ProvisionResult{CleanupRequired: true}) ||
			!errors.Is(err, ErrSourceKeyringExists) ||
			!errors.Is(err, ErrSourceCleanupRequired) ||
			!errors.Is(err, unix.EIO) {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if reader.reads.Load() != 0 {
			t.Fatal("known target plus unknown staging generated a key")
		}
		got, readErr := os.ReadFile(sourceTarget(root))
		if readErr != nil || !bytes.Equal(got, target) {
			t.Fatalf("known target changed: got=%q err=%v", got, readErr)
		}
		clear(got)
	})
}

func TestSourceProvisionRejectsUnsafePathBoundary(t *testing.T) {
	tests := map[string]func(*testing.T, sourceProvisionTestRoot){
		"root writable by group": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.root, 0o720); err != nil {
				t.Fatal(err)
			}
		},
		"etc writable by group": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(filepath.Join(root.root, "etc"), 0o775); err != nil {
				t.Fatal(err)
			}
		},
		"source directory mode 0755": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.directory, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"source directory sticky": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.directory, 0o700|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			mutate(t, root)
			result, err := provisionSourceForTest(t, root, sourceProvisionTestOps(0x46))
			if result != (ProvisionResult{}) || !errors.Is(err, ErrUnsafeSourceKeyring) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if _, statErr := os.Lstat(sourceTarget(root)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unsafe boundary gained a target: %v", statErr)
			}
		})
	}
}

func TestSourceProvisionRejectsSymlinkedFixedComponents(t *testing.T) {
	for _, component := range []string{"etc", "recasaos"} {
		t.Run(component, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(parent, "root")
			if err := os.Mkdir(base, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(base, 0o700); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			if err := os.Chmod(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			if component == "etc" {
				if err := os.Symlink(outside, filepath.Join(base, "etc")); err != nil {
					t.Fatal(err)
				}
			} else {
				etc := filepath.Join(base, "etc")
				if err := os.Mkdir(etc, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(etc, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(etc, "recasaos")); err != nil {
					t.Fatal(err)
				}
			}
			rootFD, err := unix.Open(
				base,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(rootFD)
			var rootStat unix.Stat_t
			if err := unix.Fstat(rootFD, &rootStat); err != nil {
				t.Fatal(err)
			}
			result, provisionErr := provisionSystemKeyringSourceAt(
				rootFD,
				rootStat.Uid,
				rootStat.Gid,
				sourceProvisionTestOps(0x47),
			)
			if result != (ProvisionResult{}) || provisionErr == nil {
				t.Fatalf("result=%+v err=%v", result, provisionErr)
			}
			if _, err := os.Lstat(filepath.Join(outside, CredentialName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("symlink target gained a keyring: %v", err)
			}
		})
	}
}

func TestSourceProvisionUsesOnlyRequiredNoReplaceFlags(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x48)
	openat := ops.openat
	var anonymousFlags, namedFlags int
	var anonymousMode, namedMode uint32
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		switch {
		case name == "." && flags&unix.O_TMPFILE == unix.O_TMPFILE:
			anonymousFlags, anonymousMode = flags, mode
			return -1, unix.EOPNOTSUPP
		case name == sourceKeyringStagingName:
			namedFlags, namedMode = flags, mode
		}
		return openat(directoryFD, name, flags, mode)
	}
	var renameFlags uint
	renameat2 := ops.renameat2
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		renameFlags = flags
		return renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if err != nil || result != (ProvisionResult{Created: true}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	wantAnonymousFlags := unix.O_TMPFILE | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if anonymousFlags != wantAnonymousFlags ||
		anonymousMode != 0 {
		t.Fatalf("anonymous flags=%#x mode=%#o", anonymousFlags, anonymousMode)
	}
	wantNamedFlags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC |
		unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
	if namedFlags != wantNamedFlags ||
		namedMode != 0 {
		t.Fatalf("named flags=%#x mode=%#o", namedFlags, namedMode)
	}
	if renameFlags != uint(unix.RENAME_NOREPLACE) {
		t.Fatalf("rename flags=%#x", renameFlags)
	}
}

func TestSourceProvisionHandlesPartialIOAndEINTR(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x49)
	forceNamedSourceProvision(&ops)
	write := ops.write
	var writeInterrupted atomic.Bool
	ops.write = func(fd int, data []byte) (int, error) {
		if writeInterrupted.CompareAndSwap(false, true) {
			return 0, unix.EINTR
		}
		if len(data) > 7 {
			data = data[:7]
		}
		return write(fd, data)
	}
	pread := ops.pread
	var readInterrupted atomic.Bool
	ops.pread = func(fd int, data []byte, offset int64) (int, error) {
		if readInterrupted.CompareAndSwap(false, true) {
			return 0, unix.EINTR
		}
		if len(data) > 11 {
			data = data[:11]
		}
		return pread(fd, data, offset)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if err != nil || result != (ProvisionResult{Created: true}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
}

func TestSourceProvisionPrepublicationFailureCleansNamedCandidate(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps('K')
	forceNamedSourceProvision(&ops)
	fsync := ops.fsync
	ops.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFREG {
			return unix.EIO
		}
		return fsync(fd)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || err == nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if strings.Contains(err.Error(), strings.Repeat("K", 16)) {
		t.Fatalf("error leaked raw key bytes: %v", err)
	}
	for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("prepublication failure left %s: %v", path, statErr)
		}
	}
}

func TestSourceProvisionStagingDirectorySyncFailureNeverRenames(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x4a)
	forceNamedSourceProvision(&ops)
	fsync := ops.fsync
	var stagingSyncFailed atomic.Bool
	ops.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
			stagingSyncFailed.CompareAndSwap(false, true) {
			return unix.EIO
		}
		return fsync(fd)
	}
	var renameCalled atomic.Bool
	ops.renameat2 = func(int, string, int, string, uint) error {
		renameCalled.Store(true)
		return errors.New("test sentinel: rename called after staging sync failure")
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || !errors.Is(err, unix.EIO) ||
		errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !stagingSyncFailed.Load() || renameCalled.Load() {
		t.Fatalf(
			"stagingSyncFailed=%t renameCalled=%t",
			stagingSyncFailed.Load(),
			renameCalled.Load(),
		)
	}
	for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("staging sync failure left %s: %v", path, statErr)
		}
	}
}

func TestSourceProvisionDirectorySyncFailureRetainsCreatedTarget(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x4a)
	forceNamedSourceProvision(&ops)
	fsync := ops.fsync
	ops.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			if _, err := os.Lstat(sourceTarget(root)); err == nil {
				return unix.EIO
			}
		}
		return fsync(fd)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) || err == nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	first := readAndValidateProvisionedSource(t, root)
	defer clear(first)
	second, secondErr := provisionSourceForTest(t, root, sourceProvisionTestOps(0x4b))
	if second != (ProvisionResult{}) || !errors.Is(secondErr, ErrSourceKeyringExists) {
		t.Fatalf("second result=%+v err=%v", second, secondErr)
	}
	after, readErr := os.ReadFile(sourceTarget(root))
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(after)
	if !bytes.Equal(first, after) {
		t.Fatal("retry replaced created-but-durability-unknown source")
	}
}

func TestSourceProvisionCleanupFailureLeavesRecoveryMarker(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps('L')
	forceNamedSourceProvision(&ops)
	ops.renameat2 = func(int, string, int, string, uint) error { return unix.EIO }
	ops.unlinkat = func(int, string, int) error { return unix.EIO }
	result, err := provisionSourceForTest(t, root, ops)
	if !result.CleanupRequired || result.Created || err == nil ||
		!errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if strings.Contains(err.Error(), strings.Repeat("L", 16)) {
		t.Fatalf("error leaked raw key bytes: %v", err)
	}
	if _, statErr := os.Lstat(sourceStaging(root)); statErr != nil {
		t.Fatalf("recovery marker missing: %v", statErr)
	}
	second, secondErr := provisionSourceForTest(t, root, sourceProvisionTestOps(0x4c))
	if second != (ProvisionResult{CleanupRequired: true}) ||
		!errors.Is(secondErr, ErrSourceCleanupRequired) {
		t.Fatalf("second result=%+v err=%v", second, secondErr)
	}
	if _, statErr := os.Lstat(sourceTarget(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("target appeared despite recovery marker: %v", statErr)
	}
}

func TestSourceProvisionCleanupSyncFailureIsRecoveryRequired(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x4d)
	forceNamedSourceProvision(&ops)
	var renameAttempted atomic.Bool
	ops.renameat2 = func(int, string, int, string, uint) error {
		renameAttempted.Store(true)
		return unix.EIO
	}
	fsync := ops.fsync
	ops.fsync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR && renameAttempted.Load() {
			return unix.EIO
		}
		return fsync(fd)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{CleanupRequired: true}) || err == nil ||
		!errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !renameAttempted.Load() {
		t.Fatal("rename failure path was not exercised")
	}
	if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("cleanup-sync failure left visible marker: %v", statErr)
	}
}

func TestSourceProvisionRenameUnsupportedNeverFallsBackToPlainRename(t *testing.T) {
	for _, errno := range []error{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			ops := sourceProvisionTestOps(0x4e)
			forceNamedSourceProvision(&ops)
			ops.renameat2 = func(int, string, int, string, uint) error { return errno }
			result, err := provisionSourceForTest(t, root, ops)
			if result != (ProvisionResult{}) ||
				!errors.Is(err, ErrSourceProvisionUnsupported) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
				if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("unsupported rename left %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestSourceProvisionLosingRenameNeverOverwritesCompetitor(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x4f)
	forceNamedSourceProvision(&ops)
	competitor := []byte("competitor-source-sentinel")
	renameat2 := ops.renameat2
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := os.WriteFile(sourceTarget(root), competitor, 0o600); err != nil {
			return err
		}
		return renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || !errors.Is(err, ErrSourceKeyringExists) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	got, readErr := os.ReadFile(sourceTarget(root))
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(got)
	if !bytes.Equal(got, competitor) {
		t.Fatalf("competitor changed: got %q", got)
	}
	if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("losing staging survived: %v", statErr)
	}
}

func TestSourceProvisionRenameConflictRemainsHoldAfterCompetitorDisappears(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x4f)
	forceNamedSourceProvision(&ops)
	renameat2 := ops.renameat2
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := os.WriteFile(sourceTarget(root), []byte("transient competitor"), 0o600); err != nil {
			return err
		}
		err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags)
		if err == nil {
			return errors.New("rename unexpectedly replaced transient competitor")
		}
		if removeErr := os.Remove(sourceTarget(root)); removeErr != nil {
			return errors.Join(err, removeErr)
		}
		return err
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || !errors.Is(err, ErrSourceKeyringExists) ||
		!errors.Is(err, unix.EEXIST) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("transient conflict left %s: %v", path, statErr)
		}
	}
}

func TestSourceProvisionAnonymousPathUsesRealEmptyPathLinkWithoutExclusiveFlag(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	probeFD, probeErr := unix.Openat(
		root.rootFD,
		"etc/recasaos",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	tmpFD, tmpErr := unix.Openat(
		probeFD,
		".",
		unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	_ = unix.Close(probeFD)
	if tmpErr != nil {
		t.Skipf("filesystem does not support O_TMPFILE: %v", tmpErr)
	}
	_ = unix.Close(tmpFD)

	ops := sourceProvisionTestOps(0x50)
	var gotOldPath string
	var gotFlags int
	var actualLinkErr error
	ops.linkat = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags int) error {
		gotOldPath, gotFlags = oldName, flags
		actualLinkErr = unix.Linkat(
			oldDirectoryFD,
			oldName,
			newDirectoryFD,
			newName,
			flags,
		)
		return actualLinkErr
	}
	result, err := provisionSourceForTest(t, root, ops)
	if gotOldPath != "" || gotFlags != unix.AT_EMPTY_PATH {
		t.Fatalf("linkat oldPath=%q flags=%#x", gotOldPath, gotFlags)
	}
	if actualLinkErr != nil {
		if errors.Is(actualLinkErr, unix.ENOENT) {
			if err != nil || result != (ProvisionResult{Created: true}) {
				t.Fatalf("named fallback result=%+v err=%v", result, err)
			}
			data := readAndValidateProvisionedSource(t, root)
			clear(data)
			if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("AT_EMPTY_PATH fallback retained staging: %v", statErr)
			}
			return
		}
		t.Fatalf("real AT_EMPTY_PATH link failed: %v", actualLinkErr)
	}
	if err != nil || result != (ProvisionResult{Created: true}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
}

func TestSourceProvisionAnonymousPublicationStateMatrix(t *testing.T) {
	tests := []struct {
		name       string
		linkErr    error
		wantResult ProvisionResult
	}{
		{
			name:       "success",
			wantResult: ProvisionResult{Created: true},
		},
		{
			name:       "publication visible after EIO",
			linkErr:    unix.EIO,
			wantResult: ProvisionResult{Created: true, DurabilityUnknown: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			ops := sourceProvisionTestOps(0x51)
			candidateFD := emulateAnonymousSourceOpen(&ops)
			fstat := ops.fstat
			var published atomic.Bool
			ops.fstat = func(fd int, stat *unix.Stat_t) error {
				if err := fstat(fd, stat); err != nil {
					return err
				}
				if published.Load() && fd == *candidateFD {
					stat.Nlink = 1
				}
				return nil
			}
			fstatat := ops.fstatat
			ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
				if name != CredentialName || !published.Load() {
					return fstatat(directoryFD, name, stat, flags)
				}
				if err := fstat(*candidateFD, stat); err != nil {
					return err
				}
				stat.Nlink = 1
				return nil
			}
			ops.linkat = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags int) error {
				if oldDirectoryFD != *candidateFD || oldName != "" ||
					newName != CredentialName || flags != unix.AT_EMPTY_PATH {
					t.Fatalf(
						"linkat oldFD=%d candidateFD=%d oldName=%q newName=%q flags=%#x",
						oldDirectoryFD,
						*candidateFD,
						oldName,
						newName,
						flags,
					)
				}
				published.Store(true)
				return test.linkErr
			}
			result, err := provisionSourceForTest(t, root, ops)
			if result != test.wantResult {
				t.Fatalf("result=%+v want=%+v err=%v", result, test.wantResult, err)
			}
			if test.linkErr == nil && err != nil {
				t.Fatalf("unexpected success error: %v", err)
			}
			if test.linkErr != nil && !errors.Is(err, test.linkErr) {
				t.Fatalf("err=%v does not contain %v", err, test.linkErr)
			}
		})
	}
}

func TestSourceProvisionAnonymousConflictPreservesCompetitor(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x52)
	emulateAnonymousSourceOpen(&ops)
	competitor := []byte("anonymous-link-competitor")
	ops.linkat = func(int, string, int, string, int) error {
		if err := os.WriteFile(sourceTarget(root), competitor, 0o600); err != nil {
			t.Fatalf("create competitor: %v", err)
		}
		return unix.EEXIST
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || !errors.Is(err, ErrSourceKeyringExists) ||
		!errors.Is(err, unix.EEXIST) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	got, readErr := os.ReadFile(sourceTarget(root))
	if readErr != nil || !bytes.Equal(got, competitor) {
		t.Fatalf("competitor changed: got=%q err=%v", got, readErr)
	}
	clear(got)
}

func TestSourceProvisionAnonymousENOENTFallsBackWithSameKey(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x52)
	candidateFD := emulateAnonymousSourceOpen(&ops)
	var anonymousData []byte
	var linkAttempted bool
	write := ops.write
	ops.write = func(fd int, data []byte) (int, error) {
		n, err := write(fd, data)
		if n > 0 && fd == *candidateFD && !linkAttempted {
			anonymousData = append(anonymousData, data[:n]...)
		}
		return n, err
	}
	ops.linkat = func(int, string, int, string, int) error {
		linkAttempted = true
		return unix.ENOENT
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true}) || err != nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	published := readAndValidateProvisionedSource(t, root)
	defer clear(published)
	defer clear(anonymousData)
	if len(anonymousData) != len(published) || !bytes.Equal(anonymousData, published) {
		t.Fatal("named fallback did not publish the anonymous candidate key bytes")
	}
	if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("ENOENT fallback retained staging: %v", statErr)
	}
}

func TestSourceProvisionAnonymousDefinitiveLinkErrorsDoNotFallback(t *testing.T) {
	for _, errno := range []error{
		unix.EPERM,
		unix.EACCES,
		unix.EROFS,
		unix.EINVAL,
		unix.ENOSYS,
		unix.EBADF,
		unix.EXDEV,
		unix.EOPNOTSUPP,
	} {
		t.Run(errno.Error(), func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			ops := sourceProvisionTestOps(0x53)
			emulateAnonymousSourceOpen(&ops)
			ops.linkat = func(int, string, int, string, int) error {
				return errno
			}
			result, err := provisionSourceForTest(t, root, ops)
			if result != (ProvisionResult{}) || !errors.Is(err, errno) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
				if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("definitive link error created %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestSourceProvisionDoesNotTreatAnonymousPolicyDenialAsFallback(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x51)
	openat := ops.openat
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		if name == "." && flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return -1, unix.EPERM
		}
		return openat(directoryFD, name, flags, mode)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{}) || !errors.Is(err, unix.EPERM) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, path := range []string{sourceTarget(root), sourceStaging(root)} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("policy denial created %s: %v", path, statErr)
		}
	}
}

func TestSourceProvisionCandidateCloseErrorPreservesCreatedState(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x52)
	forceNamedSourceProvision(&ops)
	openat := ops.openat
	candidateFD := -1
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		fd, err := openat(directoryFD, name, flags, mode)
		if err == nil && name == sourceKeyringStagingName {
			candidateFD = fd
		}
		return fd, err
	}
	closeFD := ops.close
	ops.close = func(fd int) error {
		err := closeFD(fd)
		if fd == candidateFD {
			return errors.Join(err, unix.EIO)
		}
		return err
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) ||
		!errors.Is(err, unix.EIO) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
}

func TestSourceProvisionRenameErrorAfterPublicationIsCreatedUnknown(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x53)
	forceNamedSourceProvision(&ops)
	renameat2 := ops.renameat2
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		return unix.EIO
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) ||
		!errors.Is(err, unix.EIO) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
	if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staging survived completed rename: %v", statErr)
	}
}

func TestSourceProvisionRenameErrorWithNewMarkerRequiresCleanup(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x56)
	forceNamedSourceProvision(&ops)
	renameat2 := ops.renameat2
	marker := []byte("unrelated concurrent marker")
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if err := os.WriteFile(sourceStaging(root), marker, 0o600); err != nil {
			t.Fatalf("create concurrent marker: %v", err)
		}
		return unix.EIO
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{
		Created:           true,
		DurabilityUnknown: true,
		CleanupRequired:   true,
	}) || !errors.Is(err, unix.EIO) || !errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
	gotMarker, readErr := os.ReadFile(sourceStaging(root))
	if readErr != nil || !bytes.Equal(gotMarker, marker) {
		t.Fatalf("concurrent marker changed: got=%q err=%v", gotMarker, readErr)
	}
}

func TestSourceProvisionRenameAndInspectionErrorsPreserveUnknownPublication(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x54)
	forceNamedSourceProvision(&ops)
	renameat2 := ops.renameat2
	var published atomic.Bool
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		published.Store(true)
		return unix.EIO
	}
	fstatat := ops.fstatat
	ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
		if name == CredentialName && published.Load() {
			return unix.EACCES
		}
		return fstatat(directoryFD, name, stat, flags)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{
		Created:           true,
		DurabilityUnknown: true,
		CleanupRequired:   true,
	}) || !errors.Is(err, unix.EIO) || !errors.Is(err, unix.EACCES) ||
		!errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
	if _, statErr := os.Lstat(sourceStaging(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("completed rename retained staging: %v", statErr)
	}
}

func TestSourceProvisionStagingInspectionErrorAfterRenameFailurePreservesMarker(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x55)
	forceNamedSourceProvision(&ops)
	var renameAttempted atomic.Bool
	ops.renameat2 = func(int, string, int, string, uint) error {
		renameAttempted.Store(true)
		return unix.EIO
	}
	fstatat := ops.fstatat
	ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
		if name == sourceKeyringStagingName && renameAttempted.Load() {
			return unix.EACCES
		}
		return fstatat(directoryFD, name, stat, flags)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{
		Created:           true,
		DurabilityUnknown: true,
		CleanupRequired:   true,
	}) || !errors.Is(err, unix.EIO) || !errors.Is(err, unix.EACCES) ||
		!errors.Is(err, ErrSourceCleanupRequired) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, statErr := os.Lstat(sourceStaging(root)); statErr != nil {
		t.Fatalf("ambiguous staging marker was not preserved: %v", statErr)
	}
	if _, statErr := os.Lstat(sourceTarget(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed rename created target: %v", statErr)
	}
}

func TestSourceProvisionPostPublicationStatFailureIsCreatedUnknown(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x56)
	forceNamedSourceProvision(&ops)
	fstatat := ops.fstatat
	ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
		if name == CredentialName {
			if _, err := os.Lstat(sourceTarget(root)); err == nil {
				return unix.EIO
			}
		}
		return fstatat(directoryFD, name, stat, flags)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) ||
		!errors.Is(err, unix.EIO) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
}

func TestSourceProvisionPathReplacementAfterPublishIsCreatedUnknown(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x57)
	forceNamedSourceProvision(&ops)
	renameat2 := ops.renameat2
	movedDirectory := root.directory + ".moved"
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if err := os.Rename(root.directory, movedDirectory); err != nil {
			return err
		}
		return os.Mkdir(root.directory, 0o700)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) ||
		!errors.Is(err, ErrUnsafeSourceKeyring) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, statErr := os.Lstat(sourceTarget(root)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("replacement canonical directory gained target: %v", statErr)
	}
	movedTarget := filepath.Join(movedDirectory, CredentialName)
	data, readErr := os.ReadFile(movedTarget)
	if readErr != nil {
		t.Fatalf("published inode was not preserved in displaced directory: %v", readErr)
	}
	defer clear(data)
	parsed, parseErr := ParseKeyring(data)
	if parseErr != nil {
		t.Fatalf("displaced publication is malformed: %v", parseErr)
	}
	parsed.Destroy()
}

func TestSourceProvisionTargetReplacementAfterPublishIsCreatedUnknown(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	ops := sourceProvisionTestOps(0x58)
	forceNamedSourceProvision(&ops)
	openat := ops.openat
	var targetOpenCount atomic.Int32
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		if name == CredentialName {
			targetOpenCount.Add(1)
		}
		return openat(directoryFD, name, flags, mode)
	}
	renameat2 := ops.renameat2
	competitor := []byte("post-publication-competitor")
	ops.renameat2 = func(oldDirectoryFD int, oldName string, newDirectoryFD int, newName string, flags uint) error {
		if err := renameat2(oldDirectoryFD, oldName, newDirectoryFD, newName, flags); err != nil {
			return err
		}
		if err := os.Remove(sourceTarget(root)); err != nil {
			return err
		}
		return os.WriteFile(sourceTarget(root), competitor, 0o600)
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result != (ProvisionResult{Created: true, DurabilityUnknown: true}) ||
		!errors.Is(err, ErrUnsafeSourceKeyring) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if got := targetOpenCount.Load(); got != 0 {
		t.Fatalf("post-publication replacement was opened %d times", got)
	}
	got, readErr := os.ReadFile(sourceTarget(root))
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(got)
	if !bytes.Equal(got, competitor) {
		t.Fatalf("post-publication competitor changed: got %q", got)
	}
}

func TestSourceProvisionConcurrentCallsPublishAtMostOneKeyring(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	const callers = 32
	type outcome struct {
		result ProvisionResult
		err    error
	}
	outcomes := make(chan outcome, callers)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(callers)
	for index := 0; index < callers; index++ {
		go func(fill byte) {
			ready.Done()
			<-start
			ops := sourceProvisionTestOps(fill)
			forceNamedSourceProvision(&ops)
			result, err := provisionSystemKeyringSourceAt(
				root.rootFD,
				root.owner,
				root.group,
				ops,
			)
			outcomes <- outcome{result: result, err: err}
		}(byte(index + 1))
	}
	ready.Wait()
	close(start)
	created := 0
	for index := 0; index < callers; index++ {
		outcome := <-outcomes
		if outcome.result.Created {
			created++
			if outcome.err != nil {
				t.Fatalf("created outcome err=%v result=%+v", outcome.err, outcome.result)
			}
			continue
		}
		if !errors.Is(outcome.err, ErrSourceKeyringExists) &&
			!errors.Is(outcome.err, ErrSourceCleanupRequired) {
			t.Fatalf("loser result=%+v err=%v", outcome.result, outcome.err)
		}
	}
	if created != 1 {
		t.Fatalf("created=%d want=1", created)
	}
	data := readAndValidateProvisionedSource(t, root)
	clear(data)
	if _, err := os.Lstat(sourceStaging(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrent staging survived: %v", err)
	}
}

func TestSourceMetadataPredicatesRejectOwnershipModeAndTypeConfusion(t *testing.T) {
	base := unix.Stat_t{
		Mode: unix.S_IFDIR | 0o755,
		Uid:  100,
		Gid:  200,
	}
	if !safeSourceAncestor(base, 100, 200) {
		t.Fatal("safe ancestor rejected")
	}
	mutations := map[string]func(*unix.Stat_t){
		"type":        func(stat *unix.Stat_t) { stat.Mode = unix.S_IFREG | 0o755 },
		"uid":         func(stat *unix.Stat_t) { stat.Uid++ },
		"gid":         func(stat *unix.Stat_t) { stat.Gid++ },
		"group write": func(stat *unix.Stat_t) { stat.Mode |= 0o020 },
		"other write": func(stat *unix.Stat_t) { stat.Mode |= 0o002 },
		"setuid":      func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISUID },
		"setgid":      func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISGID },
		"sticky":      func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISVTX },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if safeSourceAncestor(candidate, 100, 200) {
				t.Fatalf("unsafe ancestor accepted: %+v", candidate)
			}
		})
	}
	directory := base
	directory.Mode = unix.S_IFDIR | 0o700
	if !safeSourceDirectory(directory, 100, 200) {
		t.Fatal("safe source directory rejected")
	}
	for _, mode := range []uint32{0o500, 0o600, 0o710, 0o755} {
		candidate := directory
		candidate.Mode = unix.S_IFDIR | mode
		if safeSourceDirectory(candidate, 100, 200) {
			t.Fatalf("source directory mode %#o accepted", mode)
		}
	}
}

func TestSourceProvisionErrorsNeverContainSerializedKeyring(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	fill := byte('S')
	ops := sourceProvisionTestOps(fill)
	forceNamedSourceProvision(&ops)
	ops.renameat2 = func(int, string, int, string, uint) error {
		return fmt.Errorf("static publish failure")
	}
	result, err := provisionSourceForTest(t, root, ops)
	if result.Created || err == nil {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, secret := range []string{
		strings.Repeat(string(fill), keySize),
		"RCSMBKEY",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked keyring material %q: %v", secret, err)
		}
	}
}
