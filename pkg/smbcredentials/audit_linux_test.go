//go:build linux

package smbcredentials

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

func requireClearedAuditBuffer(t *testing.T, buffer []byte, context string) {
	t.Helper()
	for index, value := range buffer {
		if value != 0 {
			t.Fatalf("%s buffer byte %d was not cleared", context, index)
		}
	}
}

func auditSourceForTest(
	root sourceProvisionTestRoot,
	ops sourceAuditOps,
) error {
	rootFD, err := unix.Open(
		root.root,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	return checkSystemKeyringSourceStructureAt(
		rootFD,
		root.owner,
		root.group,
		ops,
	)
}

func canonicalSourceAuditData(t *testing.T, count int) []byte {
	t.Helper()
	if count < 1 || count > maxKeys {
		t.Fatalf("invalid test key count %d", count)
	}
	randomBytes := make([]byte, count*keySize)
	for index := 0; index < count; index++ {
		for offset := 0; offset < keySize; offset++ {
			randomBytes[index*keySize+offset] = byte(0x20 + index)
		}
	}
	defer clear(randomBytes)
	random := bytes.NewReader(randomBytes)
	keyring, err := newKeyring(random)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index < count; index++ {
		rotated, rotateErr := keyring.rotate(random)
		keyring.Destroy()
		if rotateErr != nil {
			t.Fatal(rotateErr)
		}
		keyring = rotated
	}
	data, err := keyring.Marshal()
	keyring.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeSourceAuditTarget(
	t *testing.T,
	root sourceProvisionTestRoot,
	data []byte,
	mode os.FileMode,
) {
	t.Helper()
	if err := os.WriteFile(sourceTarget(root), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sourceTarget(root), mode); err != nil {
		t.Fatal(err)
	}
}

func provisionCanonicalSourceForAudit(
	t *testing.T,
	root sourceProvisionTestRoot,
	fill byte,
) {
	t.Helper()
	ops := sourceProvisionTestOps(fill)
	forceNamedSourceProvision(&ops)
	result, err := provisionSourceForTest(t, root, ops)
	if err != nil || result != (ProvisionResult{Created: true}) {
		t.Fatalf("provision audit fixture result=%+v err=%v", result, err)
	}
}

func TestSourceAuditOpsExposeOnlyReadCapabilities(t *testing.T) {
	auditType := reflect.TypeOf(sourceAuditOps{})
	if auditType.NumField() != 2 ||
		auditType.Field(0).Name != "sourcePathOps" ||
		auditType.Field(1).Name != "pread" {
		t.Fatalf("sourceAuditOps fields changed: %v", auditType)
	}
	pathType := reflect.TypeOf(sourcePathOps{})
	wantPathFields := []string{"openat", "fstat", "fstatat", "close"}
	if pathType.NumField() != len(wantPathFields) {
		t.Fatalf("sourcePathOps field count=%d", pathType.NumField())
	}
	for index, want := range wantPathFields {
		if got := pathType.Field(index).Name; got != want {
			t.Fatalf("sourcePathOps field %d=%q want=%q", index, got, want)
		}
	}
	forbidden := []string{
		"random", "write", "chmod", "chown", "sync", "link", "rename", "unlink",
	}
	for index := 0; index < auditType.NumField(); index++ {
		name := strings.ToLower(auditType.Field(index).Name)
		for _, fragment := range forbidden {
			if strings.Contains(name, fragment) {
				t.Fatalf("audit ops expose mutation capability %q", name)
			}
		}
	}
}

func TestSourceAuditAcceptsCanonicalKeyringWithoutSideEffects(t *testing.T) {
	const wantPinnedFlags = unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
	const wantDirectoryFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if sourceObjectPathOpenFlags != wantPinnedFlags {
		t.Fatalf("sourceObjectPathOpenFlags=%#x want=%#x", sourceObjectPathOpenFlags, wantPinnedFlags)
	}
	if sourceDirectoryPathOpenFlags != wantDirectoryFlags {
		t.Fatalf(
			"sourceDirectoryPathOpenFlags=%#x want=%#x",
			sourceDirectoryPathOpenFlags,
			wantDirectoryFlags,
		)
	}

	root := newSourceProvisionTestRoot(t)
	provisionCanonicalSourceForAudit(t, root, 0x61)
	beforeData, err := os.ReadFile(sourceTarget(root))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(beforeData)
	var before unix.Stat_t
	if err := unix.Lstat(sourceTarget(root), &before); err != nil {
		t.Fatal(err)
	}

	ops := defaultSourceAuditOps()
	openat := ops.openat
	var pinnedOpens atomic.Int32
	var readOpens atomic.Int32
	readFD := -1
	var captured []byte
	ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
		if name == CredentialName {
			switch flags {
			case unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW:
				pinnedOpens.Add(1)
			case unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW |
				unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOATIME:
				readOpens.Add(1)
			default:
				t.Errorf("unexpected target open flags %#x", flags)
				return -1, unix.EINVAL
			}
			if mode != 0 {
				t.Errorf("target open mode %#o", mode)
				return -1, unix.EINVAL
			}
		} else if name == "etc" || name == "recasaos" {
			if flags != unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW {
				t.Errorf("directory %q open flags %#x", name, flags)
				return -1, unix.EINVAL
			}
			if mode != 0 {
				t.Errorf("directory %q open mode %#o", name, mode)
				return -1, unix.EINVAL
			}
		}
		fd, err := openat(directoryFD, name, flags, mode)
		if err == nil && name == CredentialName && flags&unix.O_PATH == 0 {
			readFD = fd
		}
		return fd, err
	}
	fstat := ops.fstat
	targetStatCalls := 0
	finalRecheckSawCleared := false
	ops.fstat = func(fd int, stat *unix.Stat_t) error {
		if fd == readFD {
			targetStatCalls++
			if targetStatCalls == 3 {
				finalRecheckSawCleared = true
				for index, value := range captured {
					if value != 0 {
						t.Errorf("final recheck retained audit buffer byte %d", index)
						return unix.EINVAL
					}
				}
			}
		}
		return fstat(fd, stat)
	}
	fstatat := ops.fstatat
	ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
		if flags != unix.AT_SYMLINK_NOFOLLOW {
			t.Errorf("fstatat %q flags=%#x", name, flags)
			return unix.EINVAL
		}
		return fstatat(directoryFD, name, stat, flags)
	}
	pread := ops.pread
	var preadCalls atomic.Int32
	ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
		preadCalls.Add(1)
		if captured == nil {
			captured = buffer[:cap(buffer)]
		}
		return pread(fd, buffer, offset)
	}

	if err := auditSourceForTest(root, ops); err != nil {
		t.Fatal(err)
	}
	if pinnedOpens.Load() != 1 || readOpens.Load() != 1 || preadCalls.Load() < 2 ||
		!finalRecheckSawCleared {
		t.Fatalf(
			"pinned=%d read=%d pread=%d final-cleared=%v",
			pinnedOpens.Load(),
			readOpens.Load(),
			preadCalls.Load(),
			finalRecheckSawCleared,
		)
	}
	requireClearedAuditBuffer(t, captured, "successful audit")
	var after unix.Stat_t
	if err := unix.Lstat(sourceTarget(root), &after); err != nil {
		t.Fatal(err)
	}
	if !sameSourceAuditSnapshot(before, after) || before.Atim != after.Atim {
		t.Fatalf("audit changed target metadata: before=%+v after=%+v", before, after)
	}
	afterData, err := os.ReadFile(sourceTarget(root))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(afterData)
	if !bytes.Equal(beforeData, afterData) {
		t.Fatal("audit changed target bytes")
	}
}

func TestSourceAuditAcceptsMaximumCanonicalKeyring(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	data := canonicalSourceAuditData(t, maxKeys)
	defer clear(data)
	if len(data) != maxKeyringBytes {
		t.Fatalf("maximum keyring length=%d want=%d", len(data), maxKeyringBytes)
	}
	writeSourceAuditTarget(t, root, data, 0o400)
	if err := auditSourceForTest(root, defaultSourceAuditOps()); err != nil {
		t.Fatal(err)
	}
}

func TestSourceAuditPublicWrapperRejectsNonRootBeforeFilesystemAccess(t *testing.T) {
	if os.Getuid() == 0 && os.Geteuid() == 0 && os.Getgid() == 0 && os.Getegid() == 0 {
		t.Skip("test process is fully root")
	}
	if err := CheckSystemKeyringSourceStructure(); !errors.Is(err, ErrUnsafeSourceKeyring) {
		t.Fatalf("CheckSystemKeyringSourceStructure() error=%v", err)
	}
}

func TestSourceAuditStableMissingAndRecoveryMarkerPrecedence(t *testing.T) {
	t.Run("stable missing", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		ops := defaultSourceAuditOps()
		fstatat := ops.fstatat
		markerChecks := 0
		targetConfirmations := 0
		ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
			if flags != unix.AT_SYMLINK_NOFOLLOW {
				t.Errorf("fstatat %q flags=%#x", name, flags)
				return unix.EINVAL
			}
			switch name {
			case sourceKeyringStagingName:
				markerChecks++
			case CredentialName:
				targetConfirmations++
			}
			return fstatat(directoryFD, name, stat, flags)
		}
		openat := ops.openat
		targetOpens := 0
		ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
			if name == CredentialName {
				targetOpens++
				if flags != unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW || mode != 0 {
					t.Errorf("missing target open flags=%#x mode=%#o", flags, mode)
					return -1, unix.EINVAL
				}
			}
			return openat(directoryFD, name, flags, mode)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrSourceKeyringMissing) ||
			errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceCleanupRequired) {
			t.Fatalf("stable missing error=%v", err)
		}
		if markerChecks != 3 || targetConfirmations != 2 || targetOpens != 1 {
			t.Fatalf(
				"stable missing marker checks=%d target confirmations=%d target opens=%d",
				markerChecks,
				targetConfirmations,
				targetOpens,
			)
		}
	})

	markerCreators := map[string]func(*testing.T, string){
		"regular": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("marker"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			if err := os.Symlink("missing", path); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, path string) {
			if err := unix.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "marker-other")
			if err := os.WriteFile(other, []byte("marker"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(other, path); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range markerCreators {
		t.Run("marker "+name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x62)
			create(t, sourceStaging(root))
			ops := defaultSourceAuditOps()
			openat := ops.openat
			var targetOpens atomic.Int32
			ops.openat = func(directoryFD int, candidate string, flags int, mode uint32) (int, error) {
				if candidate == CredentialName {
					targetOpens.Add(1)
				}
				return openat(directoryFD, candidate, flags, mode)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrSourceCleanupRequired) || targetOpens.Load() != 0 {
				t.Fatalf("error=%v target opens=%d", err, targetOpens.Load())
			}
		})
	}

	for _, injected := range []error{unix.EIO, unix.EACCES} {
		t.Run("marker inspection "+injected.Error(), func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x63)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			var targetOpens atomic.Int32
			ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
				if name == CredentialName {
					targetOpens.Add(1)
				}
				return openat(directoryFD, name, flags, mode)
			}
			fstatat := ops.fstatat
			ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
				if name == sourceKeyringStagingName {
					return injected
				}
				return fstatat(directoryFD, name, stat, flags)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrSourceCleanupRequired) || !errors.Is(err, injected) ||
				targetOpens.Load() != 0 {
				t.Fatalf("error=%v target opens=%d", err, targetOpens.Load())
			}
		})
	}

	for name, fileType := range map[string]uint32{
		"marker socket metadata":       unix.S_IFSOCK,
		"marker char device metadata":  unix.S_IFCHR,
		"marker block device metadata": unix.S_IFBLK,
	} {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x63)
			ops := defaultSourceAuditOps()
			fstatat := ops.fstatat
			var targetOpens atomic.Int32
			ops.fstatat = func(directoryFD int, candidate string, stat *unix.Stat_t, flags int) error {
				if candidate == sourceKeyringStagingName {
					*stat = unix.Stat_t{Mode: fileType | 0o600}
					return nil
				}
				return fstatat(directoryFD, candidate, stat, flags)
			}
			openat := ops.openat
			ops.openat = func(directoryFD int, candidate string, flags int, mode uint32) (int, error) {
				if candidate == CredentialName {
					targetOpens.Add(1)
				}
				return openat(directoryFD, candidate, flags, mode)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrSourceCleanupRequired) || targetOpens.Load() != 0 {
				t.Fatalf("error=%v target opens=%d", err, targetOpens.Load())
			}
		})
	}
}

func TestSourceAuditMarkerAndTargetRacesFailClosed(t *testing.T) {
	t.Run("marker appears during missing confirmation", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		ops := defaultSourceAuditOps()
		fstatat := ops.fstatat
		markerChecks := 0
		ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
			if name == sourceKeyringStagingName {
				markerChecks++
				if markerChecks == 2 {
					if err := os.WriteFile(sourceStaging(root), []byte("marker"), 0o600); err != nil {
						return err
					}
				}
			}
			return fstatat(directoryFD, name, stat, flags)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrSourceCleanupRequired) ||
			errors.Is(err, ErrSourceKeyringMissing) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("marker appears during final missing confirmation", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		ops := defaultSourceAuditOps()
		fstatat := ops.fstatat
		markerChecks := 0
		targetConfirmations := 0
		ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
			switch name {
			case sourceKeyringStagingName:
				markerChecks++
				if markerChecks == 3 {
					if err := os.WriteFile(sourceStaging(root), []byte("marker"), 0o600); err != nil {
						return err
					}
				}
			case CredentialName:
				targetConfirmations++
			}
			return fstatat(directoryFD, name, stat, flags)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrSourceCleanupRequired) ||
			errors.Is(err, ErrSourceKeyringMissing) ||
			markerChecks != 3 || targetConfirmations != 1 {
			t.Fatalf(
				"error=%v marker checks=%d target confirmations=%d",
				err,
				markerChecks,
				targetConfirmations,
			)
		}
	})

	t.Run("target appears during missing confirmation", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		data := canonicalSourceAuditData(t, 1)
		defer clear(data)
		ops := defaultSourceAuditOps()
		fstatat := ops.fstatat
		appeared := false
		ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
			if name == CredentialName && !appeared {
				appeared = true
				writeSourceAuditTarget(t, root, data, 0o400)
			}
			return fstatat(directoryFD, name, stat, flags)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceKeyringMissing) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("target appears during final missing confirmation", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		data := canonicalSourceAuditData(t, 1)
		defer clear(data)
		ops := defaultSourceAuditOps()
		fstatat := ops.fstatat
		markerChecks := 0
		targetConfirmations := 0
		ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
			if name == sourceKeyringStagingName {
				markerChecks++
			}
			if name == CredentialName {
				targetConfirmations++
				if targetConfirmations == 2 {
					writeSourceAuditTarget(t, root, data, 0o400)
				}
			}
			return fstatat(directoryFD, name, stat, flags)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceKeyringMissing) ||
			markerChecks != 3 || targetConfirmations != 2 {
			t.Fatalf(
				"error=%v marker checks=%d target confirmations=%d",
				err,
				markerChecks,
				targetConfirmations,
			)
		}
	})

	for _, test := range []struct {
		name     string
		injected error
	}{
		{name: "appears"},
		{name: "inspection unknown", injected: unix.EIO},
	} {
		test := test
		t.Run("final marker phase "+test.name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x64)
			ops := defaultSourceAuditOps()
			fstatat := ops.fstatat
			markerChecks := 0
			ops.fstatat = func(directoryFD int, name string, stat *unix.Stat_t, flags int) error {
				if name == sourceKeyringStagingName {
					markerChecks++
					if markerChecks == 5 {
						if test.injected != nil {
							return test.injected
						}
						*stat = unix.Stat_t{Mode: unix.S_IFREG | 0o600}
						return nil
					}
				}
				return fstatat(directoryFD, name, stat, flags)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrSourceCleanupRequired) ||
				errors.Is(err, ErrSourceKeyringMissing) || markerChecks != 5 {
				t.Fatalf("error=%v marker checks=%d", err, markerChecks)
			}
			if test.injected != nil && !errors.Is(err, test.injected) {
				t.Fatalf("error=%v does not contain %v", err, test.injected)
			}
		})
	}

	t.Run("observed target disappears before read open", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x64)
		ops := defaultSourceAuditOps()
		openat := ops.openat
		targetOpens := 0
		ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
			if name == CredentialName {
				targetOpens++
				if targetOpens == 2 {
					if err := os.Remove(sourceTarget(root)); err != nil {
						return -1, err
					}
					return -1, unix.ENOENT
				}
			}
			return openat(directoryFD, name, flags, mode)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceKeyringMissing) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestSourceAuditSpecialTargetsNeverReachDataOpen(t *testing.T) {
	creators := map[string]func(*testing.T, sourceProvisionTestRoot){
		"directory": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Mkdir(sourceTarget(root), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Symlink("missing", sourceTarget(root)); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := unix.Mkfifo(sourceTarget(root), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root sourceProvisionTestRoot) {
			data := canonicalSourceAuditData(t, 1)
			defer clear(data)
			other := filepath.Join(root.directory, "hardlink-other")
			if err := os.WriteFile(other, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(other, 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(other, sourceTarget(root)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, create := range creators {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			create(t, root)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			var pinnedOpens atomic.Int32
			var dataOpens atomic.Int32
			ops.openat = func(directoryFD int, candidate string, flags int, mode uint32) (int, error) {
				if candidate == CredentialName {
					if flags&unix.O_PATH != 0 {
						pinnedOpens.Add(1)
					} else {
						dataOpens.Add(1)
					}
				}
				return openat(directoryFD, candidate, flags, mode)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrUnsafeSourceKeyring) ||
				pinnedOpens.Load() != 1 || dataOpens.Load() != 0 {
				t.Fatalf(
					"error=%v pinned=%d data=%d",
					err,
					pinnedOpens.Load(),
					dataOpens.Load(),
				)
			}
		})
	}

	for name, fileType := range map[string]uint32{
		"socket metadata":       unix.S_IFSOCK,
		"char device metadata":  unix.S_IFCHR,
		"block device metadata": unix.S_IFBLK,
	} {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x64)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			pinnedFD := -1
			var pinnedOpens atomic.Int32
			var dataOpens atomic.Int32
			ops.openat = func(directoryFD int, candidate string, flags int, mode uint32) (int, error) {
				fd, err := openat(directoryFD, candidate, flags, mode)
				if candidate == CredentialName {
					if flags&unix.O_PATH != 0 {
						pinnedOpens.Add(1)
						if err == nil {
							pinnedFD = fd
						}
					} else {
						dataOpens.Add(1)
					}
				}
				return fd, err
			}
			fstat := ops.fstat
			ops.fstat = func(fd int, stat *unix.Stat_t) error {
				if err := fstat(fd, stat); err != nil {
					return err
				}
				if fd == pinnedFD {
					stat.Mode = fileType | 0o400
				}
				return nil
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrUnsafeSourceKeyring) ||
				pinnedOpens.Load() != 1 || dataOpens.Load() != 0 {
				t.Fatalf(
					"error=%v pinned=%d data=%d",
					err,
					pinnedOpens.Load(),
					dataOpens.Load(),
				)
			}
		})
	}
}

func TestSourceAuditMetadataAndSizePredicates(t *testing.T) {
	base := unix.Stat_t{
		Mode:  unix.S_IFREG | 0o400,
		Nlink: 1,
		Uid:   100,
		Gid:   200,
		Size:  int64(minSourceAuditKeyringBytes),
	}
	if !safeSourceAuditTarget(base, 100, 200) {
		t.Fatal("safe audit metadata rejected")
	}
	mutations := map[string]func(*unix.Stat_t){
		"directory":   func(stat *unix.Stat_t) { stat.Mode = unix.S_IFDIR | 0o400 },
		"fifo":        func(stat *unix.Stat_t) { stat.Mode = unix.S_IFIFO | 0o400 },
		"socket":      func(stat *unix.Stat_t) { stat.Mode = unix.S_IFSOCK | 0o400 },
		"char device": func(stat *unix.Stat_t) { stat.Mode = unix.S_IFCHR | 0o400 },
		"block device": func(stat *unix.Stat_t) {
			stat.Mode = unix.S_IFBLK | 0o400
		},
		"uid":       func(stat *unix.Stat_t) { stat.Uid++ },
		"gid":       func(stat *unix.Stat_t) { stat.Gid++ },
		"zero link": func(stat *unix.Stat_t) { stat.Nlink = 0 },
		"hardlink":  func(stat *unix.Stat_t) { stat.Nlink = 2 },
		"mode 0600": func(stat *unix.Stat_t) { stat.Mode = unix.S_IFREG | 0o600 },
		"setuid":    func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISUID },
		"setgid":    func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISGID },
		"sticky":    func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISVTX },
		"negative size": func(stat *unix.Stat_t) {
			stat.Size = -1
		},
		"zero size": func(stat *unix.Stat_t) { stat.Size = 0 },
		"below minimum": func(stat *unix.Stat_t) {
			stat.Size = int64(minSourceAuditKeyringBytes - 1)
		},
		"above maximum": func(stat *unix.Stat_t) {
			stat.Size = int64(maxKeyringBytes + 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if safeSourceAuditTarget(candidate, 100, 200) {
				t.Fatalf("unsafe metadata accepted: %+v", candidate)
			}
		})
	}
	maximum := base
	maximum.Size = int64(maxKeyringBytes)
	if !safeSourceAuditTarget(maximum, 100, 200) {
		t.Fatal("maximum safe size rejected")
	}
}

func TestSourceAuditRejectsOutOfRangeSizeBeforeDataOpen(t *testing.T) {
	for _, size := range []int{0, minSourceAuditKeyringBytes - 1, maxKeyringBytes + 1} {
		t.Run("size-"+strconv.Itoa(size), func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			writeSourceAuditTarget(t, root, bytes.Repeat([]byte{0x41}, size), 0o400)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			var dataOpens atomic.Int32
			ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
				if name == CredentialName && flags&unix.O_PATH == 0 {
					dataOpens.Add(1)
				}
				return openat(directoryFD, name, flags, mode)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrUnsafeSourceKeyring) || dataOpens.Load() != 0 {
				t.Fatalf("size=%d error=%v data opens=%d", size, err, dataOpens.Load())
			}
		})
	}
}

func TestSourceAuditRejectsEveryNonCanonicalKeyring(t *testing.T) {
	one := canonicalSourceAuditData(t, 1)
	defer clear(one)
	two := canonicalSourceAuditData(t, 2)
	defer clear(two)
	const fixedSize = len(keyringMagic) + 1 + 1 + keyIDSize
	const entrySize = keyIDSize + keySize

	clone := func(data []byte) []byte { return append([]byte(nil), data...) }
	tests := map[string][]byte{
		"bad magic": func() []byte {
			data := clone(one)
			data[0] ^= 0xff
			return data
		}(),
		"bad version": func() []byte {
			data := clone(one)
			data[len(keyringMagic)] = 2
			return data
		}(),
		"zero count": func() []byte {
			data := clone(one)
			data[len(keyringMagic)+1] = 0
			return data
		}(),
		"excess count": func() []byte {
			data := clone(one)
			data[len(keyringMagic)+1] = maxKeys + 1
			return data
		}(),
		"active missing": func() []byte {
			data := clone(one)
			clear(data[len(keyringMagic)+2 : fixedSize])
			return data
		}(),
		"id key mismatch": func() []byte {
			data := clone(one)
			data[len(data)-1] ^= 0x01
			return data
		}(),
		"duplicate": func() []byte {
			data := clone(two)
			copy(data[fixedSize+entrySize:fixedSize+2*entrySize], data[fixedSize:fixedSize+entrySize])
			return data
		}(),
		"unsorted": func() []byte {
			data := clone(two)
			first := clone(data[fixedSize : fixedSize+entrySize])
			copy(data[fixedSize:fixedSize+entrySize], data[fixedSize+entrySize:fixedSize+2*entrySize])
			copy(data[fixedSize+entrySize:fixedSize+2*entrySize], first)
			clear(first)
			return data
		}(),
		"truncated": clone(two[:len(two)-1]),
		"trailing":  append(clone(one), 0),
	}
	parsed, err := ParseKeyring(one)
	if err != nil {
		t.Fatal(err)
	}
	activeID := parsed.ActiveID()
	parsed.Destroy()
	rawSecrets := [][]byte{
		clone(two[fixedSize+keyIDSize : fixedSize+entrySize]),
		clone(two[fixedSize+entrySize+keyIDSize : fixedSize+2*entrySize]),
	}
	for _, secret := range rawSecrets {
		secret := secret
		defer clear(secret)
	}
	for name, data := range tests {
		data := data
		t.Run(name, func(t *testing.T) {
			defer clear(data)
			root := newSourceProvisionTestRoot(t)
			writeSourceAuditTarget(t, root, data, 0o400)
			ops := defaultSourceAuditOps()
			pread := ops.pread
			var captured []byte
			ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
				if captured == nil {
					captured = buffer[:cap(buffer)]
				}
				return pread(fd, buffer, offset)
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrUnsafeSourceKeyring) ||
				!errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("error=%v", err)
			}
			requireClearedAuditBuffer(t, captured, "malformed audit")
			for _, secret := range []string{"RCSMBKEY", activeID} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked keyring material %q: %v", secret, err)
				}
			}
			errorBytes := []byte(err.Error())
			for secretIndex, secret := range rawSecrets {
				if bytes.Contains(errorBytes, secret) {
					t.Fatalf("error leaked raw key %d: %v", secretIndex, err)
				}
				encoded := make([]byte, hex.EncodedLen(len(secret)))
				hex.Encode(encoded, secret)
				leaked := bytes.Contains(errorBytes, encoded)
				clear(encoded)
				if leaked {
					t.Fatalf("error leaked hex key %d: %v", secretIndex, err)
				}
			}
		})
	}
}

func TestSourceAuditPreadStateMachine(t *testing.T) {
	t.Run("partial and EINTR", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x65)
		ops := defaultSourceAuditOps()
		pread := ops.pread
		calls := 0
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			calls++
			if calls == 1 {
				return 0, unix.EINTR
			}
			if len(buffer) > 7 {
				buffer = buffer[:7]
			}
			return pread(fd, buffer, offset)
		}
		if err := auditSourceForTest(root, ops); err != nil {
			t.Fatal(err)
		}
		if calls < 3 {
			t.Fatalf("pread calls=%d", calls)
		}
	})

	t.Run("short read", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x66)
		data, err := os.ReadFile(sourceTarget(root))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		limit := int64(len(data) / 2)
		ops := defaultSourceAuditOps()
		pread := ops.pread
		var captured []byte
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			if captured == nil {
				captured = buffer[:cap(buffer)]
			}
			if offset >= limit {
				return 0, nil
			}
			if remaining := int(limit - offset); len(buffer) > remaining {
				buffer = buffer[:remaining]
			}
			return pread(fd, buffer, offset)
		}
		err = auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error=%v", err)
		}
		requireClearedAuditBuffer(t, captured, "short-read audit")
	})

	t.Run("extra byte", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x67)
		data, err := os.ReadFile(sourceTarget(root))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		ops := defaultSourceAuditOps()
		pread := ops.pread
		var captured []byte
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			if captured == nil {
				captured = buffer[:cap(buffer)]
			}
			if offset == int64(len(data)) && len(buffer) > 0 {
				buffer[0] = 0x7f
				return 1, nil
			}
			return pread(fd, buffer, offset)
		}
		err = auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("error=%v", err)
		}
		requireClearedAuditBuffer(t, captured, "extra-byte audit")
	})
}

func TestSourceAuditGenericIOErrorsRemainIndeterminate(t *testing.T) {
	t.Run("pin open", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x67)
		ops := defaultSourceAuditOps()
		openat := ops.openat
		ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
			if name == CredentialName && flags&unix.O_PATH != 0 {
				return -1, unix.EIO
			}
			return openat(directoryFD, name, flags, mode)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, unix.EIO) ||
			errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceKeyringMissing) ||
			errors.Is(err, ErrSourceCleanupRequired) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("pread", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x67)
		ops := defaultSourceAuditOps()
		var captured []byte
		ops.pread = func(_ int, buffer []byte, _ int64) (int, error) {
			captured = buffer[:cap(buffer)]
			buffer[0] = 0x6b
			return 1, unix.EIO
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, unix.EIO) ||
			errors.Is(err, ErrUnsafeSourceKeyring) ||
			errors.Is(err, ErrSourceKeyringMissing) ||
			errors.Is(err, ErrSourceCleanupRequired) {
			t.Fatalf("error=%v", err)
		}
		for index, value := range captured {
			if value != 0 {
				t.Fatalf("failed-read buffer byte %d was not cleared", index)
			}
		}
	})
}

func TestSourceAuditRejectsTargetAndAncestorReplacement(t *testing.T) {
	t.Run("pinned target replaced by symlink before read open", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x68)
		ops := defaultSourceAuditOps()
		openat := ops.openat
		targetOpens := 0
		ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
			if name == CredentialName {
				targetOpens++
				if targetOpens == 2 {
					if err := os.Rename(sourceTarget(root), sourceTarget(root)+".pinned"); err != nil {
						return -1, err
					}
					if err := os.Symlink(CredentialName+".pinned", sourceTarget(root)); err != nil {
						return -1, err
					}
				}
			}
			return openat(directoryFD, name, flags, mode)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) ||
			!errors.Is(err, unix.ELOOP) ||
			errors.Is(err, ErrSourceKeyringMissing) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("pinned target replaced before read open", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x68)
		replacement := canonicalSourceAuditData(t, 1)
		defer clear(replacement)
		ops := defaultSourceAuditOps()
		openat := ops.openat
		targetOpens := 0
		ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
			if name == CredentialName {
				targetOpens++
				if targetOpens == 2 {
					if err := os.Rename(sourceTarget(root), sourceTarget(root)+".pinned"); err != nil {
						return -1, err
					}
					writeSourceAuditTarget(t, root, replacement, 0o400)
				}
			}
			return openat(directoryFD, name, flags, mode)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("fixed name replaced during read", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x69)
		replacement := canonicalSourceAuditData(t, 1)
		defer clear(replacement)
		ops := defaultSourceAuditOps()
		pread := ops.pread
		replaced := false
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			if !replaced {
				replaced = true
				if err := os.Rename(sourceTarget(root), sourceTarget(root)+".opened"); err != nil {
					return 0, err
				}
				writeSourceAuditTarget(t, root, replacement, 0o400)
			}
			return pread(fd, buffer, offset)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("source directory replaced during read", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x6a)
		moved := root.directory + ".opened"
		ops := defaultSourceAuditOps()
		pread := ops.pread
		replaced := false
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			if !replaced {
				replaced = true
				if err := os.Rename(root.directory, moved); err != nil {
					return 0, err
				}
				if err := os.Mkdir(root.directory, 0o700); err != nil {
					return 0, err
				}
			}
			return pread(fd, buffer, offset)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrUnsafeSourceKeyring) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("marker appears during read", func(t *testing.T) {
		root := newSourceProvisionTestRoot(t)
		provisionCanonicalSourceForAudit(t, root, 0x6b)
		ops := defaultSourceAuditOps()
		pread := ops.pread
		created := false
		ops.pread = func(fd int, buffer []byte, offset int64) (int, error) {
			if !created {
				created = true
				if err := os.WriteFile(sourceStaging(root), []byte("marker"), 0o600); err != nil {
					return 0, err
				}
			}
			return pread(fd, buffer, offset)
		}
		err := auditSourceForTest(root, ops)
		if !errors.Is(err, ErrSourceCleanupRequired) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestSourceAuditRejectsMetadataChangeDuringRead(t *testing.T) {
	for _, test := range []struct {
		name       string
		statCall   int
		mutateStat func(*unix.Stat_t)
	}{
		{
			name:     "ctime before parse",
			statCall: 2,
			mutateStat: func(stat *unix.Stat_t) {
				stat.Ctim.Nsec++
			},
		},
		{
			name:     "mtime before parse",
			statCall: 2,
			mutateStat: func(stat *unix.Stat_t) {
				stat.Mtim.Nsec++
			},
		},
		{
			name:     "ctime during final recheck",
			statCall: 3,
			mutateStat: func(stat *unix.Stat_t) {
				stat.Ctim.Nsec++
			},
		},
		{
			name:     "mtime during final recheck",
			statCall: 3,
			mutateStat: func(stat *unix.Stat_t) {
				stat.Mtim.Nsec++
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x6c)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			readFD := -1
			ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
				fd, err := openat(directoryFD, name, flags, mode)
				if err == nil && name == CredentialName && flags&unix.O_PATH == 0 {
					readFD = fd
				}
				return fd, err
			}
			fstat := ops.fstat
			targetStats := 0
			ops.fstat = func(fd int, stat *unix.Stat_t) error {
				if err := fstat(fd, stat); err != nil {
					return err
				}
				if fd == readFD {
					targetStats++
					if targetStats == test.statCall {
						test.mutateStat(stat)
					}
				}
				return nil
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, ErrUnsafeSourceKeyring) || targetStats != test.statCall {
				t.Fatalf("error=%v target stat calls=%d", err, targetStats)
			}
		})
	}
}

func TestSourceAuditRejectsUnsafeAncestorBoundary(t *testing.T) {
	mutations := map[string]func(*testing.T, sourceProvisionTestRoot){
		"root group writable": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.root, 0o720); err != nil {
				t.Fatal(err)
			}
		},
		"etc group writable": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(filepath.Join(root.root, "etc"), 0o775); err != nil {
				t.Fatal(err)
			}
		},
		"source mode 0755": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.directory, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"source sticky": func(t *testing.T, root sourceProvisionTestRoot) {
			if err := os.Chmod(root.directory, 0o700|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x6d)
			mutate(t, root)
			err := auditSourceForTest(root, defaultSourceAuditOps())
			if !errors.Is(err, ErrUnsafeSourceKeyring) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSourceAuditCloseFailuresAreReportedAfterAllFDsClose(t *testing.T) {
	for _, fail := range []string{"pinned", "read", "directory", "etc"} {
		t.Run(fail, func(t *testing.T) {
			root := newSourceProvisionTestRoot(t)
			provisionCanonicalSourceForAudit(t, root, 0x6e)
			ops := defaultSourceAuditOps()
			openat := ops.openat
			pinnedFD := -1
			readFD := -1
			capturedDirectoryFD := -1
			capturedEtcFD := -1
			ops.openat = func(directoryFD int, name string, flags int, mode uint32) (int, error) {
				fd, err := openat(directoryFD, name, flags, mode)
				if err == nil {
					switch name {
					case CredentialName:
						if flags&unix.O_PATH != 0 {
							pinnedFD = fd
						} else {
							readFD = fd
						}
					case "recasaos":
						capturedDirectoryFD = fd
					case "etc":
						capturedEtcFD = fd
					}
				}
				return fd, err
			}
			closeFD := ops.close
			closeCounts := make(map[int]int)
			injected := false
			ops.close = func(fd int) error {
				closeCounts[fd]++
				actualErr := closeFD(fd)
				shouldFail := fail == "pinned" && fd == pinnedFD ||
					fail == "read" && fd == readFD ||
					fail == "directory" && fd == capturedDirectoryFD ||
					fail == "etc" && fd == capturedEtcFD
				if shouldFail && !injected {
					injected = true
					return errors.Join(actualErr, unix.EIO)
				}
				return actualErr
			}
			err := auditSourceForTest(root, ops)
			if !errors.Is(err, unix.EIO) || !injected {
				t.Fatalf("error=%v injected=%v", err, injected)
			}
			expectedFDs := map[string]int{
				"pinned":    pinnedFD,
				"read":      readFD,
				"directory": capturedDirectoryFD,
				"etc":       capturedEtcFD,
			}
			if len(closeCounts) != len(expectedFDs) {
				t.Fatalf("closed distinct fds=%d want=%d: %v", len(closeCounts), len(expectedFDs), closeCounts)
			}
			for name, fd := range expectedFDs {
				if fd < 0 || closeCounts[fd] != 1 {
					t.Fatalf("%s fd=%d close count=%d; all=%v", name, fd, closeCounts[fd], closeCounts)
				}
			}
		})
	}
}

func TestSourceAuditConcurrentReadOnlyChecks(t *testing.T) {
	root := newSourceProvisionTestRoot(t)
	provisionCanonicalSourceForAudit(t, root, 0x6f)
	const callers = 32
	errorsOut := make(chan error, callers)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			ready.Done()
			<-start
			errorsOut <- auditSourceForTest(root, defaultSourceAuditOps())
		}()
	}
	ready.Wait()
	close(start)
	for index := 0; index < callers; index++ {
		if err := <-errorsOut; err != nil {
			t.Fatalf("concurrent audit error=%v", err)
		}
	}
}
