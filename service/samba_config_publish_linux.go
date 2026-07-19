//go:build linux

package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var sha256EmptyDigest = sha256.Sum256(nil)

const sambaConfigQuarantineMarker = ".recasaos-quarantine-"

// Cleanup first moves the proven inode to an unpredictable quarantine name,
// revalidates it, and only then unlinks it. A detected replacement is restored
// or preserved and blocks future publishes; ordinary successful updates do not
// accumulate directory entries. A non-cooperating same-UID/root actor racing
// after the final identity check is outside the trusted-host boundary.
func publishSambaConfigCAS(expected sambaConfigSnapshot, data []byte, permission fs.FileMode, cleanupHook func(string)) (sambaConfigSnapshot, error) {
	directoryPath := filepath.Dir(expected.path)
	if err := refuseSambaConfigQuarantine(directoryPath); err != nil {
		return sambaConfigSnapshot{}, err
	}
	temporary, err := os.CreateTemp(directoryPath, "."+filepath.Base(expected.path)+".cas-*")
	if err != nil {
		return sambaConfigSnapshot{}, err
	}
	temporaryPath := temporary.Name()
	closeRetained := func(cause error) (sambaConfigSnapshot, error) {
		_ = temporary.Truncate(0)
		_ = temporary.Chmod(0o600)
		_ = temporary.Sync()
		info, statErr := temporary.Stat()
		closeErr := temporary.Close()
		if statErr != nil {
			return sambaConfigSnapshot{}, errors.Join(cause, statErr, closeErr)
		}
		zero := sambaConfigSnapshot{path: temporaryPath, exists: true, data: []byte{}, permission: 0o600, identity: info, digest: sha256EmptyDigest}
		return sambaConfigSnapshot{}, errors.Join(cause, closeErr, discardTemporarySambaConfigSnapshotIfOwned(zero, nil))
	}
	if err := temporary.Chmod(permission.Perm()); err != nil {
		return closeRetained(err)
	}
	written, err := temporary.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return closeRetained(err)
	}
	if err := temporary.Sync(); err != nil {
		return closeRetained(err)
	}
	if err := temporary.Close(); err != nil {
		return sambaConfigSnapshot{}, errors.Join(err, quarantineUnknownSambaConfig(temporaryPath))
	}
	candidate, err := readSambaConfigSnapshot(temporaryPath, true, "")
	if err != nil {
		return sambaConfigSnapshot{}, errors.Join(err, quarantineUnknownSambaConfig(temporaryPath))
	}

	if !expected.exists {
		if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, expected.path, unix.RENAME_NOREPLACE); err != nil {
			cleanupErr := discardTemporarySambaConfigSnapshotIfOwned(candidate, cleanupHook)
			if errors.Is(err, unix.EEXIST) {
				return sambaConfigSnapshot{}, errors.Join(fmt.Errorf("%w: %s appeared before publish", errSambaConfigConflict, expected.path), cleanupErr)
			}
			return sambaConfigSnapshot{}, errors.Join(err, cleanupErr)
		}
		return candidate, syncSambaConfigDirectory(directoryPath)
	}

	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, expected.path, unix.RENAME_EXCHANGE); err != nil {
		cleanupErr := discardTemporarySambaConfigSnapshotIfOwned(candidate, cleanupHook)
		if errors.Is(err, unix.ENOENT) {
			return sambaConfigSnapshot{}, errors.Join(fmt.Errorf("%w: %s disappeared before publish", errSambaConfigConflict, expected.path), cleanupErr)
		}
		return sambaConfigSnapshot{}, errors.Join(err, cleanupErr)
	}
	displaced, displacedErr := readSambaConfigSnapshot(temporaryPath, true, "")
	if displacedErr == nil && sambaConfigSnapshotsEqual(expected, displaced) {
		return candidate, errors.Join(discardTemporarySambaConfigSnapshotIfOwned(displaced, cleanupHook), syncSambaConfigDirectory(directoryPath))
	}

	current, currentErr := readSambaConfigSnapshot(expected.path, true, "")
	if currentErr == nil && sambaConfigSnapshotsEqual(candidate, current) {
		if rollbackErr := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, expected.path, unix.RENAME_EXCHANGE); rollbackErr == nil {
			rolledBackTemporary, inspectRollbackErr := readSambaConfigSnapshot(temporaryPath, true, "")
			if inspectRollbackErr == nil && sambaConfigSnapshotsEqual(candidate, rolledBackTemporary) {
				return sambaConfigSnapshot{}, errors.Join(
					fmt.Errorf("%w: displaced config did not match snapshot for %s", errSambaConfigConflict, expected.path),
					displacedErr,
					discardTemporarySambaConfigSnapshotIfOwned(rolledBackTemporary, cleanupHook),
					syncSambaConfigDirectory(directoryPath),
				)
			}
			return sambaConfigSnapshot{}, errors.Join(
				fmt.Errorf("%w: rollback target changed; unknown config preserved at %s", errSambaConfigConflict, temporaryPath),
				displacedErr,
				inspectRollbackErr,
				quarantineUnknownSambaConfig(temporaryPath),
				syncSambaConfigDirectory(directoryPath),
			)
		} else {
			return sambaConfigSnapshot{}, errors.Join(
				fmt.Errorf("%w: could not roll back conditional publish; displaced config quarantined", errSambaConfigConflict),
				displacedErr,
				rollbackErr,
				quarantineUnknownSambaConfig(temporaryPath),
			)
		}
	}
	return sambaConfigSnapshot{}, errors.Join(
		fmt.Errorf("%w: publish target changed again; displaced config quarantined", errSambaConfigConflict),
		displacedErr,
		currentErr,
		quarantineUnknownSambaConfig(temporaryPath),
	)
}

func removeSambaConfigCAS(expected sambaConfigSnapshot, cleanupHook func(string)) error {
	if err := refuseSambaConfigQuarantine(filepath.Dir(expected.path)); err != nil {
		return err
	}
	if err := discardSambaConfigSnapshotIfOwned(expected, cleanupHook); err != nil {
		return err
	}
	if _, err := os.Lstat(expected.path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: new content appeared at %s during conditional removal", errSambaConfigConflict, expected.path)
	}
	return syncSambaConfigDirectory(filepath.Dir(expected.path))
}

func discardSambaConfigSnapshotIfOwned(expected sambaConfigSnapshot, cleanupHook func(string)) error {
	if !expected.exists {
		return nil
	}
	current, err := readSambaConfigSnapshot(expected.path, true, "")
	if err != nil || !sambaConfigSnapshotsEqual(expected, current) {
		return errors.Join(fmt.Errorf("%w: refusing to discard changed config %s", errSambaConfigConflict, expected.path), err)
	}
	if cleanupHook != nil {
		cleanupHook(expected.path)
	}
	retainedPath, err := randomQuarantineConfigPath(expected.path)
	if err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, expected.path, unix.AT_FDCWD, retainedPath, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("%w: move proven config to retained tombstone: %v", errSambaConfigConflict, err)
	}
	moved, inspectErr := readSambaConfigSnapshot(retainedPath, true, "")
	if inspectErr != nil || !sambaConfigSnapshotsEqual(expected, moved) {
		rollbackErr := unix.Renameat2(unix.AT_FDCWD, retainedPath, unix.AT_FDCWD, expected.path, unix.RENAME_NOREPLACE)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("%w: unknown config preserved at %s", errSambaConfigConflict, retainedPath), inspectErr, rollbackErr)
		}
		return errors.Join(fmt.Errorf("%w: cleanup target changed before move", errSambaConfigConflict), inspectErr)
	}
	opened, err := os.OpenFile(retainedPath, os.O_WRONLY|syscallNoFollow, 0)
	if err != nil {
		return fmt.Errorf("retained proven Samba config at %s: %w", retainedPath, err)
	}
	openedInfo, statErr := opened.Stat()
	if statErr != nil || !os.SameFile(moved.identity, openedInfo) {
		return errors.Join(fmt.Errorf("%w: retained Samba config changed before sanitizing", errSambaConfigConflict), statErr, opened.Close())
	}
	if err := opened.Truncate(0); err != nil {
		return errors.Join(err, opened.Close())
	}
	if err := opened.Chmod(0o600); err != nil {
		return errors.Join(err, opened.Close())
	}
	if err := opened.Sync(); err != nil {
		return errors.Join(err, opened.Close())
	}
	if err := opened.Close(); err != nil {
		return err
	}
	final, err := readSambaConfigSnapshot(retainedPath, true, "")
	if err != nil || !os.SameFile(moved.identity, final.identity) || len(final.data) != 0 || final.permission != 0o600 {
		return errors.Join(fmt.Errorf("%w: quarantine changed; unknown path preserved at %s", errSambaConfigConflict, retainedPath), err)
	}
	if err := os.Remove(retainedPath); err != nil {
		return fmt.Errorf("remove proven Samba quarantine file: %w", err)
	}
	return syncSambaConfigDirectory(filepath.Dir(expected.path))
}

func discardTemporarySambaConfigSnapshotIfOwned(expected sambaConfigSnapshot, cleanupHook func(string)) error {
	err := discardSambaConfigSnapshotIfOwned(expected, cleanupHook)
	if err == nil {
		return nil
	}
	return errors.Join(err, quarantineUnknownSambaConfig(expected.path))
}

// quarantineUnknownSambaConfig never opens, truncates, or unlinks an inode
// whose identity is unknown. It only moves the pathname to a reserved marker
// which makes every future publish fail closed pending administrator review.
func quarantineUnknownSambaConfig(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	retainedPath, err := randomQuarantineConfigPath(path)
	if err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, retainedPath, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("%w: preserve unknown Samba config at %s: %v", errSambaConfigConflict, path, err)
	}
	return syncSambaConfigDirectory(filepath.Dir(path))
}

const syscallNoFollow = unix.O_NOFOLLOW

func randomQuarantineConfigPath(original string) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		candidate := filepath.Join(filepath.Dir(original), "."+filepath.Base(original)+sambaConfigQuarantineMarker+hex.EncodeToString(random))
		if _, err := os.Lstat(candidate); errors.Is(err, fs.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not reserve a Samba quarantine name")
}

func refuseSambaConfigQuarantine(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), sambaConfigQuarantineMarker) || strings.HasPrefix(entry.Name(), ".") && strings.Contains(entry.Name(), ".cas-") {
			return fmt.Errorf("%w: unresolved Samba config quarantine or staging file %s requires administrator review", errSambaConfigConflict, filepath.Join(directory, entry.Name()))
		}
	}
	return nil
}
