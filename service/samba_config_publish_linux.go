//go:build linux

package service

import (
	"bytes"
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

// sambaConfigDirectorySync is the pinned-directory durability barrier. It is a
// variable so tests can inject sync failures without a pathname-based seam.
var sambaConfigDirectorySync = unix.Fsync

// sambaConfigDirectory is a pinned Samba configuration directory. Every
// staging, read, rename, quarantine, and cleanup operation resolves relative
// to this descriptor, so replacing the directory path or one of its
// ancestors cannot redirect a publish. The final path component must be a
// real directory; a symlinked parent fails closed at the pin.
type sambaConfigDirectory struct {
	path string
	fd   int
}

func openSambaConfigDirectory(path string) (sambaConfigDirectory, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sambaConfigDirectory{}, fmt.Errorf("pin Samba config directory %s: %w", path, err)
	}
	return sambaConfigDirectory{path: path, fd: fd}, nil
}

func (directory sambaConfigDirectory) close() {
	_ = unix.Close(directory.fd)
}

func (directory sambaConfigDirectory) displayPath(base string) string {
	return filepath.Join(directory.path, base)
}

func (directory sambaConfigDirectory) sync() error {
	if err := sambaConfigDirectorySync(directory.fd); err != nil {
		return fmt.Errorf("sync Samba config directory %s: %w", directory.path, err)
	}
	return nil
}

func singleLinkRegularStat(stat *unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
}

// readSnapshot reads one configuration name relative to the pinned
// directory. The name is statx-checked before and after the open, and the
// opened descriptor must match the pre-open device and inode before any
// content is used.
func (directory sambaConfigDirectory) readSnapshot(base string, required bool, requiredMarker string) (sambaConfigSnapshot, error) {
	displayPath := directory.displayPath(base)
	var named unix.Stat_t
	err := unix.Fstatat(directory.fd, base, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) && !required {
		return sambaConfigSnapshot{path: displayPath}, nil
	}
	if err != nil {
		return sambaConfigSnapshot{}, fmt.Errorf("inspect Samba config %s: %w", displayPath, err)
	}
	if !singleLinkRegularStat(&named) {
		return sambaConfigSnapshot{}, fmt.Errorf("inspect Samba config %s: Samba config must be a regular non-symlink file with exactly one hard link", displayPath)
	}
	fd, err := unix.Openat(directory.fd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sambaConfigSnapshot{}, fmt.Errorf("open Samba config %s: %w", displayPath, err)
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = unix.Close(fd)
		return sambaConfigSnapshot{}, fmt.Errorf("inspect opened Samba config %s: %w", displayPath, err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		_ = unix.Close(fd)
		return sambaConfigSnapshot{}, fmt.Errorf("Samba config %s changed while opening", displayPath)
	}
	if !singleLinkRegularStat(&opened) {
		_ = unix.Close(fd)
		return sambaConfigSnapshot{}, fmt.Errorf("inspect opened Samba config %s: Samba config must be a regular non-symlink file with exactly one hard link", displayPath)
	}
	openedFile := os.NewFile(uintptr(fd), displayPath)
	if openedFile == nil {
		_ = unix.Close(fd)
		return sambaConfigSnapshot{}, fmt.Errorf("open Samba config %s: invalid descriptor", displayPath)
	}
	info, statErr := openedFile.Stat()
	if statErr != nil {
		_ = openedFile.Close()
		return sambaConfigSnapshot{}, fmt.Errorf("inspect opened Samba config %s: %w", displayPath, statErr)
	}
	data, readErr := io.ReadAll(io.LimitReader(openedFile, maxSambaConfigBytes+1))
	closeErr := openedFile.Close()
	if readErr != nil || closeErr != nil {
		return sambaConfigSnapshot{}, errors.Join(readErr, closeErr)
	}
	if len(data) > maxSambaConfigBytes {
		return sambaConfigSnapshot{}, fmt.Errorf("Samba config %s exceeds %d bytes", displayPath, maxSambaConfigBytes)
	}
	if requiredMarker != "" && !bytes.HasPrefix(data, []byte(requiredMarker)) {
		return sambaConfigSnapshot{}, fmt.Errorf("refusing to overwrite unmanaged Samba config %s", displayPath)
	}
	return sambaConfigSnapshot{
		path:       displayPath,
		exists:     true,
		data:       data,
		permission: info.Mode().Perm(),
		identity:   info,
		digest:     sha256.Sum256(data),
	}, nil
}

func randomSambaCASName(prefix, base string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "." + base + prefix + hex.EncodeToString(random), nil
}

// createStaging reserves an unpredictable O_EXCL staging name in the pinned
// directory and returns it with the writable descriptor.
func (directory sambaConfigDirectory) createStaging(base string, permission fs.FileMode) (string, *os.File, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomSambaCASName(".cas-", base)
		if err != nil {
			return "", nil, err
		}
		fd, err := unix.Openat(directory.fd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(permission.Perm()))
		if err == nil {
			file := os.NewFile(uintptr(fd), directory.displayPath(name))
			if file == nil {
				_ = unix.Close(fd)
				return "", nil, errors.New("open staged Samba config: invalid descriptor")
			}
			return name, file, nil
		}
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return "", nil, fmt.Errorf("create staged Samba config in %s: %w", directory.path, err)
	}
	return "", nil, errors.New("could not reserve a Samba staging name")
}

func (directory sambaConfigDirectory) openRetained(base string) (*os.File, error) {
	fd, err := unix.Openat(directory.fd, base, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), directory.displayPath(base))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open retained Samba config: invalid descriptor")
	}
	return file, nil
}

func (directory sambaConfigDirectory) randomQuarantineName(base string) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		candidate, err := randomSambaCASName(sambaConfigQuarantineMarker, base)
		if err != nil {
			return "", err
		}
		var stat unix.Stat_t
		err = unix.Fstatat(directory.fd, candidate, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not reserve a Samba quarantine name")
}

// refuseQuarantine fails closed while an unresolved quarantine or staging
// entry exists in the pinned directory.
func (directory sambaConfigDirectory) refuseQuarantine() error {
	duplicate, err := unix.Dup(directory.fd)
	if err != nil {
		return err
	}
	opened := os.NewFile(uintptr(duplicate), directory.path)
	if opened == nil {
		_ = unix.Close(duplicate)
		return errors.New("inspect Samba config directory: invalid descriptor")
	}
	entries, readErr := opened.ReadDir(-1)
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), sambaConfigQuarantineMarker) || strings.HasPrefix(entry.Name(), ".") && strings.Contains(entry.Name(), ".cas-") {
			return fmt.Errorf("%w: unresolved Samba config quarantine or staging file %s requires administrator review", errSambaConfigConflict, directory.displayPath(entry.Name()))
		}
	}
	return nil
}

func refuseSambaConfigQuarantine(directoryPath string) error {
	directory, err := openSambaConfigDirectory(directoryPath)
	if err != nil {
		return err
	}
	defer directory.close()
	return directory.refuseQuarantine()
}

// quarantineUnknown never opens, truncates, or unlinks an inode whose
// identity is unknown. It only moves the name to a reserved marker which
// makes every future publish fail closed pending administrator review.
func (directory sambaConfigDirectory) quarantineUnknown(base string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(directory.fd, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	retainedName, err := directory.randomQuarantineName(base)
	if err != nil {
		return err
	}
	if err := unix.Renameat2(directory.fd, base, directory.fd, retainedName, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("%w: preserve unknown Samba config at %s: %v", errSambaConfigConflict, directory.displayPath(base), err)
	}
	return directory.sync()
}

// Cleanup first moves the proven inode to an unpredictable quarantine name,
// revalidates it, and only then unlinks it. A detected replacement is restored
// or preserved and blocks future publishes; ordinary successful updates do not
// accumulate directory entries. A non-cooperating same-UID/root actor racing
// after the final identity check is outside the trusted-host boundary.
func discardSambaConfigSnapshotIfOwned(directory sambaConfigDirectory, expected sambaConfigSnapshot, cleanupHook func(string)) error {
	if !expected.exists {
		return nil
	}
	base := filepath.Base(expected.path)
	current, err := directory.readSnapshot(base, true, "")
	if err != nil || !sambaConfigSnapshotsEqual(expected, current) {
		return errors.Join(fmt.Errorf("%w: refusing to discard changed config %s", errSambaConfigConflict, expected.path), err)
	}
	if cleanupHook != nil {
		cleanupHook(expected.path)
	}
	retainedName, err := directory.randomQuarantineName(base)
	if err != nil {
		return err
	}
	if err := unix.Renameat2(directory.fd, base, directory.fd, retainedName, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("%w: move proven config to retained tombstone: %v", errSambaConfigConflict, err)
	}
	moved, inspectErr := directory.readSnapshot(retainedName, true, "")
	if inspectErr != nil || !sambaConfigSnapshotsEqual(expected, moved) {
		rollbackErr := unix.Renameat2(directory.fd, retainedName, directory.fd, base, unix.RENAME_NOREPLACE)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("%w: unknown config preserved at %s", errSambaConfigConflict, directory.displayPath(retainedName)), inspectErr, rollbackErr)
		}
		return errors.Join(fmt.Errorf("%w: cleanup target changed before move", errSambaConfigConflict), inspectErr)
	}
	opened, err := directory.openRetained(retainedName)
	if err != nil {
		return fmt.Errorf("retained proven Samba config at %s: %w", directory.displayPath(retainedName), err)
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
	final, err := directory.readSnapshot(retainedName, true, "")
	if err != nil || !os.SameFile(moved.identity, final.identity) || len(final.data) != 0 || final.permission != 0o600 {
		return errors.Join(fmt.Errorf("%w: quarantine changed; unknown path preserved at %s", errSambaConfigConflict, directory.displayPath(retainedName)), err)
	}
	if err := unix.Unlinkat(directory.fd, retainedName, 0); err != nil {
		return fmt.Errorf("remove proven Samba quarantine file: %w", err)
	}
	return directory.sync()
}

func discardTemporarySambaConfigSnapshotIfOwned(directory sambaConfigDirectory, expected sambaConfigSnapshot, cleanupHook func(string)) error {
	err := discardSambaConfigSnapshotIfOwned(directory, expected, cleanupHook)
	if err == nil {
		return nil
	}
	return errors.Join(err, directory.quarantineUnknown(filepath.Base(expected.path)))
}

func publishSambaConfigCAS(expected sambaConfigSnapshot, data []byte, permission fs.FileMode, cleanupHook func(string)) (sambaConfigSnapshot, error) {
	targetBase := filepath.Base(expected.path)
	directory, err := openSambaConfigDirectory(filepath.Dir(expected.path))
	if err != nil {
		return sambaConfigSnapshot{}, err
	}
	defer directory.close()
	if err := directory.refuseQuarantine(); err != nil {
		return sambaConfigSnapshot{}, err
	}
	stagingName, staging, err := directory.createStaging(targetBase, permission)
	if err != nil {
		return sambaConfigSnapshot{}, err
	}
	closeRetained := func(cause error) (sambaConfigSnapshot, error) {
		_ = staging.Truncate(0)
		_ = staging.Chmod(0o600)
		_ = staging.Sync()
		info, statErr := staging.Stat()
		closeErr := staging.Close()
		if statErr != nil {
			return sambaConfigSnapshot{}, errors.Join(cause, statErr, closeErr)
		}
		zero := sambaConfigSnapshot{path: directory.displayPath(stagingName), exists: true, data: []byte{}, permission: 0o600, identity: info, digest: sha256EmptyDigest}
		return sambaConfigSnapshot{}, errors.Join(cause, closeErr, discardTemporarySambaConfigSnapshotIfOwned(directory, zero, nil))
	}
	if err := staging.Chmod(permission.Perm()); err != nil {
		return closeRetained(err)
	}
	written, err := staging.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return closeRetained(err)
	}
	if err := staging.Sync(); err != nil {
		return closeRetained(err)
	}
	if err := staging.Close(); err != nil {
		return sambaConfigSnapshot{}, errors.Join(err, directory.quarantineUnknown(stagingName))
	}
	candidate, err := directory.readSnapshot(stagingName, true, "")
	if err != nil {
		return sambaConfigSnapshot{}, errors.Join(err, directory.quarantineUnknown(stagingName))
	}

	if !expected.exists {
		if err := unix.Renameat2(directory.fd, stagingName, directory.fd, targetBase, unix.RENAME_NOREPLACE); err != nil {
			cleanupErr := discardTemporarySambaConfigSnapshotIfOwned(directory, candidate, cleanupHook)
			if errors.Is(err, unix.EEXIST) {
				return sambaConfigSnapshot{}, errors.Join(fmt.Errorf("%w: %s appeared before publish", errSambaConfigConflict, expected.path), cleanupErr)
			}
			return sambaConfigSnapshot{}, errors.Join(err, cleanupErr)
		}
		return candidate, directory.sync()
	}

	if err := unix.Renameat2(directory.fd, stagingName, directory.fd, targetBase, unix.RENAME_EXCHANGE); err != nil {
		cleanupErr := discardTemporarySambaConfigSnapshotIfOwned(directory, candidate, cleanupHook)
		if errors.Is(err, unix.ENOENT) {
			return sambaConfigSnapshot{}, errors.Join(fmt.Errorf("%w: %s disappeared before publish", errSambaConfigConflict, expected.path), cleanupErr)
		}
		return sambaConfigSnapshot{}, errors.Join(err, cleanupErr)
	}
	displaced, displacedErr := directory.readSnapshot(stagingName, true, "")
	if displacedErr == nil && sambaConfigSnapshotsEqual(expected, displaced) {
		return candidate, errors.Join(discardTemporarySambaConfigSnapshotIfOwned(directory, displaced, cleanupHook), directory.sync())
	}

	current, currentErr := directory.readSnapshot(targetBase, true, "")
	if currentErr == nil && sambaConfigSnapshotsEqual(candidate, current) {
		if rollbackErr := unix.Renameat2(directory.fd, stagingName, directory.fd, targetBase, unix.RENAME_EXCHANGE); rollbackErr == nil {
			rolledBackTemporary, inspectRollbackErr := directory.readSnapshot(stagingName, true, "")
			if inspectRollbackErr == nil && sambaConfigSnapshotsEqual(candidate, rolledBackTemporary) {
				return sambaConfigSnapshot{}, errors.Join(
					fmt.Errorf("%w: displaced config did not match snapshot for %s", errSambaConfigConflict, expected.path),
					displacedErr,
					discardTemporarySambaConfigSnapshotIfOwned(directory, rolledBackTemporary, cleanupHook),
					directory.sync(),
				)
			}
			return sambaConfigSnapshot{}, errors.Join(
				fmt.Errorf("%w: rollback target changed; unknown config preserved at %s", errSambaConfigConflict, directory.displayPath(stagingName)),
				displacedErr,
				inspectRollbackErr,
				directory.quarantineUnknown(stagingName),
				directory.sync(),
			)
		} else {
			return sambaConfigSnapshot{}, errors.Join(
				fmt.Errorf("%w: could not roll back conditional publish; displaced config quarantined", errSambaConfigConflict),
				displacedErr,
				rollbackErr,
				directory.quarantineUnknown(stagingName),
			)
		}
	}
	return sambaConfigSnapshot{}, errors.Join(
		fmt.Errorf("%w: publish target changed again; displaced config quarantined", errSambaConfigConflict),
		displacedErr,
		currentErr,
		directory.quarantineUnknown(stagingName),
	)
}

func removeSambaConfigCAS(expected sambaConfigSnapshot, cleanupHook func(string)) error {
	targetBase := filepath.Base(expected.path)
	directory, err := openSambaConfigDirectory(filepath.Dir(expected.path))
	if err != nil {
		return err
	}
	defer directory.close()
	if err := directory.refuseQuarantine(); err != nil {
		return err
	}
	if err := discardSambaConfigSnapshotIfOwned(directory, expected, cleanupHook); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(directory.fd, targetBase, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil || !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: new content appeared at %s during conditional removal", errSambaConfigConflict, expected.path)
	}
	return directory.sync()
}
