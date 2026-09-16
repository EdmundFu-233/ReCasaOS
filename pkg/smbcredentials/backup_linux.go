//go:build linux

package smbcredentials

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const (
	backupKeyringName  = CredentialName + ".backup"
	backupStagingName  = "." + CredentialName + ".backup.staging"
	backupOpenFlags    = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
	backupStagingFlags = unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
	minBackupBytes     = len(keyringMagic) + 1 + 1 + keyIDSize + (keyIDSize + keySize)
	maxBackupBytes     = len(keyringMagic) + 1 + 1 + keyIDSize + maxKeys*(keyIDSize+keySize)
)

// BackupKeyring publishes one canonical Marshal of the keyring to the fixed
// backup name beside the live source. It never overwrites an existing backup
// and never accepts a caller-supplied path.
func BackupKeyring(keyring *Keyring) (result BackupResult, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return BackupResult{}, ErrUnsafeSourceKeyring
	}
	if keyring == nil {
		return BackupResult{}, ErrInvalidKeyring
	}
	ops := defaultSourceProvisionOps()
	rootFD, openErr := ops.openat(
		unix.AT_FDCWD,
		"/",
		sourceDirectoryReadOpenFlags,
		0,
	)
	if openErr != nil {
		return BackupResult{}, sourceProvisionFailure("open backup keyring root", openErr)
	}
	result, err = backupKeyringAt(rootFD, 0, 0, keyring, ops)
	if closeErr := ops.close(rootFD); closeErr != nil {
		if result.Created {
			result.DurabilityUnknown = true
		}
		err = errors.Join(err, sourceProvisionFailure("close backup keyring root", closeErr))
	}
	return result, err
}

// backupKeyringAt is the testable descriptor-relative core. The production
// wrapper alone chooses the root descriptor and requires uid/gid 0.
func backupKeyringAt(
	rootFD int,
	owner uint32,
	group uint32,
	keyring *Keyring,
	ops sourceProvisionOps,
) (result BackupResult, err error) {
	path, openErr := openSourceProvisionPath(
		rootFD,
		owner,
		group,
		sourceDirectoryReadOpenFlags,
		ops.sourcePathOps,
	)
	if openErr != nil {
		return BackupResult{}, openErr
	}
	defer func() {
		if closeErr := path.close(ops.sourcePathOps); closeErr != nil {
			if result.Created {
				result.DurabilityUnknown = true
			}
			err = errors.Join(err, closeErr)
		}
	}()
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return BackupResult{}, err
	}

	fd, openErr := ops.openat(path.directoryFD, backupStagingName, backupStagingFlags, 0)
	if openErr != nil {
		if errors.Is(openErr, unix.EEXIST) {
			return BackupResult{CleanupRequired: true}, errors.Join(
				ErrSourceCleanupRequired,
				sourceProvisionFailure("reserve keyring backup staging object", openErr),
			)
		}
		return BackupResult{}, sourceProvisionFailure("reserve keyring backup staging object", openErr)
	}
	defer func() {
		if closeErr := sourceCloseFailure("close keyring backup candidate", fd, ops); closeErr != nil {
			if result.Created {
				result.DurabilityUnknown = true
			}
			err = errors.Join(err, closeErr)
		}
	}()

	data, marshalErr := keyring.Marshal()
	if marshalErr != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(marshalErr, cleanupErr)
	}
	defer clear(data)
	if err := prepareSourceCandidate(fd, 1, path.owner, path.group, data, ops); err != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(err, cleanupErr)
	}
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(err, cleanupErr)
	}
	stagingState, stagingErr := inspectSourceName(path.directoryFD, backupStagingName, fd, ops)
	if stagingErr != nil || stagingState != sourceNameCandidate {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(ErrSourceCleanupRequired, stagingErr, cleanupErr)
	}
	targetState, targetErr := inspectSourceName(path.directoryFD, backupKeyringName, fd, ops)
	if targetErr != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(ErrSourceCleanupRequired, targetErr, cleanupErr)
	}
	if targetState != sourceNameAbsent {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(ErrBackupExists, cleanupErr)
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(
			sourceProvisionFailure("sync keyring backup directory", err),
			cleanupErr,
		)
	}
	if renameErr := ops.renameat2(
		path.directoryFD,
		backupStagingName,
		path.directoryFD,
		backupKeyringName,
		uint(unix.RENAME_NOREPLACE),
	); renameErr != nil {
		stillDirty, cleanupErr := cleanupBackupStaging(path, fd, ops)
		if errors.Is(renameErr, unix.EEXIST) {
			return BackupResult{CleanupRequired: stillDirty}, errors.Join(ErrBackupExists, cleanupErr)
		}
		return BackupResult{CleanupRequired: stillDirty}, errors.Join(
			sourceProvisionFailure("publish keyring backup", renameErr),
			cleanupErr,
		)
	}
	if err := validateBackupPublished(path, fd, data, ops); err != nil {
		// The rename won but post-publish verification failed. A staging
		// object reappearing here means residue: hold for the operator.
		stagingState, stagingErr := inspectSourceName(path.directoryFD, backupStagingName, fd, ops)
		dirty := stagingErr != nil || stagingState != sourceNameAbsent
		return BackupResult{Created: true, DurabilityUnknown: true, CleanupRequired: dirty}, errors.Join(err, stagingErr)
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		return BackupResult{Created: true, DurabilityUnknown: true}, sourceProvisionFailure(
			"sync published keyring backup directory",
			err,
		)
	}
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return BackupResult{Created: true, DurabilityUnknown: true}, err
	}
	return BackupResult{Created: true}, nil
}

func validateBackupPublished(
	path *sourceProvisionPath,
	candidateFD int,
	data []byte,
	ops sourceProvisionOps,
) error {
	if err := validateSourceCandidate(candidateFD, 1, path.owner, path.group, data, ops); err != nil {
		return err
	}
	var candidate unix.Stat_t
	if err := ops.fstat(candidateFD, &candidate); err != nil {
		return sourceProvisionFailure("inspect published keyring backup", err)
	}
	var named unix.Stat_t
	if err := ops.fstatat(path.directoryFD, backupKeyringName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return sourceProvisionFailure("bind published keyring backup", err)
	}
	if !sameSourceIdentity(named, candidate) {
		return ErrUnsafeSourceKeyring
	}
	stagingState, stagingErr := inspectSourceName(path.directoryFD, backupStagingName, candidateFD, ops)
	if stagingErr != nil || stagingState != sourceNameAbsent {
		return errors.Join(ErrUnsafeSourceKeyring, stagingErr)
	}
	return nil
}

func cleanupBackupStaging(
	path *sourceProvisionPath,
	fd int,
	ops sourceProvisionOps,
) (bool, error) {
	state, inspectErr := inspectSourceName(path.directoryFD, backupStagingName, fd, ops)
	if inspectErr != nil {
		return true, errors.Join(ErrSourceCleanupRequired, inspectErr)
	}
	if state == sourceNameAbsent {
		return false, nil
	}
	if state != sourceNameCandidate {
		return true, ErrSourceCleanupRequired
	}
	if err := ops.unlinkat(path.directoryFD, backupStagingName, 0); err != nil {
		return true, errors.Join(
			ErrSourceCleanupRequired,
			sourceProvisionFailure("remove keyring backup staging object", err),
		)
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		return true, errors.Join(
			ErrSourceCleanupRequired,
			sourceProvisionFailure("sync keyring backup staging cleanup", err),
		)
	}
	return false, nil
}

// RestoreKeyring loads the fixed backup name and parses it as a keyring. The
// live source is never touched: the caller decides how to adopt the restored
// keys (for example by sealing a cutover under them in a maintenance window).
func RestoreKeyring() (*Keyring, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return nil, ErrUnsafeSourceKeyring
	}
	ops := defaultSourceProvisionOps()
	rootFD, openErr := ops.openat(
		unix.AT_FDCWD,
		"/",
		sourceDirectoryReadOpenFlags,
		0,
	)
	if openErr != nil {
		return nil, sourceProvisionFailure("open restore keyring root", openErr)
	}
	defer func() {
		_ = ops.close(rootFD)
	}()
	return restoreKeyringAt(rootFD, 0, 0, ops)
}

func restoreKeyringAt(
	rootFD int,
	owner uint32,
	group uint32,
	ops sourceProvisionOps,
) (*Keyring, error) {
	path, openErr := openSourceProvisionPath(
		rootFD,
		owner,
		group,
		sourceDirectoryReadOpenFlags,
		ops.sourcePathOps,
	)
	if openErr != nil {
		return nil, openErr
	}
	defer func() {
		_ = path.close(ops.sourcePathOps)
	}()
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return nil, err
	}
	fd, openErr := ops.openat(path.directoryFD, backupKeyringName, backupOpenFlags, 0)
	if openErr != nil {
		return nil, sourceProvisionFailure("open keyring backup", openErr)
	}
	defer func() {
		_ = sourceCloseFailure("close keyring backup", fd, ops)
	}()
	var stat unix.Stat_t
	if err := ops.fstat(fd, &stat); err != nil {
		return nil, sourceProvisionFailure("inspect keyring backup", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != 1 ||
		stat.Uid != path.owner || stat.Gid != path.group ||
		stat.Mode&0o777 != 0o400 || hasSpecialModeBits(stat.Mode) ||
		stat.Size < int64(minBackupBytes) || stat.Size > int64(maxBackupBytes) {
		return nil, ErrUnsafeSourceKeyring
	}
	data, err := sourcePreadExact(fd, int(stat.Size), ops)
	if err != nil {
		clear(data)
		return nil, sourceProvisionFailure("read keyring backup", err)
	}
	defer clear(data)
	state, inspectErr := inspectSourceName(path.directoryFD, backupKeyringName, fd, ops)
	if inspectErr != nil || state != sourceNameCandidate {
		return nil, errors.Join(ErrUnsafeSourceKeyring, inspectErr)
	}
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return nil, err
	}
	restored, parseErr := ParseKeyring(data)
	if parseErr != nil {
		return nil, errors.Join(ErrUnsafeSourceKeyring, parseErr)
	}
	return restored, nil
}

// RemoveBackup deletes the fixed backup name. Backup rotation is explicit:
// verify the new backup, then remove the old one with this call.
func RemoveBackup() (bool, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return false, ErrUnsafeSourceKeyring
	}
	ops := defaultSourceProvisionOps()
	rootFD, openErr := ops.openat(
		unix.AT_FDCWD,
		"/",
		sourceDirectoryReadOpenFlags,
		0,
	)
	if openErr != nil {
		return false, sourceProvisionFailure("open backup removal root", openErr)
	}
	defer func() {
		_ = ops.close(rootFD)
	}()
	return removeBackupAt(rootFD, 0, 0, ops)
}

func removeBackupAt(
	rootFD int,
	owner uint32,
	group uint32,
	ops sourceProvisionOps,
) (bool, error) {
	path, openErr := openSourceProvisionPath(
		rootFD,
		owner,
		group,
		sourceDirectoryReadOpenFlags,
		ops.sourcePathOps,
	)
	if openErr != nil {
		return false, openErr
	}
	defer func() {
		_ = path.close(ops.sourcePathOps)
	}()
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return false, err
	}
	if err := ops.unlinkat(path.directoryFD, backupKeyringName, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, sourceProvisionFailure("remove keyring backup", err)
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		return true, sourceProvisionFailure("sync keyring backup removal", err)
	}
	return true, nil
}
