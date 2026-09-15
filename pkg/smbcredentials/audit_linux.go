//go:build linux

package smbcredentials

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const minSourceAuditKeyringBytes = len(keyringMagic) + 1 + 1 + keyIDSize + keyIDSize + keySize

// sourceAuditOps deliberately cannot mutate the source namespace or target.
// Tests receive this narrower capability set instead of provisioning ops.
type sourceAuditOps struct {
	sourcePathOps
	pread func(int, []byte, int64) (int, error)
}

func defaultSourceAuditOps() sourceAuditOps {
	return sourceAuditOps{
		sourcePathOps: defaultSourcePathOps(),
		pread:         unix.Pread,
	}
}

// CheckSystemKeyringSourceStructure performs a read-only structural snapshot
// of the fixed SourceKeyringPath. A nil result means only that the object was
// safely bound, bounded, and canonically parseable during this call. It does
// not prove provenance, prior or durable provisioning, post-return continuity,
// identity with a runtime systemd credential or database state, activation
// safety, or idempotent provisioning. The function returns no keyring, key ID,
// bytes, or other key material.
//
// ErrSourceKeyringMissing is returned only after the safe namespace, marker,
// and absent target are repeatedly checked. ErrSourceCleanupRequired means a
// marker is present or its state is unknown. ErrUnsafeSourceKeyring covers an
// unsafe or inconsistent boundary, target, or read; malformed canonical bytes
// also preserve ErrInvalidKeyring for errors.Is. Other I/O errors are
// indeterminate hard failures. Every non-nil result is fail-closed, and a
// missing result does not authorize provisioning or retry.
func CheckSystemKeyringSourceStructure() (err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrUnsafeSourceKeyring
	}
	ops := defaultSourceAuditOps()
	rootFD, openErr := ops.openat(
		unix.AT_FDCWD,
		"/",
		sourceDirectoryPathOpenFlags,
		0,
	)
	if openErr != nil {
		return sourceAuditFailure("open source keyring audit root", openErr)
	}
	err = checkSystemKeyringSourceStructureAt(rootFD, 0, 0, ops)
	if closeErr := ops.close(rootFD); closeErr != nil {
		err = errors.Join(err, sourceAuditFailure("close source keyring audit root", closeErr))
	}
	return err
}

// checkSystemKeyringSourceStructureAt is the testable descriptor-relative
// core. The production wrapper alone chooses the root descriptor and requires
// real/effective uid/gid 0.
func checkSystemKeyringSourceStructureAt(
	rootFD int,
	owner uint32,
	group uint32,
	ops sourceAuditOps,
) (err error) {
	path, openErr := openSourceProvisionPath(
		rootFD,
		owner,
		group,
		sourceDirectoryPathOpenFlags,
		ops.sourcePathOps,
	)
	if openErr != nil {
		return openErr
	}
	defer func() {
		err = errors.Join(err, path.close(ops.sourcePathOps))
	}()

	if markerErr := requireSourceAuditMarkerAbsent(path.directoryFD, ops); markerErr != nil {
		return markerErr
	}
	if pathErr := path.revalidate(ops.sourcePathOps); pathErr != nil {
		return pathErr
	}

	pinnedFD, pinnedOpenErr := ops.openat(
		path.directoryFD,
		CredentialName,
		sourceObjectPathOpenFlags,
		0,
	)
	if pinnedOpenErr != nil {
		if errors.Is(pinnedOpenErr, unix.ENOENT) {
			return confirmSourceAuditTargetMissing(path, ops)
		}
		return sourceAuditFailure("pin source keyring audit target", pinnedOpenErr)
	}
	defer func() {
		if closeErr := ops.close(pinnedFD); closeErr != nil {
			err = errors.Join(
				err,
				sourceAuditFailure("close pinned source keyring audit target", closeErr),
			)
		}
	}()

	var pinned unix.Stat_t
	if statErr := ops.fstat(pinnedFD, &pinned); statErr != nil {
		return sourceAuditFailure("inspect pinned source keyring audit target", statErr)
	}
	if !safeSourceAuditTarget(pinned, owner, group) {
		return ErrUnsafeSourceKeyring
	}
	if bindErr := bindSourceAuditTarget(path, pinned, ops); bindErr != nil {
		return bindErr
	}
	if markerErr := requireSourceAuditMarkerAbsent(path.directoryFD, ops); markerErr != nil {
		return markerErr
	}

	readFlags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW |
		unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOATIME
	readFD, readOpenErr := ops.openat(path.directoryFD, CredentialName, readFlags, 0)
	if readOpenErr != nil {
		if errors.Is(readOpenErr, unix.ENOENT) || errors.Is(readOpenErr, unix.ELOOP) {
			return errors.Join(
				ErrUnsafeSourceKeyring,
				sourceAuditFailure("open source keyring audit target", readOpenErr),
			)
		}
		return sourceAuditFailure("open source keyring audit target", readOpenErr)
	}
	defer func() {
		if closeErr := ops.close(readFD); closeErr != nil {
			err = errors.Join(
				err,
				sourceAuditFailure("close source keyring audit target", closeErr),
			)
		}
	}()

	var opened unix.Stat_t
	if statErr := ops.fstat(readFD, &opened); statErr != nil {
		return sourceAuditFailure("inspect opened source keyring audit target", statErr)
	}
	if !safeSourceAuditTarget(opened, owner, group) ||
		!sameSourceAuditSnapshot(pinned, opened) {
		return ErrUnsafeSourceKeyring
	}
	if bindErr := bindSourceAuditTarget(path, opened, ops); bindErr != nil {
		return bindErr
	}
	if markerErr := requireSourceAuditMarkerAbsent(path.directoryFD, ops); markerErr != nil {
		return markerErr
	}

	data, readErr := sourceAuditPreadExact(readFD, int(opened.Size), ops)
	if readErr != nil {
		clear(data)
		readFailure := sourceAuditFailure("read source keyring audit target", readErr)
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return errors.Join(ErrUnsafeSourceKeyring, readFailure)
		}
		return readFailure
	}
	defer clear(data)

	if verifyErr := recheckSourceAuditTarget(path, readFD, opened, ops); verifyErr != nil {
		return verifyErr
	}

	keyring, parseErr := ParseKeyring(data)
	if parseErr != nil {
		return errors.Join(
			ErrUnsafeSourceKeyring,
			sourceAuditFailure("parse source keyring audit target", parseErr),
		)
	}
	keyring.Destroy()
	clear(data)

	return recheckSourceAuditTarget(path, readFD, opened, ops)
}

func confirmSourceAuditTargetMissing(path *sourceProvisionPath, ops sourceAuditOps) error {
	if pathErr := path.revalidate(ops.sourcePathOps); pathErr != nil {
		return pathErr
	}
	if markerErr := requireSourceAuditMarkerAbsent(path.directoryFD, ops); markerErr != nil {
		return markerErr
	}
	var target unix.Stat_t
	if err := ops.fstatat(
		path.directoryFD,
		CredentialName,
		&target,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return ErrUnsafeSourceKeyring
	} else if !errors.Is(err, unix.ENOENT) {
		return sourceAuditFailure("confirm missing source keyring audit target", err)
	}
	if pathErr := path.revalidate(ops.sourcePathOps); pathErr != nil {
		return pathErr
	}
	if markerErr := requireSourceAuditMarkerAbsent(path.directoryFD, ops); markerErr != nil {
		return markerErr
	}
	if err := ops.fstatat(
		path.directoryFD,
		CredentialName,
		&target,
		unix.AT_SYMLINK_NOFOLLOW,
	); err == nil {
		return ErrUnsafeSourceKeyring
	} else if !errors.Is(err, unix.ENOENT) {
		return sourceAuditFailure("reconfirm missing source keyring audit target", err)
	}
	return ErrSourceKeyringMissing
}

func recheckSourceAuditTarget(
	path *sourceProvisionPath,
	readFD int,
	expected unix.Stat_t,
	ops sourceAuditOps,
) error {
	var after unix.Stat_t
	if statErr := ops.fstat(readFD, &after); statErr != nil {
		return sourceAuditFailure("recheck opened source keyring audit target", statErr)
	}
	if !safeSourceAuditTarget(after, path.owner, path.group) ||
		!sameSourceAuditSnapshot(expected, after) {
		return ErrUnsafeSourceKeyring
	}
	if bindErr := bindSourceAuditTarget(path, after, ops); bindErr != nil {
		return bindErr
	}
	return requireSourceAuditMarkerAbsent(path.directoryFD, ops)
}

func bindSourceAuditTarget(
	path *sourceProvisionPath,
	opened unix.Stat_t,
	ops sourceAuditOps,
) error {
	if err := path.revalidate(ops.sourcePathOps); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := ops.fstatat(
		path.directoryFD,
		CredentialName,
		&named,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		bindFailure := sourceAuditFailure("bind source keyring audit target", err)
		if errors.Is(err, unix.ENOENT) {
			return errors.Join(ErrUnsafeSourceKeyring, bindFailure)
		}
		return bindFailure
	}
	if !safeSourceAuditTarget(named, path.owner, path.group) ||
		!sameSourceAuditSnapshot(named, opened) {
		return ErrUnsafeSourceKeyring
	}
	return nil
}

func requireSourceAuditMarkerAbsent(directoryFD int, ops sourceAuditOps) error {
	exists, err := sourceNameExists(directoryFD, sourceKeyringStagingName, ops.sourcePathOps)
	if err != nil {
		return errors.Join(ErrSourceCleanupRequired, err)
	}
	if exists {
		return ErrSourceCleanupRequired
	}
	return nil
}

func safeSourceAuditTarget(stat unix.Stat_t, owner uint32, group uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		uint64(stat.Nlink) == 1 &&
		stat.Uid == owner &&
		stat.Gid == group &&
		stat.Mode&0o777 == 0o400 &&
		!hasSpecialModeBits(stat.Mode) &&
		stat.Size >= int64(minSourceAuditKeyringBytes) &&
		stat.Size <= int64(maxKeyringBytes)
}

func sameSourceAuditSnapshot(before unix.Stat_t, after unix.Stat_t) bool {
	return sameSourceIdentity(before, after) &&
		before.Mode == after.Mode &&
		before.Nlink == after.Nlink &&
		before.Uid == after.Uid &&
		before.Gid == after.Gid &&
		before.Size == after.Size &&
		before.Mtim == after.Mtim &&
		before.Ctim == after.Ctim
}

func sourceAuditPreadExact(fd int, length int, ops sourceAuditOps) ([]byte, error) {
	buffer := make([]byte, length+1)
	offset := 0
	for offset < len(buffer) {
		n, err := ops.pread(fd, buffer[offset:], int64(offset))
		if n > 0 {
			offset += n
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return buffer[:offset], err
		}
		if n == 0 {
			break
		}
	}
	if offset != length {
		return buffer[:offset], io.ErrUnexpectedEOF
	}
	return buffer[:offset], nil
}

func sourceAuditFailure(operation string, err error) error {
	if err == nil {
		return errors.New(operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
