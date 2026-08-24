//go:build linux

package smbcredentials

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const sourceKeyringStagingName = "." + CredentialName + ".provisioning"

var errAnonymousSourcePublishUnavailable = errors.New(
	"anonymous ReCasaOS SMB source publication is unavailable",
)

type sourceProvisionOps struct {
	random    io.Reader
	openat    func(int, string, int, uint32) (int, error)
	fstat     func(int, *unix.Stat_t) error
	fstatat   func(int, string, *unix.Stat_t, int) error
	write     func(int, []byte) (int, error)
	pread     func(int, []byte, int64) (int, error)
	fchown    func(int, int, int) error
	fchmod    func(int, uint32) error
	fsync     func(int) error
	linkat    func(int, string, int, string, int) error
	renameat2 func(int, string, int, string, uint) error
	unlinkat  func(int, string, int) error
	close     func(int) error
}

func defaultSourceProvisionOps() sourceProvisionOps {
	return sourceProvisionOps{
		random:    rand.Reader,
		openat:    unix.Openat,
		fstat:     unix.Fstat,
		fstatat:   unix.Fstatat,
		write:     unix.Write,
		pread:     unix.Pread,
		fchown:    unix.Fchown,
		fchmod:    unix.Fchmod,
		fsync:     unix.Fsync,
		linkat:    unix.Linkat,
		renameat2: unix.Renameat2,
		unlinkat:  unix.Unlinkat,
		close:     unix.Close,
	}
}

type sourceProvisionPath struct {
	rootFD      int
	etcFD       int
	directoryFD int
	owner       uint32
	group       uint32
	root        unix.Stat_t
	etc         unix.Stat_t
	directory   unix.Stat_t
}

type sourceNameState uint8

const (
	sourceNameAbsent sourceNameState = iota
	sourceNameCandidate
	sourceNameOther
)

// ProvisionSystemKeyringSource creates only SourceKeyringPath. It never
// accepts a caller-supplied path, key, reader, or syscall hook.
func ProvisionSystemKeyringSource() (result ProvisionResult, err error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ProvisionResult{}, ErrUnsafeSourceKeyring
	}
	ops := defaultSourceProvisionOps()
	rootFD, openErr := ops.openat(
		unix.AT_FDCWD,
		"/",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if openErr != nil {
		return ProvisionResult{}, sourceProvisionFailure("open source keyring root", openErr)
	}
	result, err = provisionSystemKeyringSourceAt(rootFD, 0, 0, ops)
	if closeErr := ops.close(rootFD); closeErr != nil {
		if result.Created {
			result.DurabilityUnknown = true
		}
		err = errors.Join(err, sourceProvisionFailure("close source keyring root", closeErr))
	}
	return result, err
}

// provisionSystemKeyringSourceAt is the testable descriptor-relative core. The
// production wrapper alone chooses the root descriptor and requires uid/gid 0.
func provisionSystemKeyringSourceAt(
	rootFD int,
	owner uint32,
	group uint32,
	ops sourceProvisionOps,
) (result ProvisionResult, err error) {
	path, openErr := openSourceProvisionPath(rootFD, owner, group, ops)
	if openErr != nil {
		return ProvisionResult{}, openErr
	}
	defer func() {
		if closeErr := path.close(ops); closeErr != nil {
			if result.Created {
				result.DurabilityUnknown = true
			}
			err = errors.Join(err, closeErr)
		}
	}()

	if namespaceResult, namespaceErr := requireEmptySourceNamespace(path.directoryFD, ops); namespaceErr != nil {
		return namespaceResult, namespaceErr
	}

	keyring, keyErr := newKeyring(ops.random)
	if keyErr != nil {
		return ProvisionResult{}, sourceProvisionFailure("generate source keyring", keyErr)
	}
	defer keyring.Destroy()
	data, marshalErr := keyring.Marshal()
	if marshalErr != nil {
		return ProvisionResult{}, sourceProvisionFailure("marshal source keyring", marshalErr)
	}
	defer clear(data)

	result, err, fallback := provisionAnonymousSource(path, data, ops)
	if !fallback {
		return result, err
	}
	return provisionNamedSource(path, data, ops)
}

func openSourceProvisionPath(
	rootFD int,
	owner uint32,
	group uint32,
	ops sourceProvisionOps,
) (*sourceProvisionPath, error) {
	path := &sourceProvisionPath{
		rootFD:      rootFD,
		etcFD:       -1,
		directoryFD: -1,
		owner:       owner,
		group:       group,
	}
	if err := ops.fstat(rootFD, &path.root); err != nil {
		return nil, sourceProvisionFailure("inspect source keyring root", err)
	}
	if !safeSourceAncestor(path.root, owner, group) {
		return nil, ErrUnsafeSourceKeyring
	}

	etcFD, err := ops.openat(
		rootFD,
		"etc",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, sourceProvisionFailure("open source keyring etc directory", err)
	}
	path.etcFD = etcFD
	if err := ops.fstat(etcFD, &path.etc); err != nil {
		_ = path.close(ops)
		return nil, sourceProvisionFailure("inspect source keyring etc directory", err)
	}
	if !safeSourceAncestor(path.etc, owner, group) {
		_ = path.close(ops)
		return nil, ErrUnsafeSourceKeyring
	}

	directoryFD, err := ops.openat(
		etcFD,
		"recasaos",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		_ = path.close(ops)
		return nil, sourceProvisionFailure("open source keyring directory", err)
	}
	path.directoryFD = directoryFD
	if err := ops.fstat(directoryFD, &path.directory); err != nil {
		_ = path.close(ops)
		return nil, sourceProvisionFailure("inspect source keyring directory", err)
	}
	if !safeSourceDirectory(path.directory, owner, group) {
		_ = path.close(ops)
		return nil, ErrUnsafeSourceKeyring
	}
	if err := path.revalidate(ops); err != nil {
		_ = path.close(ops)
		return nil, err
	}
	return path, nil
}

func (p *sourceProvisionPath) revalidate(ops sourceProvisionOps) error {
	var root, etc, directory unix.Stat_t
	if err := ops.fstat(p.rootFD, &root); err != nil {
		return sourceProvisionFailure("recheck source keyring root", err)
	}
	if err := ops.fstat(p.etcFD, &etc); err != nil {
		return sourceProvisionFailure("recheck source keyring etc directory", err)
	}
	if err := ops.fstat(p.directoryFD, &directory); err != nil {
		return sourceProvisionFailure("recheck source keyring directory", err)
	}
	if !sameSourceIdentity(root, p.root) || !sameSourceIdentity(etc, p.etc) ||
		!sameSourceIdentity(directory, p.directory) ||
		!safeSourceAncestor(root, p.owner, p.group) ||
		!safeSourceAncestor(etc, p.owner, p.group) ||
		!safeSourceDirectory(directory, p.owner, p.group) {
		return ErrUnsafeSourceKeyring
	}
	var namedEtc, namedDirectory unix.Stat_t
	if err := ops.fstatat(p.rootFD, "etc", &namedEtc, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return sourceProvisionFailure("bind source keyring etc directory", err)
	}
	if err := ops.fstatat(p.etcFD, "recasaos", &namedDirectory, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return sourceProvisionFailure("bind source keyring directory", err)
	}
	if !sameSourceIdentity(namedEtc, p.etc) || !sameSourceIdentity(namedDirectory, p.directory) {
		return ErrUnsafeSourceKeyring
	}
	return nil
}

func (p *sourceProvisionPath) close(ops sourceProvisionOps) error {
	var result error
	if p.directoryFD >= 0 {
		result = errors.Join(
			result,
			sourceCloseFailure("close source keyring directory", p.directoryFD, ops),
		)
		p.directoryFD = -1
	}
	if p.etcFD >= 0 {
		result = errors.Join(
			result,
			sourceCloseFailure("close source keyring etc directory", p.etcFD, ops),
		)
		p.etcFD = -1
	}
	return result
}

func provisionAnonymousSource(
	path *sourceProvisionPath,
	data []byte,
	ops sourceProvisionOps,
) (result ProvisionResult, err error, fallback bool) {
	flags := unix.O_TMPFILE | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, openErr := ops.openat(path.directoryFD, ".", flags, 0)
	if openErr != nil {
		if anonymousSourceOpenUnavailable(openErr) {
			return ProvisionResult{}, nil, true
		}
		return ProvisionResult{}, sourceProvisionFailure(
			"create anonymous source keyring candidate",
			openErr,
		), false
	}

	result, err, fallback = publishAnonymousSourceCandidate(path, fd, data, ops)
	if closeErr := sourceCloseFailure("close anonymous source keyring candidate", fd, ops); closeErr != nil {
		if result.Created {
			result.DurabilityUnknown = true
		}
		err = errors.Join(err, closeErr)
		fallback = false
	}
	return result, err, fallback
}

func publishAnonymousSourceCandidate(
	path *sourceProvisionPath,
	fd int,
	data []byte,
	ops sourceProvisionOps,
) (ProvisionResult, error, bool) {
	if err := prepareSourceCandidate(fd, 0, path.owner, path.group, data, ops); err != nil {
		return ProvisionResult{}, err, false
	}
	if err := path.revalidate(ops); err != nil {
		return ProvisionResult{}, err, false
	}
	targetState, stateErr := inspectSourceName(path.directoryFD, CredentialName, fd, ops)
	if stateErr != nil {
		return ProvisionResult{}, stateErr, false
	}
	if targetState != sourceNameAbsent {
		return ProvisionResult{}, ErrSourceKeyringExists, false
	}

	linkErr := ops.linkat(fd, "", path.directoryFD, CredentialName, unix.AT_EMPTY_PATH)
	state, inspectErr := inspectSourceName(path.directoryFD, CredentialName, fd, ops)
	if linkErr == nil {
		result := ProvisionResult{Created: true}
		if state != sourceNameCandidate {
			result.DurabilityUnknown = true
			finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
			return finalized, errors.Join(
				ErrUnsafeSourceKeyring,
				inspectErr,
				finalErr,
			), false
		}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, finalErr, false
	}
	if inspectErr != nil {
		result := ProvisionResult{Created: true, DurabilityUnknown: true}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, errors.Join(
			sourceProvisionFailure("publish anonymous source keyring", linkErr),
			inspectErr,
			finalErr,
		), false
	}
	if state == sourceNameCandidate {
		result := ProvisionResult{Created: true, DurabilityUnknown: true}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, errors.Join(
			sourceProvisionFailure("publish anonymous source keyring", linkErr),
			inspectErr,
			finalErr,
		), false
	}
	if errors.Is(linkErr, unix.EEXIST) {
		return ProvisionResult{}, errors.Join(
			ErrSourceKeyringExists,
			sourceProvisionFailure("publish anonymous source keyring", linkErr),
			inspectErr,
		), false
	}
	if state == sourceNameOther {
		result := ProvisionResult{Created: true, DurabilityUnknown: true}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, errors.Join(
			sourceProvisionFailure("publish anonymous source keyring", linkErr),
			ErrUnsafeSourceKeyring,
			finalErr,
		), false
	}
	if errors.Is(linkErr, unix.ENOENT) {
		if inspectErr != nil {
			return ProvisionResult{}, inspectErr, false
		}
		if err := validateSourceCandidate(fd, 0, path.owner, path.group, data, ops); err != nil {
			return ProvisionResult{}, err, false
		}
		if err := path.revalidate(ops); err != nil {
			return ProvisionResult{}, err, false
		}
		return ProvisionResult{}, errAnonymousSourcePublishUnavailable, true
	}
	if sourceLinkFailureDefinitive(linkErr) {
		return ProvisionResult{}, sourceProvisionFailure(
			"publish anonymous source keyring",
			linkErr,
		), false
	}
	result := ProvisionResult{Created: true, DurabilityUnknown: true}
	finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
	return finalized, errors.Join(
		sourceProvisionFailure("publish anonymous source keyring", linkErr),
		finalErr,
	), false
}

func provisionNamedSource(
	path *sourceProvisionPath,
	data []byte,
	ops sourceProvisionOps,
) (result ProvisionResult, err error) {
	if err := path.revalidate(ops); err != nil {
		return ProvisionResult{}, err
	}
	if namespaceResult, namespaceErr := requireEmptySourceNamespace(path.directoryFD, ops); namespaceErr != nil {
		return namespaceResult, namespaceErr
	}

	flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC |
		unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY
	fd, openErr := ops.openat(path.directoryFD, sourceKeyringStagingName, flags, 0)
	if openErr != nil {
		if errors.Is(openErr, unix.EEXIST) {
			return ProvisionResult{CleanupRequired: true}, errors.Join(
				ErrSourceCleanupRequired,
				sourceProvisionFailure("reserve source keyring staging object", openErr),
			)
		}
		return ProvisionResult{}, sourceProvisionFailure(
			"reserve source keyring staging object",
			openErr,
		)
	}

	result, err = publishNamedSourceCandidate(path, fd, data, ops)
	if closeErr := sourceCloseFailure("close named source keyring candidate", fd, ops); closeErr != nil {
		if result.Created {
			result.DurabilityUnknown = true
		}
		err = errors.Join(err, closeErr)
	}
	return result, err
}

func publishNamedSourceCandidate(
	path *sourceProvisionPath,
	fd int,
	data []byte,
	ops sourceProvisionOps,
) (result ProvisionResult, err error) {
	prepared := false
	defer func() {
		if result.Created || !prepared {
			return
		}
		cleanupRequired, cleanupErr := cleanupNamedSourceCandidate(path, fd, ops)
		result.CleanupRequired = result.CleanupRequired || cleanupRequired
		err = errors.Join(err, cleanupErr)
	}()

	if err := prepareSourceCandidate(fd, 1, path.owner, path.group, data, ops); err != nil {
		prepared = true
		return ProvisionResult{}, err
	}
	prepared = true
	if err := path.revalidate(ops); err != nil {
		return ProvisionResult{}, err
	}
	stagingState, stagingErr := inspectSourceName(
		path.directoryFD,
		sourceKeyringStagingName,
		fd,
		ops,
	)
	if stagingErr != nil || stagingState != sourceNameCandidate {
		return ProvisionResult{CleanupRequired: true}, errors.Join(
			ErrSourceCleanupRequired,
			stagingErr,
		)
	}
	targetState, targetErr := inspectSourceName(path.directoryFD, CredentialName, fd, ops)
	if targetErr != nil {
		return ProvisionResult{CleanupRequired: true}, errors.Join(
			ErrSourceCleanupRequired,
			targetErr,
		)
	}
	if targetState != sourceNameAbsent {
		return ProvisionResult{}, ErrSourceKeyringExists
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		return ProvisionResult{}, sourceProvisionFailure(
			"sync source keyring staging directory",
			err,
		)
	}

	renameErr := ops.renameat2(
		path.directoryFD,
		sourceKeyringStagingName,
		path.directoryFD,
		CredentialName,
		uint(unix.RENAME_NOREPLACE),
	)
	targetState, targetErr = inspectSourceName(path.directoryFD, CredentialName, fd, ops)
	stagingState, stagingErr = inspectSourceName(
		path.directoryFD,
		sourceKeyringStagingName,
		fd,
		ops,
	)
	if renameErr == nil {
		result = ProvisionResult{Created: true}
		if targetErr != nil || stagingErr != nil ||
			targetState != sourceNameCandidate ||
			stagingState != sourceNameAbsent {
			result.DurabilityUnknown = true
			result.CleanupRequired = stagingErr != nil || stagingState != sourceNameAbsent
			finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
			var recoveryErr error
			if result.CleanupRequired {
				recoveryErr = ErrSourceCleanupRequired
			}
			return finalized, errors.Join(
				ErrUnsafeSourceKeyring,
				targetErr,
				stagingErr,
				recoveryErr,
				finalErr,
			)
		}
		return finalizePublishedSource(path, fd, data, result, ops)
	}
	if targetErr != nil || stagingErr != nil {
		result = ProvisionResult{
			Created:           true,
			DurabilityUnknown: true,
			CleanupRequired:   true,
		}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, errors.Join(
			sourceProvisionFailure("publish named source keyring", renameErr),
			ErrSourceCleanupRequired,
			targetErr,
			stagingErr,
			finalErr,
		)
	}
	if targetState == sourceNameCandidate {
		result = ProvisionResult{
			Created:           true,
			DurabilityUnknown: true,
			CleanupRequired:   stagingState != sourceNameAbsent,
		}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		var recoveryErr error
		if result.CleanupRequired {
			recoveryErr = ErrSourceCleanupRequired
		}
		return finalized, errors.Join(
			sourceProvisionFailure("publish named source keyring", renameErr),
			targetErr,
			recoveryErr,
			finalErr,
		)
	}
	if errors.Is(renameErr, unix.EEXIST) && stagingState == sourceNameCandidate {
		return ProvisionResult{}, errors.Join(
			ErrSourceKeyringExists,
			sourceProvisionFailure("publish named source keyring", renameErr),
			targetErr,
		)
	}
	if targetState == sourceNameOther || stagingState != sourceNameCandidate {
		result = ProvisionResult{
			Created:           true,
			DurabilityUnknown: true,
			CleanupRequired:   true,
		}
		finalized, finalErr := finalizePublishedSource(path, fd, data, result, ops)
		return finalized, errors.Join(
			sourceProvisionFailure("publish named source keyring", renameErr),
			ErrUnsafeSourceKeyring,
			ErrSourceCleanupRequired,
			finalErr,
		)
	}
	if sourceRenameUnsupported(renameErr) {
		return ProvisionResult{}, errors.Join(
			ErrSourceProvisionUnsupported,
			sourceProvisionFailure("publish named source keyring", renameErr),
			targetErr,
		)
	}
	return ProvisionResult{}, errors.Join(
		sourceProvisionFailure("publish named source keyring", renameErr),
		targetErr,
	)
}

func prepareSourceCandidate(
	fd int,
	wantLinks uint64,
	owner uint32,
	group uint32,
	data []byte,
	ops sourceProvisionOps,
) error {
	var initial unix.Stat_t
	if err := ops.fstat(fd, &initial); err != nil {
		return sourceProvisionFailure("inspect source keyring candidate", err)
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFREG || uint64(initial.Nlink) != wantLinks ||
		initial.Size != 0 {
		return ErrUnsafeSourceKeyring
	}
	if err := sourceWriteFull(fd, data, ops); err != nil {
		return sourceProvisionFailure("write source keyring candidate", err)
	}
	if err := ops.fchown(fd, int(owner), int(group)); err != nil {
		return sourceProvisionFailure("set source keyring ownership", err)
	}
	if err := ops.fchmod(fd, 0o400); err != nil {
		return sourceProvisionFailure("set source keyring permissions", err)
	}
	if err := validateSourceCandidate(fd, wantLinks, owner, group, data, ops); err != nil {
		return err
	}
	if err := ops.fsync(fd); err != nil {
		return sourceProvisionFailure("sync source keyring candidate", err)
	}
	return validateSourceCandidate(fd, wantLinks, owner, group, data, ops)
}

func validateSourceCandidate(
	fd int,
	wantLinks uint64,
	owner uint32,
	group uint32,
	data []byte,
	ops sourceProvisionOps,
) error {
	var stat unix.Stat_t
	if err := ops.fstat(fd, &stat); err != nil {
		return sourceProvisionFailure("inspect prepared source keyring", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Nlink) != wantLinks ||
		stat.Uid != owner || stat.Gid != group || stat.Mode&0o777 != 0o400 ||
		hasSpecialModeBits(stat.Mode) || stat.Size != int64(len(data)) {
		return ErrUnsafeSourceKeyring
	}
	readback, err := sourcePreadExact(fd, len(data), ops)
	if err != nil {
		clear(readback)
		return sourceProvisionFailure("read back source keyring candidate", err)
	}
	defer clear(readback)
	if !bytes.Equal(readback, data) {
		return ErrUnsafeSourceKeyring
	}
	parsed, parseErr := ParseKeyring(readback)
	if parseErr != nil {
		return sourceProvisionFailure("parse source keyring candidate", parseErr)
	}
	parsed.Destroy()
	return nil
}

func finalizePublishedSource(
	path *sourceProvisionPath,
	fd int,
	data []byte,
	result ProvisionResult,
	ops sourceProvisionOps,
) (ProvisionResult, error) {
	verifyBefore := validatePublishedSource(path, fd, data, ops)
	var syncErr error
	if err := ops.fsync(path.directoryFD); err != nil {
		syncErr = sourceProvisionFailure("sync published source keyring directory", err)
	}
	pathErr := path.revalidate(ops)
	verifyAfter := validatePublishedSource(path, fd, data, ops)
	err := errors.Join(verifyBefore, syncErr, pathErr, verifyAfter)
	if err != nil {
		result.DurabilityUnknown = true
	}
	return result, err
}

func validatePublishedSource(
	path *sourceProvisionPath,
	candidateFD int,
	data []byte,
	ops sourceProvisionOps,
) error {
	if err := validateSourceCandidate(
		candidateFD,
		1,
		path.owner,
		path.group,
		data,
		ops,
	); err != nil {
		return err
	}
	var candidate unix.Stat_t
	if statErr := ops.fstat(candidateFD, &candidate); statErr != nil {
		return sourceProvisionFailure("inspect published source candidate", statErr)
	}
	var named unix.Stat_t
	if statErr := ops.fstatat(
		path.directoryFD,
		CredentialName,
		&named,
		unix.AT_SYMLINK_NOFOLLOW,
	); statErr != nil {
		return sourceProvisionFailure("bind published source keyring", statErr)
	}
	if !sameSourceIdentity(named, candidate) {
		return ErrUnsafeSourceKeyring
	}
	return nil
}

func cleanupNamedSourceCandidate(
	path *sourceProvisionPath,
	fd int,
	ops sourceProvisionOps,
) (bool, error) {
	// The root-owned 0700 directory is the serialization boundary. There is no
	// Linux unlink-if-name-still-matches-inode primitive, so out-of-protocol root
	// recovery must not race this identity check and unlink.
	state, inspectErr := inspectSourceName(
		path.directoryFD,
		sourceKeyringStagingName,
		fd,
		ops,
	)
	if inspectErr != nil {
		return true, errors.Join(ErrSourceCleanupRequired, inspectErr)
	}
	if state == sourceNameAbsent {
		return false, nil
	}
	if state != sourceNameCandidate {
		return true, ErrSourceCleanupRequired
	}
	if err := ops.unlinkat(path.directoryFD, sourceKeyringStagingName, 0); err != nil {
		return true, errors.Join(
			ErrSourceCleanupRequired,
			sourceProvisionFailure("remove source keyring staging object", err),
		)
	}
	if err := ops.fsync(path.directoryFD); err != nil {
		return true, errors.Join(
			ErrSourceCleanupRequired,
			sourceProvisionFailure("sync source keyring staging cleanup", err),
		)
	}
	return false, nil
}

func sourceWriteFull(fd int, data []byte, ops sourceProvisionOps) error {
	for written := 0; written < len(data); {
		n, err := ops.write(fd, data[written:])
		if n > 0 {
			written += n
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func sourcePreadExact(fd int, length int, ops sourceProvisionOps) ([]byte, error) {
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

func inspectSourceName(
	directoryFD int,
	name string,
	candidateFD int,
	ops sourceProvisionOps,
) (sourceNameState, error) {
	var named unix.Stat_t
	if err := ops.fstatat(directoryFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return sourceNameAbsent, nil
		}
		return sourceNameAbsent, sourceProvisionFailure("inspect source keyring name", err)
	}
	var candidate unix.Stat_t
	if err := ops.fstat(candidateFD, &candidate); err != nil {
		return sourceNameOther, sourceProvisionFailure("inspect source keyring candidate identity", err)
	}
	if sameSourceIdentity(named, candidate) {
		return sourceNameCandidate, nil
	}
	return sourceNameOther, nil
}

func sourceNameExists(directoryFD int, name string, ops sourceProvisionOps) (bool, error) {
	var stat unix.Stat_t
	err := ops.fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return false, sourceProvisionFailure("inspect source keyring namespace", err)
}

func requireEmptySourceNamespace(
	directoryFD int,
	ops sourceProvisionOps,
) (ProvisionResult, error) {
	targetExists, targetErr := sourceNameExists(directoryFD, CredentialName, ops)
	stagingExists, stagingErr := sourceNameExists(
		directoryFD,
		sourceKeyringStagingName,
		ops,
	)
	if targetErr != nil || stagingErr != nil {
		var existsErr error
		if targetErr == nil && targetExists {
			existsErr = ErrSourceKeyringExists
		}
		return ProvisionResult{CleanupRequired: true}, errors.Join(
			ErrSourceCleanupRequired,
			existsErr,
			targetErr,
			stagingErr,
		)
	}
	if targetExists {
		result := ProvisionResult{CleanupRequired: stagingExists}
		if stagingExists {
			return result, errors.Join(ErrSourceKeyringExists, ErrSourceCleanupRequired)
		}
		return result, ErrSourceKeyringExists
	}
	if stagingExists {
		return ProvisionResult{CleanupRequired: true}, ErrSourceCleanupRequired
	}
	return ProvisionResult{}, nil
}

func safeSourceAncestor(stat unix.Stat_t, owner uint32, group uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Uid == owner &&
		stat.Gid == group &&
		stat.Mode&0o022 == 0 &&
		!hasSpecialModeBits(stat.Mode)
}

func safeSourceDirectory(stat unix.Stat_t, owner uint32, group uint32) bool {
	return safeSourceAncestor(stat, owner, group) && stat.Mode&0o777 == 0o700
}

func sameSourceIdentity(left unix.Stat_t, right unix.Stat_t) bool {
	return uint64(left.Dev) == uint64(right.Dev) && uint64(left.Ino) == uint64(right.Ino)
}

func anonymousSourceOpenUnavailable(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EISDIR) ||
		errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENOSYS)
}

func sourceRenameUnsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

func sourceLinkFailureDefinitive(err error) bool {
	return errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EROFS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EBADF) ||
		errors.Is(err, unix.EXDEV) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

func sourceCloseFailure(operation string, fd int, ops sourceProvisionOps) error {
	if err := ops.close(fd); err != nil {
		return sourceProvisionFailure(operation, err)
	}
	return nil
}

func sourceProvisionFailure(operation string, err error) error {
	if err == nil {
		return errors.New(operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
