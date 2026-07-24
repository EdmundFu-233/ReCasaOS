//go:build linux

package publicfiles

import (
	"encoding/binary"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const (
	verifierAccessACLXattr = "system.posix_acl_access"

	posixACLXattrVersion = 0x0002
	posixACLUndefinedID  = ^uint32(0)

	posixACLUserObject  = 0x01
	posixACLUser        = 0x02
	posixACLGroupObject = 0x04
	posixACLMask        = 0x10
	posixACLOther       = 0x20

	posixACLRead = 0x04

	posixACLXattrHeaderSize     = 4
	posixACLXattrEntrySize      = 8
	systemdCredentialACLEntries = 5
	systemdCredentialACLSize    = posixACLXattrHeaderSize +
		systemdCredentialACLEntries*posixACLXattrEntrySize
)

type verifierACLEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

func validateVerifierFileCandidate(stat *unix.Stat_t) error {
	return validateVerifierFileCandidateForUID(stat, uint32(os.Geteuid()))
}

// validateVerifierFileCandidateForUID performs only checks that are valid on
// an O_PATH descriptor. A root-owned 0440 file is only a candidate here:
// validateVerifierFileDescriptor must still prove the exact systemd ACL on a
// readable descriptor before any verifier bytes are read.
func validateVerifierFileCandidateForUID(
	stat *unix.Stat_t,
	effectiveUID uint32,
) error {
	if !isSingleLinkRegular(stat) {
		return errors.New("verifier file must be a stable single-link regular file")
	}
	if stat.Uid != 0 && stat.Uid != effectiveUID {
		return errors.New("verifier file must be owned by root or the service user")
	}

	permissions := stat.Mode & 0o7777
	if permissions == 0o400 || permissions == 0o600 {
		return nil
	}
	if effectiveUID != 0 &&
		stat.Uid == 0 &&
		stat.Gid == 0 &&
		permissions == 0o440 {
		return nil
	}
	return errors.New("verifier file permissions must be exactly 0400 or 0600, or use the exact root-owned systemd credential access ACL")
}

func validateVerifierFileDescriptor(fd int, stat *unix.Stat_t) error {
	accessACL, err := readVerifierAccessACL(fd)
	if err != nil {
		return err
	}
	var afterACL unix.Stat_t
	if err := unix.Fstat(fd, &afterACL); err != nil {
		return errors.New("cannot revalidate verifier file after inspecting its access ACL")
	}
	if !sameVerifierFileMetadata(stat, &afterACL) {
		return errors.New("verifier file changed while its access ACL was inspected")
	}
	return validateVerifierFileMetadata(&afterACL, accessACL, uint32(os.Geteuid()))
}

func readVerifierAccessACL(fd int) ([]byte, error) {
	if fd < 0 {
		return nil, errors.New("cannot inspect verifier file access ACL")
	}

	accessACL := make([]byte, systemdCredentialACLSize)
	n, err := unix.Fgetxattr(
		fd,
		verifierAccessACLXattr,
		accessACL,
	)
	if err == nil {
		return accessACL[:n], nil
	}
	// Absence or filesystem-level lack of ACL support is safe only for the
	// private 0400/0600 metadata branch below. The root-owned 0440 branch still
	// requires all 44 exact ACL bytes and therefore fails closed here.
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if errors.Is(err, unix.ERANGE) {
		return nil, errors.New("verifier file access ACL contains unexpected entries")
	}
	return nil, errors.New("cannot inspect verifier file access ACL")
}

func sameVerifierFileMetadata(first, second *unix.Stat_t) bool {
	return first != nil &&
		second != nil &&
		first.Dev == second.Dev &&
		first.Ino == second.Ino &&
		first.Mode == second.Mode &&
		first.Nlink == second.Nlink &&
		first.Uid == second.Uid &&
		first.Gid == second.Gid &&
		first.Size == second.Size &&
		first.Mtim == second.Mtim &&
		first.Ctim == second.Ctim
}

func validateVerifierFileMetadata(
	stat *unix.Stat_t,
	accessACL []byte,
	effectiveUID uint32,
) error {
	if err := validateVerifierFileCandidateForUID(stat, effectiveUID); err != nil {
		return err
	}

	permissions := stat.Mode & 0o7777
	if permissions == 0o400 || permissions == 0o600 {
		if accessACL != nil {
			return errors.New("private verifier file must not have an extended access ACL")
		}
		return nil
	}

	// systemd prefers a root-owned, read-only credential with a named-user
	// ACL. Linux mirrors the ACL mask into the group mode bits, so that exact
	// ACL appears as 0440 even though group:: has no permissions. Ordinary
	// group-readable 0440 files and every additional ACL principal remain
	// rejected.
	if isExactSystemdCredentialACL(accessACL, effectiveUID) {
		return nil
	}
	return errors.New("verifier file permissions must be exactly 0400 or 0600, or use the exact root-owned systemd credential access ACL")
}

func isExactSystemdCredentialACL(accessACL []byte, effectiveUID uint32) bool {
	if len(accessACL) != systemdCredentialACLSize ||
		binary.LittleEndian.Uint32(accessACL[:posixACLXattrHeaderSize]) !=
			posixACLXattrVersion {
		return false
	}

	expected := [...]verifierACLEntry{
		{tag: posixACLUserObject, perm: posixACLRead, id: posixACLUndefinedID},
		{tag: posixACLUser, perm: posixACLRead, id: effectiveUID},
		{tag: posixACLGroupObject, perm: 0, id: posixACLUndefinedID},
		{tag: posixACLMask, perm: posixACLRead, id: posixACLUndefinedID},
		{tag: posixACLOther, perm: 0, id: posixACLUndefinedID},
	}
	for index, want := range expected {
		offset := posixACLXattrHeaderSize + index*posixACLXattrEntrySize
		got := verifierACLEntry{
			tag:  binary.LittleEndian.Uint16(accessACL[offset : offset+2]),
			perm: binary.LittleEndian.Uint16(accessACL[offset+2 : offset+4]),
			id:   binary.LittleEndian.Uint32(accessACL[offset+4 : offset+8]),
		}
		if got != want {
			return false
		}
	}
	return true
}
