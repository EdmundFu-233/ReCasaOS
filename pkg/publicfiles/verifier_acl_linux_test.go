//go:build linux

package publicfiles

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func encodeVerifierAccessACL(
	version uint32,
	entries ...verifierACLEntry,
) []byte {
	encoded := make(
		[]byte,
		posixACLXattrHeaderSize+len(entries)*posixACLXattrEntrySize,
	)
	binary.LittleEndian.PutUint32(encoded[:posixACLXattrHeaderSize], version)
	for index, entry := range entries {
		offset := posixACLXattrHeaderSize + index*posixACLXattrEntrySize
		binary.LittleEndian.PutUint16(encoded[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:offset+4], entry.perm)
		binary.LittleEndian.PutUint32(encoded[offset+4:offset+8], entry.id)
	}
	return encoded
}

func exactSystemdCredentialACLForTest(serviceUID uint32) []byte {
	return encodeVerifierAccessACL(
		posixACLXattrVersion,
		verifierACLEntry{
			tag:  posixACLUserObject,
			perm: posixACLRead,
			id:   posixACLUndefinedID,
		},
		verifierACLEntry{
			tag:  posixACLUser,
			perm: posixACLRead,
			id:   serviceUID,
		},
		verifierACLEntry{
			tag: posixACLGroupObject,
			id:  posixACLUndefinedID,
		},
		verifierACLEntry{
			tag:  posixACLMask,
			perm: posixACLRead,
			id:   posixACLUndefinedID,
		},
		verifierACLEntry{
			tag: posixACLOther,
			id:  posixACLUndefinedID,
		},
	)
}

func TestExactSystemdCredentialACL(t *testing.T) {
	const serviceUID = uint32(12345)
	valid := exactSystemdCredentialACLForTest(serviceUID)
	if !isExactSystemdCredentialACL(valid, serviceUID) {
		t.Fatal("exact systemd credential ACL was rejected")
	}

	wrongVersion := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(
		wrongVersion[:posixACLXattrHeaderSize],
		posixACLXattrVersion+1,
	)
	bigEndianVersion := append([]byte{}, valid...)
	binary.BigEndian.PutUint32(
		bigEndianVersion[:posixACLXattrHeaderSize],
		posixACLXattrVersion,
	)
	wrongObjectID := append([]byte{}, valid...)
	binary.LittleEndian.PutUint32(
		wrongObjectID[posixACLXattrHeaderSize+4:posixACLXattrHeaderSize+8],
		0,
	)
	wrongOrder := append([]byte{}, valid...)
	firstNamed := posixACLXattrHeaderSize + posixACLXattrEntrySize
	groupObject := firstNamed + posixACLXattrEntrySize
	copy(
		wrongOrder[firstNamed:firstNamed+posixACLXattrEntrySize],
		valid[groupObject:groupObject+posixACLXattrEntrySize],
	)
	copy(
		wrongOrder[groupObject:groupObject+posixACLXattrEntrySize],
		valid[firstNamed:firstNamed+posixACLXattrEntrySize],
	)

	tests := []struct {
		name string
		acl  []byte
	}{
		{name: "missing", acl: nil},
		{name: "truncated", acl: valid[:len(valid)-1]},
		{name: "one trailing byte", acl: append(append([]byte{}, valid...), 0)},
		{name: "trailing entry", acl: append(append([]byte{}, valid...), make([]byte, posixACLXattrEntrySize)...)},
		{name: "wrong version", acl: wrongVersion},
		{name: "big-endian version", acl: bigEndianVersion},
		{name: "wrong object ID", acl: wrongObjectID},
		{name: "wrong entry order", acl: wrongOrder},
		{
			name: "wrong service user",
			acl:  exactSystemdCredentialACLForTest(serviceUID + 1),
		},
		{
			name: "ordinary group readable",
			acl: encodeVerifierAccessACL(
				posixACLXattrVersion,
				verifierACLEntry{
					tag:  posixACLUserObject,
					perm: posixACLRead,
					id:   posixACLUndefinedID,
				},
				verifierACLEntry{
					tag:  posixACLGroupObject,
					perm: posixACLRead,
					id:   posixACLUndefinedID,
				},
				verifierACLEntry{
					tag: posixACLOther,
					id:  posixACLUndefinedID,
				},
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if isExactSystemdCredentialACL(test.acl, serviceUID) {
				t.Fatal("unsafe or malformed ACL was accepted")
			}
		})
	}

	mutations := []struct {
		name  string
		index int
		entry verifierACLEntry
	}{
		{
			name:  "owner writable",
			index: 0,
			entry: verifierACLEntry{
				tag:  posixACLUserObject,
				perm: posixACLRead | 0x02,
				id:   posixACLUndefinedID,
			},
		},
		{
			name:  "named user writable",
			index: 1,
			entry: verifierACLEntry{
				tag:  posixACLUser,
				perm: posixACLRead | 0x02,
				id:   serviceUID,
			},
		},
		{
			name:  "group object readable",
			index: 2,
			entry: verifierACLEntry{
				tag:  posixACLGroupObject,
				perm: posixACLRead,
				id:   posixACLUndefinedID,
			},
		},
		{
			name:  "mask writable",
			index: 3,
			entry: verifierACLEntry{
				tag:  posixACLMask,
				perm: posixACLRead | 0x02,
				id:   posixACLUndefinedID,
			},
		},
		{
			name:  "other readable",
			index: 4,
			entry: verifierACLEntry{
				tag:  posixACLOther,
				perm: posixACLRead,
				id:   posixACLUndefinedID,
			},
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			entries := []verifierACLEntry{
				{
					tag:  posixACLUserObject,
					perm: posixACLRead,
					id:   posixACLUndefinedID,
				},
				{
					tag:  posixACLUser,
					perm: posixACLRead,
					id:   serviceUID,
				},
				{
					tag: posixACLGroupObject,
					id:  posixACLUndefinedID,
				},
				{
					tag:  posixACLMask,
					perm: posixACLRead,
					id:   posixACLUndefinedID,
				},
				{
					tag: posixACLOther,
					id:  posixACLUndefinedID,
				},
			}
			entries[mutation.index] = mutation.entry
			if isExactSystemdCredentialACL(
				encodeVerifierAccessACL(posixACLXattrVersion, entries...),
				serviceUID,
			) {
				t.Fatal("credential ACL mutation was accepted")
			}
		})
	}
}

func TestVerifierAccessACLRequiresReadableDescriptor(t *testing.T) {
	serviceUID := uint32(os.Geteuid()) + 1
	if serviceUID == 0 {
		serviceUID = 1
	}
	expected := exactSystemdCredentialACLForTest(serviceUID)
	verifierPath := filepath.Join(protectedTestDirectory(t), "verifier")
	if err := os.WriteFile(verifierPath, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(
		verifierPath,
		verifierAccessACLXattr,
		expected,
		0,
	); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("test filesystem does not support POSIX access ACLs")
		}
		t.Fatalf("set POSIX access ACL: %v", err)
	}

	fd, err := unix.Open(
		verifierPath,
		unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	if _, err := readVerifierAccessACL(fd); err == nil ||
		!strings.Contains(err.Error(), "cannot inspect verifier file access ACL") {
		t.Fatalf("O_PATH ACL inspection returned %v, want fail closed", err)
	}

	readableFD, err := reopenPinnedRegular(fd)
	if err != nil {
		t.Fatalf("reopen pinned ACL fixture: %v", err)
	}
	defer unix.Close(readableFD)

	got, err := readVerifierAccessACL(readableFD)
	if err != nil {
		t.Fatalf("read POSIX access ACL from readable descriptor: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("readable descriptor ACL bytes = %x, want %x", got, expected)
	}
}

func TestVerifierMetadataAcceptsOnlyPrivateOrExactSystemdACL(t *testing.T) {
	const serviceUID = uint32(12345)
	exactACL := exactSystemdCredentialACLForTest(serviceUID)

	for _, stat := range []unix.Stat_t{
		{
			Mode:  unix.S_IFREG | 0o400,
			Nlink: 1,
			Uid:   serviceUID,
			Gid:   serviceUID,
		},
		{
			Mode:  unix.S_IFREG | 0o600,
			Nlink: 1,
			Uid:   serviceUID,
			Gid:   serviceUID,
		},
		{
			Mode:  unix.S_IFREG | 0o400,
			Nlink: 1,
			Uid:   0,
			Gid:   0,
		},
		{
			Mode:  unix.S_IFREG | 0o600,
			Nlink: 1,
			Uid:   0,
			Gid:   0,
		},
	} {
		if err := validateVerifierFileMetadata(&stat, nil, serviceUID); err != nil {
			t.Fatalf("private verifier metadata was rejected: %v", err)
		}
	}

	systemdCredential := unix.Stat_t{
		Mode:  unix.S_IFREG | 0o440,
		Nlink: 1,
		Uid:   0,
		Gid:   0,
	}
	if err := validateVerifierFileCandidateForUID(
		&systemdCredential,
		serviceUID,
	); err != nil {
		t.Fatalf("systemd credential candidate metadata was rejected: %v", err)
	}
	if err := validateVerifierFileMetadata(
		&systemdCredential,
		exactACL,
		serviceUID,
	); err != nil {
		t.Fatalf("exact systemd credential metadata was rejected: %v", err)
	}

	tests := []struct {
		name string
		stat unix.Stat_t
		acl  []byte
	}{
		{
			name: "ordinary root group-readable file",
			stat: systemdCredential,
		},
		{
			name: "systemd ACL on service-owned file",
			stat: unix.Stat_t{
				Mode:  unix.S_IFREG | 0o440,
				Nlink: 1,
				Uid:   serviceUID,
				Gid:   serviceUID,
			},
			acl: exactACL,
		},
		{
			name: "systemd ACL with non-root group",
			stat: unix.Stat_t{
				Mode:  unix.S_IFREG | 0o440,
				Nlink: 1,
				Uid:   0,
				Gid:   serviceUID,
			},
			acl: exactACL,
		},
		{
			name: "extended ACL on private service file",
			stat: unix.Stat_t{
				Mode:  unix.S_IFREG | 0o400,
				Nlink: 1,
				Uid:   serviceUID,
				Gid:   serviceUID,
			},
			acl: exactACL,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateVerifierFileMetadata(&test.stat, test.acl, serviceUID)
			if err == nil {
				t.Fatal("unsafe verifier metadata was accepted")
			}
			if !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("unsafe verifier metadata returned unhelpful error: %v", err)
			}
		})
	}
}
