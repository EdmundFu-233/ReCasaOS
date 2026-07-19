//go:build !linux

package service

import (
	"errors"
	"os"
)

var errSambaMountUnsupported = errors.New("secure Samba mounts require Linux")

func (s *connectionsStruct) MountSmaba(string, string, string, string, *os.File, string) error {
	return errSambaMountUnsupported
}

func (s *connectionsStruct) UnmountSmaba(*os.File, string) error {
	return errSambaMountUnsupported
}

func (s *connectionsStruct) InspectSambaMount(string, string, string) (SambaMountIdentity, bool, error) {
	return SambaMountIdentity{}, false, errSambaMountUnsupported
}

func (s *connectionsStruct) ValidateSambaMount(string, string, string, uint64) (bool, error) {
	return false, errSambaMountUnsupported
}

func CurrentBootID() (string, error) {
	return "", errSambaMountUnsupported
}
