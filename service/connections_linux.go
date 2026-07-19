//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

func (s *connectionsStruct) MountSmaba(username, host, directory, port string, mountDirectory *os.File, password string) error {
	if err := ValidateSambaConnectionFields(username, password, host, port); err != nil {
		return err
	}
	if err := validateSambaDirectory(directory); err != nil {
		return err
	}
	if mountDirectory == nil {
		return errors.New("Samba mount directory descriptor is nil")
	}
	directoryInfo, err := mountDirectory.Stat()
	if err != nil || !directoryInfo.IsDir() {
		return errors.Join(errors.New("invalid Samba mount directory descriptor"), err)
	}
	mountTarget := fmt.Sprintf("/proc/self/fd/%d", mountDirectory.Fd())
	return unix.Mount(
		fmt.Sprintf("//%s/%s", host, directory),
		mountTarget,
		"cifs",
		unix.MS_NOATIME|unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC,
		sambaMountOptions(username, password, port),
	)
}

func sambaMountOptions(username, password, port string) string {
	// Never downgrade: both discovery and the kernel mount must authenticate
	// every SMB message. Servers that cannot sign are intentionally rejected.
	return fmt.Sprintf("username=%s,password=%s,port=%s,sec=ntlmsspi,sign", username, password, port)
}

func (s *connectionsStruct) UnmountSmaba(parentDirectory *os.File, child string) error {
	if parentDirectory == nil {
		return errors.New("Samba unmount parent descriptor is nil")
	}
	if err := filesecurity.ValidatePathComponent(child); err != nil {
		return fmt.Errorf("invalid Samba unmount child: %w", err)
	}
	directoryInfo, err := parentDirectory.Stat()
	if err != nil || !directoryInfo.IsDir() {
		return errors.Join(errors.New("invalid Samba unmount parent descriptor"), err)
	}
	// The mounted child descriptor must already be closed by the caller. Holding
	// it open can make a normal CIFS unmount fail with EBUSY. Do not use
	// MNT_DETACH: ownership is revalidated immediately before and after this call.
	return unix.Unmount(fmt.Sprintf("/proc/self/fd/%d/%s", parentDirectory.Fd(), child), 0)
}

func (s *connectionsStruct) InspectSambaMount(mountPoint, host, directory string) (SambaMountIdentity, bool, error) {
	if err := filesecurity.ValidatePathComponent(host); err != nil {
		return SambaMountIdentity{}, false, err
	}
	if err := validateSambaDirectory(directory); err != nil {
		return SambaMountIdentity{}, false, err
	}
	// Read the complete table. SingleEntryFilter stops at the first match and
	// therefore cannot detect a stacked mount at the same mount point.
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return SambaMountIdentity{}, false, err
	}
	return inspectSambaMountEntries(mountPoint, host, directory, mounts)
}

func (s *connectionsStruct) ValidateSambaMount(mountPoint, host, directory string, expectedMountID uint64) (bool, error) {
	if err := filesecurity.ValidatePathComponent(host); err != nil {
		return false, err
	}
	if err := validateSambaDirectory(directory); err != nil {
		return false, err
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return false, err
	}
	return validateSambaMountEntries(mountPoint, host, directory, expectedMountID, mounts)
}

func CurrentBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read Linux boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if len(bootID) != 36 {
		return "", errors.New("invalid Linux boot ID")
	}
	for index, character := range bootID {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return "", errors.New("invalid Linux boot ID")
			}
			continue
		}
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return "", errors.New("invalid Linux boot ID")
		}
	}
	return bootID, nil
}
