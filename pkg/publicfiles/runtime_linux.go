//go:build linux

package publicfiles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	serviceRuntimeStatusPath          = "/proc/self/status"
	serviceRuntimeStatusMaxBytes      = 64 << 10
	serviceRuntimeCgroupPath          = "/proc/self/cgroup"
	serviceRuntimeCgroupMaxBytes      = 16 << 10
	serviceRuntimeCgroupUnitPath      = "/system.slice/recasaos-public-files.service"
	serviceRuntimeMountInfoPath       = "/proc/self/mountinfo"
	serviceRuntimeMountInfoMaxBytes   = 4 << 20
	serviceRuntimeCgroupLimitsPath    = "/run/recasaos-cgroup"
	serviceRuntimeCgroupLimitMaxBytes = 64
	serviceRuntimeMemoryMaxFile       = "memory.max"
	serviceRuntimeMemoryMaxValue      = "536870912"
	serviceRuntimeMemorySwapMaxFile   = "memory.swap.max"
	serviceRuntimeMemorySwapMaxValue  = "0"
	serviceRuntimeProcessLimitFile    = "pids.max"
	serviceRuntimeProcessLimitValue   = "256"
)

var ErrUnsafeServiceRuntime = errors.New("public file service runtime isolation is unsafe")

// ValidateServiceRuntime fails closed unless the current Linux process is a
// dedicated non-root, no-capability, no-new-privileges, seccomp-filtered
// service. The systemd unit is the primary sandbox; this check prevents a
// copied binary or weakened override from silently running with management
// authority.
func ValidateServiceRuntime() error {
	if err := disableServiceRuntimeDumpability(); err != nil {
		return fmt.Errorf("%w: cannot disable process memory inspection: %v", ErrUnsafeServiceRuntime, err)
	}
	status, err := readServiceRuntimeStatus(serviceRuntimeStatusPath)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect process status: %v", ErrUnsafeServiceRuntime, err)
	}
	if err := validateServiceRuntimeStatus(status, os.Geteuid(), os.Getegid()); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeServiceRuntime, err)
	}
	cgroup, err := readServiceRuntimeFile(
		serviceRuntimeCgroupPath,
		serviceRuntimeCgroupMaxBytes,
	)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect process cgroup: %v", ErrUnsafeServiceRuntime, err)
	}
	if err := validateServiceRuntimeCgroup(cgroup); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeServiceRuntime, err)
	}
	if err := validateServiceRuntimeCgroupLimits(serviceRuntimeCgroupLimitsPath); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeServiceRuntime, err)
	}
	return nil
}

func disableServiceRuntimeDumpability() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	value, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		uintptr(unix.PR_GET_DUMPABLE),
		0,
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	if value != 0 {
		return errors.New("process remains dumpable")
	}
	return nil
}

func readServiceRuntimeStatus(path string) ([]byte, error) {
	return readServiceRuntimeFile(path, serviceRuntimeStatusMaxBytes)
}

func readServiceRuntimeFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("runtime inspection limit is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maxBytes {
		return nil, errors.New("runtime inspection file exceeds the safety limit")
	}
	return content, nil
}

func validateServiceRuntimeCgroup(content []byte) error {
	if len(content) == 0 ||
		len(content) > serviceRuntimeCgroupMaxBytes ||
		content[len(content)-1] != '\n' ||
		strings.ContainsRune(string(content), '\x00') {
		return errors.New("service cgroup metadata is malformed")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 1 {
		return errors.New("service requires the unified cgroup v2 hierarchy")
	}
	fields := strings.Split(lines[0], ":")
	if len(fields) != 3 ||
		fields[0] != "0" ||
		fields[1] != "" ||
		fields[2] != serviceRuntimeCgroupUnitPath {
		return errors.New("service is not running in its reviewed cgroup v2 unit")
	}
	return nil
}

func validateServiceRuntimeCgroupLimits(path string) error {
	directoryFD, err := unix.Open(
		path,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return fmt.Errorf("cannot open the service cgroup limit view: %w", err)
	}
	defer unix.Close(directoryFD)

	var directoryMetadata unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryMetadata); err != nil {
		return fmt.Errorf("cannot inspect the service cgroup limit directory: %w", err)
	}
	if directoryMetadata.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("service cgroup limit view is not a directory")
	}
	if directoryMetadata.Uid != 0 ||
		directoryMetadata.Gid != 0 ||
		directoryMetadata.Mode&0o222 != 0 {
		return errors.New("service cgroup limit directory metadata is unsafe")
	}

	mountInfo, err := readServiceRuntimeFile(
		serviceRuntimeMountInfoPath,
		serviceRuntimeMountInfoMaxBytes,
	)
	if err != nil {
		return fmt.Errorf("cannot inspect the service mount table: %w", err)
	}

	limits := []struct {
		name     string
		expected string
	}{
		{name: serviceRuntimeMemoryMaxFile, expected: serviceRuntimeMemoryMaxValue},
		{name: serviceRuntimeMemorySwapMaxFile, expected: serviceRuntimeMemorySwapMaxValue},
		{name: serviceRuntimeProcessLimitFile, expected: serviceRuntimeProcessLimitValue},
	}
	for _, limit := range limits {
		content, mountID, err := readServiceRuntimeCgroupLimitAt(
			directoryFD,
			limit.name,
			serviceRuntimeCgroupLimitMaxBytes,
		)
		if err != nil {
			return fmt.Errorf("cannot inspect service cgroup limit %s: %w", limit.name, err)
		}
		if err := validateServiceRuntimeCgroupLimitMount(
			mountInfo,
			mountID,
			limit.name,
		); err != nil {
			return err
		}
		if err := validateServiceRuntimeCgroupLimitValue(
			limit.name,
			content,
			limit.expected,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateServiceRuntimeCgroupLimitMount(
	content []byte,
	expectedMountID uint64,
	name string,
) error {
	if expectedMountID == 0 ||
		name == "" ||
		strings.ContainsRune(name, '/') ||
		len(content) == 0 ||
		len(content) > serviceRuntimeMountInfoMaxBytes ||
		content[len(content)-1] != '\n' ||
		strings.ContainsRune(string(content), '\x00') {
		return errors.New("service mount metadata is malformed")
	}

	expectedRoot := serviceRuntimeCgroupUnitPath + "/" + name
	expectedTarget := serviceRuntimeCgroupLimitsPath + "/" + name
	matches := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return errors.New("service mount metadata is malformed")
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		if separator < 0 || separator+3 >= len(fields) {
			return errors.New("service mount metadata is malformed")
		}
		if fields[4] != expectedTarget {
			continue
		}
		matches++

		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mountID != expectedMountID {
			return errors.New("service cgroup limit mount identity is unexpected")
		}
		if fields[3] != expectedRoot {
			return errors.New("service cgroup limit view is bound from an unexpected cgroup")
		}
		if fields[separator+1] != "cgroup2" {
			return errors.New("service cgroup limit mount is not cgroup v2")
		}
		if !commaSeparatedRuntimeOption(fields[5], "ro") ||
			commaSeparatedRuntimeOption(fields[5], "rw") {
			return errors.New("service cgroup limit mount is not read-only")
		}
	}
	if matches != 1 {
		return errors.New("service cgroup limit mount must appear exactly once")
	}
	return nil
}

func commaSeparatedRuntimeOption(options, expected string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func readServiceRuntimeCgroupLimitAt(
	directoryFD int,
	name string,
	maxBytes int64,
) ([]byte, uint64, error) {
	if maxBytes <= 0 {
		return nil, 0, errors.New("runtime inspection limit is invalid")
	}
	fileFD, err := unix.Openat(
		directoryFD,
		name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, 0, err
	}
	file := os.NewFile(uintptr(fileFD), name)
	if file == nil {
		unix.Close(fileFD)
		return nil, 0, errors.New("cannot represent the runtime inspection file")
	}
	defer file.Close()

	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fileFD, &filesystem); err != nil {
		return nil, 0, err
	}
	if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, 0, errors.New("runtime cgroup limit is not backed by cgroup v2")
	}
	if filesystem.Flags&unix.ST_RDONLY == 0 {
		return nil, 0, errors.New("runtime cgroup limit is not mounted read-only")
	}

	var metadata unix.Statx_t
	if err := unix.Statx(
		fileFD,
		"",
		unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT,
		unix.STATX_TYPE|unix.STATX_MNT_ID,
		&metadata,
	); err != nil {
		return nil, 0, err
	}
	if metadata.Mask&unix.STATX_MNT_ID == 0 || metadata.Mnt_id == 0 {
		return nil, 0, errors.New("runtime cgroup limit has no stable mount identity")
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, 0, errors.New("runtime cgroup limit is not a regular file")
	}

	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(content)) > maxBytes {
		return nil, 0, errors.New("runtime inspection file exceeds the safety limit")
	}
	return content, metadata.Mnt_id, nil
}

func validateServiceRuntimeCgroupLimitValue(name string, content []byte, expected string) error {
	if string(content) != expected+"\n" {
		return fmt.Errorf("service cgroup limit %s differs from the reviewed boundary", name)
	}
	return nil
}

func validateServiceRuntimeStatus(status []byte, effectiveUID, effectiveGID int) error {
	if effectiveUID <= 0 {
		return errors.New("service must not run as root")
	}
	if effectiveGID <= 0 {
		return errors.New("service must not run with the root group")
	}
	effectiveUIDValue := uint64(effectiveUID)
	effectiveGIDValue := uint64(effectiveGID)

	required := map[string]bool{
		"Uid":        true,
		"Gid":        true,
		"Groups":     true,
		"Umask":      true,
		"CapInh":     true,
		"CapPrm":     true,
		"CapEff":     true,
		"CapBnd":     true,
		"CapAmb":     true,
		"NoNewPrivs": true,
		"Seccomp":    true,
	}
	fields := make(map[string]string, len(required))
	for _, line := range strings.Split(string(status), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || !required[key] {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return fmt.Errorf("process status contains duplicate %s fields", key)
		}
		fields[key] = strings.TrimSpace(value)
	}
	for key := range required {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("process status is missing %s", key)
		}
	}

	if err := validateRuntimeIDs("Uid", fields["Uid"], effectiveUIDValue); err != nil {
		return err
	}
	if err := validateRuntimeIDs("Gid", fields["Gid"], effectiveGIDValue); err != nil {
		return err
	}
	for _, group := range strings.Fields(fields["Groups"]) {
		value, err := strconv.ParseUint(group, 10, 32)
		if err != nil || value != effectiveGIDValue {
			return errors.New("service has an unexpected supplementary group")
		}
	}
	umask, err := strconv.ParseUint(fields["Umask"], 8, 32)
	if err != nil || umask != 0o077 {
		return errors.New("service umask must be exactly 0077")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, err := strconv.ParseUint(fields[key], 16, 64)
		if err != nil || value != 0 {
			return fmt.Errorf("%s must be zero", key)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("NoNewPrivs must be enabled")
	}
	if fields["Seccomp"] != "2" {
		return errors.New("seccomp filtering must be enabled")
	}
	return nil
}

func validateRuntimeIDs(name, encoded string, expected uint64) error {
	values := strings.Fields(encoded)
	if len(values) != 4 {
		return fmt.Errorf("%s must contain four identities", name)
	}
	for _, value := range values {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed != expected {
			return fmt.Errorf("%s identities must all match the effective identity", name)
		}
	}
	return nil
}
