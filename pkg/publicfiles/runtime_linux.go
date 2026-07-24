//go:build linux

package publicfiles

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	serviceRuntimeStatusPath     = "/proc/self/status"
	serviceRuntimeStatusMaxBytes = 64 << 10
)

var ErrUnsafeServiceRuntime = errors.New("public file service runtime isolation is unsafe")

// ValidateServiceRuntime fails closed unless the current Linux process is a
// dedicated non-root, no-capability, no-new-privileges, seccomp-filtered
// service. The systemd unit is the primary sandbox; this check prevents a
// copied binary or weakened override from silently running with management
// authority.
func ValidateServiceRuntime() error {
	status, err := readServiceRuntimeStatus(serviceRuntimeStatusPath)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect process status: %v", ErrUnsafeServiceRuntime, err)
	}
	if err := validateServiceRuntimeStatus(status, os.Geteuid(), os.Getegid()); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeServiceRuntime, err)
	}
	return nil
}

func readServiceRuntimeStatus(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	status, err := io.ReadAll(io.LimitReader(file, serviceRuntimeStatusMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(status) > serviceRuntimeStatusMaxBytes {
		return nil, errors.New("process status exceeds the safety limit")
	}
	return status, nil
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
