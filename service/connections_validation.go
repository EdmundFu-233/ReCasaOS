package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/moby/sys/mountinfo"
)

// ValidateSambaConnectionFields rejects values that could be interpreted as
// additional comma-separated mount.cifs options and applies bounded lengths.
func ValidateSambaConnectionFields(username, password, host, port string) error {
	if username == "" || len(username) > 255 || len(password) > 1024 || len(host) > 255 {
		return errors.New("invalid Samba credential or host length")
	}
	if err := filesecurity.ValidatePathComponent(host); err != nil {
		return fmt.Errorf("invalid Samba host: %w", err)
	}
	if err := validateSambaHost(host); err != nil {
		return err
	}
	for fieldName, value := range map[string]string{"username": username, "password": password, "host": host} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, ",\x00\r\n") {
			return fmt.Errorf("invalid Samba %s", fieldName)
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return fmt.Errorf("invalid Samba %s", fieldName)
			}
		}
	}
	return validateSambaPort(port)
}

func validateSambaPort(port string) error {
	// Linux CIFS mountinfo does not reliably expose the negotiated port, so a
	// non-default port cannot be proven during later ownership checks.
	if port != "445" {
		return errors.New("only the canonical Samba port 445 is supported")
	}
	return nil
}

type SambaMountIdentity struct {
	MountID    uint64
	Mountpoint string
	FSType     string
	Source     string
}

func inspectSambaMountEntries(mountPoint, host, directory string, mounts []*mountinfo.Info) (SambaMountIdentity, bool, error) {
	matchingMounts := make([]*mountinfo.Info, 0, 1)
	for _, mounted := range mounts {
		if mounted != nil && mounted.Mountpoint == mountPoint {
			matchingMounts = append(matchingMounts, mounted)
		}
	}
	if len(matchingMounts) == 0 {
		return SambaMountIdentity{}, false, nil
	}
	if len(matchingMounts) != 1 {
		return SambaMountIdentity{}, false, errors.New("multiple mount entries for Samba mount point")
	}
	mounted := matchingMounts[0]
	expectedSource := fmt.Sprintf("//%s/%s", host, directory)
	if mounted.FSType != "cifs" || mounted.Source != expectedSource {
		return SambaMountIdentity{}, false, fmt.Errorf("unexpected mount identity at %s", mountPoint)
	}
	if mounted.ID <= 0 {
		return SambaMountIdentity{}, false, fmt.Errorf("invalid mount ID at %s", mountPoint)
	}
	return SambaMountIdentity{
		MountID:    uint64(mounted.ID),
		Mountpoint: mounted.Mountpoint,
		FSType:     mounted.FSType,
		Source:     mounted.Source,
	}, true, nil
}

func validateSambaMountEntries(mountPoint, host, directory string, expectedMountID uint64, mounts []*mountinfo.Info) (bool, error) {
	identity, mounted, err := inspectSambaMountEntries(mountPoint, host, directory, mounts)
	if err != nil || !mounted {
		return false, err
	}
	if expectedMountID == 0 || identity.MountID != expectedMountID {
		return false, fmt.Errorf("mount ID %d does not match persisted mount ID %d", identity.MountID, expectedMountID)
	}
	return true, nil
}

func FilterSambaMountableShares(directories []string, limit int) ([]string, error) {
	filtered := make([]string, 0, len(directories))
	for _, directory := range directories {
		if strings.HasSuffix(directory, "$") {
			continue
		}
		filtered = append(filtered, directory)
		if len(filtered) > limit {
			return nil, errors.New("invalid Samba directory count")
		}
	}
	if err := ValidateSambaDirectories(filtered, limit); err != nil {
		return nil, err
	}
	return filtered, nil
}

func EncodeSambaMountIDs(mountIDs map[string]uint64, limit int) (string, error) {
	if len(mountIDs) == 0 || len(mountIDs) > limit {
		return "", errors.New("invalid Samba mount identity count")
	}
	for directory, mountID := range mountIDs {
		if err := validateSambaDirectory(directory); err != nil || mountID == 0 {
			return "", errors.New("invalid Samba mount identity")
		}
	}
	encoded, err := json.Marshal(mountIDs)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func ParseSambaMountIDs(value string, limit int) (map[string]uint64, error) {
	if value == "" {
		return map[string]uint64{}, nil
	}
	mountIDs := map[string]uint64{}
	if err := json.Unmarshal([]byte(value), &mountIDs); err != nil || len(mountIDs) == 0 || len(mountIDs) > limit {
		return nil, errors.New("invalid persisted Samba mount identities")
	}
	for directory, mountID := range mountIDs {
		if err := validateSambaDirectory(directory); err != nil || mountID == 0 {
			return nil, errors.New("invalid persisted Samba mount identity")
		}
	}
	return mountIDs, nil
}

func validateSambaHost(host string) error {
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return errors.New("invalid Samba host")
	}
	for _, character := range host {
		if character > unicode.MaxASCII || !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(".-_", character)) {
			return errors.New("invalid Samba host")
		}
	}
	return nil
}

func ParseSambaDirectories(value string, limit int) ([]string, error) {
	if value == "" {
		return nil, errors.New("no Samba directories persisted")
	}
	directories := strings.Split(value, ",")
	if len(directories) == 0 || len(directories) > limit {
		return nil, errors.New("invalid Samba directory count")
	}
	if err := ValidateSambaDirectories(directories, limit); err != nil {
		return nil, err
	}
	return directories, nil
}

// ParsePersistedSambaConnection distinguishes the pre-ownership CasaOS schema
// from records created by ReCasaOS. Legacy rows are accepted only when both
// ownership fields are empty; they are parsed with the same bounds and path
// rules, but administrative shares are returned only in allDirectories so a
// caller can prove that no old mount boundary exists before migrating/deleting.
// A partially populated ownership tuple is never treated as trusted state.
func ParsePersistedSambaConnection(directoriesValue, port, bootID, mountIDsValue string, limit int) (directories, allDirectories []string, normalizedPort string, legacy bool, err error) {
	if (bootID == "") != (mountIDsValue == "") {
		return nil, nil, "", false, errors.New("incomplete persisted Samba ownership identity")
	}
	if bootID != "" {
		if err := validateSambaPort(port); err != nil {
			return nil, nil, "", false, err
		}
		directories, err := ParseSambaDirectories(directoriesValue, limit)
		return directories, directories, port, false, err
	}

	legacyDirectories, err := parseLegacySambaDirectories(directoriesValue, limit)
	if err != nil {
		return nil, nil, "", true, err
	}
	normalizedPort = port
	if normalizedPort == "" {
		normalizedPort = "445"
	}
	directories = make([]string, 0, len(legacyDirectories))
	for _, directory := range legacyDirectories {
		if !strings.HasSuffix(directory, "$") {
			directories = append(directories, directory)
		}
	}
	return directories, legacyDirectories, normalizedPort, true, nil
}

func ValidateLegacySambaHost(host string) error {
	if len(host) == 0 || len(host) > 255 {
		return errors.New("invalid legacy Samba host length")
	}
	if err := filesecurity.ValidatePathComponent(host); err != nil {
		return fmt.Errorf("invalid legacy Samba host: %w", err)
	}
	return validateSambaHost(host)
}

func ValidateLegacySambaDirectory(directory string) error {
	return validateSambaDirectoryName(directory, true)
}

func parseLegacySambaDirectories(value string, limit int) ([]string, error) {
	if value == "" {
		return nil, errors.New("no legacy Samba directories persisted")
	}
	directories := strings.Split(value, ",")
	if len(directories) == 0 || len(directories) > limit {
		return nil, errors.New("invalid legacy Samba directory count")
	}
	seen := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if err := validateSambaDirectoryName(directory, true); err != nil {
			return nil, err
		}
		if _, exists := seen[directory]; exists {
			return nil, errors.New("duplicate legacy Samba directory")
		}
		seen[directory] = struct{}{}
	}
	return directories, nil
}

func ValidateSambaDirectories(directories []string, limit int) error {
	if len(directories) == 0 || len(directories) > limit {
		return errors.New("invalid Samba directory count")
	}
	seen := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if err := validateSambaDirectory(directory); err != nil {
			return err
		}
		if _, exists := seen[directory]; exists {
			return errors.New("duplicate Samba directory")
		}
		seen[directory] = struct{}{}
	}
	return nil
}

func validateSambaDirectory(directory string) error {
	return validateSambaDirectoryName(directory, false)
}

func validateSambaDirectoryName(directory string, allowHidden bool) error {
	if err := filesecurity.ValidatePathComponent(directory); err != nil {
		return fmt.Errorf("invalid Samba directory: %w", err)
	}
	if !utf8.ValidString(directory) || strings.TrimSpace(directory) != directory || strings.ContainsAny(directory, ",\\\x00\r\n") {
		return errors.New("invalid Samba directory")
	}
	if !allowHidden && strings.HasSuffix(directory, "$") {
		return errors.New("hidden or administrative Samba share is not mountable")
	}
	for _, character := range directory {
		if unicode.IsControl(character) {
			return errors.New("invalid Samba directory")
		}
	}
	return nil
}
