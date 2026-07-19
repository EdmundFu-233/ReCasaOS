package filesecurity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ManagementFileRootsEnv = "RECASAOS_MANAGEMENT_FILE_ROOTS"

var (
	// ErrManagedRootsUnsupported is returned on platforms where the kernel
	// cannot provide the descriptor-relative resolution guarantees required by
	// the privileged management file API.
	ErrManagedRootsUnsupported = errors.New("managed file roots require Linux openat2 support")
	// ErrManagedPathOutsideRoots is returned when a client-selected host path
	// is not a canonical absolute path below an explicitly configured root.
	ErrManagedPathOutsideRoots = errors.New("managed path is outside configured roots")
	// ErrInvalidManagedRoot is returned for unsafe operator configuration.
	ErrInvalidManagedRoot = errors.New("invalid management file root")
)

var defaultManagementFileRoots = []string{"/DATA", "/mnt", "/media"}

// ManagedLocation is the lexical mapping of an absolute management path to a
// configured root. Relative is only for diagnostics and descriptor-relative
// syscalls; callers must not join it back into a pathname and use os.* APIs.
type ManagedLocation struct {
	Root      string
	Relative  string
	Canonical string
}

// ParseManagementFileRoots parses the comma-separated operator setting. An
// empty setting uses the CasaOS data and mount roots. The filesystem root is
// deliberately forbidden: allowing it would turn every path check into an
// authorization no-op.
func ParseManagementFileRoots(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return append([]string(nil), defaultManagementFileRoots...), nil
	}

	seen := make(map[string]struct{})
	roots := make([]string, 0, strings.Count(value, ",")+1)
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("%w: empty entry", ErrInvalidManagedRoot)
		}
		root, err := canonicalAbsoluteManagedPath(item)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidManagedRoot, item)
		}
		if root == string(filepath.Separator) {
			return nil, fmt.Errorf("%w: filesystem root is forbidden", ErrInvalidManagedRoot)
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: no roots configured", ErrInvalidManagedRoot)
	}

	// Matching the most specific root first keeps nested roots deterministic.
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) == len(roots[j]) {
			return roots[i] < roots[j]
		}
		return len(roots[i]) > len(roots[j])
	})
	return roots, nil
}

// MatchManagementPath performs only the lexical authorization mapping. The
// ManagedRoots implementation pins the selected root and performs the actual
// filesystem operation with openat2; this helper is intentionally not an I/O
// authorization primitive on its own.
func MatchManagementPath(roots []string, absolutePath string) (ManagedLocation, error) {
	canonical, err := canonicalAbsoluteManagedPath(absolutePath)
	if err != nil {
		return ManagedLocation{}, ErrManagedPathOutsideRoots
	}

	for _, configuredRoot := range roots {
		root, rootErr := canonicalAbsoluteManagedPath(configuredRoot)
		if rootErr != nil || root == string(filepath.Separator) {
			return ManagedLocation{}, fmt.Errorf("%w: %q", ErrInvalidManagedRoot, configuredRoot)
		}
		relative, relErr := filepath.Rel(root, canonical)
		if relErr != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if relative == "" {
			relative = "."
		}
		return ManagedLocation{Root: root, Relative: relative, Canonical: canonical}, nil
	}
	return ManagedLocation{}, ErrManagedPathOutsideRoots
}

// MatchManagementChild maps a validated relative path below a client-selected
// management directory without ever treating the child as an absolute path.
func MatchManagementChild(roots []string, base, relative string) (ManagedLocation, error) {
	if err := ValidateRelativePath(relative); err != nil {
		return ManagedLocation{}, err
	}
	baseLocation, err := MatchManagementPath(roots, base)
	if err != nil {
		return ManagedLocation{}, err
	}

	childRelative := filepath.Join(baseLocation.Relative, filepath.Clean(relative))
	if err := ValidateRelativePath(childRelative); err != nil {
		return ManagedLocation{}, err
	}
	canonical := filepath.Join(baseLocation.Root, childRelative)
	return ManagedLocation{Root: baseLocation.Root, Relative: childRelative, Canonical: canonical}, nil
}

// ValidatePathComponent accepts exactly one ordinary filesystem name. It is
// used when protocol identifiers such as a Samba host/share are also rendered
// as directory names below an already authorized root.
func ValidatePathComponent(value string) error {
	if value == "" || value == "." || value == ".." || len(value) > 255 || strings.IndexByte(value, 0) >= 0 {
		return ErrUnsafePath
	}
	if filepath.Base(value) != value || strings.ContainsRune(value, filepath.Separator) {
		return ErrUnsafePath
	}
	return nil
}

func canonicalAbsoluteManagedPath(value string) (string, error) {
	if value == "" || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return "", ErrManagedPathOutsideRoots
	}

	// Directory requests from the legacy UI commonly include a trailing slash.
	// Accept that spelling, but reject internal duplicate separators and dot
	// components instead of silently normalizing attacker-controlled input.
	trimmed := strings.TrimRightFunc(value, func(character rune) bool {
		return character <= 0xff && os.IsPathSeparator(uint8(character))
	})
	if trimmed == "" {
		trimmed = string(filepath.Separator)
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned != trimmed {
		return "", ErrManagedPathOutsideRoots
	}
	return cleaned, nil
}
