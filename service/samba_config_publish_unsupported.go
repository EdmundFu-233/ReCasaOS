//go:build !linux

package service

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func publishSambaConfigCAS(expected sambaConfigSnapshot, data []byte, permission fs.FileMode, _ func(string)) (sambaConfigSnapshot, error) {
	if err := verifySambaConfigSnapshot(expected); err != nil {
		return sambaConfigSnapshot{}, err
	}
	if err := writeFileAtomic(expected.path, data, permission); err != nil {
		return sambaConfigSnapshot{}, err
	}
	written, err := readSambaConfigSnapshot(expected.path, true, "")
	return written, err
}

func removeSambaConfigCAS(expected sambaConfigSnapshot, _ func(string)) error {
	if err := verifySambaConfigSnapshot(expected); err != nil {
		return err
	}
	if err := os.Remove(expected.path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(expected.path)); err != nil {
		return fmt.Errorf("sync removed Samba config: %w", err)
	}
	return nil
}
