//go:build !linux

package filesecurity

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ReplaceRegularFile on non-Linux platforms preserves the previous
// CreateTemp-plus-Rename behavior as an explicitly best-effort fallback.
// The descriptor-pinned guarantees of the Linux implementation do not
// apply; production management writes require Linux.
func ReplaceRegularFile(absolutePath string, data []byte, permission fs.FileMode) error {
	if !filepath.IsAbs(absolutePath) || permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return errors.New("refusing unsafe atomic replace destination")
	}
	directoryPath := filepath.Dir(absolutePath)
	temporary, err := os.CreateTemp(directoryPath, "."+filepath.Base(absolutePath)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(permission); err != nil {
		return errors.Join(err, temporary.Close())
	}
	written, writeErr := temporary.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return errors.Join(writeErr, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, absolutePath); err != nil {
		return fmt.Errorf("publish replace staging: %w", err)
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
