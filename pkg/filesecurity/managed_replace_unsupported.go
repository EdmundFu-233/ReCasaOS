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
	_, err := ReplaceRegularFileWithCommit(absolutePath, data, permission)
	return err
}

// ReplaceRegularFileWithCommit is ReplaceRegularFile with an explicit commit
// report. published becomes true once the destination name has been replaced;
// a failure of the final directory durability sync is then returned together
// with published == true.
func ReplaceRegularFileWithCommit(absolutePath string, data []byte, permission fs.FileMode) (bool, error) {
	if !filepath.IsAbs(absolutePath) || permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return false, errors.New("refusing unsafe atomic replace destination")
	}
	directoryPath := filepath.Dir(absolutePath)
	temporary, err := os.CreateTemp(directoryPath, "."+filepath.Base(absolutePath)+".tmp-*")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(permission); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	written, writeErr := temporary.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return false, errors.Join(writeErr, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, absolutePath); err != nil {
		return false, fmt.Errorf("publish replace staging: %w", err)
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return true, err
	}
	return true, errors.Join(directory.Sync(), directory.Close())
}
