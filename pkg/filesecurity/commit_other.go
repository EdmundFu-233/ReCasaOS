//go:build !linux

package filesecurity

import "os"

func commitNoReplaceAtomic(staging, destination string) (bool, error) {
	// A hard link publishes the fully synced inode atomically and fails when
	// destination already exists. Filesystems without hard-link support fail
	// closed instead of exposing a partially copied final pathname.
	if err := os.Link(staging, destination); err != nil {
		return true, err
	}
	if err := os.Remove(staging); err != nil {
		// Destination is already a complete committed file. Do not report it as
		// uncommitted; stale staging cleanup is safe to retry independently.
		return true, nil
	}
	return true, nil
}
