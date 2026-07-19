package file

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

const (
	maxManagedArchiveEntries int64 = 100_000
	maxManagedArchiveDepth         = 128
)

type managedArchiveBudget struct {
	entries int64
}

// AddManagedFile archives a client-selected management path by opening every
// member through the startup-pinned ManagedRoots descriptor set. commonPath is
// used only to derive archive member names; it is never used for filesystem
// access. Symlinks and magic links fail closed in ManagedRoots.
func AddManagedFile(writer ArchiveWriter, roots *filesecurity.ManagedRoots, absolutePath, commonPath string) error {
	return addManagedFile(writer, roots, absolutePath, commonPath, 0, &managedArchiveBudget{})
}

func addManagedFile(writer ArchiveWriter, roots *filesecurity.ManagedRoots, absolutePath, commonPath string, depth int, budget *managedArchiveBudget) error {
	if writer == nil || roots == nil {
		return errors.New("managed archive is not initialized")
	}
	if budget == nil {
		return errors.New("managed archive traversal budget is unavailable")
	}
	if depth > maxManagedArchiveDepth {
		return errors.New("managed archive exceeds depth limit")
	}
	if budget.entries >= maxManagedArchiveEntries {
		return errors.New("managed archive exceeds entry limit")
	}
	budget.entries++
	if strings.TrimSpace(commonPath) == "" || !filepath.IsAbs(commonPath) {
		return errors.New("managed archive name root is invalid")
	}

	location, err := roots.Match(absolutePath)
	if err != nil {
		return err
	}
	nameRoot := filepath.Clean(commonPath)
	name, err := filepath.Rel(nameRoot, location.Canonical)
	if err != nil || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return fmt.Errorf("managed archive member is outside its naming root")
	}

	opened, err := roots.OpenPath(location.Canonical)
	if err != nil {
		return err
	}
	info, err := opened.Stat()
	if err != nil {
		_ = opened.Close()
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		_ = opened.Close()
		return nil
	}
	if name == "." {
		if info.IsDir() {
			name = ""
		} else {
			name = filepath.Base(location.Canonical)
		}
	}

	if info.Mode().IsRegular() {
		writeErr := writer.Write(ArchiveEntry{Info: info, Name: name, Reader: opened})
		closeErr := opened.Close()
		return errors.Join(writeErr, closeErr)
	}

	if name != "" {
		if err := writer.Write(ArchiveEntry{Info: info, Name: name}); err != nil {
			_ = opened.Close()
			return err
		}
	}
	for {
		entries, readErr := opened.ReadDir(256)
		for _, entry := range entries {
			// Linux directory entry names cannot contain a path separator or NUL;
			// validate anyway so this invariant remains explicit and testable.
			if entry.Name() == "" || entry.Name() == "." || entry.Name() == ".." || strings.ContainsRune(entry.Name(), filepath.Separator) || strings.IndexByte(entry.Name(), 0) >= 0 {
				_ = opened.Close()
				return errors.New("managed archive contains an invalid directory entry")
			}
			if err := addManagedFile(writer, roots, filepath.Join(location.Canonical, entry.Name()), nameRoot, depth+1, budget); err != nil {
				_ = opened.Close()
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = opened.Close()
			return readErr
		}
	}
	return opened.Close()
}
