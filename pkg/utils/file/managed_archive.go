package file

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	if writer == nil || roots == nil {
		return errors.New("managed archive is not initialized")
	}
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

	budget := &managedArchiveBudget{}
	var archiveBase string
	first := true
	return roots.WalkManagedArchive(location.Canonical, func(relative string, depth int, info os.FileInfo, reader io.Reader) error {
		if depth > maxManagedArchiveDepth {
			return errors.New("managed archive exceeds depth limit")
		}
		if budget.entries >= maxManagedArchiveEntries {
			return errors.New("managed archive exceeds entry limit")
		}
		budget.entries++

		if first {
			if relative != "" {
				return errors.New("managed archive traversal root is invalid")
			}
			archiveBase = name
			if archiveBase == "." {
				if info.IsDir() {
					archiveBase = ""
				} else {
					archiveBase = filepath.Base(location.Canonical)
				}
			}
			first = false
		}

		entryName := archiveBase
		if relative != "" {
			if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return errors.New("managed archive traversal name is invalid")
			}
			entryName = relative
			if archiveBase != "" {
				entryName = filepath.Join(archiveBase, relative)
			}
		}
		if info.IsDir() && entryName == "" {
			return nil
		}
		return writer.Write(ArchiveEntry{Info: info, Name: entryName, Reader: reader})
	})
}
