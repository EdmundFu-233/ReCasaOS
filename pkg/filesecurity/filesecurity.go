package filesecurity

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxUploadChunkSize limits the amount of file data accepted by one upload
	// request. Multipart framing is accounted for separately by HTTP handlers.
	MaxUploadChunkSize int64 = 256 << 20
	// A single resumable upload is limited to 64 GiB. Larger transfers need a
	// dedicated, quota-aware data plane instead of the root management API.
	MaxUploadChunks    int64 = 256
	MaxUploadTotalSize       = MaxUploadChunkSize * MaxUploadChunks
)

var ErrUnsafePath = errors.New("unsafe relative path")

// ValidateRelativePath accepts only non-empty paths relative to an upload
// base. Parent components are rejected even when filepath.Clean would fold
// them back into the base, which keeps the policy simple and auditable.
func ValidateRelativePath(relative string) error {
	if strings.TrimSpace(relative) == "" || strings.IndexByte(relative, 0) >= 0 {
		return ErrUnsafePath
	}
	if filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" {
		return ErrUnsafePath
	}

	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == ".." {
			return ErrUnsafePath
		}
	}

	cleaned := filepath.Clean(relative)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return ErrUnsafePath
	}
	return nil
}

// JoinWithinBase joins a user-controlled relative path to base and verifies
// both lexical containment and the resolved location of every existing path
// prefix. This rejects prefix-confusion and existing symlinks that escape the
// base while still allowing the final file or directories not to exist yet.
func JoinWithinBase(base, relative string) (string, error) {
	if strings.TrimSpace(base) == "" || strings.IndexByte(base, 0) >= 0 {
		return "", fmt.Errorf("upload base is empty or invalid")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return "", err
	}

	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolve upload base: %w", err)
	}
	baseInfo, err := os.Stat(baseAbs)
	if err != nil {
		return "", fmt.Errorf("stat upload base: %w", err)
	}
	if !baseInfo.IsDir() {
		return "", fmt.Errorf("upload base is not a directory")
	}

	target := filepath.Join(baseAbs, filepath.Clean(relative))
	if !within(baseAbs, target) {
		return "", ErrUnsafePath
	}

	baseResolved, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return "", fmt.Errorf("resolve upload base symlinks: %w", err)
	}
	existing, err := nearestExistingPath(target)
	if err != nil {
		return "", err
	}
	existingResolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("resolve upload target symlinks: %w", err)
	}
	if !within(baseResolved, existingResolved) {
		return "", ErrUnsafePath
	}

	return target, nil
}

// ValidateChunk prevents zero/negative indexing and excessive allocation in
// resumable-upload status tracking.
func ValidateChunk(totalChunks, chunkNumber int64) error {
	if totalChunks < 1 || totalChunks > MaxUploadChunks {
		return fmt.Errorf("totalChunks must be between 1 and %d", MaxUploadChunks)
	}
	if chunkNumber < 1 || chunkNumber > totalChunks {
		return fmt.Errorf("chunkNumber must be between 1 and totalChunks")
	}
	return nil
}

// ValidateUploadSizes bounds upload metadata before it is used for offsets or
// allocation. Zero-byte files are supported as one empty chunk.
func ValidateUploadSizes(chunkSize, currentChunkSize, totalSize, totalChunks int64) error {
	if chunkSize < 1 || chunkSize > MaxUploadChunkSize {
		return fmt.Errorf("chunkSize must be between 1 and %d", MaxUploadChunkSize)
	}
	if currentChunkSize < 0 || currentChunkSize > chunkSize || currentChunkSize > MaxUploadChunkSize {
		return fmt.Errorf("currentChunkSize is out of range")
	}
	if totalSize < 0 || totalSize > MaxUploadTotalSize {
		return fmt.Errorf("totalSize is out of range")
	}
	if totalChunks < 1 || totalChunks > MaxUploadChunks {
		return fmt.Errorf("totalChunks must be between 1 and %d", MaxUploadChunks)
	}
	if totalSize > totalChunks*chunkSize {
		return fmt.Errorf("totalSize exceeds declared chunk capacity")
	}
	if totalSize == 0 && (totalChunks != 1 || currentChunkSize != 0) {
		return fmt.Errorf("zero-byte upload metadata is inconsistent")
	}
	if totalSize > 0 && currentChunkSize == 0 {
		return fmt.Errorf("non-empty upload chunk is empty")
	}
	return nil
}

// CommitNoReplace publishes a fully written staging file without replacing an
// existing destination. Platforms/filesystems without a proven atomic
// no-replace primitive fail closed; the final pathname is never exposed while
// content is still being copied.
func CommitNoReplace(staging, destination string) error {
	info, err := os.Lstat(staging)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("upload staging path is not a regular file")
	}
	source, err := os.Open(staging)
	if err != nil {
		return err
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return fmt.Errorf("upload staging file changed before commit")
	}
	if err := source.Sync(); err != nil {
		return fmt.Errorf("sync upload staging file: %w", err)
	}

	// Assemble a complete hidden inode on the destination filesystem first.
	// Upload bases can contain USB/NFS mount points, so the original staging
	// path is not necessarily on the same filesystem as the destination.
	destinationStage, err := os.CreateTemp(filepath.Dir(destination), ".recasaos-upload-*")
	if err != nil {
		return fmt.Errorf("create target-local upload staging file: %w", err)
	}
	destinationStagePath := destinationStage.Name()
	committed := false
	defer func() {
		_ = destinationStage.Close()
		if !committed {
			_ = os.Remove(destinationStagePath)
		}
	}()
	if _, err := io.Copy(destinationStage, source); err != nil {
		return fmt.Errorf("copy upload to target filesystem: %w", err)
	}
	if err := destinationStage.Sync(); err != nil {
		return fmt.Errorf("sync target-local upload staging file: %w", err)
	}
	if err := destinationStage.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("set target-local upload permissions: %w", err)
	}
	if err := destinationStage.Close(); err != nil {
		return fmt.Errorf("close target-local upload staging file: %w", err)
	}

	if supported, err := commitNoReplaceAtomic(destinationStagePath, destination); supported {
		if err != nil {
			return fmt.Errorf("publish upload without replacing destination: %w", err)
		}
		committed = true
		_ = os.Remove(staging)
		return nil
	}
	return errors.New("atomic no-replace publication is unavailable")
}

func nearestExistingPath(target string) (string, error) {
	current := target
	for {
		_, err := os.Lstat(current)
		if err == nil {
			return current, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect upload target: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing upload target prefix")
		}
		current = parent
	}
}

func within(base, target string) bool {
	relative, err := filepath.Rel(base, target)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
