package filesecurity

import (
	"errors"
	"fmt"
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
