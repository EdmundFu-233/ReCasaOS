package filesecurity

import "testing"

func TestValidateChunkBounds(t *testing.T) {
	tests := []struct {
		name        string
		totalChunks int64
		chunkNumber int64
		wantError   bool
	}{
		{name: "first", totalChunks: 1, chunkNumber: 1},
		{name: "zero chunk", totalChunks: 1, chunkNumber: 0, wantError: true},
		{name: "past end", totalChunks: 2, chunkNumber: 3, wantError: true},
		{name: "zero total", totalChunks: 0, chunkNumber: 1, wantError: true},
		{name: "too many chunks", totalChunks: MaxUploadChunks + 1, chunkNumber: 1, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateChunk(test.totalChunks, test.chunkNumber)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateChunk(%d, %d) error = %v, wantError %v", test.totalChunks, test.chunkNumber, err, test.wantError)
			}
		})
	}
}

func TestValidateUploadSizesBounds(t *testing.T) {
	tests := []struct {
		name             string
		chunkSize        int64
		currentChunkSize int64
		totalSize        int64
		totalChunks      int64
		wantError        bool
	}{
		{name: "valid", chunkSize: 1024, currentChunkSize: 512, totalSize: 1536, totalChunks: 2},
		{name: "empty", chunkSize: 1024, currentChunkSize: 0, totalSize: 0, totalChunks: 1},
		{name: "oversized request", chunkSize: MaxUploadChunkSize + 1, currentChunkSize: 1, totalSize: 1, totalChunks: 1, wantError: true},
		{name: "oversized total", chunkSize: MaxUploadChunkSize, currentChunkSize: 1, totalSize: MaxUploadTotalSize + 1, totalChunks: MaxUploadChunks, wantError: true},
		{name: "negative total", chunkSize: 1024, currentChunkSize: 1, totalSize: -1, totalChunks: 1, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateUploadSizes(test.chunkSize, test.currentChunkSize, test.totalSize, test.totalChunks)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateUploadSizes() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
