package file

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestGetThumbnailByWebPhotoPreservesOutputFormat(t *testing.T) {
	tests := []struct {
		extension string
		format    string
	}{
		{extension: ".jpg", format: "jpeg"},
		{extension: ".jpeg", format: "jpeg"},
		{extension: ".png", format: "png"},
		{extension: ".gif", format: "gif"},
		{extension: ".tif", format: "tiff"},
		{extension: ".tiff", format: "tiff"},
		{extension: ".bmp", format: "bmp"},
	}

	for _, test := range tests {
		t.Run(test.extension, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source"+test.extension)
			writeThumbnailTestPNG(t, path, 4, 2)

			thumbnail, err := GetThumbnailByWebPhoto(path, 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			decoded, format, err := image.Decode(bytes.NewReader(thumbnail))
			if err != nil {
				t.Fatal(err)
			}
			if format != test.format {
				t.Fatalf("encoded format = %q, want %q", format, test.format)
			}
			if got := decoded.Bounds().Size(); got.X != 2 || got.Y != 1 {
				t.Fatalf("thumbnail dimensions = %v, want (2,1)", got)
			}
		})
	}
}

func TestGetThumbnailByWebPhotoRejectsUnsafeInputs(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "source.png")
	writeThumbnailTestPNG(t, valid, 4, 2)

	tests := []struct {
		name   string
		path   string
		width  int
		height int
	}{
		{name: "both dimensions zero", path: valid},
		{name: "negative dimension", path: valid, width: -1},
		{name: "oversized dimension", path: valid, width: maxThumbnailDimension + 1},
		{name: "oversized output", path: valid, width: maxThumbnailDimension, height: maxThumbnailDimension},
		{name: "directory source", path: t.TempDir(), width: 100},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := GetThumbnailByWebPhoto(test.path, test.width, test.height); err == nil {
				t.Fatal("unsafe input unexpectedly succeeded")
			}
		})
	}
}

func TestGetThumbnailByWebPhotoRejectsUnsupportedAndOversizedFiles(t *testing.T) {
	unsupported := filepath.Join(t.TempDir(), "source.webp")
	writeThumbnailTestPNG(t, unsupported, 2, 2)
	if _, err := GetThumbnailByWebPhoto(unsupported, 1, 0); err == nil {
		t.Fatal("unsupported output extension unexpectedly succeeded")
	}

	oversized := filepath.Join(t.TempDir(), "oversized.png")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxThumbnailSourceBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := GetThumbnailByWebPhoto(oversized, 1, 0); err == nil {
		t.Fatal("oversized source unexpectedly succeeded")
	}
}

func TestThumbnailDimensionsPreservesAspectRatio(t *testing.T) {
	width, height, err := thumbnailDimensions(3, 2, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if width != 100 || height != 67 {
		t.Fatalf("dimensions = (%d,%d), want (100,67)", width, height)
	}

	width, height, err = thumbnailDimensions(2, 3, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if width != 67 || height != 100 {
		t.Fatalf("dimensions = (%d,%d), want (67,100)", width, height)
	}
}

func TestThumbnailDecodeCapacityFailsFast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.png")
	writeThumbnailTestPNG(t, path, 4, 2)
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	for index := 0; index < cap(thumbnailDecodeSlots); index++ {
		thumbnailDecodeSlots <- struct{}{}
	}
	defer func() {
		for index := 0; index < cap(thumbnailDecodeSlots); index++ {
			<-thumbnailDecodeSlots
		}
	}()
	if _, err := GetImageFromFile(source, path, 2, 0); !errors.Is(err, ErrThumbnailBusy) {
		t.Fatalf("saturated decoder error = %v", err)
	}
}

func TestDirectEXIFThumbnailPathIsDisabled(t *testing.T) {
	if _, err := GetThumbnailByOwnerPhotos("ignored"); err == nil {
		t.Fatal("direct EXIF thumbnail unexpectedly enabled")
	}
}

func writeThumbnailTestPNG(t *testing.T, path string, width, height int) {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 20), G: uint8(y * 30), B: 120, A: 255})
		}
	}

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(file, img); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
