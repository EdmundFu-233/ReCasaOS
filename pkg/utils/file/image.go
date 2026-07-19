package file

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dsoprea/go-exif/v3"
	exifcommon "github.com/dsoprea/go-exif/v3/common"
	"golang.org/x/image/bmp"
	golangdraw "golang.org/x/image/draw"
	"golang.org/x/image/tiff"
)

const (
	maxThumbnailSourceBytes  int64 = 128 << 20
	maxThumbnailSourcePixels int64 = 64_000_000
	maxThumbnailOutputPixels int64 = 16_000_000
	maxThumbnailDimension          = 8192
)

func GetImage(path string, width, height int) ([]byte, error) {
	if thumbnail, err := GetThumbnailByOwnerPhotos(path); err == nil {
		return thumbnail, nil
	} else {
		return GetThumbnailByWebPhoto(path, width, height)
	}
}
func GetThumbnailByOwnerPhotos(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	buff := &bytes.Buffer{}

	defer file.Close()
	offset := 0
	offsets := []int{12, 30}

	head := make([]byte, 0xffff)

	r := io.TeeReader(file, buff)
	_, err = r.Read(head)
	if err != nil {
		return nil, err
	}

	for _, offset = range offsets {
		if _, err = exif.ParseExifHeader(head[offset:]); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	im, err := exifcommon.NewIfdMappingWithStandard()
	if err != nil {
		return nil, err
	}

	_, index, err := exif.Collect(im, exif.NewTagIndex(), head[offset:])
	if err != nil {
		return nil, err
	}

	ifd := index.RootIfd.NextIfd()
	if ifd == nil {
		return nil, exif.ErrNoThumbnail
	}
	thumbnail, err := ifd.Thumbnail()
	if err != nil {
		return nil, err
	}
	return thumbnail, nil
}
func GetThumbnailByWebPhoto(path string, width, height int) (thumbnail []byte, err error) {
	defer func() {
		if recover() != nil {
			thumbnail = nil
			err = errors.New("invalid image data")
		}
	}()

	if width < 0 || height < 0 || width > maxThumbnailDimension || height > maxThumbnailDimension {
		return nil, errors.New("invalid thumbnail dimensions")
	}
	if width == 0 && height == 0 {
		return nil, errors.New("thumbnail width and height cannot both be zero")
	}

	src, err := decodeThumbnailSource(path)
	if err != nil {
		return nil, err
	}

	width, height, err = thumbnailDimensions(src.Bounds().Dx(), src.Bounds().Dy(), width, height)
	if err != nil {
		return nil, err
	}
	if !thumbnailPixelCountWithinLimit(width, height, maxThumbnailOutputPixels) {
		return nil, errors.New("thumbnail dimensions exceed the output limit")
	}

	resized := image.NewNRGBA(image.Rect(0, 0, width, height))
	golangdraw.CatmullRom.Scale(resized, resized.Bounds(), src, src.Bounds(), golangdraw.Src, nil)

	var buf bytes.Buffer
	if err := encodeThumbnail(&buf, resized, filepath.Ext(path)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeThumbnailSource(path string) (image.Image, error) {
	source, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("thumbnail source must be a regular file")
	}
	if info.Size() > maxThumbnailSourceBytes {
		return nil, errors.New("thumbnail source exceeds the size limit")
	}

	config, _, err := image.DecodeConfig(source)
	if err != nil {
		return nil, err
	}
	if !thumbnailPixelCountWithinLimit(config.Width, config.Height, maxThumbnailSourcePixels) {
		return nil, errors.New("thumbnail source dimensions exceed the pixel limit")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	decoded, _, err := image.Decode(source)
	if err != nil {
		return nil, err
	}
	if !thumbnailPixelCountWithinLimit(decoded.Bounds().Dx(), decoded.Bounds().Dy(), maxThumbnailSourcePixels) {
		return nil, errors.New("decoded thumbnail source exceeds the pixel limit")
	}
	return decoded, nil
}

func thumbnailDimensions(sourceWidth, sourceHeight, width, height int) (int, int, error) {
	if sourceWidth <= 0 || sourceHeight <= 0 {
		return 0, 0, errors.New("invalid source image dimensions")
	}
	if width == 0 {
		calculated := (int64(height)*int64(sourceWidth) + int64(sourceHeight)/2) / int64(sourceHeight)
		if calculated < 1 {
			calculated = 1
		}
		if calculated > maxThumbnailDimension {
			return 0, 0, errors.New("calculated thumbnail width exceeds the dimension limit")
		}
		width = int(calculated)
	}
	if height == 0 {
		calculated := (int64(width)*int64(sourceHeight) + int64(sourceWidth)/2) / int64(sourceWidth)
		if calculated < 1 {
			calculated = 1
		}
		if calculated > maxThumbnailDimension {
			return 0, 0, errors.New("calculated thumbnail height exceeds the dimension limit")
		}
		height = int(calculated)
	}
	return width, height, nil
}

func thumbnailPixelCountWithinLimit(width, height int, limit int64) bool {
	return width > 0 && height > 0 && int64(width) <= limit/int64(height)
}

func encodeThumbnail(destination io.Writer, img image.Image, extension string) error {
	switch strings.ToLower(extension) {
	case ".jpg", ".jpeg":
		return jpeg.Encode(destination, img, &jpeg.Options{Quality: 95})
	case ".png":
		encoder := png.Encoder{CompressionLevel: png.DefaultCompression}
		return encoder.Encode(destination, img)
	case ".gif":
		return gif.Encode(destination, img, &gif.Options{NumColors: 256})
	case ".tif", ".tiff":
		return tiff.Encode(destination, img, &tiff.Options{Compression: tiff.Deflate, Predictor: true})
	case ".bmp":
		return bmp.Encode(destination, img)
	default:
		return fmt.Errorf("unsupported thumbnail output format %q", extension)
	}
}

func ImageExtArray() []string {

	ext := []string{
		"ase",
		"art",
		"bmp",
		"blp",
		"cd5",
		"cit",
		"cpt",
		"cr2",
		"cut",
		"dds",
		"dib",
		"djvu",
		"egt",
		"exif",
		"gif",
		"gpl",
		"grf",
		"icns",
		"ico",
		"iff",
		"jng",
		"jpeg",
		"jpg",
		"jfif",
		"jp2",
		"jps",
		"lbm",
		"max",
		"miff",
		"mng",
		"msp",
		"nitf",
		"ota",
		"pbm",
		"pc1",
		"pc2",
		"pc3",
		"pcf",
		"pcx",
		"pdn",
		"pgm",
		"PI1",
		"PI2",
		"PI3",
		"pict",
		"pct",
		"pnm",
		"pns",
		"ppm",
		"psb",
		"psd",
		"pdd",
		"psp",
		"px",
		"pxm",
		"pxr",
		"qfx",
		"raw",
		"rle",
		"sct",
		"sgi",
		"rgb",
		"int",
		"bw",
		"tga",
		"tiff",
		"tif",
		"vtf",
		"xbm",
		"xcf",
		"xpm",
		"3dv",
		"amf",
		"ai",
		"awg",
		"cgm",
		"cdr",
		"cmx",
		"dxf",
		"e2d",
		"egt",
		"eps",
		"fs",
		"gbr",
		"odg",
		"svg",
		"stl",
		"vrml",
		"x3d",
		"sxd",
		"v2d",
		"vnd",
		"wmf",
		"emf",
		"art",
		"xar",
		"png",
		"webp",
		"jxr",
		"hdp",
		"wdp",
		"cur",
		"ecw",
		"iff",
		"lbm",
		"liff",
		"nrrd",
		"pam",
		"pcx",
		"pgf",
		"sgi",
		"rgb",
		"rgba",
		"bw",
		"int",
		"inta",
		"sid",
		"ras",
		"sun",
		"tga",
	}

	return ext
}

/**
* @description:get a image's ext
* @param {string} path "file path"
* @return {string} ext "file ext"
* @return {error} err "error info"
 */
func GetImageExt(p string) (string, error) {
	file, err := os.Open(p)
	if err != nil {
		return "", err
	}

	buff := make([]byte, 512)

	_, err = file.Read(buff)

	if err != nil {
		return "", err
	}

	filetype := http.DetectContentType(buff)

	ext := ImageExtArray()

	for i := 0; i < len(ext); i++ {
		if strings.Contains(ext[i], filetype[6:]) {
			return ext[i], nil
		}
	}

	return "", errors.New("invalid image type")
}

func GetImageExtByName(p string) (string, error) {

	extArr := ImageExtArray()
	ext := filepath.Ext(p)
	for i := 0; i < len(extArr); i++ {
		if strings.Contains(ext, extArr[i]) {
			return extArr[i], nil
		}
	}
	return "", errors.New("invalid image type")
}
