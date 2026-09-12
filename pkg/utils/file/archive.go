package file

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	archivepath "path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// ArchiveWriter is the minimal streaming interface used by the download
// handlers.  Keeping it local avoids pulling a general-purpose extraction
// library into the privileged file service.
type ArchiveWriter interface {
	Create(io.Writer) error
	Write(ArchiveEntry) error
	Close() error
}

// ArchiveEntry contains one safe, relative archive member.
type ArchiveEntry struct {
	Info   os.FileInfo
	Name   string
	Reader io.Reader
}

const (
	maxArchiveEntries   int64 = 10_000
	maxArchiveInputSize int64 = 64 << 30
	maxArchivePathDepth       = 128
)

type archiveBudget struct {
	entries int64
	bytes   int64
}

func (b *archiveBudget) reserve(info os.FileInfo, name string) error {
	if info == nil || info.Size() < 0 {
		return errors.New("archive entry metadata is invalid")
	}
	if strings.Count(filepath.ToSlash(name), "/") > maxArchivePathDepth {
		return errors.New("archive path depth exceeds limit")
	}
	if b.entries >= maxArchiveEntries || info.Size() > maxArchiveInputSize-b.bytes {
		return errors.New("archive input exceeds entry or byte budget")
	}
	b.entries++
	b.bytes += info.Size()
	return nil
}

type zipArchiveWriter struct {
	writer *zip.Writer
	budget archiveBudget
}

func (z *zipArchiveWriter) Create(output io.Writer) error {
	if output == nil {
		return errors.New("archive output is nil")
	}
	if z.writer != nil {
		return errors.New("archive writer already initialized")
	}
	z.writer = zip.NewWriter(output)
	return nil
}

func (z *zipArchiveWriter) Write(entry ArchiveEntry) error {
	if z.writer == nil {
		return errors.New("archive writer is not initialized")
	}
	if entry.Info == nil {
		return errors.New("archive entry metadata is missing")
	}

	name, err := safeArchiveName(entry.Name, entry.Info.IsDir())
	if err != nil {
		return err
	}
	if err := z.budget.reserve(entry.Info, name); err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(entry.Info)
	if err != nil {
		return err
	}
	header.Name = name
	if entry.Info.Mode().IsRegular() {
		header.Method = zip.Deflate
	}

	destination, err := z.writer.CreateHeader(header)
	if err != nil {
		return err
	}
	if entry.Info.IsDir() {
		return nil
	}
	if entry.Reader == nil {
		return errors.New("regular archive entry has no reader")
	}
	_, err = io.CopyN(destination, entry.Reader, entry.Info.Size())
	return err
}

func (z *zipArchiveWriter) Close() error {
	if z.writer == nil {
		return nil
	}
	return z.writer.Close()
}

type tarArchiveWriter struct {
	gzip   bool
	tar    *tar.Writer
	gzipIO *gzip.Writer
	budget archiveBudget
}

func (t *tarArchiveWriter) Create(output io.Writer) error {
	if output == nil {
		return errors.New("archive output is nil")
	}
	if t.tar != nil {
		return errors.New("archive writer already initialized")
	}

	if t.gzip {
		t.gzipIO = gzip.NewWriter(output)
		// A stable timestamp makes otherwise identical downloads reproducible.
		t.gzipIO.Header.ModTime = time.Unix(0, 0)
		output = t.gzipIO
	}
	t.tar = tar.NewWriter(output)
	return nil
}

func (t *tarArchiveWriter) Write(entry ArchiveEntry) error {
	if t.tar == nil {
		return errors.New("archive writer is not initialized")
	}
	if entry.Info == nil {
		return errors.New("archive entry metadata is missing")
	}

	name, err := safeArchiveName(entry.Name, entry.Info.IsDir())
	if err != nil {
		return err
	}
	if err := t.budget.reserve(entry.Info, name); err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(entry.Info, "")
	if err != nil {
		return err
	}
	header.Name = name
	if err := t.tar.WriteHeader(header); err != nil {
		return err
	}
	if entry.Info.IsDir() {
		return nil
	}
	if entry.Reader == nil {
		return errors.New("regular archive entry has no reader")
	}
	_, err = io.CopyN(t.tar, entry.Reader, entry.Info.Size())
	return err
}

func (t *tarArchiveWriter) Close() error {
	if t.tar == nil {
		return nil
	}
	err := t.tar.Close()
	if t.gzipIO != nil {
		if gzipErr := t.gzipIO.Close(); err == nil {
			err = gzipErr
		}
	}
	return err
}

// GetCompressionAlgorithm returns only formats implemented with the Go
// standard library.  The removed legacy formats relied on an unmaintained
// extraction package with known path-traversal vulnerabilities.
func GetCompressionAlgorithm(format string) (string, ArchiveWriter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "zip":
		return ".zip", &zipArchiveWriter{}, nil
	case "tar":
		return ".tar", &tarArchiveWriter{}, nil
	case "targz", "tar.gz", "tgz":
		return ".tar.gz", &tarArchiveWriter{gzip: true}, nil
	default:
		return "", nil, fmt.Errorf("unsupported archive format %q; supported formats are zip, tar, and targz", format)
	}
}

// AddFile recursively adds filePath while rejecting symbolic links observed in
// every path component. Every member name is derived with filepath.Rel and
// validated before it reaches an archive header. Privileged callers must still
// serialize changes to the source tree because portable pathname APIs cannot
// eliminate a hostile local rename race.
func AddFile(writer ArchiveWriter, filePath, commonPath string) error {
	if writer == nil {
		return errors.New("archive writer is nil")
	}
	if strings.TrimSpace(commonPath) == "" {
		return errors.New("archive root is empty")
	}

	root, err := filepath.Abs(filepath.Clean(commonPath))
	if err != nil {
		return err
	}
	current, err := filepath.Abs(filepath.Clean(filePath))
	if err != nil {
		return err
	}
	name, err := filepath.Rel(root, current)
	if err != nil {
		return err
	}
	if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return fmt.Errorf("archive member %q is outside root %q", current, root)
	}
	rawInfo, err := os.Lstat(current)
	if err != nil {
		return err
	}
	if rawInfo.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	info, err := lstatArchivePathWithoutSymlinks(root, current)
	if err != nil {
		return err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil
	}

	if name == "." {
		if info.IsDir() {
			name = ""
		} else {
			name = filepath.Base(current)
		}
	}

	if name != "" {
		var reader io.Reader
		var source *os.File
		if info.Mode().IsRegular() {
			source, err = os.Open(current)
			if err != nil {
				return err
			}
			defer source.Close()
			openedInfo, statErr := source.Stat()
			if statErr != nil {
				return statErr
			}
			if !os.SameFile(info, openedInfo) {
				return fmt.Errorf("archive member changed while opening: %q", current)
			}
			reader = source
		}

		if err := writer.Write(ArchiveEntry{Info: info, Name: name, Reader: reader}); err != nil {
			return err
		}
	}

	if !info.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(current)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := AddFile(writer, filepath.Join(current, entry.Name()), root); err != nil {
			return err
		}
	}
	return nil
}

func lstatArchivePathWithoutSymlinks(root, current string) (os.FileInfo, error) {
	relative, err := filepath.Rel(root, current)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("archive path is outside its root")
	}
	path := root
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("archive root cannot be a symbolic link")
	}
	if relative == "." {
		return info, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		path = filepath.Join(path, component)
		info, err = os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("archive path contains a symbolic link: %q", path)
		}
	}
	return info, nil
}

func safeArchiveName(name string, directory bool) (string, error) {
	portable := filepath.ToSlash(name)
	if !utf8.ValidString(portable) || strings.ContainsRune(portable, '\\') || strings.IndexFunc(portable, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return "", fmt.Errorf("archive member name is not portable: %q", name)
	}

	if directory && strings.HasSuffix(portable, "/") {
		// A single trailing slash is the only spelling change accepted here.
		// Archive producers may already mark a directory that way, while every
		// other normalization could collapse two distinct source names.
		portable = strings.TrimSuffix(portable, "/")
	}
	cleaned := archivepath.Clean(portable)
	if cleaned != portable || cleaned == "." || !fs.ValidPath(cleaned) {
		return "", fmt.Errorf("unsafe archive member name: %q", name)
	}
	for _, component := range strings.Split(cleaned, "/") {
		if strings.ContainsAny(component, `<>:"|?*`) ||
			strings.HasSuffix(component, ".") ||
			strings.HasSuffix(component, " ") ||
			isWindowsReservedArchiveComponent(component) {
			return "", fmt.Errorf("archive member name is not portable: %q", name)
		}
	}
	if directory {
		cleaned += "/"
	}
	return cleaned, nil
}

func isWindowsReservedArchiveComponent(component string) bool {
	base := component
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = strings.TrimRight(base, " ")
	for _, reserved := range []string{"CON", "PRN", "AUX", "NUL"} {
		if strings.EqualFold(base, reserved) {
			return true
		}
	}
	if len(base) < 4 ||
		(!strings.EqualFold(base[:3], "COM") && !strings.EqualFold(base[:3], "LPT")) {
		return false
	}
	switch base[3:] {
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
		return true
	default:
		return false
	}
}
