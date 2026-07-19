package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestZipArchiveSkipsSymlinksAndKeepsRelativeNames(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "readme.txt"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "leak")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	var output bytes.Buffer
	_, writer, err := GetCompressionAlgorithm("zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Create(&output); err != nil {
		t.Fatal(err)
	}
	if err := AddFile(writer, root, root); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, member := range reader.File {
		names = append(names, member.Name)
		if member.Name == "leak" {
			t.Fatal("symbolic link target was added to archive")
		}
	}
	sort.Strings(names)
	want := []string{"docs/", "docs/readme.txt"}
	if len(names) != len(want) {
		t.Fatalf("archive names = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("archive names = %v, want %v", names, want)
		}
	}
}

func TestTarGzArchiveRoundTrip(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	extension, writer, err := GetCompressionAlgorithm("targz")
	if err != nil {
		t.Fatal(err)
	}
	if extension != ".tar.gz" {
		t.Fatalf("extension = %q", extension)
	}
	if err := writer.Create(&output); err != nil {
		t.Fatal(err)
	}
	if err := AddFile(writer, filePath, filePath); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	header, err := tarReader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "hello.txt" {
		t.Fatalf("member name = %q", header.Name)
	}
	content, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Fatalf("member content = %q", content)
	}
}

func TestAddFileRejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	_, writer, err := GetCompressionAlgorithm("tar")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Create(&output); err != nil {
		t.Fatal(err)
	}
	if err := AddFile(writer, outside, root); err == nil {
		t.Fatal("expected outside-root archive member to be rejected")
	}
}

func TestAddFileRejectsAncestorSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	var output bytes.Buffer
	_, writer, err := GetCompressionAlgorithm("zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Create(&output); err != nil {
		t.Fatal(err)
	}
	if err := AddFile(writer, filepath.Join(link, "secret.txt"), root); err == nil {
		t.Fatal("ancestor symlink target was archived")
	}
}

func TestGetCompressionAlgorithmRejectsLegacyFormats(t *testing.T) {
	for _, format := range []string{"rar", "tarxz", "tarlz4", "tarbz2"} {
		if _, _, err := GetCompressionAlgorithm(format); err == nil {
			t.Fatalf("format %q unexpectedly accepted", format)
		}
	}
}
