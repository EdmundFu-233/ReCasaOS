package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

var nonPortableArchiveNameTests = []struct {
	label                 string
	name                  string
	cannotCreateOnPOSIX   bool
	requiresLinuxBytePath bool
}{
	{label: "backslash parent", name: `..\escape`},
	{label: "backslash nested parent", name: `dir\..\escape`},
	{label: "backslash rooted", name: `\absolute`},
	{label: "windows drive backslash", name: `C:\escape`},
	{label: "windows drive slash", name: `C:/escape`},
	{label: "windows alternate stream", name: `name:stream`},
	{label: "windows less than", name: `bad<name`},
	{label: "windows greater than", name: `bad>name`},
	{label: "windows double quote", name: `bad"name`},
	{label: "windows pipe", name: `bad|name`},
	{label: "windows question mark", name: `bad?name`},
	{label: "windows asterisk", name: `bad*name`},
	{label: "trailing dot", name: `docs/file.`},
	{label: "trailing space", name: `docs/file `},
	{label: "directory component trailing dot", name: `docs./file`},
	{label: "directory component trailing space", name: `docs /file`},
	{label: "reserved con", name: `CON`},
	{label: "reserved con extension", name: `docs/con.txt`},
	{label: "reserved prn extension", name: `docs/prn.txt`},
	{label: "reserved aux mixed case", name: `Aux.log`},
	{label: "reserved nul", name: `nul`},
	{label: "reserved nul extension", name: `NUL.data`},
	{label: "reserved com1", name: `COM1`},
	{label: "reserved com9 extension", name: `com9.log`},
	{label: "reserved com superscript one", name: `COM¹`},
	{label: "reserved com superscript two extension", name: `com².log`},
	{label: "reserved com superscript three mixed case", name: `Com³.data`},
	{label: "reserved lpt1", name: `LPT1`},
	{label: "reserved lpt9 extension", name: `lpt9.txt`},
	{label: "reserved lpt superscript one", name: `LPT¹`},
	{label: "reserved lpt superscript two extension", name: `lpt².txt`},
	{label: "reserved lpt superscript three mixed case", name: `LpT³.data`},
	{label: "nul control", name: "nul\x00name", cannotCreateOnPOSIX: true},
	{label: "line feed", name: "line\nbreak"},
	{label: "escape control", name: "esc\x1b[2J"},
	{label: "unit separator control", name: "unit\x1fname"},
	{label: "delete control", name: "delete\x7fname"},
	{label: "invalid utf8", name: string([]byte{0xff}), requiresLinuxBytePath: true},
}

func TestSafeArchiveNameRejectsNonPortableNames(t *testing.T) {
	for _, test := range nonPortableArchiveNameTests {
		t.Run(test.label, func(t *testing.T) {
			for _, directory := range []bool{false, true} {
				if name, err := safeArchiveName(test.name, directory); err == nil {
					t.Fatalf("safeArchiveName(%q, %t) = %q, want error", test.name, directory, name)
				}
			}
		})
	}
}

func TestSafeArchiveNameRejectsNormalization(t *testing.T) {
	for _, name := range []string{
		"",
		".",
		"..",
		"docs//readme.txt",
		"docs/./readme.txt",
		"docs/../readme.txt",
		"../readme.txt",
		"/absolute.txt",
		"docs/",
	} {
		t.Run(name, func(t *testing.T) {
			if normalized, err := safeArchiveName(name, false); err == nil {
				t.Fatalf("safeArchiveName(%q, false) = %q, want error", name, normalized)
			}
		})
	}

	if name, err := safeArchiveName("docs//", true); err == nil {
		t.Fatalf("safeArchiveName(%q, true) = %q, want error", "docs//", name)
	}
}

func TestSafeArchiveNamePreservesPortableNames(t *testing.T) {
	tests := []struct {
		name      string
		directory bool
		want      string
	}{
		{name: "docs/readme.txt", want: "docs/readme.txt"},
		{name: "photos/summer trip.jpg", want: "photos/summer trip.jpg"},
		{name: "docs/.hidden", want: "docs/.hidden"},
		{name: "devices/COM0.txt", want: "devices/COM0.txt"},
		{name: "devices/LPT10.txt", want: "devices/LPT10.txt"},
		{name: "资料/说明-é.txt", want: "资料/说明-é.txt"},
		{name: "组合/e\u0301.txt", want: "组合/e\u0301.txt"},
		{name: "docs", directory: true, want: "docs/"},
		{name: "资料/", directory: true, want: "资料/"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := safeArchiveName(test.name, test.directory)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("safeArchiveName(%q, %t) = %q, want %q", test.name, test.directory, got, test.want)
			}
		})
	}
}

func TestSafeArchiveNameConvertsNativeSeparators(t *testing.T) {
	native := filepath.Join("docs", "readme.txt")
	got, err := safeArchiveName(native, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docs/readme.txt" {
		t.Fatalf("safeArchiveName(%q, false) = %q, want %q", native, got, "docs/readme.txt")
	}
}

func TestArchiveWritersRejectNonPortableNames(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"zip", "tar"} {
		for _, test := range nonPortableArchiveNameTests {
			t.Run(format+"/"+test.label, func(t *testing.T) {
				var output bytes.Buffer
				_, writer, err := GetCompressionAlgorithm(format)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Create(&output); err != nil {
					t.Fatal(err)
				}
				writeErr := writer.Write(ArchiveEntry{Info: info, Name: test.name, Reader: bytes.NewReader([]byte("x"))})
				closeErr := writer.Close()
				if writeErr == nil {
					t.Fatalf("%s writer accepted archive member %q", format, test.name)
				}
				if closeErr != nil {
					t.Fatalf("close %s writer after rejected member: %v", format, closeErr)
				}
			})
		}
	}
}

func TestArchiveWritersConvertNativeSeparators(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("portable"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	native := filepath.Join("docs", "readme.txt")
	for _, format := range []string{"zip", "tar"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			_, writer, err := GetCompressionAlgorithm(format)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Create(&output); err != nil {
				t.Fatal(err)
			}
			if err := writer.Write(ArchiveEntry{Info: info, Name: native, Reader: bytes.NewReader([]byte("portable"))}); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			got := archiveMemberNames(t, format, output.Bytes())
			if len(got) != 1 || got[0] != "docs/readme.txt" {
				t.Fatalf("%s member names = %q, want [%q]", format, got, "docs/readme.txt")
			}
		})
	}
}

func TestAddFileRejectsNonPortableNamesFromPOSIXFilesystem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create the non-portable POSIX names exercised here")
	}

	for _, format := range []string{"zip", "tar"} {
		for _, test := range nonPortableArchiveNameTests {
			t.Run(format+"/reject/"+test.label, func(t *testing.T) {
				if test.cannotCreateOnPOSIX {
					t.Skip("POSIX filesystems cannot create names containing NUL")
				}
				if test.requiresLinuxBytePath && runtime.GOOS != "linux" {
					t.Skip("the host filesystem does not guarantee byte-preserving invalid UTF-8 names")
				}
				root := t.TempDir()
				selected := filepath.Join(root, filepath.FromSlash(test.name))
				if err := os.MkdirAll(filepath.Dir(selected), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selected, []byte("unsafe"), 0o600); err != nil {
					t.Fatal(err)
				}

				var output bytes.Buffer
				_, writer, err := GetCompressionAlgorithm(format)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Create(&output); err != nil {
					t.Fatal(err)
				}
				archiveErr := AddFile(writer, selected, root)
				closeErr := writer.Close()
				if archiveErr == nil {
					t.Fatalf("AddFile archived non-portable POSIX path %q as %s", test.name, format)
				}
				if closeErr != nil {
					t.Fatalf("close %s writer after rejected path: %v", format, closeErr)
				}
			})
		}
	}
}

func TestAddFilePreservesPortableNativePaths(t *testing.T) {
	for _, format := range []string{"zip", "tar"} {
		for _, name := range []string{"docs/readme.txt", "资料/说明-é.txt", "组合/e\u0301.txt"} {
			t.Run(format+"/accept/"+name, func(t *testing.T) {
				root := t.TempDir()
				native := filepath.FromSlash(name)
				selected := filepath.Join(root, native)
				if err := os.MkdirAll(filepath.Dir(selected), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selected, []byte("portable"), 0o600); err != nil {
					t.Fatal(err)
				}

				var output bytes.Buffer
				_, writer, err := GetCompressionAlgorithm(format)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Create(&output); err != nil {
					t.Fatal(err)
				}
				if err := AddFile(writer, selected, root); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				got := archiveMemberNames(t, format, output.Bytes())
				if len(got) != 1 || got[0] != name {
					t.Fatalf("%s member names = %q, want [%q]", format, got, name)
				}
			})
		}
	}
}

func TestTarArchiveDirectoryHeaderRoundTrip(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "parent", "docs")
	if err := os.MkdirAll(directory, 0o750); err != nil {
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
	if err := AddFile(writer, directory, root); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader := tar.NewReader(bytes.NewReader(output.Bytes()))
	header, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "parent/docs/" || header.Typeflag != tar.TypeDir {
		t.Fatalf("tar directory header = {Name: %q, Typeflag: %d}, want {Name: %q, Typeflag: %d}", header.Name, header.Typeflag, "parent/docs/", tar.TypeDir)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("tar contains an unexpected second member: %v", err)
	}
}

func archiveMemberNames(t *testing.T, format string, data []byte) []string {
	t.Helper()
	switch format {
	case "zip":
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(reader.File))
		for _, member := range reader.File {
			names = append(names, member.Name)
		}
		return names
	case "tar":
		var names []string
		reader := tar.NewReader(bytes.NewReader(data))
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return names
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, header.Name)
		}
	default:
		t.Fatalf("unsupported test archive format %q", format)
		return nil
	}
}

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
