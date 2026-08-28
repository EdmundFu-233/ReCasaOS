package service

import (
	"os"
	"strings"
	"testing"
)

func TestReadCasaOSLogTailReturnsRequestedCompleteLines(t *testing.T) {
	t.Parallel()

	file, err := os.CreateTemp(t.TempDir(), "casaos-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("line-1\nline-2\nline-3\n"); err != nil {
		t.Fatal(err)
	}

	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := readCasaOSLogTail(file, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "line-2\nline-3\n" {
		t.Fatalf("tail = %q, want %q", got, "line-2\nline-3\n")
	}
}

func TestReadCasaOSLogTailBoundsLargeFilesAndDiscardsPartialPrefix(t *testing.T) {
	t.Parallel()

	const lineSize = 1000
	line := strings.Repeat("x", lineSize-1) + "\n"
	content := strings.Repeat(line, int(maxCasaOSLogBytes/int64(lineSize))+4)
	file, err := os.CreateTemp(t.TempDir(), "casaos-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}

	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := readCasaOSLogTail(file, maxCasaOSLogLines+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > int(maxCasaOSLogBytes) {
		t.Fatalf("tail length = %d, exceeds %d-byte bound", len(got), maxCasaOSLogBytes)
	}
	if got == "" || got[0] != 'x' || got[len(got)-1] != '\n' {
		t.Fatalf("tail is not complete-line data: length=%d prefix=%q suffix=%q", len(got), got[:min(len(got), 8)], got[max(0, len(got)-8):])
	}
	if !strings.HasPrefix(got, line) {
		t.Fatal("tail did not start at a complete log line")
	}
	if strings.Count(got, "\n") != maxCasaOSLogLines {
		t.Fatalf("tail line count = %d, want %d", strings.Count(got, "\n"), maxCasaOSLogLines)
	}
}

func TestLastCasaOSLogLinesHandlesTrailingNewline(t *testing.T) {
	t.Parallel()

	if got := string(lastCasaOSLogLines([]byte("a\nb\nc\n"), 2)); got != "b\nc\n" {
		t.Fatalf("tail = %q, want %q", got, "b\nc\n")
	}
	if got := string(lastCasaOSLogLines([]byte("a\nb\nc"), 1)); got != "c" {
		t.Fatalf("tail without newline = %q, want %q", got, "c")
	}
}
