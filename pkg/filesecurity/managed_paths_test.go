package filesecurity

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseManagementFileRoots(t *testing.T) {
	roots, err := ParseManagementFileRoots("")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roots, []string{"/DATA", "/mnt", "/media"}) {
		t.Fatalf("default roots = %#v", roots)
	}

	roots, err = ParseManagementFileRoots(" /srv/data, /mnt/archive/, /srv/data ")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roots, []string{"/mnt/archive", "/srv/data"}) {
		t.Fatalf("parsed roots = %#v", roots)
	}

	for _, value := range []string{"/", "relative", "/safe,,/other", "/safe/../etc"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParseManagementFileRoots(value); !errors.Is(err, ErrInvalidManagedRoot) {
				t.Fatalf("ParseManagementFileRoots(%q) error = %v", value, err)
			}
		})
	}
}

func TestMatchManagementPathUsesMostSpecificRoot(t *testing.T) {
	roots, err := ParseManagementFileRoots("/DATA,/DATA/Media,/mnt")
	if err != nil {
		t.Fatal(err)
	}
	location, err := MatchManagementPath(roots, "/DATA/Media/photos/image.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if location.Root != "/DATA/Media" || location.Relative != filepath.Join("photos", "image.jpg") {
		t.Fatalf("location = %#v", location)
	}
}

func TestMatchManagementPathRejectsAliasesAndPrefixConfusion(t *testing.T) {
	roots := []string{"/DATA", "/mnt", "/media"}
	for _, value := range []string{
		"",
		"relative",
		"/",
		"/etc/passwd",
		"/DATA-backup/secret",
		"/DATA/../etc/passwd",
		"/DATA//secret",
		"/DATA/./secret",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := MatchManagementPath(roots, value); !errors.Is(err, ErrManagedPathOutsideRoots) {
				t.Fatalf("MatchManagementPath(%q) error = %v", value, err)
			}
		})
	}

	location, err := MatchManagementPath(roots, "/DATA/photos/")
	if err != nil {
		t.Fatal(err)
	}
	if location.Canonical != "/DATA/photos" || location.Relative != "photos" {
		t.Fatalf("location = %#v", location)
	}
}

func TestMatchManagementChildCannotEscapeBase(t *testing.T) {
	roots := []string{"/DATA"}
	location, err := MatchManagementChild(roots, "/DATA/uploads", "nested/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if location.Canonical != "/DATA/uploads/nested/file.txt" || location.Relative != "uploads/nested/file.txt" {
		t.Fatalf("location = %#v", location)
	}

	for _, relative := range []string{"../escape", "/etc/passwd", "nested/../../escape"} {
		if _, err := MatchManagementChild(roots, "/DATA/uploads", relative); err == nil {
			t.Fatalf("relative path %q unexpectedly accepted", relative)
		}
	}
}

func TestValidatePathComponent(t *testing.T) {
	for _, value := range []string{"server.local", "share name", "2001:db8::1"} {
		if err := ValidatePathComponent(value); err != nil {
			t.Fatalf("ValidatePathComponent(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", ".", "..", "../host", "host/share", "bad\x00name"} {
		if err := ValidatePathComponent(value); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("ValidatePathComponent(%q) = %v", value, err)
		}
	}
}
