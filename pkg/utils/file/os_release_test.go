package file

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOSReleaseFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "os-release")
	content := "# comment\nNAME=ReCasaOS\nPRETTY_NAME=\"ReCasaOS Secure\"\nEMPTY=\nINVALID\n"
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	values, err := readOSRelease(filename)
	if err != nil {
		t.Fatal(err)
	}
	if values["NAME"] != "ReCasaOS" {
		t.Fatalf("NAME = %q", values["NAME"])
	}
	if values["PRETTY_NAME"] != "ReCasaOS Secure" {
		t.Fatalf("PRETTY_NAME = %q", values["PRETTY_NAME"])
	}
	if value, ok := values["EMPTY"]; !ok || value != "" {
		t.Fatalf("EMPTY = %q, present = %v", value, ok)
	}
}
