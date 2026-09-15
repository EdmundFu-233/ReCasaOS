package oauthsecurity

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOAuthSecurityHasNoProductionCallSite pins the staging boundary: the
// package is reviewed and tested, but no route, service, or startup path may
// import it until the complete flow (exchange, sealed token storage, rotation,
// and revocation) is independently reviewed. Removing this guard is a review
// decision, not a refactor.
func TestOAuthSecurityHasNoProductionCallSite(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate oauthsecurity test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	packageDirectory := filepath.Dir(currentFile)
	const modulePrefix = "github.com/IceWhaleTech/CasaOS/pkg/oauthsecurity"

	scanned := 0
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if entry.IsDir() {
			switch name {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == packageDirectory {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		if strings.Contains(string(content), modulePrefix) {
			relative, _ := filepath.Rel(repositoryRoot, path)
			t.Errorf("production file %s imports the staged oauthsecurity package", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no production Go files were scanned")
	}
}
