package startscripts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestShebangIsHonoured(t *testing.T) {
	dir := t.TempDir()
	// interpreter of our own (only /bin/sh is guaranteed, e.g. in build sandboxes); it receives
	// the shebang's argument, then the script
	bin := t.TempDir()
	write(t, bin, "interp", "#!/bin/sh\necho from-shebang \"$@\"\n", 0o700)
	write(t, dir, "a.sh", "#!"+filepath.Join(bin, "interp")+" arg\nexit 7\n", 0o700)
	results, err := Run(context.Background(), dir, 5*time.Second)
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results = %+v, err = %v", results, err)
	}
	if !strings.HasPrefix(results[0].Output, "from-shebang arg ") {
		t.Fatalf("shebang ignored: output %q", results[0].Output)
	}
}

func TestFailureDoesNotStopTheRest(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "1-fails.sh", "exit 3\n", 0o700)
	write(t, dir, "2-runs.sh", "echo second\n", 0o700)
	results, _ := Run(context.Background(), dir, 5*time.Second)
	if len(results) != 2 || results[0].Err == nil || results[1].Err != nil || results[1].Output != "second\n" {
		t.Fatalf("results = %+v", results)
	}
}

func TestTimeout(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "hangs.sh", "exec sleep 30\n", 0o700)
	start := time.Now()
	results, _ := Run(context.Background(), dir, 200*time.Millisecond)
	if time.Since(start) > 5*time.Second || len(results) != 1 || results[0].Err == nil ||
		!strings.Contains(results[0].Err.Error(), "timed out") {
		t.Fatalf("results = %+v after %s", results, time.Since(start))
	}
}

func TestUnsafeEntriesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	write(t, dir, "writable.sh", "touch "+marker+"\n", 0o722)
	writableTarget := filepath.Join(t.TempDir(), "target.sh")
	write(t, filepath.Dir(writableTarget), "target.sh", "touch "+marker+"\n", 0o766)
	if err := os.Symlink(writableTarget, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	results, _ := Run(context.Background(), dir, 5*time.Second)
	for _, r := range results {
		if r.Err == nil {
			t.Fatalf("%s was run", r.Path)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("group/world-writable script was run")
	}
}

func TestMissingDirectory(t *testing.T) {
	results, err := Run(context.Background(), filepath.Join(t.TempDir(), "absent"), time.Second)
	if err != nil || results != nil {
		t.Fatalf("results = %+v, err = %v", results, err)
	}
}

func TestSymlinkToSafeScriptRuns(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.sh")
	write(t, filepath.Dir(target), "target.sh", "echo via-link\n", 0o500)
	if err := os.Symlink(target, filepath.Join(dir, "link.sh")); err != nil {
		t.Fatal(err)
	}
	results, _ := Run(context.Background(), dir, 5*time.Second)
	if len(results) != 1 || results[0].Err != nil || results[0].Output != "via-link\n" {
		t.Fatalf("results = %+v", results)
	}
}
