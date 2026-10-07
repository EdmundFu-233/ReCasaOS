package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemctl puts a systemctl on PATH that records its arguments and exits
// with the given status.
func fakeSystemctl(t *testing.T, status int) string {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > " + record + "\necho 'failed to talk to init' >&2\nexit " + string(rune('0'+status)) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return record
}

func TestPowerActionsUseSystemd(t *testing.T) {
	system := NewSystemService()
	for _, tc := range []struct {
		action func() error
		want   string
	}{
		{system.SystemReboot, "--no-block reboot"},
		{system.SystemShutdown, "--no-block poweroff"},
	} {
		record := fakeSystemctl(t, 0)
		if err := tc.action(); err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		args, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(args)); got != tc.want {
			t.Fatalf("systemctl %q, want %q", got, tc.want)
		}
	}
}

func TestPowerActionsReportFailure(t *testing.T) {
	fakeSystemctl(t, 1)
	err := NewSystemService().SystemReboot()
	if err == nil || !strings.Contains(err.Error(), "failed to talk to init") {
		t.Fatalf("err = %v, want the systemctl failure with its output", err)
	}
}
