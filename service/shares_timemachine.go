package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrTimeMachineUnsupported: smbd cannot load vfs_fruit, so a Time Machine
// share would refuse every connection (testparm parses without loading modules).
var ErrTimeMachineUnsupported = errors.New("Time Machine needs Samba's vfs_fruit module (Debian/Ubuntu: package samba-vfs-modules)")

// smbdBuildOptions is `smbd -b`; replaced in tests.
var smbdBuildOptions = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output := &boundedCommandOutput{limit: 256 << 10}
	command := exec.CommandContext(ctx, "smbd", "-b")
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	return output.buffer.Bytes(), err
}

// ValidateTimeMachineSupport checks that MODULESDIR/vfs/fruit.so exists.
// No smbd, or no MODULESDIR line: no check (never a false refusal).
func ValidateTimeMachineSupport() error {
	output, err := smbdBuildOptions()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, dir, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || key != "MODULESDIR" {
			continue
		}
		if _, err := os.Stat(filepath.Join(strings.TrimSpace(dir), "vfs", "fruit.so")); err != nil {
			return ErrTimeMachineUnsupported
		}
		return nil
	}
	return nil
}
