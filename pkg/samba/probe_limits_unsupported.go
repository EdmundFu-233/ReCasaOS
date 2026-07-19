//go:build !linux

package samba

import (
	"os"
	"os/exec"
)

func configureProbeCommand(*exec.Cmd) error { return nil }

func applyProbeResourceLimits() error { return nil }

func verifyProbeSandbox() error { return nil }

func probeExecutablePath() (string, error) { return os.Executable() }
