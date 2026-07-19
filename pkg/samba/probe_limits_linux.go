//go:build linux

package samba

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func configureProbeCommand(command *exec.Cmd) error {
	attributes := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if os.Geteuid() == 0 {
		// A non-nil empty Groups slice makes os/exec call setgroups(0, nil)
		// before setgid/setuid. Never retain the daemon's supplementary groups.
		attributes.Credential = &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}
	}
	command.SysProcAttr = attributes
	return nil
}

func applyProbeResourceLimits() error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_AS, 1 << 30},
		{unix.RLIMIT_CPU, 6},
		{unix.RLIMIT_NOFILE, 32},
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_FSIZE, 1 << 20},
		{unix.RLIMIT_MEMLOCK, 0},
	}
	for _, limit := range limits {
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.value, Max: limit.value}); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func verifyProbeSandbox() error {
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		return syscall.EPERM
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return syscall.EPERM
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		return syscall.EPERM
	}
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivileges != 1 {
		return syscall.EPERM
	}
	for _, expected := range []struct {
		resource int
		current  uint64
	}{
		{unix.RLIMIT_AS, 1 << 30},
		{unix.RLIMIT_CPU, 6},
		{unix.RLIMIT_NOFILE, 32},
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_FSIZE, 1 << 20},
		{unix.RLIMIT_MEMLOCK, 0},
	} {
		var actual unix.Rlimit
		if err := unix.Getrlimit(expected.resource, &actual); err != nil || actual.Cur != expected.current || actual.Max != expected.current {
			return syscall.EPERM
		}
	}
	return nil
}

func probeExecutablePath() (string, error) { return "/proc/self/exe", nil }
