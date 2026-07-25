//go:build linux && recasaos_publicfiles_systemd_test

package publicfiles

import "golang.org/x/sys/unix"

const systemdStorageWorkerFixture = "worker-load.bin"

// holdStorageFileWorkerForSystemdTest is compiled only into the dedicated
// GitHub-hosted systemd integration binary. After the first real read response
// for the exact synthetic fixture, the worker stops itself. The coordinator
// must use its normal pidfd cancellation path to terminate it; no release
// binary contains this implementation.
func holdStorageFileWorkerForSystemdTest(
	relativePath string,
	offset int64,
) error {
	if relativePath != systemdStorageWorkerFixture || offset != 0 {
		return nil
	}
	return unix.Kill(unix.Getpid(), unix.SIGSTOP)
}
