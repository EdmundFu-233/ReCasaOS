//go:build linux && !recasaos_publicfiles_systemd_test

package publicfiles

import "os/exec"

const storageWorkerSystemdTestEnabled = false

func holdStorageFileWorkerForSystemdTest(string, int64) error {
	return nil
}

func reportStorageWorkerSystemdTestEvent(systemdStorageWorkerTestEvent) {}

func configureStorageWorkerSystemdTestCommand(*exec.Cmd) {}
