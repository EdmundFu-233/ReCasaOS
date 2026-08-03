//go:build linux && recasaos_publicfiles_systemd_test

package publicfiles

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

const systemdStorageWorkerFixture = "worker-load.bin"
const storageWorkerSystemdTestEnabled = true

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
	reportStorageWorkerSystemdTestEvent(
		systemdStorageWorkerTestChildFirstReadSent,
	)
	return unix.Kill(unix.Getpid(), unix.SIGSTOP)
}

func reportStorageWorkerSystemdTestEvent(
	event systemdStorageWorkerTestEvent,
) {
	var name string
	switch event {
	case systemdStorageWorkerTestHandlerEntered:
		name = "handler-entered"
	case systemdStorageWorkerTestDownloadSlotAcquired:
		name = "handler-download-slot-acquired"
	case systemdStorageWorkerTestDownloadSlotRejected:
		name = "handler-download-slot-rejected"
	case systemdStorageWorkerTestContextRejected:
		name = "coordinator-context-rejected"
	case systemdStorageWorkerTestPreSlotRejected:
		name = "coordinator-pre-slot-rejected"
	case systemdStorageWorkerTestManagerUnavailable:
		name = "coordinator-manager-unavailable"
	case systemdStorageWorkerTestSignalFailure:
		name = "coordinator-signal-failure"
	case systemdStorageWorkerTestQuarantineLimit:
		name = "coordinator-quarantine-limit"
	case systemdStorageWorkerTestSlotsFull:
		name = "coordinator-slots-full"
	case systemdStorageWorkerTestSlotAcquired:
		name = "coordinator-slot-acquired"
	case systemdStorageWorkerTestStartCapacityFailure:
		name = "worker-start-capacity-failure"
	case systemdStorageWorkerTestStartProtocolFailure:
		name = "worker-start-protocol-failure"
	case systemdStorageWorkerTestPostStartRejected:
		name = "worker-post-start-rejected"
	case systemdStorageWorkerTestProcessRegistered:
		name = "worker-process-registered"
	case systemdStorageWorkerTestOpenResponse:
		name = "coordinator-open-response"
	case systemdStorageWorkerTestFirstReadResponse:
		name = "coordinator-first-read-response"
	case systemdStorageWorkerTestChildFirstReadSent:
		name = "child-first-read-sent"
	default:
		return
	}
	_, _ = fmt.Fprintf(
		os.Stderr,
		"recasaos-systemd-test-event=%s\n",
		name,
	)
}

func configureStorageWorkerSystemdTestCommand(command *exec.Cmd) {
	if command != nil {
		command.Stderr = os.Stderr
	}
}
