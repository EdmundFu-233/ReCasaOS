//go:build !linux

package publicfiles

const storageWorkerSystemdTestEnabled = false

func reportStorageWorkerSystemdTestEvent(systemdStorageWorkerTestEvent) {}
