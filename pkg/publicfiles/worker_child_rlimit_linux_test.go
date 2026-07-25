//go:build linux && !race

package publicfiles

import (
	"os"
	"os/exec"
	"testing"
)

const (
	testStorageWorkerAddressSpaceHelper         = "RECASAOS_TEST_STORAGE_WORKER_ADDRESS_SPACE"
	testStorageWorkerAddressSpaceHelperArgument = "recasaos-address-space-helper-v1"
)

// The race runtime reserves a multi-terabyte shadow address range, so it cannot
// exercise the reviewed 2 GiB production ceiling. Pure validation tests remain
// enabled under -race; this real setrlimit check runs only in a disposable
// non-race subprocess so it cannot lower the parent test process's hard limit.
func TestApplyStorageWorkerAddressSpaceLimitInSubprocess(t *testing.T) {
	helperRequested := os.Getenv(testStorageWorkerAddressSpaceHelper) == "1" &&
		len(os.Args) >= 3 &&
		os.Args[len(os.Args)-2] == "--" &&
		os.Args[len(os.Args)-1] == testStorageWorkerAddressSpaceHelperArgument
	if helperRequested {
		if err := applyStorageWorkerAddressSpaceLimit(); err != nil {
			t.Fatalf("applyStorageWorkerAddressSpaceLimit() error = %v", err)
		}
		return
	}

	command := exec.Command(
		os.Args[0],
		"-test.run=^TestApplyStorageWorkerAddressSpaceLimitInSubprocess$",
		"--",
		testStorageWorkerAddressSpaceHelperArgument,
	)
	command.Env = []string{
		testStorageWorkerAddressSpaceHelper + "=1",
		"GOMEMLIMIT=24MiB",
		"GOMAXPROCS=1",
		"GOTRACEBACK=none",
		"LANG=C",
		"LC_ALL=C",
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"address-space helper error = %v\noutput:\n%s",
			err,
			output,
		)
	}
}
