//go:build linux

package publicfiles

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReceiveStorageWorkerFrameClosesRightsOnTruncation(t *testing.T) {
	tests := []struct {
		name          string
		rightsCount   int
		oversizeBytes int
	}{
		{name: "ancillary rights truncation", rightsCount: storageWorkerMaxRights + 1},
		{name: "packet truncation", rightsCount: 1, oversizeBytes: storageWorkerMaxFramePayload + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, childSocket, err := newStorageWorkerSocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			defer childSocket.Close()

			files := make([]*os.File, test.rightsCount)
			descriptors := make([]int, test.rightsCount)
			for index := range files {
				file, err := os.CreateTemp(protectedTestDirectory(t), "storage-worker-right-")
				if err != nil {
					t.Fatal(err)
				}
				files[index] = file
				descriptors[index] = int(file.Fd())
				t.Cleanup(func() {
					_ = file.Close()
				})
			}
			for _, file := range files {
				if count := countOpenFileTarget(t, file.Name()); count != 1 {
					t.Fatalf("initial open descriptors for %s = %d, want 1", file.Name(), count)
				}
			}

			packet, err := marshalStorageWorkerFrame(storageWorkerFrame{
				opcode:    storageWorkerListResponse,
				requestID: 1,
				status:    storageWorkerStatusOK,
				payload:   []byte("x"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.oversizeBytes != 0 {
				packet = append(packet, make([]byte, test.oversizeBytes)...)
			}
			if err := unix.Sendmsg(
				int(childSocket.Fd()),
				packet,
				unix.UnixRights(descriptors...),
				nil,
				0,
			); err != nil {
				t.Fatal(err)
			}
			if _, _, err := receiveStorageWorkerFrame(
				connection,
				time.Now().Add(time.Second),
			); !errors.Is(err, errStorageProtocol) {
				t.Fatalf("receiveStorageWorkerFrame() error = %v, want errStorageProtocol", err)
			}
			for _, file := range files {
				if count := countOpenFileTarget(t, file.Name()); count != 1 {
					t.Fatalf("open descriptors for %s after rejection = %d, want 1", file.Name(), count)
				}
			}
		})
	}
}

func countOpenFileTarget(t *testing.T, target string) int {
	t.Helper()
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, descriptor := range descriptors {
		resolved, err := os.Readlink("/proc/self/fd/" + descriptor.Name())
		if err == nil && resolved == target {
			count++
		}
	}
	return count
}
