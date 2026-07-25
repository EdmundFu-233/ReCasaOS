//go:build linux

package publicfiles

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testStorageWorkerHelperEnvironment = "RECASAOS_TEST_STORAGE_WORKER_HELPER"
	testStorageWorkerModeEnvironment   = "RECASAOS_TEST_STORAGE_WORKER_MODE"
	testStorageWorkerActionEnvironment = "RECASAOS_TEST_STORAGE_WORKER_ACTION"
	testStorageWorkerData              = "isolated storage worker bytes"
)

func TestIsolatedStorageManagerRoundTripAndCapacity(t *testing.T) {
	t.Parallel()

	manager, verifier := newTestIsolatedStorageManager(
		t,
		testStorageWorkerCommandFactory(func(string) string { return "success" }),
		1,
		1,
	)
	if verifier != testStorageVerifier() {
		t.Fatalf("bootstrap verifier = %x, want %x", verifier, testStorageVerifier())
	}

	entries, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries)
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if len(entries) != 1 || entries[0] != (Entry{Name: "report.txt", Type: "file", Size: 7}) {
		t.Fatalf("list() entries = %#v, want one reviewed entry", entries)
	}

	file, info, err := manager.openRegular(context.Background(), "report.txt")
	if err != nil {
		t.Fatalf("openRegular() error = %v", err)
	}
	if info.Name() != "report.txt" || info.Size() != int64(len(testStorageWorkerData)) {
		t.Fatalf("openRegular() info = name %q size %d", info.Name(), info.Size())
	}
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageCapacity) {
		t.Fatalf("list() while file worker is active error = %v, want errStorageCapacity", err)
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(payload) != testStorageWorkerData {
		t.Fatalf("ReadAll() = %q, want %q", payload, testStorageWorkerData)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close() error = %v", err)
	}
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); err != nil {
		t.Fatalf("list() after file Close() error = %v", err)
	}
}

func TestIsolatedStorageTimeoutKillsWorkerAndRestoresAdmission(t *testing.T) {
	t.Parallel()

	var listStarts atomic.Int32
	factory := testStorageWorkerCommandFactory(func(mode string) string {
		if mode == storageWorkerModeList && listStarts.Add(1) == 1 {
			return "hang"
		}
		return "success"
	})
	manager, _ := newTestIsolatedStorageManager(t, factory, 1, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := manager.list(ctx, "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageTimeout) {
		t.Fatalf("timed list error = %v, want errStorageTimeout", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed list took %s, want bounded cancellation", elapsed)
	}
	waitForStorageTestCondition(t, 2*time.Second, func() bool {
		return manager.quarantine.Load() == 0 && len(manager.slots) == 0
	})
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); err != nil {
		t.Fatalf("list() after killed worker was reaped error = %v", err)
	}
}

func TestIsolatedStorageSignalFailureClosesAdmission(t *testing.T) {
	t.Parallel()

	manager, _ := newTestIsolatedStorageManager(
		t,
		testStorageWorkerCommandFactory(func(mode string) string {
			if mode == storageWorkerModeList {
				return "delayed-exit"
			}
			return "success"
		}),
		1,
		1,
	)
	manager.signal = func(_ int, _ unix.Signal) error {
		return unix.EPERM
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := manager.list(ctx, "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageTimeout) {
		t.Fatalf("timed list error = %v, want errStorageTimeout", err)
	}
	if !manager.signalFailure.Load() {
		t.Fatal("pidfd signal failure did not close worker admission")
	}
	if got := manager.quarantine.Load(); got != 1 {
		t.Fatalf("quarantined workers after pidfd signal failure = %d, want 1", got)
	}
	if got := len(manager.slots); got != 1 {
		t.Fatalf("occupied slots before independently exiting worker is reaped = %d, want 1", got)
	}
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageCapacity) {
		t.Fatalf("list() after pidfd signal failure error = %v, want errStorageCapacity", err)
	}
	waitForStorageTestCondition(t, 5*time.Second, func() bool {
		return manager.quarantine.Load() == 0 && len(manager.slots) == 0
	})
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageCapacity) {
		t.Fatalf("list() after failed signal target was reaped error = %v, want permanent errStorageCapacity", err)
	}
}

func TestIsolatedStorageFileTreatsEarlyEOFAsSourceFailure(t *testing.T) {
	t.Parallel()

	manager, _ := newTestIsolatedStorageManager(
		t,
		testStorageWorkerCommandFactory(func(mode string) string {
			if mode == storageWorkerModeFile {
				return "early-eof"
			}
			return "success"
		}),
		1,
		1,
	)
	file, _, err := manager.openRegular(context.Background(), "report.txt")
	if err != nil {
		t.Fatalf("openRegular() error = %v", err)
	}
	buffer := make([]byte, 8)
	if _, err := file.Read(buffer); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Read() error = %v, want io.ErrUnexpectedEOF", err)
	}
	source, ok := file.(storageSourceError)
	if !ok || !errors.Is(source.sourceError(), io.ErrUnexpectedEOF) {
		t.Fatalf("sourceError() = %v, want io.ErrUnexpectedEOF", source.sourceError())
	}
	if err := file.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Close() error = %v, want io.ErrUnexpectedEOF", err)
	}
	waitForStorageTestCondition(t, 2*time.Second, func() bool {
		return manager.quarantine.Load() == 0 && len(manager.slots) == 0
	})
}

func TestIsolatedStorageRejectsMalformedWorkerResponse(t *testing.T) {
	t.Parallel()

	manager, _ := newTestIsolatedStorageManager(
		t,
		testStorageWorkerCommandFactory(func(mode string) string {
			if mode == storageWorkerModeList {
				return "malformed"
			}
			return "success"
		}),
		1,
		1,
	)
	if _, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries); !errors.Is(err, errStorageProtocol) {
		t.Fatalf("list() error = %v, want errStorageProtocol", err)
	}
	waitForStorageTestCondition(t, 2*time.Second, func() bool {
		return manager.quarantine.Load() == 0 && len(manager.slots) == 0
	})
}

func TestIsolatedStorageManagerCloseAbortsActiveWorker(t *testing.T) {
	t.Parallel()

	manager, _ := newTestIsolatedStorageManager(
		t,
		testStorageWorkerCommandFactory(func(mode string) string {
			if mode == storageWorkerModeList {
				return "hang"
			}
			return "success"
		}),
		1,
		1,
	)
	listResult := make(chan error, 1)
	go func() {
		_, err := manager.list(context.Background(), "", DefaultMaxDirectoryEntries)
		listResult <- err
	}()
	waitForStorageTestCondition(t, 2*time.Second, func() bool {
		return len(manager.slots) == 1
	})
	if err := manager.close(); err != nil {
		t.Fatalf("manager close() error = %v", err)
	}
	select {
	case err := <-listResult:
		if !errors.Is(err, errStorageProtocol) &&
			!errors.Is(err, errStorageCapacity) {
			t.Fatalf("list() after manager close error = %v, want closed-worker error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("list() remained blocked after manager close")
	}
	waitForStorageTestCondition(t, 2*time.Second, func() bool {
		return manager.quarantine.Load() == 0 && len(manager.slots) == 0
	})
}

func TestClassifyStorageWorkerStartError(t *testing.T) {
	t.Parallel()

	for _, capacityError := range []error{
		syscall.EAGAIN,
		syscall.EMFILE,
		syscall.ENFILE,
		syscall.ENOMEM,
		syscall.ENOBUFS,
		errStorageCapacity,
	} {
		if got := classifyStorageWorkerStartError(capacityError); !errors.Is(got, errStorageCapacity) {
			t.Fatalf("classifyStorageWorkerStartError(%v) = %v, want errStorageCapacity", capacityError, got)
		}
	}
	if got := classifyStorageWorkerStartError(syscall.EINVAL); !errors.Is(got, errStorageProtocol) {
		t.Fatalf("classifyStorageWorkerStartError(EINVAL) = %v, want errStorageProtocol", got)
	}
}

func TestIsolatedStorageRejectsUndispatchedWorkerArguments(t *testing.T) {
	t.Parallel()

	if !hasUndispatchedStorageWorkerArgument([]string{
		"/usr/bin/embedding-service",
		InternalStorageWorkerArgument,
		storageWorkerModeBootstrap,
	}) {
		t.Fatal("internal worker argument was not detected")
	}
	for _, arguments := range [][]string{
		nil,
		{"/usr/bin/embedding-service"},
		{"/usr/bin/embedding-service", "serve", InternalStorageWorkerArgument},
	} {
		if hasUndispatchedStorageWorkerArgument(arguments) {
			t.Fatalf("ordinary arguments were rejected: %q", arguments)
		}
	}
}

func TestIsolatedStorageHelperProcess(t *testing.T) {
	if os.Getenv(testStorageWorkerHelperEnvironment) != "1" {
		return
	}
	connection, err := storageWorkerConnectionFromFD(storageWorkerIPCFileDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	mode := os.Getenv(testStorageWorkerModeEnvironment)
	action := os.Getenv(testStorageWorkerActionEnvironment)
	switch mode {
	case storageWorkerModeBootstrap:
		runTestStorageBootstrapHelper(t, connection)
	case storageWorkerModeList:
		runTestStorageListHelper(t, connection, action)
	case storageWorkerModeFile:
		runTestStorageFileHelper(t, connection, action)
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func testStorageWorkerCommandFactory(
	action func(mode string) string,
) storageWorkerCommandFactory {
	return func(mode string, childSocket *os.File, pidfd *int) (*exec.Cmd, error) {
		command := exec.Command(os.Args[0], "-test.run=^TestIsolatedStorageHelperProcess$")
		command.Env = []string{
			testStorageWorkerHelperEnvironment + "=1",
			testStorageWorkerModeEnvironment + "=" + mode,
			testStorageWorkerActionEnvironment + "=" + action(mode),
			"GOMAXPROCS=1",
			"GOTRACEBACK=none",
		}
		command.ExtraFiles = []*os.File{childSocket}
		command.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			PidFD:   pidfd,
		}
		return command, nil
	}
}

func newTestIsolatedStorageManager(
	t *testing.T,
	factory storageWorkerCommandFactory,
	maxWorkers int,
	quarantineAdmissionLimit int32,
) (*isolatedStorageManager, [32]byte) {
	t.Helper()
	root := t.TempDir()
	manager, verifier, err := newIsolatedStorageWith(
		root,
		filepath.Join(root, "unused-verifier"),
		factory,
		maxWorkers,
		quarantineAdmissionLimit,
	)
	if err != nil {
		t.Fatalf("newIsolatedStorageWith() error = %v", err)
	}
	t.Cleanup(func() {
		if err := manager.close(); err != nil {
			t.Errorf("manager close() error = %v", err)
		}
	})
	return manager, verifier
}

func runTestStorageBootstrapHelper(t *testing.T, connection *net.UnixConn) {
	t.Helper()
	frame, rights, err := receiveStorageWorkerFrame(connection, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer closeStorageWorkerRights(rights)
	if len(rights) != 0 || !validStorageWorkerRequestFrame(frame, storageWorkerBootstrapRequest) {
		t.Fatal("invalid bootstrap request")
	}
	var request storageBootstrapRequest
	if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(request.RootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    storageWorkerBootstrapResponse,
			requestID: frame.requestID,
			status:    storageWorkerStatusOK,
			payload: marshalStorageBootstrapResponse(storageBootstrapResponse{
				Verifier:       testStorageVerifier(),
				MountID:        99,
				FilesystemType: 0xef53,
			}),
		},
		[]int{int(root.Fd())},
		time.Now().Add(5*time.Second),
	); err != nil {
		t.Fatal(err)
	}
}

func runTestStorageListHelper(t *testing.T, connection *net.UnixConn, action string) {
	t.Helper()
	if action == "delayed-exit" {
		<-time.After(time.Second)
		return
	}
	frame, rights, err := receiveStorageWorkerFrame(connection, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(rights) != 1 || !validStorageWorkerRequestFrame(frame, storageWorkerListRequest) {
		closeStorageWorkerRights(rights)
		t.Fatal("invalid list request")
	}
	closeStorageWorkerRights(rights)
	if action == "hang" {
		<-time.After(10 * time.Minute)
		return
	}
	payload, err := json.Marshal([]Entry{{Name: "report.txt", Type: "file", Size: 7}})
	if err != nil {
		t.Fatal(err)
	}
	requestID := frame.requestID
	if action == "malformed" {
		requestID++
	}
	if err := sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    storageWorkerListResponse,
			requestID: requestID,
			status:    storageWorkerStatusOK,
			payload:   payload,
		},
		nil,
		time.Now().Add(5*time.Second),
	); err != nil {
		t.Fatal(err)
	}
}

func runTestStorageFileHelper(t *testing.T, connection *net.UnixConn, action string) {
	t.Helper()
	frame, rights, err := receiveStorageWorkerFrame(connection, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(rights) != 1 || !validStorageWorkerRequestFrame(frame, storageWorkerOpenRequest) {
		closeStorageWorkerRights(rights)
		t.Fatal("invalid open request")
	}
	closeStorageWorkerRights(rights)
	if err := sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    storageWorkerOpenResponse,
			requestID: frame.requestID,
			status:    storageWorkerStatusOK,
			payload: marshalStorageOpenResponse(storageOpenResponse{
				Size:            int64(len(testStorageWorkerData)),
				ModTimeUnixNano: time.Unix(1, 0).UnixNano(),
			}),
		},
		nil,
		time.Now().Add(5*time.Second),
	); err != nil {
		t.Fatal(err)
	}

	for {
		next, nextRights, err := receiveStorageWorkerFrame(connection, time.Now().Add(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(nextRights) != 0 {
			closeStorageWorkerRights(nextRights)
			t.Fatal("unexpected rights in file request")
		}
		switch next.opcode {
		case storageWorkerReadRequest:
			if action == "early-eof" {
				if err := sendStorageWorkerFrame(
					connection,
					storageWorkerFrame{
						opcode:    storageWorkerReadResponse,
						requestID: next.requestID,
						status:    storageWorkerStatusEOF,
					},
					nil,
					time.Now().Add(5*time.Second),
				); err != nil {
					t.Fatal(err)
				}
				continue
			}
			request, err := parseStorageReadRequest(next.payload)
			if err != nil {
				t.Fatal(err)
			}
			end := request.Offset + int64(request.Length)
			if end > int64(len(testStorageWorkerData)) {
				end = int64(len(testStorageWorkerData))
			}
			payload := []byte(testStorageWorkerData)[request.Offset:end]
			if err := sendStorageWorkerFrame(
				connection,
				storageWorkerFrame{
					opcode:    storageWorkerReadResponse,
					requestID: next.requestID,
					status:    storageWorkerStatusOK,
					payload:   payload,
				},
				nil,
				time.Now().Add(5*time.Second),
			); err != nil {
				t.Fatal(err)
			}
		case storageWorkerCloseRequest:
			if err := sendStorageWorkerFrame(
				connection,
				storageWorkerFrame{
					opcode:    storageWorkerCloseResponse,
					requestID: next.requestID,
					status:    storageWorkerStatusOK,
				},
				nil,
				time.Now().Add(5*time.Second),
			); err != nil {
				t.Fatal(err)
			}
			return
		default:
			t.Fatalf("unexpected file opcode %d", next.opcode)
		}
	}
}

func testStorageVerifier() [32]byte {
	var verifier [32]byte
	for index := range verifier {
		verifier[index] = byte(index + 1)
	}
	return verifier
}

func waitForStorageTestCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for storage worker condition")
}
