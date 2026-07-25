//go:build linux

package publicfiles

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	InternalStorageWorkerArgument = "--internal-public-files-storage-worker"

	storageWorkerModeBootstrap = "bootstrap"
	storageWorkerModeList      = "list"
	storageWorkerModeFile      = "file"

	storageWorkerIPCFileDescriptor = uintptr(3)
	storageWorkerChildIdleTimeout  = 45 * time.Second

	storageWorkerStatmPath     = "/proc/self/statm"
	storageWorkerStatmMaxBytes = int64(256)

	// The Go runtime reserves architecture- and toolchain-dependent virtual
	// address ranges before main starts. Bound only subsequent growth so a
	// reviewed toolchain cannot begin above a fixed whole-process limit.
	//
	// 256 MiB provides four additional 64 MiB heap arenas on 64-bit Go and is
	// deliberately much larger than the worker's 24 MiB soft Go memory budget.
	// The post-set check keeps at least half of it available. The 2 GiB ceiling
	// remains a finite, portable per-process bound on supported 32-bit Linux.
	storageWorkerAddressSpaceHeadroom       = uint64(256 << 20)
	storageWorkerAddressSpaceMinimumReserve = uint64(128 << 20)
	storageWorkerAddressSpaceCeiling        = uint64(2 << 30)
)

// RunInternalStorageWorker is called only by the standalone binary's hidden
// self-exec mode. It deliberately accepts no HTTP listener, bearer, database,
// management socket or writable share descriptor.
func RunInternalStorageWorker(mode string) error {
	switch mode {
	case storageWorkerModeBootstrap, storageWorkerModeList, storageWorkerModeFile:
	default:
		return errStorageProtocol
	}
	if err := validateStorageWorkerEnvironment(); err != nil {
		return err
	}
	if err := ValidateServiceRuntime(); err != nil {
		return err
	}
	if err := applyStorageWorkerFixedResourceLimits(); err != nil {
		return err
	}

	connection, err := storageWorkerConnectionFromFD(storageWorkerIPCFileDescriptor)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := validateStorageWorkerConnection(connection, os.Getppid()); err != nil {
		return err
	}
	// net.FileConn and SO_PEERCRED validation may initialize lazy runtime
	// mappings. Include them in the address-space baseline, but still apply the
	// hard limit before reading the first IPC request.
	if err := applyStorageWorkerAddressSpaceLimit(); err != nil {
		return err
	}

	switch mode {
	case storageWorkerModeBootstrap:
		return runStorageBootstrapWorker(connection)
	case storageWorkerModeList:
		return runStorageListWorker(connection)
	case storageWorkerModeFile:
		return runStorageFileWorker(connection)
	default:
		return errStorageProtocol
	}
}

func validateStorageWorkerEnvironment() error {
	expected := map[string]string{
		"GOMEMLIMIT":  "24MiB",
		"GOMAXPROCS":  "1",
		"GOTRACEBACK": "none",
		"LANG":        "C",
		"LC_ALL":      "C",
	}
	environment := os.Environ()
	if len(environment) != len(expected) {
		return errStorageProtocol
	}
	for _, item := range environment {
		name, value, found := strings.Cut(item, "=")
		if !found || expected[name] != value {
			return errStorageProtocol
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		return errStorageProtocol
	}
	return nil
}

func applyStorageWorkerFixedResourceLimits() error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_CPU, 300},
		{unix.RLIMIT_NOFILE, 16},
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_FSIZE, 0},
		{unix.RLIMIT_MEMLOCK, 0},
	}
	for _, limit := range limits {
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{
			Cur: limit.value,
			Max: limit.value,
		}); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func applyStorageWorkerAddressSpaceLimit() error {
	pageSize := os.Getpagesize()
	if pageSize <= 0 {
		return errStorageProtocol
	}
	pageSizeBytes := uint64(pageSize)
	before, err := currentStorageWorkerVirtualMemory(pageSizeBytes)
	if err != nil {
		return err
	}
	target, err := calculateStorageWorkerAddressSpaceLimit(before, pageSizeBytes)
	if err != nil {
		return err
	}

	var inherited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &inherited); err != nil {
		return err
	}
	if err := validateStorageWorkerInheritedAddressSpaceLimit(inherited, target); err != nil {
		return err
	}
	if err := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{
		Cur: target,
		Max: target,
	}); err != nil {
		return err
	}

	var applied unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &applied); err != nil {
		return err
	}
	after, err := currentStorageWorkerVirtualMemory(pageSizeBytes)
	if err != nil {
		return err
	}
	return validateStorageWorkerAppliedAddressSpaceLimit(applied, target, after)
}

func currentStorageWorkerVirtualMemory(pageSize uint64) (uint64, error) {
	content, err := readServiceRuntimeFile(
		storageWorkerStatmPath,
		storageWorkerStatmMaxBytes,
	)
	if err != nil {
		return 0, err
	}
	return parseStorageWorkerVirtualMemory(content, pageSize)
}

func parseStorageWorkerVirtualMemory(content []byte, pageSize uint64) (uint64, error) {
	if pageSize == 0 ||
		len(content) == 0 ||
		int64(len(content)) > storageWorkerStatmMaxBytes ||
		content[len(content)-1] != '\n' {
		return 0, errStorageProtocol
	}
	var (
		fieldCount int
		inField    bool
		lineFeeds  int
		pages      uint64
		value      uint64
	)
	for _, character := range content {
		switch {
		case character >= '0' && character <= '9':
			digit := uint64(character - '0')
			if !inField {
				fieldCount++
				inField = true
				value = 0
			}
			if value > (^uint64(0)-digit)/10 {
				return 0, errStorageProtocol
			}
			value = value*10 + digit
		case character == ' ', character == '\t':
			if inField {
				if fieldCount == 1 {
					pages = value
				}
				inField = false
			}
		case character == '\n':
			lineFeeds++
			if inField {
				if fieldCount == 1 {
					pages = value
				}
				inField = false
			}
		default:
			return 0, errStorageProtocol
		}
	}
	if lineFeeds != 1 || inField || fieldCount != 7 {
		return 0, errStorageProtocol
	}
	if pages == 0 || pages > ^uint64(0)/pageSize {
		return 0, errStorageProtocol
	}
	return pages * pageSize, nil
}

func calculateStorageWorkerAddressSpaceLimit(
	current uint64,
	pageSize uint64,
) (uint64, error) {
	if current == 0 ||
		pageSize == 0 ||
		current%pageSize != 0 ||
		storageWorkerAddressSpaceHeadroom%pageSize != 0 ||
		storageWorkerAddressSpaceMinimumReserve%pageSize != 0 ||
		storageWorkerAddressSpaceCeiling%pageSize != 0 ||
		storageWorkerAddressSpaceMinimumReserve > storageWorkerAddressSpaceHeadroom ||
		current > storageWorkerAddressSpaceCeiling-storageWorkerAddressSpaceHeadroom {
		return 0, errStorageProtocol
	}
	return current + storageWorkerAddressSpaceHeadroom, nil
}

func validateStorageWorkerInheritedAddressSpaceLimit(
	inherited unix.Rlimit,
	target uint64,
) error {
	if target == 0 ||
		inherited.Cur > inherited.Max ||
		inherited.Cur < target ||
		inherited.Max < target {
		return errStorageProtocol
	}
	return nil
}

func validateStorageWorkerAppliedAddressSpaceLimit(
	applied unix.Rlimit,
	target uint64,
	current uint64,
) error {
	if target == 0 ||
		applied.Cur != target ||
		applied.Max != target ||
		current > target ||
		target-current < storageWorkerAddressSpaceMinimumReserve {
		return errStorageProtocol
	}
	return nil
}

func runStorageBootstrapWorker(connection *net.UnixConn) error {
	frame, rights, err := receiveStorageWorkerFrame(
		connection,
		time.Now().Add(storageWorkerChildIdleTimeout),
	)
	if err != nil {
		return err
	}
	defer closeStorageWorkerRights(rights)
	if len(rights) != 0 ||
		!validStorageWorkerRequestFrame(frame, storageWorkerBootstrapRequest) {
		return errStorageProtocol
	}
	var request storageBootstrapRequest
	if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil {
		return err
	}
	rootPath, err := validateAbsoluteConfigPath(request.RootPath, false)
	if err != nil || rootPath != request.RootPath {
		return sendStorageWorkerError(
			connection,
			storageWorkerBootstrapResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}
	verifierPath, err := validateAbsoluteConfigPath(request.VerifierPath, true)
	if err != nil || verifierPath != request.VerifierPath {
		return sendStorageWorkerError(
			connection,
			storageWorkerBootstrapResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}

	verifier, err := readVerifierFileSecure(verifierPath)
	if err != nil {
		return sendStorageWorkerError(
			connection,
			storageWorkerBootstrapResponse,
			frame.requestID,
			storageWorkerStatusInternal,
		)
	}
	root, err := openSecureRoot(rootPath)
	if err != nil {
		return sendStorageWorkerError(
			connection,
			storageWorkerBootstrapResponse,
			frame.requestID,
			storageWorkerStatusForError(err),
		)
	}
	defer root.close()
	if root.file == nil {
		return errStorageProtocol
	}
	return sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    storageWorkerBootstrapResponse,
			requestID: frame.requestID,
			status:    storageWorkerStatusOK,
			payload: marshalStorageBootstrapResponse(storageBootstrapResponse{
				Verifier:       verifier,
				MountID:        root.mountID,
				FilesystemType: root.filesystemType,
			}),
		},
		[]int{int(root.file.Fd())},
		time.Now().Add(storageWorkerChildIdleTimeout),
	)
}

func runStorageListWorker(connection *net.UnixConn) error {
	frame, root, err := receiveStorageRootRequest(connection, storageWorkerListRequest)
	if err != nil {
		return err
	}
	defer root.close()

	var request storageListRequest
	if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil ||
		request.MaxEntries < 1 ||
		request.MaxEntries > DefaultMaxDirectoryEntries {
		return sendStorageWorkerError(
			connection,
			storageWorkerListResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}
	relativePath, err := validateRelativePath(request.Path, true)
	if err != nil || relativePath != request.Path {
		return sendStorageWorkerError(
			connection,
			storageWorkerListResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}
	entries, err := root.list(relativePath, request.MaxEntries)
	if err != nil {
		return sendStorageWorkerError(
			connection,
			storageWorkerListResponse,
			frame.requestID,
			storageWorkerStatusForError(err),
		)
	}
	payload, err := json.Marshal(entries)
	if err != nil || len(payload) == 0 || len(payload) > storageWorkerMaxListPayload {
		return sendStorageWorkerError(
			connection,
			storageWorkerListResponse,
			frame.requestID,
			storageWorkerStatusInternal,
		)
	}
	for offset := 0; offset < len(payload); {
		end := offset + storageWorkerMaxFramePayload
		if end > len(payload) {
			end = len(payload)
		}
		flags := uint16(0)
		if end != len(payload) {
			flags = storageWorkerFlagMore
		}
		if err := sendStorageWorkerFrame(
			connection,
			storageWorkerFrame{
				opcode:    storageWorkerListResponse,
				requestID: frame.requestID,
				status:    storageWorkerStatusOK,
				flags:     flags,
				payload:   payload[offset:end],
			},
			nil,
			time.Now().Add(storageWorkerChildIdleTimeout),
		); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func runStorageFileWorker(connection *net.UnixConn) error {
	frame, root, err := receiveStorageRootRequest(connection, storageWorkerOpenRequest)
	if err != nil {
		return err
	}
	var request storageOpenRequest
	if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil {
		_ = root.close()
		return sendStorageWorkerError(
			connection,
			storageWorkerOpenResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}
	relativePath, err := validateRelativePath(request.Path, false)
	if err != nil || relativePath != request.Path {
		_ = root.close()
		return sendStorageWorkerError(
			connection,
			storageWorkerOpenResponse,
			frame.requestID,
			storageWorkerStatusInvalid,
		)
	}
	file, info, err := root.openRegular(relativePath)
	closeRootErr := root.close()
	if err != nil {
		return sendStorageWorkerError(
			connection,
			storageWorkerOpenResponse,
			frame.requestID,
			storageWorkerStatusForError(err),
		)
	}
	if closeRootErr != nil {
		_ = file.Close()
		return errStorageProtocol
	}
	defer file.Close()
	if err := sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    storageWorkerOpenResponse,
			requestID: frame.requestID,
			status:    storageWorkerStatusOK,
			payload: marshalStorageOpenResponse(storageOpenResponse{
				Size:            info.Size(),
				ModTimeUnixNano: info.ModTime().UnixNano(),
			}),
		},
		nil,
		time.Now().Add(storageWorkerChildIdleTimeout),
	); err != nil {
		return err
	}

	expectedID := frame.requestID + 1
	for {
		next, rights, err := receiveStorageWorkerFrame(
			connection,
			time.Now().Add(storageWorkerChildIdleTimeout),
		)
		if err != nil {
			return err
		}
		closeStorageWorkerRights(rights)
		if len(rights) != 0 ||
			next.requestID != expectedID ||
			next.status != storageWorkerStatusOK ||
			next.flags != 0 {
			return errStorageProtocol
		}
		expectedID++

		switch next.opcode {
		case storageWorkerReadRequest:
			readRequest, err := parseStorageReadRequest(next.payload)
			if err != nil {
				return err
			}
			buffer := make([]byte, int(readRequest.Length))
			count, readErr := unix.Pread(
				int(file.Fd()),
				buffer,
				readRequest.Offset,
			)
			if readErr != nil {
				return sendStorageWorkerError(
					connection,
					storageWorkerReadResponse,
					next.requestID,
					storageWorkerStatusInternal,
				)
			}
			status := storageWorkerStatusOK
			if count == 0 {
				status = storageWorkerStatusEOF
			}
			if err := sendStorageWorkerFrame(
				connection,
				storageWorkerFrame{
					opcode:    storageWorkerReadResponse,
					requestID: next.requestID,
					status:    status,
					payload:   buffer[:count],
				},
				nil,
				time.Now().Add(storageWorkerChildIdleTimeout),
			); err != nil {
				return err
			}
			if err := holdStorageFileWorkerForSystemdTest(
				request.Path,
				readRequest.Offset,
			); err != nil {
				return err
			}
		case storageWorkerCloseRequest:
			if len(next.payload) != 0 {
				return errStorageProtocol
			}
			return sendStorageWorkerFrame(
				connection,
				storageWorkerFrame{
					opcode:    storageWorkerCloseResponse,
					requestID: next.requestID,
					status:    storageWorkerStatusOK,
				},
				nil,
				time.Now().Add(storageWorkerChildIdleTimeout),
			)
		default:
			return errStorageProtocol
		}
	}
}

func receiveStorageRootRequest(
	connection *net.UnixConn,
	expectedOpcode storageWorkerOpcode,
) (storageWorkerFrame, *secureRoot, error) {
	frame, rights, err := receiveStorageWorkerFrame(
		connection,
		time.Now().Add(storageWorkerChildIdleTimeout),
	)
	if err != nil {
		return storageWorkerFrame{}, nil, err
	}
	if len(rights) != 1 ||
		!validStorageWorkerRequestFrame(frame, expectedOpcode) {
		closeStorageWorkerRights(rights)
		return storageWorkerFrame{}, nil, errStorageProtocol
	}

	var (
		mountID        uint64
		filesystemType uint32
	)
	switch expectedOpcode {
	case storageWorkerListRequest:
		var request storageListRequest
		if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil {
			closeStorageWorkerRights(rights)
			return storageWorkerFrame{}, nil, err
		}
		mountID = request.MountID
		filesystemType = request.FilesystemType
	case storageWorkerOpenRequest:
		var request storageOpenRequest
		if err := unmarshalStorageWorkerJSON(frame.payload, &request); err != nil {
			closeStorageWorkerRights(rights)
			return storageWorkerFrame{}, nil, err
		}
		mountID = request.MountID
		filesystemType = request.FilesystemType
	default:
		closeStorageWorkerRights(rights)
		return storageWorkerFrame{}, nil, errStorageProtocol
	}

	rootFD := rights[0]
	root, err := secureRootFromWorkerFD(rootFD, mountID, filesystemType)
	if err != nil {
		_ = unix.Close(rootFD)
		return storageWorkerFrame{}, nil, err
	}
	return frame, root, nil
}

func validStorageWorkerRequestFrame(
	frame storageWorkerFrame,
	expected storageWorkerOpcode,
) bool {
	return frame.opcode == expected &&
		frame.requestID != 0 &&
		frame.status == storageWorkerStatusOK &&
		frame.flags == 0
}

func storageWorkerStatusForError(err error) storageWorkerStatus {
	switch {
	case errors.Is(err, errEntryLimit):
		return storageWorkerStatusEntryLimit
	case isHiddenFilesystemError(err):
		return storageWorkerStatusHidden
	case errors.Is(err, ErrUnsupported),
		errors.Is(err, errPublicRootFilesystemNotAllowed):
		return storageWorkerStatusUnsupported
	default:
		return storageWorkerStatusInternal
	}
}

func sendStorageWorkerError(
	connection *net.UnixConn,
	opcode storageWorkerOpcode,
	requestID uint64,
	status storageWorkerStatus,
) error {
	if status == storageWorkerStatusOK || status == storageWorkerStatusEOF {
		return errStorageProtocol
	}
	return sendStorageWorkerFrame(
		connection,
		storageWorkerFrame{
			opcode:    opcode,
			requestID: requestID,
			status:    status,
		},
		nil,
		time.Now().Add(storageWorkerChildIdleTimeout),
	)
}

func storageWorkerError(status storageWorkerStatus) error {
	switch status {
	case storageWorkerStatusHidden:
		return syscall.ENOENT
	case storageWorkerStatusEntryLimit:
		return errEntryLimit
	case storageWorkerStatusUnsupported:
		return ErrUnsupported
	case storageWorkerStatusInvalid:
		return errStorageProtocol
	case storageWorkerStatusInternal:
		return errors.New("public file storage worker failed")
	default:
		return errStorageProtocol
	}
}

func workerFileInfo(name string, response storageOpenResponse) fileInfo {
	return isolatedFileInfo{
		name:    path.Base(name),
		size:    response.Size,
		modTime: time.Unix(0, response.ModTimeUnixNano),
	}
}

// Isolated worker responses are always regular files; no host inode, owner,
// mode bits or absolute path are exposed to the parent.
type isolatedFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (i isolatedFileInfo) Name() string       { return i.name }
func (i isolatedFileInfo) Size() int64        { return i.size }
func (i isolatedFileInfo) Mode() os.FileMode  { return 0o400 }
func (i isolatedFileInfo) ModTime() time.Time { return i.modTime }
func (i isolatedFileInfo) IsDir() bool        { return false }
func (i isolatedFileInfo) Sys() any           { return nil }
