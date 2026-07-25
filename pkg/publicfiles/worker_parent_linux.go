//go:build linux

package publicfiles

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultMaxActiveStorageWorkers = 8
	// DefaultQuarantineAdmissionLimit stops new work once this many killed
	// workers remain unreaped. Already-running workers may subsequently join
	// quarantine, so one coordinator generation can retain at most active
	// capacity plus this admission limit minus one children (11 with the
	// production defaults). Unkillable children from older systemd generations
	// remain bounded by the unit-wide TasksMax and MemoryMax cgroup limits.
	DefaultQuarantineAdmissionLimit = 4

	storageWorkerBootstrapTimeout = 12 * time.Second
	storageWorkerOperationTimeout = 10 * time.Second
	storageWorkerReadTimeout      = 30 * time.Second
	storageWorkerExitTimeout      = time.Second
)

type storageWorkerCommandFactory func(
	mode string,
	childSocket *os.File,
	pidfd *int,
) (*exec.Cmd, error)

type storageWorkerSignaler func(pidfd int, signal unix.Signal) error

type isolatedStorageManager struct {
	root                     *os.File
	mountID                  uint64
	filesystemType           uint32
	commandFactory           storageWorkerCommandFactory
	signal                   storageWorkerSignaler
	slots                    chan struct{}
	quarantineAdmissionLimit int32
	quarantine               atomic.Int32
	signalFailure            atomic.Bool
	requestID                atomic.Uint64

	mu      sync.Mutex
	closed  bool
	workers map[*isolatedStorageProcess]struct{}
}

type isolatedStorageProcess struct {
	manager *isolatedStorageManager
	command *exec.Cmd
	conn    *net.UnixConn
	pidfd   int
	done    chan struct{}
	waitErr error

	mu          sync.Mutex
	finished    bool
	quarantined bool
	abortOnce   sync.Once
	releaseOnce sync.Once
	signal      storageWorkerSignaler
}

type isolatedStorageFile struct {
	process     *isolatedStorageProcess
	context     context.Context
	stopContext func() bool
	info        isolatedFileInfo
	nextID      uint64
	offset      int64

	mu        sync.Mutex
	closed    bool
	sourceErr error
}

func newIsolatedStorage(
	rootPath string,
	verifierPath string,
) (storageBackend, [32]byte, error) {
	if hasUndispatchedStorageWorkerArgument(os.Args) {
		// If an embedding executable forgot to dispatch the hidden worker
		// argument, fail before another self-exec can create a process chain.
		return nil, [32]byte{}, errStorageProtocol
	}
	return newIsolatedStorageWith(
		rootPath,
		verifierPath,
		defaultStorageWorkerCommand,
		DefaultMaxActiveStorageWorkers,
		DefaultQuarantineAdmissionLimit,
	)
}

func hasUndispatchedStorageWorkerArgument(arguments []string) bool {
	return len(arguments) >= 2 &&
		arguments[1] == InternalStorageWorkerArgument
}

func newIsolatedStorageWith(
	rootPath string,
	verifierPath string,
	commandFactory storageWorkerCommandFactory,
	maxWorkers int,
	quarantineAdmissionLimit int32,
) (*isolatedStorageManager, [32]byte, error) {
	var zero [32]byte
	if commandFactory == nil ||
		maxWorkers < 1 ||
		maxWorkers > DefaultMaxActiveStorageWorkers ||
		quarantineAdmissionLimit < 1 ||
		quarantineAdmissionLimit > DefaultQuarantineAdmissionLimit {
		return nil, zero, errStorageProtocol
	}
	manager := &isolatedStorageManager{
		commandFactory:           commandFactory,
		slots:                    make(chan struct{}, maxWorkers),
		quarantineAdmissionLimit: quarantineAdmissionLimit,
		signal:                   signalStorageWorker,
		workers:                  make(map[*isolatedStorageProcess]struct{}),
	}
	response, root, err := manager.bootstrap(rootPath, verifierPath)
	if err != nil {
		return nil, zero, err
	}
	manager.root = root
	manager.mountID = response.MountID
	manager.filesystemType = response.FilesystemType
	return manager, response.Verifier, nil
}

func defaultStorageWorkerCommand(
	mode string,
	childSocket *os.File,
	pidfd *int,
) (*exec.Cmd, error) {
	if childSocket == nil || pidfd == nil {
		return nil, errStorageProtocol
	}
	command := exec.Command(
		"/proc/self/exe",
		InternalStorageWorkerArgument,
		mode,
	)
	command.Env = []string{
		"GOMEMLIMIT=24MiB",
		"GOMAXPROCS=1",
		"GOTRACEBACK=none",
		"LANG=C",
		"LC_ALL=C",
	}
	command.ExtraFiles = []*os.File{childSocket}
	command.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		PidFD:   pidfd,
	}
	if storageWorkerSystemdTestEnabled {
		configureStorageWorkerSystemdTestCommand(command)
	}
	return command, nil
}

func signalStorageWorker(pidfd int, signal unix.Signal) error {
	return unix.PidfdSendSignal(pidfd, signal, nil, 0)
}

func (m *isolatedStorageManager) bootstrap(
	rootPath string,
	verifierPath string,
) (storageBootstrapResponse, *os.File, error) {
	var zero storageBootstrapResponse
	process, err := startIsolatedStorageProcess(nil, m.commandFactory, storageWorkerModeBootstrap)
	if err != nil {
		return zero, nil, err
	}
	go process.reap()
	requestID := uint64(1)
	payload, err := marshalStorageWorkerJSON(storageBootstrapRequest{
		RootPath:     rootPath,
		VerifierPath: verifierPath,
	})
	if err != nil {
		process.abort()
		return zero, nil, err
	}
	deadline := time.Now().Add(storageWorkerBootstrapTimeout)
	if err := sendStorageWorkerFrame(
		process.conn,
		storageWorkerFrame{
			opcode:    storageWorkerBootstrapRequest,
			requestID: requestID,
			status:    storageWorkerStatusOK,
			payload:   payload,
		},
		nil,
		deadline,
	); err != nil {
		process.abort()
		return zero, nil, classifyStorageWorkerIPCError(context.Background(), err)
	}
	frame, rights, err := receiveStorageWorkerFrame(process.conn, deadline)
	if err != nil {
		process.abort()
		return zero, nil, classifyStorageWorkerIPCError(context.Background(), err)
	}
	if frame.opcode != storageWorkerBootstrapResponse ||
		frame.requestID != requestID ||
		frame.flags != 0 {
		closeStorageWorkerRights(rights)
		process.abort()
		return zero, nil, errStorageProtocol
	}
	if frame.status != storageWorkerStatusOK {
		closeStorageWorkerRights(rights)
		if len(frame.payload) != 0 {
			process.abort()
			return zero, nil, errStorageProtocol
		}
		if err := process.finishNormally(storageWorkerExitTimeout); err != nil {
			return zero, nil, err
		}
		return zero, nil, storageWorkerError(frame.status)
	}
	if len(rights) != 1 {
		closeStorageWorkerRights(rights)
		process.abort()
		return zero, nil, errStorageProtocol
	}
	response, err := parseStorageBootstrapResponse(frame.payload)
	if err != nil {
		closeStorageWorkerRights(rights)
		process.abort()
		return zero, nil, err
	}
	root := os.NewFile(uintptr(rights[0]), "public-files-bootstrap-root")
	if root == nil {
		closeStorageWorkerRights(rights)
		process.abort()
		return zero, nil, errStorageProtocol
	}
	if err := process.finishNormally(storageWorkerExitTimeout); err != nil {
		_ = root.Close()
		return zero, nil, err
	}
	return response, root, nil
}

func (m *isolatedStorageManager) list(
	ctx context.Context,
	relativePath string,
	maxEntries int,
) ([]Entry, error) {
	process, err := m.startRequestWorker(ctx, storageWorkerModeList)
	if err != nil {
		return nil, err
	}
	stopContext := context.AfterFunc(ctx, process.abort)
	defer stopContext()

	requestID := m.nextRequestID()
	payload, err := marshalStorageWorkerJSON(storageListRequest{
		Path:           relativePath,
		MaxEntries:     maxEntries,
		MountID:        m.mountID,
		FilesystemType: m.filesystemType,
	})
	if err != nil {
		process.abort()
		return nil, err
	}
	deadline := storageWorkerDeadline(ctx, storageWorkerOperationTimeout)
	if err := m.sendRootRequest(
		process,
		storageWorkerFrame{
			opcode:    storageWorkerListRequest,
			requestID: requestID,
			status:    storageWorkerStatusOK,
			payload:   payload,
		},
		ctx,
		deadline,
	); err != nil {
		process.abort()
		return nil, err
	}

	var encoded []byte
	for {
		frame, rights, err := receiveStorageWorkerFrame(
			process.conn,
			deadline,
		)
		if err != nil {
			process.abort()
			return nil, classifyStorageWorkerIPCError(ctx, err)
		}
		if len(rights) != 0 ||
			frame.opcode != storageWorkerListResponse ||
			frame.requestID != requestID {
			closeStorageWorkerRights(rights)
			process.abort()
			return nil, errStorageProtocol
		}
		if frame.status != storageWorkerStatusOK {
			if frame.flags != 0 || len(frame.payload) != 0 {
				process.abort()
				return nil, errStorageProtocol
			}
			if err := process.finishNormally(storageWorkerExitTimeout); err != nil {
				return nil, err
			}
			return nil, storageWorkerError(frame.status)
		}
		if len(frame.payload) == 0 ||
			len(encoded)+len(frame.payload) > storageWorkerMaxListPayload {
			process.abort()
			return nil, errStorageProtocol
		}
		encoded = append(encoded, frame.payload...)
		if frame.flags&storageWorkerFlagMore == 0 {
			break
		}
	}
	if err := process.finishNormally(storageWorkerExitTimeout); err != nil {
		return nil, err
	}
	entries, err := decodeStorageWorkerEntries(encoded, maxEntries)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (m *isolatedStorageManager) openRegular(
	ctx context.Context,
	relativePath string,
) (storageFile, fileInfo, error) {
	process, err := m.startRequestWorker(ctx, storageWorkerModeFile)
	if err != nil {
		return nil, nil, err
	}
	stopContext := context.AfterFunc(ctx, process.abort)
	requestID := m.nextRequestID()
	payload, err := marshalStorageWorkerJSON(storageOpenRequest{
		Path:           relativePath,
		MountID:        m.mountID,
		FilesystemType: m.filesystemType,
	})
	if err != nil {
		stopContext()
		process.abort()
		return nil, nil, err
	}
	deadline := storageWorkerDeadline(ctx, storageWorkerOperationTimeout)
	if err := m.sendRootRequest(
		process,
		storageWorkerFrame{
			opcode:    storageWorkerOpenRequest,
			requestID: requestID,
			status:    storageWorkerStatusOK,
			payload:   payload,
		},
		ctx,
		deadline,
	); err != nil {
		stopContext()
		process.abort()
		return nil, nil, err
	}
	frame, rights, err := receiveStorageWorkerFrame(
		process.conn,
		deadline,
	)
	if err != nil {
		stopContext()
		process.abort()
		return nil, nil, classifyStorageWorkerIPCError(ctx, err)
	}
	if len(rights) != 0 ||
		frame.opcode != storageWorkerOpenResponse ||
		frame.requestID != requestID ||
		frame.flags != 0 {
		closeStorageWorkerRights(rights)
		stopContext()
		process.abort()
		return nil, nil, errStorageProtocol
	}
	if frame.status != storageWorkerStatusOK {
		stopContext()
		if len(frame.payload) != 0 {
			process.abort()
			return nil, nil, errStorageProtocol
		}
		if err := process.finishNormally(storageWorkerExitTimeout); err != nil {
			return nil, nil, err
		}
		return nil, nil, storageWorkerError(frame.status)
	}
	response, err := parseStorageOpenResponse(frame.payload)
	if err != nil {
		stopContext()
		process.abort()
		return nil, nil, err
	}
	if storageWorkerSystemdTestEnabled {
		reportStorageWorkerSystemdTestEvent(
			systemdStorageWorkerTestOpenResponse,
		)
	}
	info := isolatedFileInfo{
		name:    path.Base(relativePath),
		size:    response.Size,
		modTime: time.Unix(0, response.ModTimeUnixNano),
	}
	file := &isolatedStorageFile{
		process:     process,
		context:     ctx,
		stopContext: stopContext,
		info:        info,
		nextID:      requestID + 1,
	}
	return file, info, nil
}

func (m *isolatedStorageManager) sendRootRequest(
	process *isolatedStorageProcess,
	frame storageWorkerFrame,
	ctx context.Context,
	deadline time.Time,
) error {
	m.mu.Lock()
	if m.closed || m.root == nil {
		m.mu.Unlock()
		return errStorageCapacity
	}
	rootFD := int(m.root.Fd())
	err := sendStorageWorkerFrame(
		process.conn,
		frame,
		[]int{rootFD},
		deadline,
	)
	m.mu.Unlock()
	if err != nil {
		return classifyStorageWorkerIPCError(ctx, err)
	}
	return nil
}

func (m *isolatedStorageManager) startRequestWorker(
	ctx context.Context,
	mode string,
) (*isolatedStorageProcess, error) {
	if err := ctx.Err(); err != nil {
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(
				systemdStorageWorkerTestContextRejected,
			)
		}
		return nil, errStorageTimeout
	}
	var rejectionEvent systemdStorageWorkerTestEvent
	m.mu.Lock()
	if m.closed || m.root == nil ||
		m.signalFailure.Load() ||
		m.quarantine.Load() >= m.quarantineAdmissionLimit {
		if storageWorkerSystemdTestEnabled {
			rejectionEvent = systemdStorageWorkerTestPreSlotRejected
			switch {
			case m.closed || m.root == nil:
				rejectionEvent = systemdStorageWorkerTestManagerUnavailable
			case m.signalFailure.Load():
				rejectionEvent = systemdStorageWorkerTestSignalFailure
			case m.quarantine.Load() >= m.quarantineAdmissionLimit:
				rejectionEvent = systemdStorageWorkerTestQuarantineLimit
			}
		}
		m.mu.Unlock()
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(rejectionEvent)
		}
		return nil, errStorageCapacity
	}
	select {
	case m.slots <- struct{}{}:
	default:
		m.mu.Unlock()
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(
				systemdStorageWorkerTestSlotsFull,
			)
		}
		return nil, errStorageCapacity
	}
	m.mu.Unlock()
	if storageWorkerSystemdTestEnabled {
		reportStorageWorkerSystemdTestEvent(
			systemdStorageWorkerTestSlotAcquired,
		)
	}

	process, err := startIsolatedStorageProcess(m, m.commandFactory, mode)
	if err != nil {
		<-m.slots
		if storageWorkerSystemdTestEnabled {
			if errors.Is(err, errStorageCapacity) {
				reportStorageWorkerSystemdTestEvent(
					systemdStorageWorkerTestStartCapacityFailure,
				)
			} else {
				reportStorageWorkerSystemdTestEvent(
					systemdStorageWorkerTestStartProtocolFailure,
				)
			}
		}
		return nil, err
	}
	m.mu.Lock()
	if m.closed || m.signalFailure.Load() {
		m.mu.Unlock()
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(
				systemdStorageWorkerTestPostStartRejected,
			)
		}
		go process.reap()
		process.abort()
		return nil, errStorageCapacity
	}
	m.workers[process] = struct{}{}
	m.mu.Unlock()
	if storageWorkerSystemdTestEnabled {
		reportStorageWorkerSystemdTestEvent(
			systemdStorageWorkerTestProcessRegistered,
		)
	}
	go process.reap()
	return process, nil
}

func startIsolatedStorageProcess(
	manager *isolatedStorageManager,
	commandFactory storageWorkerCommandFactory,
	mode string,
) (*isolatedStorageProcess, error) {
	connection, childSocket, err := newStorageWorkerSocketPair()
	if err != nil {
		return nil, classifyStorageWorkerStartError(err)
	}
	pidfd := -1
	command, err := commandFactory(mode, childSocket, &pidfd)
	if err != nil || command == nil {
		_ = connection.Close()
		_ = childSocket.Close()
		if err != nil {
			return nil, classifyStorageWorkerStartError(err)
		}
		return nil, errStorageProtocol
	}
	if err := command.Start(); err != nil {
		_ = connection.Close()
		_ = childSocket.Close()
		return nil, classifyStorageWorkerStartError(err)
	}
	if err := childSocket.Close(); err != nil || pidfd < 0 {
		_ = connection.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return nil, errStorageProtocol
	}
	process := &isolatedStorageProcess{
		manager: manager,
		command: command,
		conn:    connection,
		pidfd:   pidfd,
		done:    make(chan struct{}),
		signal:  signalStorageWorker,
	}
	if manager != nil && manager.signal != nil {
		process.signal = manager.signal
	}
	return process, nil
}

func classifyStorageWorkerStartError(err error) error {
	switch {
	case err == nil:
		return errStorageProtocol
	case errors.Is(err, errStorageCapacity),
		errors.Is(err, unix.EAGAIN),
		errors.Is(err, unix.EMFILE),
		errors.Is(err, unix.ENFILE),
		errors.Is(err, unix.ENOMEM),
		errors.Is(err, unix.ENOBUFS):
		return errStorageCapacity
	default:
		return errStorageProtocol
	}
}

func (p *isolatedStorageProcess) reap() {
	waitErr := p.command.Wait()

	p.mu.Lock()
	p.waitErr = waitErr
	p.finished = true
	wasQuarantined := p.quarantined
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
	p.mu.Unlock()
	if wasQuarantined && p.manager != nil {
		p.manager.quarantine.Add(-1)
	}
	p.release()
	close(p.done)
}

func (p *isolatedStorageProcess) abort() {
	p.abortOnce.Do(func() {
		_ = p.conn.Close()
		release := true
		p.mu.Lock()
		if !p.finished {
			if p.manager != nil {
				p.quarantined = true
				p.manager.quarantine.Add(1)
			}
			var signalErr error
			if p.pidfd < 0 || p.signal == nil {
				signalErr = errStorageProtocol
			} else {
				// Keep the process mutex held until pidfd_send_signal returns.
				// reap closes this descriptor under the same mutex, preventing
				// descriptor reuse from ever targeting an unrelated child.
				signalErr = p.signal(p.pidfd, unix.SIGKILL)
			}
			if signalErr != nil && !errors.Is(signalErr, unix.ESRCH) {
				// Do not free the active slot when the kernel did not accept
				// the pidfd signal. A PID-based fallback would be unsafe:
				// Wait can reap the child before it acquires p.mu, allowing
				// that numeric PID to be reused. Close admission until a
				// service restart and let reap release the slot if the child
				// exits independently.
				release = false
				if p.manager != nil {
					p.manager.signalFailure.Store(true)
				}
			}
		}
		p.mu.Unlock()
		if release {
			p.release()
		}
	})
}

func (p *isolatedStorageProcess) release() {
	p.releaseOnce.Do(func() {
		if p.manager == nil {
			return
		}
		p.manager.mu.Lock()
		delete(p.manager.workers, p)
		p.manager.mu.Unlock()
		<-p.manager.slots
	})
}

func (p *isolatedStorageProcess) finishNormally(timeout time.Duration) error {
	_ = p.conn.Close()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		if p.waitErr != nil {
			return errStorageProtocol
		}
		return nil
	case <-timer.C:
		p.abort()
		return errStorageTimeout
	}
}

func (m *isolatedStorageManager) close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	root := m.root
	m.root = nil
	workers := make([]*isolatedStorageProcess, 0, len(m.workers))
	for worker := range m.workers {
		workers = append(workers, worker)
	}
	m.mu.Unlock()

	for _, worker := range workers {
		worker.abort()
	}
	if root != nil {
		return root.Close()
	}
	return nil
}

func (m *isolatedStorageManager) nextRequestID() uint64 {
	for {
		id := m.requestID.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (f *isolatedStorageFile) Read(buffer []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if f.sourceErr != nil {
		return 0, f.sourceErr
	}
	if err := f.context.Err(); err != nil {
		f.fail(errStorageTimeout)
		return 0, f.sourceErr
	}
	if f.offset >= f.info.size {
		return 0, io.EOF
	}
	length := len(buffer)
	if length > storageWorkerMaxReadBytes {
		length = storageWorkerMaxReadBytes
	}
	if remaining := f.info.size - f.offset; int64(length) > remaining {
		length = int(remaining)
	}
	payload, err := marshalStorageReadRequest(storageReadRequest{
		Offset: f.offset,
		Length: uint32(length),
	})
	if err != nil {
		f.fail(err)
		return 0, f.sourceErr
	}
	requestID := f.nextID
	f.nextID++
	deadline := storageWorkerDeadline(f.context, storageWorkerReadTimeout)
	if err := sendStorageWorkerFrame(
		f.process.conn,
		storageWorkerFrame{
			opcode:    storageWorkerReadRequest,
			requestID: requestID,
			status:    storageWorkerStatusOK,
			payload:   payload,
		},
		nil,
		deadline,
	); err != nil {
		f.fail(classifyStorageWorkerIPCError(f.context, err))
		return 0, f.sourceErr
	}
	frame, rights, err := receiveStorageWorkerFrame(f.process.conn, deadline)
	if err != nil {
		f.fail(classifyStorageWorkerIPCError(f.context, err))
		return 0, f.sourceErr
	}
	if len(rights) != 0 ||
		frame.opcode != storageWorkerReadResponse ||
		frame.requestID != requestID ||
		frame.flags != 0 {
		closeStorageWorkerRights(rights)
		f.fail(errStorageProtocol)
		return 0, f.sourceErr
	}
	if frame.status == storageWorkerStatusEOF {
		if len(frame.payload) != 0 {
			f.fail(errStorageProtocol)
			return 0, f.sourceErr
		}
		// Read requests are never sent at or beyond the advertised size. An
		// early EOF therefore means the source changed or the worker violated
		// the protocol; abort the committed HTTP response as truncated.
		f.fail(io.ErrUnexpectedEOF)
		return 0, f.sourceErr
	}
	if frame.status != storageWorkerStatusOK ||
		len(frame.payload) == 0 ||
		len(frame.payload) > length {
		if frame.status == storageWorkerStatusInternal && len(frame.payload) == 0 {
			f.fail(storageWorkerError(frame.status))
		} else {
			f.fail(errStorageProtocol)
		}
		return 0, f.sourceErr
	}
	if storageWorkerSystemdTestEnabled {
		reportStorageWorkerSystemdTestEvent(
			systemdStorageWorkerTestReadResponse,
		)
	}
	count := copy(buffer, frame.payload)
	f.offset += int64(count)
	return count, nil
}

func (f *isolatedStorageFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if f.sourceErr != nil {
		return 0, f.sourceErr
	}
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = f.offset
	case io.SeekEnd:
		base = f.info.size
	default:
		return 0, errStorageProtocol
	}
	next := base + offset
	if next < 0 ||
		(offset > 0 && next < base) ||
		(offset < 0 && next > base) {
		return 0, errStorageProtocol
	}
	f.offset = next
	return next, nil
}

func (f *isolatedStorageFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.stopContext != nil {
		defer f.stopContext()
	}
	if f.sourceErr != nil || f.context.Err() != nil {
		if f.sourceErr == nil {
			f.sourceErr = errStorageTimeout
		}
		f.process.abort()
		return f.sourceErr
	}
	requestID := f.nextID
	f.nextID++
	deadline := storageWorkerDeadline(f.context, storageWorkerOperationTimeout)
	if err := sendStorageWorkerFrame(
		f.process.conn,
		storageWorkerFrame{
			opcode:    storageWorkerCloseRequest,
			requestID: requestID,
			status:    storageWorkerStatusOK,
		},
		nil,
		deadline,
	); err != nil {
		f.sourceErr = classifyStorageWorkerIPCError(f.context, err)
		f.process.abort()
		return f.sourceErr
	}
	frame, rights, err := receiveStorageWorkerFrame(f.process.conn, deadline)
	if err != nil ||
		len(rights) != 0 ||
		frame.opcode != storageWorkerCloseResponse ||
		frame.requestID != requestID ||
		frame.status != storageWorkerStatusOK ||
		frame.flags != 0 ||
		len(frame.payload) != 0 {
		closeStorageWorkerRights(rights)
		f.sourceErr = errStorageProtocol
		f.process.abort()
		return f.sourceErr
	}
	if err := f.process.finishNormally(storageWorkerExitTimeout); err != nil {
		f.sourceErr = err
		return err
	}
	return nil
}

func (f *isolatedStorageFile) sourceError() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sourceErr
}

func (f *isolatedStorageFile) fail(err error) {
	if err == nil {
		err = errStorageProtocol
	}
	f.sourceErr = err
	f.process.abort()
}

func storageWorkerDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func classifyStorageWorkerIPCError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return errStorageTimeout
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return errStorageTimeout
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return errStorageTimeout
	}
	return errStorageProtocol
}

var (
	_ storageBackend = (*isolatedStorageManager)(nil)
	_ storageFile    = (*isolatedStorageFile)(nil)
)
