package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/publicfiles"
)

const validVerifierPath = "/run/credentials/recasaos-public-files.service/recasaos-public-file-verifier"

func TestParseServeConfig(t *testing.T) {
	t.Parallel()

	args := []string{
		"serve",
		"--activation-name=public-files",
		"--listen=127.0.0.1:39777",
		"--root=/srv/public",
		"--verifier-file=" + validVerifierPath,
	}
	config, err := parseServeConfig(args)
	if err != nil {
		t.Fatalf("parseServeConfig() error = %v", err)
	}
	if config.activationName != requiredActivationName {
		t.Fatalf("activationName = %q, want %q", config.activationName, requiredActivationName)
	}
	if config.listenAddress != publicfiles.DefaultListenAddress {
		t.Fatalf("listenAddress = %q, want %q", config.listenAddress, publicfiles.DefaultListenAddress)
	}
	if config.root != "/srv/public" {
		t.Fatalf("root = %q, want /srv/public", config.root)
	}
	if config.verifierFile != validVerifierPath {
		t.Fatalf("verifierFile = %q, want %q", config.verifierFile, validVerifierPath)
	}
}

func TestParseServeConfigAllowsOptionReordering(t *testing.T) {
	t.Parallel()

	_, err := parseServeConfig([]string{
		"serve",
		"--verifier-file=" + validVerifierPath,
		"--root=/srv/public",
		"--listen=127.0.0.1:39777",
		"--activation-name=public-files",
	})
	if err != nil {
		t.Fatalf("parseServeConfig() error = %v", err)
	}
}

func TestParseServeConfigRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	t.Setenv("RECASAOS_PUBLIC_FILE_ENABLED", "1")
	t.Setenv("RECASAOS_PUBLIC_FILE_LISTEN", "127.0.0.1:39777")
	t.Setenv("RECASAOS_PUBLIC_FILE_ROOT", "/environment/root")
	t.Setenv("RECASAOS_PUBLIC_FILE_VERIFIER_FILE", "/environment/verifier")

	valid := []string{
		"serve",
		"--activation-name=public-files",
		"--listen=127.0.0.1:39777",
		"--root=/srv/public",
		"--verifier-file=" + validVerifierPath,
	}
	tests := map[string][]string{
		"empty":                    nil,
		"version with serve":       append(append([]string{}, valid...), "--version"),
		"unknown command":          append([]string{"start"}, valid[1:]...),
		"missing activation name":  append([]string{"serve"}, valid[2:]...),
		"missing listen":           append(append([]string{}, valid[:2]...), valid[3:]...),
		"missing root":             append(append([]string{}, valid[:3]...), valid[4:]...),
		"missing verifier":         append([]string{}, valid[:4]...),
		"unknown option":           append(append([]string{}, valid...), "--other=value"),
		"duplicate option":         append(append([]string{}, valid...), "--root=/srv/other"),
		"positional":               append(append([]string{}, valid...), "extra"),
		"separate option value":    []string{"serve", "--activation-name", "public-files"},
		"empty option value":       []string{"serve", "--activation-name="},
		"wrong activation name":    replaceArgument(valid, 1, "--activation-name=other"),
		"hostname listen":          replaceArgument(valid, 2, "--listen=localhost:39777"),
		"wildcard listen":          replaceArgument(valid, 2, "--listen=0.0.0.0:39777"),
		"alternate loopback":       replaceArgument(valid, 2, "--listen=127.0.0.1:39778"),
		"IPv6 loopback":            replaceArgument(valid, 2, "--listen=[::1]:39777"),
		"zero port":                replaceArgument(valid, 2, "--listen=127.0.0.1:0"),
		"noncanonical port":        replaceArgument(valid, 2, "--listen=127.0.0.1:039777"),
		"relative root":            replaceArgument(valid, 3, "--root=srv/public"),
		"alternate root":           replaceArgument(valid, 3, "--root=/srv/other"),
		"unclean root":             replaceArgument(valid, 3, "--root=/srv/../public"),
		"filesystem root":          replaceArgument(valid, 3, "--root=/"),
		"relative verifier":        replaceArgument(valid, 4, "--verifier-file=run/verifier"),
		"unclean verifier":         replaceArgument(valid, 4, "--verifier-file=/run/../verifier"),
		"filesystem root verifier": replaceArgument(valid, 4, "--verifier-file=/"),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseServeConfig(args); err == nil {
				t.Fatal("parseServeConfig() error = nil, want rejection")
			}
		})
	}
}

func TestExecuteVersionSkipsRuntimeValidation(t *testing.T) {
	t.Parallel()

	var runtimeCalls atomic.Int32
	var output bytes.Buffer
	err := execute(context.Background(), []string{"--version"}, &output, serveDependencies{
		validateRuntime: func() error {
			runtimeCalls.Add(1)
			return errors.New("must not be called")
		},
	})
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if runtimeCalls.Load() != 0 {
		t.Fatalf("runtime validation calls = %d, want 0", runtimeCalls.Load())
	}
	if output.String() != version+"\n" {
		t.Fatalf("version output = %q, want %q", output.String(), version+"\n")
	}
}

func TestLoadSystemdListenerAcceptsExactNamedTCPDescriptor(t *testing.T) {
	t.Parallel()

	file, address := newActivatedTCPFile(t, requiredActivationName)
	selected, err := loadSystemdListener(
		func(unsetEnvironment bool) []*os.File {
			if !unsetEnvironment {
				t.Error("activation environment was not requested to be unset")
			}
			return []*os.File{file}
		},
		requiredActivationName,
		address,
	)
	if err != nil {
		t.Fatalf("loadSystemdListener() error = %v", err)
	}
	if err := selected.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLoadSystemdListenerRejectsInvalidActivation(t *testing.T) {
	t.Parallel()

	t.Run("none", func(t *testing.T) {
		if _, err := loadSystemdListener(
			func(bool) []*os.File { return nil },
			requiredActivationName,
			publicfiles.DefaultListenAddress,
		); err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
	})
	t.Run("extra", func(t *testing.T) {
		first := newNamedPipeFile(t, requiredActivationName)
		second := newNamedPipeFile(t, "other")
		_, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{first, second} },
			requiredActivationName,
			publicfiles.DefaultListenAddress,
		)
		if err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
		if first.Close() == nil || second.Close() == nil {
			t.Fatal("rejected activation descriptors were not closed")
		}
	})
	t.Run("wrong name", func(t *testing.T) {
		file, address := newActivatedTCPFile(t, "other")
		if _, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{file} },
			requiredActivationName,
			address,
		); err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
		if file.Close() == nil {
			t.Fatal("rejected activation descriptor was not closed")
		}
	})
	t.Run("non listener", func(t *testing.T) {
		file := newNamedPipeFile(t, requiredActivationName)
		if _, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{file} },
			requiredActivationName,
			publicfiles.DefaultListenAddress,
		); err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
		if file.Close() == nil {
			t.Fatal("rejected activation descriptor was not closed")
		}
	})
	t.Run("non TCP listener", func(t *testing.T) {
		file := newActivatedUnixFile(t, requiredActivationName)
		if _, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{file} },
			requiredActivationName,
			publicfiles.DefaultListenAddress,
		); err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
		if file.Close() == nil {
			t.Fatal("rejected activation descriptor was not closed")
		}
	})
	t.Run("wrong address", func(t *testing.T) {
		file, _ := newActivatedTCPFile(t, requiredActivationName)
		listener, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{file} },
			requiredActivationName,
			"127.0.0.1:1",
		)
		if err == nil {
			listener.Close()
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
	})
	t.Run("unnamed descriptor", func(t *testing.T) {
		file, address := newActivatedTCPFile(t, "LISTEN_FD_3")
		if _, err := loadSystemdListener(
			func(bool) []*os.File { return []*os.File{file} },
			requiredActivationName,
			address,
		); err == nil {
			t.Fatal("loadSystemdListener() error = nil, want rejection")
		}
	})
}

func TestRunServeValidatesRuntimeBeforeLoadingActivation(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("unsafe runtime")
	var loaderCalls atomic.Int32
	err := runServe(context.Background(), serveConfig{}, serveDependencies{
		validateRuntime: func() error {
			return sentinel
		},
		environ: func() []string {
			t.Fatal("environment was inspected before runtime validation succeeded")
			return nil
		},
		activationFiles: func(bool) []*os.File {
			loaderCalls.Add(1)
			return nil
		},
		newPortal: func(publicfiles.Config) (publicFilePortal, error) {
			t.Fatal("portal factory was called")
			return nil, nil
		},
		newServer: func(http.Handler) publicFileHTTPServer {
			t.Fatal("server factory was called")
			return nil
		},
		shutdownTimeout: time.Second,
		connectionLimit: maxActiveConnections,
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runServe() error = %v, want sentinel", err)
	}
	if loaderCalls.Load() != 0 {
		t.Fatalf("activation loader calls = %d, want 0", loaderCalls.Load())
	}
}

func TestRunServeRejectsLegacyConfigurationEnvironmentWithoutExposingValue(t *testing.T) {
	t.Parallel()

	const secretValue = "must-not-appear-in-errors"
	var loaderCalls atomic.Int32
	err := runServe(context.Background(), serveConfig{}, serveDependencies{
		validateRuntime: func() error {
			return nil
		},
		environ: func() []string {
			return []string{"RECASAOS_PUBLIC_FILE_TOKEN_FILE=" + secretValue}
		},
		activationFiles: func(bool) []*os.File {
			loaderCalls.Add(1)
			return nil
		},
		newPortal: func(publicfiles.Config) (publicFilePortal, error) {
			t.Fatal("portal factory was called")
			return nil, nil
		},
		newServer: func(http.Handler) publicFileHTTPServer {
			t.Fatal("server factory was called")
			return nil
		},
		shutdownTimeout: time.Second,
		connectionLimit: maxActiveConnections,
	})
	if err == nil {
		t.Fatal("runServe() error = nil, want legacy environment rejection")
	}
	if !strings.Contains(err.Error(), "legacy public file environment configuration") {
		t.Fatalf("runServe() error = %q, want generic legacy-setting error", err)
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("runServe() error exposed environment value: %q", err)
	}
	if loaderCalls.Load() != 0 {
		t.Fatalf("activation loader calls = %d, want 0", loaderCalls.Load())
	}
}

func TestRejectLegacyConfigurationEnvironmentRejectsEveryLegacyName(t *testing.T) {
	t.Parallel()

	for _, rejectedName := range []string{
		"RECASAOS_PUBLIC_FILE_ENABLED",
		"RECASAOS_PUBLIC_FILE_ROOT",
		"RECASAOS_PUBLIC_FILE_VERIFIER_FILE",
		"RECASAOS_PUBLIC_FILE_TOKEN_FILE",
		"RECASAOS_PUBLIC_FILE_LISTEN",
		"RECASAOS_PUBLIC_FILE_FUTURE_SETTING",
	} {
		rejectedName := rejectedName
		t.Run(rejectedName, func(t *testing.T) {
			err := rejectLegacyConfigurationEnvironment([]string{
				"UNRELATED=value",
				rejectedName + "=sensitive-value",
			})
			if err == nil {
				t.Fatal("rejectLegacyConfigurationEnvironment() error = nil, want rejection")
			}
			if strings.Contains(err.Error(), rejectedName) {
				t.Fatalf("error exposed environment name: %q", err)
			}
			if strings.Contains(err.Error(), "sensitive-value") {
				t.Fatalf("error exposed environment value: %q", err)
			}
		})
	}
}

func TestRejectLegacyConfigurationEnvironmentAllowsUnsetAndEmptyNames(t *testing.T) {
	t.Parallel()

	err := rejectLegacyConfigurationEnvironment([]string{
		"RECASAOS_PUBLIC_FILE_ENABLED=",
		"RECASAOS_PUBLIC_FILE_UNKNOWN=",
		"UNRELATED=value",
	})
	if err != nil {
		t.Fatalf("rejectLegacyConfigurationEnvironment() error = %v", err)
	}
}

func TestRunServeGracefulCancellationClosesPortal(t *testing.T) {
	t.Parallel()

	activationFile, address := newActivatedTCPFile(t, requiredActivationName)
	config := testServeConfig(address)
	portal := &fakePortal{}
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var shutdownCalls atomic.Int32
	server := &fakeHTTPServer{
		serve: func(listener net.Listener) error {
			defer listener.Close()
			close(started)
			<-release
			return http.ErrServerClosed
		},
		shutdown: func(context.Context) error {
			shutdownCalls.Add(1)
			releaseOnce.Do(func() { close(release) })
			return nil
		},
		close: func() error {
			t.Error("forced Close() called during graceful shutdown")
			releaseOnce.Do(func() { close(release) })
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runServe(ctx, config, lifecycleDependencies(activationFile, portal, server, time.Second))
	}()
	<-started
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("runServe() error = %v", err)
	}
	if shutdownCalls.Load() != 1 {
		t.Fatalf("Shutdown() calls = %d, want 1", shutdownCalls.Load())
	}
	if portal.closeCalls.Load() != 1 {
		t.Fatalf("portal Close() calls = %d, want 1", portal.closeCalls.Load())
	}
}

func TestRunServeForcesCloseWithoutClosingPortalAfterShutdownTimeout(t *testing.T) {
	t.Parallel()

	activationFile, address := newActivatedTCPFile(t, requiredActivationName)
	config := testServeConfig(address)
	portal := &fakePortal{}
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	var forceCloseCalls atomic.Int32
	server := &fakeHTTPServer{
		serve: func(listener net.Listener) error {
			defer listener.Close()
			close(started)
			<-release
			return http.ErrServerClosed
		},
		shutdown: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		close: func() error {
			forceCloseCalls.Add(1)
			releaseOnce.Do(func() { close(release) })
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runServe(ctx, config, lifecycleDependencies(activationFile, portal, server, 20*time.Millisecond))
	}()
	<-started
	cancel()
	if err := <-result; err == nil {
		t.Fatal("runServe() error = nil, want forced-shutdown error")
	}
	if forceCloseCalls.Load() != 1 {
		t.Fatalf("forced Close() calls = %d, want 1", forceCloseCalls.Load())
	}
	if portal.closeCalls.Load() != 0 {
		t.Fatalf("portal Close() calls = %d, want 0 after unclean shutdown", portal.closeCalls.Load())
	}
}

func TestRunServeReturnsServeErrorAfterCleanQuiescence(t *testing.T) {
	t.Parallel()

	activationFile, address := newActivatedTCPFile(t, requiredActivationName)
	config := testServeConfig(address)
	portal := &fakePortal{}
	sentinel := errors.New("accept failed")
	server := &fakeHTTPServer{
		serve: func(listener net.Listener) error {
			_ = listener.Close()
			return sentinel
		},
		shutdown: func(context.Context) error {
			return nil
		},
		close: func() error {
			t.Error("forced Close() called after clean quiescence")
			return nil
		},
	}
	err := runServe(context.Background(), config, lifecycleDependencies(activationFile, portal, server, time.Second))
	if !errors.Is(err, sentinel) {
		t.Fatalf("runServe() error = %v, want sentinel", err)
	}
	if portal.closeCalls.Load() != 1 {
		t.Fatalf("portal Close() calls = %d, want 1", portal.closeCalls.Load())
	}
}

func TestRunServeClosesActivatedListenerWhenPortalInitializationFails(t *testing.T) {
	t.Parallel()

	activationFile, address := newActivatedTCPFile(t, requiredActivationName)
	config := testServeConfig(address)
	sentinel := errors.New("portal failed")
	dependencies := lifecycleDependencies(activationFile, nil, nil, time.Second)
	dependencies.newPortal = func(publicfiles.Config) (publicFilePortal, error) {
		return nil, sentinel
	}
	dependencies.newServer = func(http.Handler) publicFileHTTPServer {
		t.Fatal("server factory was called")
		return nil
	}
	err := runServe(context.Background(), config, dependencies)
	if !errors.Is(err, sentinel) {
		t.Fatalf("runServe() error = %v, want sentinel", err)
	}
	connection, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
	if dialErr == nil {
		connection.Close()
		t.Fatal("activated listener remained open after portal initialization failure")
	}
}

func replaceArgument(arguments []string, index int, replacement string) []string {
	result := append([]string{}, arguments...)
	result[index] = replacement
	return result
}

func newActivatedTCPFile(t *testing.T, name string) (*os.File, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	address := listener.Addr().String()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		t.Fatalf("listener type = %T, want *net.TCPListener", listener)
	}
	file, err := tcpListener.File()
	if err != nil {
		tcpListener.Close()
		t.Fatalf("TCPListener.File() error = %v", err)
	}
	if err := tcpListener.Close(); err != nil {
		file.Close()
		t.Fatalf("TCPListener.Close() error = %v", err)
	}
	return renameFile(t, file, name), address
}

func newNamedPipeFile(t *testing.T, name string) *os.File {
	t.Helper()
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	if err := writeFile.Close(); err != nil {
		readFile.Close()
		t.Fatalf("pipe writer Close() error = %v", err)
	}
	return renameFile(t, readFile, name)
}

func newActivatedUnixFile(t *testing.T, name string) *os.File {
	t.Helper()
	socketDirectory, err := os.MkdirTemp("/tmp", "recasaos-public-files-")
	if err != nil {
		t.Fatalf("os.MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketDirectory); err != nil {
			t.Errorf("remove Unix socket test directory: %v", err)
		}
	})
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: filepath.Join(socketDirectory, "activation.sock"),
		Net:  "unix",
	})
	if err != nil {
		t.Fatalf("net.ListenUnix() error = %v", err)
	}
	file, err := listener.File()
	if err != nil {
		listener.Close()
		t.Fatalf("UnixListener.File() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		file.Close()
		t.Fatalf("UnixListener.Close() error = %v", err)
	}
	return renameFile(t, file, name)
}

func renameFile(t *testing.T, file *os.File, name string) *os.File {
	t.Helper()
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		file.Close()
		t.Fatalf("dup activation descriptor: %v", err)
	}
	if err := file.Close(); err != nil {
		syscall.Close(descriptor)
		t.Fatalf("source activation descriptor Close() error = %v", err)
	}
	return os.NewFile(uintptr(descriptor), name)
}

func testServeConfig(address string) serveConfig {
	return serveConfig{
		activationName: requiredActivationName,
		listenAddress:  address,
		root:           "/srv/public",
		verifierFile:   validVerifierPath,
	}
}

func lifecycleDependencies(
	activationFile *os.File,
	portal publicFilePortal,
	server publicFileHTTPServer,
	timeout time.Duration,
) serveDependencies {
	return serveDependencies{
		validateRuntime: func() error {
			return nil
		},
		environ: func() []string {
			return nil
		},
		activationFiles: func(bool) []*os.File {
			return []*os.File{activationFile}
		},
		newPortal: func(publicfiles.Config) (publicFilePortal, error) {
			return portal, nil
		},
		newServer: func(http.Handler) publicFileHTTPServer {
			return server
		},
		shutdownTimeout: timeout,
		connectionLimit: maxActiveConnections,
	}
}

type fakePortal struct {
	closeCalls atomic.Int32
}

func (*fakePortal) ServeHTTP(http.ResponseWriter, *http.Request) {}

func (p *fakePortal) Close() error {
	p.closeCalls.Add(1)
	return nil
}

type fakeHTTPServer struct {
	serve    func(net.Listener) error
	shutdown func(context.Context) error
	close    func() error
}

func (s *fakeHTTPServer) Serve(listener net.Listener) error {
	return s.serve(listener)
}

func (s *fakeHTTPServer) Shutdown(ctx context.Context) error {
	return s.shutdown(ctx)
}

func (s *fakeHTTPServer) Close() error {
	return s.close()
}
