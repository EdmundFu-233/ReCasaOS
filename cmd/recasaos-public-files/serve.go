package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/publicfiles"
	"golang.org/x/net/netutil"
)

const (
	requiredActivationName = "public-files"
	requiredPublicRoot     = "/srv/public"
	maxActiveConnections   = 96
	gracefulShutdownLimit  = 5 * time.Second
)

var version = "development"

type serveConfig struct {
	activationName string
	listenAddress  string
	root           string
	verifierFile   string
}

type publicFilePortal interface {
	http.Handler
	Close() error
}

type publicFileHTTPServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
	Close() error
}

type acceptReadyListener struct {
	net.Listener
	accepting chan struct{}
	once      sync.Once
}

func newAcceptReadyListener(listener net.Listener) *acceptReadyListener {
	return &acceptReadyListener{
		Listener:  listener,
		accepting: make(chan struct{}),
	}
}

func (l *acceptReadyListener) Accept() (net.Conn, error) {
	l.once.Do(func() {
		close(l.accepting)
	})
	return l.Listener.Accept()
}

type serveDependencies struct {
	validateRuntime func() error
	environ         func() []string
	activationFiles func(bool) []*os.File
	newPortal       func(publicfiles.Config) (publicFilePortal, error)
	newServer       func(http.Handler) publicFileHTTPServer
	notifyReady     func() error
	shutdownTimeout time.Duration
	connectionLimit int
}

func execute(ctx context.Context, args []string, stdout io.Writer, dependencies serveDependencies) error {
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}

	config, err := parseServeConfig(args)
	if err != nil {
		return err
	}
	return runServe(ctx, config, dependencies)
}

func parseServeConfig(args []string) (serveConfig, error) {
	var config serveConfig
	if len(args) == 0 || args[0] != "serve" {
		return config, errors.New("the only supported command is serve")
	}

	values := make(map[string]string, 4)
	for _, argument := range args[1:] {
		if !strings.HasPrefix(argument, "--") {
			return config, errors.New("positional command-line arguments are forbidden")
		}
		name, value, found := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		if !found || value == "" {
			return config, errors.New("every serve option must use --name=value syntax")
		}
		switch name {
		case "activation-name", "listen", "root", "verifier-file":
		default:
			return config, errors.New("unknown command-line option")
		}
		if _, duplicate := values[name]; duplicate {
			return config, fmt.Errorf("command-line option --%s may be specified only once", name)
		}
		values[name] = value
	}

	for _, required := range []string{"activation-name", "listen", "root", "verifier-file"} {
		if _, ok := values[required]; !ok {
			return config, fmt.Errorf("required command-line option --%s is missing", required)
		}
	}
	if len(values) != 4 {
		return config, errors.New("serve requires exactly four command-line options")
	}
	if values["activation-name"] != requiredActivationName {
		return config, fmt.Errorf("activation name must be exactly %q", requiredActivationName)
	}

	listenAddress, err := publicfiles.ValidateListenAddress(values["listen"])
	if err != nil {
		return config, fmt.Errorf("listen address is invalid: %w", err)
	}
	if listenAddress != publicfiles.DefaultListenAddress {
		return config, fmt.Errorf("listen address must be exactly %q", publicfiles.DefaultListenAddress)
	}
	root, err := validateAbsolutePath(values["root"], false)
	if err != nil {
		return config, fmt.Errorf("public file root is invalid: %w", err)
	}
	if root != requiredPublicRoot {
		return config, fmt.Errorf("public file root must be exactly %q", requiredPublicRoot)
	}
	verifierFile, err := validateAbsolutePath(values["verifier-file"], true)
	if err != nil {
		return config, fmt.Errorf("public file verifier path is invalid: %w", err)
	}

	return serveConfig{
		activationName: values["activation-name"],
		listenAddress:  listenAddress,
		root:           root,
		verifierFile:   verifierFile,
	}, nil
}

func validateAbsolutePath(value string, file bool) (string, error) {
	if value == "" || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) {
		return "", errors.New("an absolute path is required")
	}
	clean := filepath.Clean(value)
	if clean != value {
		return "", errors.New("the path must already be clean")
	}
	if clean == string(filepath.Separator) {
		if file {
			return "", errors.New("the filesystem root is not a file")
		}
		return "", errors.New("the filesystem root cannot be shared")
	}
	return clean, nil
}

func runServe(ctx context.Context, config serveConfig, dependencies serveDependencies) error {
	if dependencies.validateRuntime == nil || dependencies.environ == nil || dependencies.activationFiles == nil ||
		dependencies.newPortal == nil || dependencies.newServer == nil || dependencies.notifyReady == nil {
		return errors.New("public file service dependencies are incomplete")
	}
	if dependencies.shutdownTimeout <= 0 || dependencies.connectionLimit != maxActiveConnections {
		return errors.New("public file service limits are invalid")
	}
	if err := dependencies.validateRuntime(); err != nil {
		return fmt.Errorf("runtime isolation validation failed: %w", err)
	}
	if err := rejectLegacyConfigurationEnvironment(dependencies.environ()); err != nil {
		return err
	}

	listener, err := loadSystemdListener(
		dependencies.activationFiles,
		config.activationName,
		config.listenAddress,
	)
	if err != nil {
		return err
	}
	defer listener.Close()

	portal, err := dependencies.newPortal(publicfiles.Config{
		Root:         config.root,
		VerifierFile: config.verifierFile,
	})
	if err != nil {
		return fmt.Errorf("initialize public file portal: %w", err)
	}
	if portal == nil {
		return errors.New("initialize public file portal: portal is nil")
	}

	server := dependencies.newServer(portal)
	if server == nil {
		_ = portal.Close()
		return errors.New("initialize public file HTTP server: server is nil")
	}
	if ctx.Err() != nil {
		if closeErr := portal.Close(); closeErr != nil {
			return fmt.Errorf("close public file portal after cancellation before readiness: %w", closeErr)
		}
		return nil
	}
	limitedListener := netutil.LimitListener(listener, dependencies.connectionLimit)
	readyListener := newAcceptReadyListener(limitedListener)
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(readyListener)
	}()

	var (
		serveErr          error
		serveReturned     bool
		stoppedBeforeTerm bool
	)
	select {
	case serveErr = <-serveResult:
		serveReturned = true
		closeErr := portal.Close()
		if serveErr == nil {
			if closeErr != nil {
				return fmt.Errorf("public file HTTP server stopped before readiness without a result; portal cleanup failed: %w", closeErr)
			}
			return errors.New("public file HTTP server stopped before readiness without a result")
		}
		if closeErr != nil {
			return fmt.Errorf("public file HTTP server failed before readiness: %w; portal cleanup failed: %v", serveErr, closeErr)
		}
		return fmt.Errorf("public file HTTP server failed before readiness: %w", serveErr)
	case <-readyListener.accepting:
	case <-ctx.Done():
		if cleanupErr := stopUnreadyServer(server, portal, serveResult, dependencies.shutdownTimeout); cleanupErr != nil {
			return fmt.Errorf("stop public file service after cancellation before readiness: %w", cleanupErr)
		}
		return nil
	}
	select {
	case serveErr = <-serveResult:
		serveReturned = true
		closeErr := portal.Close()
		if serveErr == nil {
			if closeErr != nil {
				return fmt.Errorf("public file HTTP server stopped before readiness notification without a result; portal cleanup failed: %w", closeErr)
			}
			return errors.New("public file HTTP server stopped before readiness notification without a result")
		}
		if closeErr != nil {
			return fmt.Errorf("public file HTTP server stopped before readiness notification: %w; portal cleanup failed: %v", serveErr, closeErr)
		}
		return fmt.Errorf("public file HTTP server stopped before readiness notification: %w", serveErr)
	default:
	}
	if ctx.Err() != nil {
		if cleanupErr := stopUnreadyServer(server, portal, serveResult, dependencies.shutdownTimeout); cleanupErr != nil {
			return fmt.Errorf("stop public file service after cancellation before readiness notification: %w", cleanupErr)
		}
		return nil
	}
	if err := dependencies.notifyReady(); err != nil {
		cleanupErr := stopUnreadyServer(server, portal, serveResult, dependencies.shutdownTimeout)
		if cleanupErr != nil {
			return fmt.Errorf("notify service readiness: %w; cleanup failed: %v", err, cleanupErr)
		}
		return fmt.Errorf("notify service readiness: %w", err)
	}
	select {
	case serveErr = <-serveResult:
		serveReturned = true
		stoppedBeforeTerm = ctx.Err() == nil
	case <-ctx.Done():
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), dependencies.shutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		cancelShutdown()
		closeErr := server.Close()
		if closeErr != nil {
			return fmt.Errorf("graceful HTTP shutdown failed: %w; forced close also failed: %v", shutdownErr, closeErr)
		}
		return fmt.Errorf("graceful HTTP shutdown failed and the server was forcibly closed: %w", shutdownErr)
	}
	if !serveReturned {
		select {
		case serveErr = <-serveResult:
			serveReturned = true
		case <-shutdownCtx.Done():
			cancelShutdown()
			closeErr := server.Close()
			if closeErr != nil {
				return fmt.Errorf("HTTP server did not stop after graceful shutdown: %w; forced close also failed: %v", shutdownCtx.Err(), closeErr)
			}
			return fmt.Errorf("HTTP server did not stop after graceful shutdown and was forcibly closed: %w", shutdownCtx.Err())
		}
	}
	cancelShutdown()

	if closeErr := portal.Close(); closeErr != nil {
		return fmt.Errorf("close public file portal after clean HTTP shutdown: %w", closeErr)
	}
	if !serveReturned || serveErr == nil {
		return errors.New("public file HTTP server stopped without a result")
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("public file HTTP server failed: %w", serveErr)
	}
	if stoppedBeforeTerm {
		return fmt.Errorf("public file HTTP server stopped before termination was requested: %w", serveErr)
	}
	return nil
}

func stopUnreadyServer(
	server publicFileHTTPServer,
	portal publicFilePortal,
	serveResult <-chan error,
	timeout time.Duration,
) error {
	closeErr := server.Close()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var serveErr error
	select {
	case serveErr = <-serveResult:
	case <-timer.C:
		return errors.Join(closeErr, errors.New("HTTP server did not stop after readiness failure"))
	}
	portalErr := portal.Close()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = fmt.Errorf("HTTP server cleanup result: %w", serveErr)
	} else {
		serveErr = nil
	}
	return errors.Join(closeErr, serveErr, portalErr)
}

func rejectLegacyConfigurationEnvironment(environment []string) error {
	const legacyPrefix = "RECASAOS_PUBLIC_FILE_"
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(name, legacyPrefix) && value != "" {
			return errors.New("legacy public file environment configuration must be unset")
		}
	}
	return nil
}

func loadSystemdListener(
	activationFiles func(bool) []*os.File,
	expectedName string,
	expectedAddress string,
) (net.Listener, error) {
	files := activationFiles(true)
	if len(files) != 1 {
		closeActivationFiles(files)
		return nil, errors.New("exactly one systemd socket activation descriptor is required")
	}
	file := files[0]
	if file == nil {
		return nil, errors.New("systemd supplied a nil socket activation descriptor")
	}
	if file.Name() != expectedName {
		_ = file.Close()
		return nil, errors.New("systemd socket activation descriptor name does not match")
	}

	listener, listenerErr := net.FileListener(file)
	closeErr := file.Close()
	if listenerErr != nil {
		if listener != nil {
			_ = listener.Close()
		}
		return nil, errors.New("systemd socket activation descriptor is not a listener")
	}
	if closeErr != nil {
		_ = listener.Close()
		return nil, errors.New("systemd socket activation descriptor could not be released")
	}
	if _, ok := listener.(*net.TCPListener); !ok {
		_ = listener.Close()
		return nil, errors.New("systemd socket activation listener must be TCP")
	}

	actualAddress, err := publicfiles.ValidateListenAddress(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("systemd socket activation listener address is unsafe: %w", err)
	}
	expectedAddress, err = publicfiles.ValidateListenAddress(expectedAddress)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("configured listener address is unsafe: %w", err)
	}
	if actualAddress != expectedAddress {
		_ = listener.Close()
		return nil, errors.New("systemd socket activation listener address does not match the configured address")
	}
	return listener, nil
}

func closeActivationFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
