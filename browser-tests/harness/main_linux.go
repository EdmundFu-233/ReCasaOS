//go:build linux && recasaos_publicfiles_browser_test

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/publicfiles"
	"golang.org/x/sys/unix"
)

const (
	harnessEnvironment       = "RECASAOS_BROWSER_TEST"
	maximumBootstrapBytes    = 4 << 10
	maximumTLSMaterialBytes  = 1 << 20
	streamFixtureSize        = int64(40 << 20)
	streamWriteChunkSize     = 32 << 10
	streamWriteDelay         = 2 * time.Millisecond
	gracefulShutdownDeadline = 5 * time.Second

	verifierPrefix = "recasaos-public-verifier-v1:sha256:"

	bearerPrefix      = "rc1_"
	bearerRandomBytes = 32
	bearerEncodedLen  = (bearerRandomBytes*8 + 5) / 6
	bearerLength      = len(bearerPrefix) + bearerEncodedLen
	bearerMinDistinct = 16
)

var strictBearerEncoding = base64.RawURLEncoding.Strict()

type bootstrapConfig struct {
	VerifierSHA256  string `json:"verifier_sha256"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

type fixtureMetadata struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type readyMessage struct {
	Origin        string                     `json:"origin"`
	ControlOrigin string                     `json:"control_origin"`
	Fixtures      map[string]fixtureMetadata `json:"fixtures"`
}

type requestSnapshot struct {
	ActiveFileRequests       int64 `json:"active_file_requests"`
	CompletedFileRequests    int64 `json:"completed_file_requests"`
	CanceledFileRequests     int64 `json:"canceled_file_requests"`
	AuthorizedListRequests   int64 `json:"authorized_list_requests"`
	AuthorizedFileRequests   int64 `json:"authorized_file_requests"`
	AuthorizedRangeRequests  int64 `json:"authorized_range_file_requests"`
	PartialFileResponses     int64 `json:"partial_file_responses"`
	AuthorizationOnOtherPath int64 `json:"authorization_on_other_path"`
	CredentialQueryRequests  int64 `json:"credential_query_requests"`
}

type requestCounters struct {
	activeFileRequests       atomic.Int64
	completedFileRequests    atomic.Int64
	canceledFileRequests     atomic.Int64
	authorizedListRequests   atomic.Int64
	authorizedFileRequests   atomic.Int64
	authorizedRangeRequests  atomic.Int64
	partialFileResponses     atomic.Int64
	authorizationOnOtherPath atomic.Int64
	credentialQueryRequests  atomic.Int64
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

func (c *requestCounters) snapshot() requestSnapshot {
	return requestSnapshot{
		ActiveFileRequests:       c.activeFileRequests.Load(),
		CompletedFileRequests:    c.completedFileRequests.Load(),
		CanceledFileRequests:     c.canceledFileRequests.Load(),
		AuthorizedListRequests:   c.authorizedListRequests.Load(),
		AuthorizedFileRequests:   c.authorizedFileRequests.Load(),
		AuthorizedRangeRequests:  c.authorizedRangeRequests.Load(),
		PartialFileResponses:     c.partialFileResponses.Load(),
		AuthorizationOnOtherPath: c.authorizationOnOtherPath.Load(),
		CredentialQueryRequests:  c.credentialQueryRequests.Load(),
	}
}

type instrumentedPortal struct {
	next           http.Handler
	verifierDigest [sha256.Size]byte
	counters       *requestCounters
}

func (h *instrumentedPortal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requestHasCredentialQuery(r.URL.RawQuery) {
		h.counters.credentialQueryRequests.Add(1)
	}

	isList := r.URL.Path == publicfiles.BasePath+"/api/list"
	isFile := r.URL.Path == publicfiles.BasePath+"/api/file"
	if !isList && !isFile && len(r.Header.Values("Authorization")) != 0 {
		h.counters.authorizationOnOtherPath.Add(1)
	}

	authorized := (isList || isFile) && requestAuthorized(r, h.verifierDigest)
	if isList && authorized {
		h.counters.authorizedListRequests.Add(1)
	}
	if !isFile || !authorized {
		h.next.ServeHTTP(w, r)
		return
	}

	h.counters.authorizedFileRequests.Add(1)
	if ranges := r.Header.Values("Range"); len(ranges) == 1 && strings.TrimSpace(ranges[0]) != "" {
		h.counters.authorizedRangeRequests.Add(1)
	}
	h.counters.activeFileRequests.Add(1)
	trackedWriter := &cancelTrackingWriter{ResponseWriter: w}
	defer func() {
		h.counters.activeFileRequests.Add(-1)
		if trackedWriter.statusCode.Load() == http.StatusPartialContent {
			h.counters.partialFileResponses.Add(1)
		}
		if recovered := recover(); recovered != nil {
			h.counters.canceledFileRequests.Add(1)
			panic(recovered)
		}
		if r.Context().Err() != nil || trackedWriter.failed.Load() {
			h.counters.canceledFileRequests.Add(1)
			return
		}
		h.counters.completedFileRequests.Add(1)
	}()

	responseWriter := http.ResponseWriter(trackedWriter)
	if r.Method == http.MethodGet && r.URL.Query().Get("path") == "stream.bin" {
		responseWriter = &throttledResponseWriter{ResponseWriter: trackedWriter}
	}
	h.next.ServeHTTP(responseWriter, r)
}

type cancelTrackingWriter struct {
	http.ResponseWriter
	failed     atomic.Bool
	statusCode atomic.Int64
}

func (w *cancelTrackingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *cancelTrackingWriter) WriteHeader(statusCode int) {
	if statusCode >= 100 && statusCode < 200 {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if w.statusCode.CompareAndSwap(0, int64(statusCode)) {
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *cancelTrackingWriter) Write(payload []byte) (int, error) {
	w.statusCode.CompareAndSwap(0, http.StatusOK)
	written, err := w.ResponseWriter.Write(payload)
	if err != nil || written != len(payload) {
		w.failed.Store(true)
	}
	return written, err
}

type throttledResponseWriter struct {
	http.ResponseWriter
}

func (w *throttledResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *throttledResponseWriter) Write(payload []byte) (int, error) {
	total := 0
	for len(payload) != 0 {
		chunkSize := len(payload)
		if chunkSize > streamWriteChunkSize {
			chunkSize = streamWriteChunkSize
		}
		time.Sleep(streamWriteDelay)
		written, err := w.ResponseWriter.Write(payload[:chunkSize])
		total += written
		payload = payload[written:]
		if err != nil {
			return total, err
		}
		if written != chunkSize {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "ReCasaOS browser harness:", err)
		os.Exit(1)
	}
}

func run() (returnErr error) {
	if os.Geteuid() == 0 {
		return errors.New("refusing to run as root")
	}
	if len(os.Args) != 1 {
		return errors.New("command-line arguments are forbidden")
	}
	if os.Getenv(harnessEnvironment) != "1" {
		return fmt.Errorf("%s must be exactly 1", harnessEnvironment)
	}
	runnerTemp := os.Getenv("RUNNER_TEMP")
	if runnerTemp == "" || !filepath.IsAbs(runnerTemp) {
		return errors.New("RUNNER_TEMP must be an absolute path")
	}
	runnerTemp = filepath.Clean(runnerTemp)
	if runnerTemp == string(filepath.Separator) {
		return errors.New("RUNNER_TEMP cannot be the filesystem root")
	}

	signalContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	config, verifierDigest, err := readBootstrapConfig(os.Stdin)
	if err != nil {
		return err
	}
	certificatePEM, privateKeyPEM, err := readTLSMaterial(runnerTemp, config)
	if err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	zeroBytes(certificatePEM)
	zeroBytes(privateKeyPEM)
	if err != nil {
		return errors.New("TLS certificate and private key are invalid")
	}

	harnessDirectory, err := os.MkdirTemp(runnerTemp, "recasaos-browser-harness-")
	if err != nil {
		return errors.New("cannot create the browser harness directory")
	}
	defer func() {
		returnErr = errors.Join(returnErr, os.RemoveAll(harnessDirectory))
	}()
	if err := os.Chmod(harnessDirectory, 0o700); err != nil {
		return errors.New("cannot restrict the browser harness directory")
	}
	if err := validateOwnedDirectory(harnessDirectory, 0o700); err != nil {
		return err
	}

	shareDirectory := filepath.Join(harnessDirectory, "share")
	if err := os.Mkdir(shareDirectory, 0o700); err != nil {
		return errors.New("cannot create the browser fixture directory")
	}
	if err := validateOwnedDirectory(shareDirectory, 0o700); err != nil {
		return err
	}

	verifierFile := filepath.Join(harnessDirectory, "verifier")
	serializedVerifier := []byte(verifierPrefix + config.VerifierSHA256 + "\n")
	if err := writeExclusiveFile(verifierFile, serializedVerifier, 0o600); err != nil {
		return fmt.Errorf("cannot create verifier: %w", err)
	}
	zeroBytes(serializedVerifier)

	fixtures, err := createFixtures(shareDirectory)
	if err != nil {
		return err
	}

	portal, err := publicfiles.New(publicfiles.Config{
		Root:         shareDirectory,
		VerifierFile: verifierFile,
	})
	if err != nil {
		return fmt.Errorf("cannot initialize the public-file portal: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, portal.Close())
	}()

	counters := &requestCounters{}
	handler := &instrumentedPortal{
		next:           portal,
		verifierDigest: verifierDigest,
		counters:       counters,
	}
	publicServer := publicfiles.NewHTTPServer(handler)
	publicServer.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}
	controlServer := newControlServer(counters)

	publicListener, err := listenLoopback()
	if err != nil {
		return fmt.Errorf("cannot create public listener: %w", err)
	}
	defer publicListener.Close()
	controlListener, err := listenLoopback()
	if err != nil {
		return fmt.Errorf("cannot create control listener: %w", err)
	}
	defer controlListener.Close()

	readyPublicListener := newAcceptReadyListener(publicListener)
	readyControlListener := newAcceptReadyListener(controlListener)
	publicResult := make(chan error, 1)
	controlResult := make(chan error, 1)
	go func() {
		publicResult <- publicServer.ServeTLS(readyPublicListener, "", "")
	}()
	go func() {
		controlResult <- controlServer.Serve(readyControlListener)
	}()

	if err := waitForAcceptLoops(
		signalContext,
		readyPublicListener.accepting,
		readyControlListener.accepting,
		publicResult,
		controlResult,
	); err != nil {
		_ = publicServer.Close()
		_ = controlServer.Close()
		return err
	}

	ready := readyMessage{
		Origin:        "https://" + publicListener.Addr().String(),
		ControlOrigin: "http://" + controlListener.Addr().String(),
		Fixtures:      fixtures,
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		_ = publicServer.Close()
		_ = controlServer.Close()
		return errors.New("cannot write readiness message")
	}

	var unexpected error
	select {
	case <-signalContext.Done():
	case err := <-publicResult:
		unexpected = unexpectedServerResult("public", err)
	case err := <-controlResult:
		unexpected = unexpectedServerResult("control", err)
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), gracefulShutdownDeadline)
	publicShutdownErr := publicServer.Shutdown(shutdownContext)
	controlShutdownErr := controlServer.Shutdown(shutdownContext)
	cancelShutdown()
	if publicShutdownErr != nil {
		publicShutdownErr = errors.Join(publicShutdownErr, publicServer.Close())
	}
	if controlShutdownErr != nil {
		controlShutdownErr = errors.Join(controlShutdownErr, controlServer.Close())
	}
	return errors.Join(unexpected, publicShutdownErr, controlShutdownErr)
}

func waitForAcceptLoops(
	ctx context.Context,
	publicAccepting <-chan struct{},
	controlAccepting <-chan struct{},
	publicResult <-chan error,
	controlResult <-chan error,
) error {
	for publicAccepting != nil || controlAccepting != nil {
		select {
		case <-ctx.Done():
			return errors.New("termination requested before readiness")
		case err := <-publicResult:
			return unexpectedServerResult("public", err)
		case err := <-controlResult:
			return unexpectedServerResult("control", err)
		case <-publicAccepting:
			publicAccepting = nil
		case <-controlAccepting:
			controlAccepting = nil
		}
	}
	select {
	case err := <-publicResult:
		return unexpectedServerResult("public", err)
	case err := <-controlResult:
		return unexpectedServerResult("control", err)
	default:
		return nil
	}
}

func readBootstrapConfig(reader io.Reader) (bootstrapConfig, [sha256.Size]byte, error) {
	var config bootstrapConfig
	var verifier [sha256.Size]byte
	content, err := io.ReadAll(io.LimitReader(reader, maximumBootstrapBytes+1))
	if err != nil {
		return config, verifier, errors.New("cannot read bootstrap configuration")
	}
	if len(content) == 0 || len(content) > maximumBootstrapBytes {
		return config, verifier, fmt.Errorf("bootstrap configuration must contain between 1 and %d bytes", maximumBootstrapBytes)
	}
	if err := validateBootstrapObjectKeys(content); err != nil {
		return config, verifier, err
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return bootstrapConfig{}, verifier, errors.New("bootstrap configuration is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return bootstrapConfig{}, verifier, errors.New("bootstrap configuration must contain exactly one JSON value")
	}
	if len(config.VerifierSHA256) != sha256.Size*2 {
		return bootstrapConfig{}, verifier, errors.New("verifier_sha256 must be 64 lowercase hexadecimal characters")
	}
	for _, character := range config.VerifierSHA256 {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return bootstrapConfig{}, verifier, errors.New("verifier_sha256 must be 64 lowercase hexadecimal characters")
		}
	}
	if _, err := hex.Decode(verifier[:], []byte(config.VerifierSHA256)); err != nil {
		return bootstrapConfig{}, [sha256.Size]byte{}, errors.New("verifier_sha256 is invalid")
	}
	if config.CertificateFile == "" || config.PrivateKeyFile == "" {
		return bootstrapConfig{}, [sha256.Size]byte{}, errors.New("certificate_file and private_key_file are required")
	}
	return config, verifier, nil
}

func validateBootstrapObjectKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("bootstrap configuration must be a JSON object")
	}
	required := map[string]bool{
		"verifier_sha256":  false,
		"certificate_file": false,
		"private_key_file": false,
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("bootstrap configuration is invalid")
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("bootstrap configuration is invalid")
		}
		seen, known := required[name]
		if !known {
			return errors.New("bootstrap configuration contains an unknown field")
		}
		if seen {
			return errors.New("bootstrap configuration contains a duplicate field")
		}
		required[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("bootstrap configuration is invalid")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("bootstrap configuration is invalid")
	}
	for _, present := range required {
		if !present {
			return errors.New("bootstrap configuration is missing a required field")
		}
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return errors.New("bootstrap configuration must contain exactly one JSON value")
	}
	return nil
}

func readTLSMaterial(runnerTemp string, config bootstrapConfig) ([]byte, []byte, error) {
	runnerFD, err := unix.Open(runnerTemp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, errors.New("RUNNER_TEMP is not a usable non-symlink directory")
	}
	defer unix.Close(runnerFD)

	certificateRelative, err := relativeFileWithin(runnerTemp, config.CertificateFile)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate_file is invalid: %w", err)
	}
	privateKeyRelative, err := relativeFileWithin(runnerTemp, config.PrivateKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("private_key_file is invalid: %w", err)
	}
	if certificateRelative == privateKeyRelative {
		return nil, nil, errors.New("certificate_file and private_key_file must be different files")
	}

	certificate, err := readOwnedRegularAt(runnerFD, certificateRelative, 0o600, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate_file is unsafe: %w", err)
	}
	privateKey, err := readOwnedRegularAt(runnerFD, privateKeyRelative, 0o600)
	if err != nil {
		zeroBytes(certificate)
		return nil, nil, fmt.Errorf("private_key_file is unsafe: %w", err)
	}
	return certificate, privateKey, nil
}

func relativeFileWithin(basePath, filePath string) (string, error) {
	if !filepath.IsAbs(filePath) || filepath.Clean(filePath) != filePath {
		return "", errors.New("an absolute, clean path is required")
	}
	relative, err := filepath.Rel(basePath, filePath)
	if err != nil ||
		relative == "." ||
		relative == ".." ||
		filepath.IsAbs(relative) ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("the file must be contained by RUNNER_TEMP")
	}
	return relative, nil
}

func readOwnedRegularAt(directoryFD int, relativePath string, allowedModes ...uint32) ([]byte, error) {
	fd, err := unix.Openat2(directoryFD, relativePath, &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: unix.RESOLVE_BENEATH |
			unix.RESOLVE_NO_MAGICLINKS |
			unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, errors.New("cannot securely open the file")
	}
	file := os.NewFile(uintptr(fd), "browser-harness-input")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cannot securely open the file")
	}
	defer file.Close()

	var metadata unix.Stat_t
	if err := unix.Fstat(fd, &metadata); err != nil {
		return nil, errors.New("cannot inspect the file")
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG || metadata.Nlink != 1 {
		return nil, errors.New("the file must be a single-link regular file")
	}
	if metadata.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("the file must be owned by the current user")
	}
	modeAllowed := false
	for _, allowedMode := range allowedModes {
		if metadata.Mode&0o7777 == allowedMode {
			modeAllowed = true
			break
		}
	}
	if !modeAllowed {
		return nil, errors.New("the file mode is not allowed")
	}
	if metadata.Size <= 0 || metadata.Size > maximumTLSMaterialBytes {
		return nil, errors.New("the file size is not allowed")
	}

	content, err := io.ReadAll(io.LimitReader(file, maximumTLSMaterialBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumTLSMaterialBytes || int64(len(content)) != metadata.Size {
		zeroBytes(content)
		return nil, errors.New("cannot read the complete file")
	}
	return content, nil
}

func validateOwnedDirectory(path string, requiredMode os.FileMode) error {
	metadata, err := os.Lstat(path)
	if err != nil {
		return errors.New("cannot inspect a browser harness directory")
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok ||
		!metadata.IsDir() ||
		metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm() != requiredMode ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("browser harness directory metadata is unsafe")
	}
	return nil
}

func writeExclusiveFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(content) {
		return errors.Join(writeErr, io.ErrShortWrite, syncErr, closeErr)
	}
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	metadata, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok ||
		!metadata.Mode().IsRegular() ||
		metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm() != mode ||
		stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("created file metadata is unsafe")
	}
	return nil
}

func createFixtures(shareDirectory string) (map[string]fixtureMetadata, error) {
	fixtures := make(map[string]fixtureMetadata, 2)
	report := []byte("ReCasaOS public-file browser integration fixture.\n")
	reportPath := filepath.Join(shareDirectory, "report.txt")
	if err := writeExclusiveFile(reportPath, report, 0o600); err != nil {
		return nil, fmt.Errorf("cannot create report.txt: %w", err)
	}
	reportDigest := sha256.Sum256(report)
	fixtures["report.txt"] = fixtureMetadata{
		Size:   int64(len(report)),
		SHA256: hex.EncodeToString(reportDigest[:]),
	}

	streamPath := filepath.Join(shareDirectory, "stream.bin")
	streamFile, err := os.OpenFile(streamPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("cannot create stream.bin")
	}
	digest := sha256.New()
	chunk := make([]byte, 64<<10)
	for index := range chunk {
		chunk[index] = byte((index*131 + 17) % 251)
	}
	var written int64
	var streamErr error
	for written < streamFixtureSize {
		toWrite := int64(len(chunk))
		if remaining := streamFixtureSize - written; remaining < toWrite {
			toWrite = remaining
		}
		count, err := streamFile.Write(chunk[:toWrite])
		if count > 0 {
			_, _ = digest.Write(chunk[:count])
			written += int64(count)
		}
		if err != nil {
			streamErr = err
			break
		}
		if int64(count) != toWrite {
			streamErr = io.ErrShortWrite
			break
		}
	}
	syncErr := streamFile.Sync()
	closeErr := streamFile.Close()
	if streamErr != nil || syncErr != nil || closeErr != nil || written != streamFixtureSize {
		return nil, errors.Join(errors.New("cannot write stream.bin"), streamErr, syncErr, closeErr)
	}
	if err := validateCreatedFixture(streamPath, streamFixtureSize); err != nil {
		return nil, err
	}
	fixtures["stream.bin"] = fixtureMetadata{
		Size:   written,
		SHA256: hex.EncodeToString(digest.Sum(nil)),
	}
	return fixtures, nil
}

func validateCreatedFixture(path string, expectedSize int64) error {
	metadata, err := os.Lstat(path)
	if err != nil {
		return errors.New("cannot inspect stream.bin")
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok ||
		!metadata.Mode().IsRegular() ||
		metadata.Mode()&os.ModeSymlink != 0 ||
		metadata.Mode().Perm() != 0o600 ||
		metadata.Size() != expectedSize ||
		stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) {
		return errors.New("stream.bin metadata is unsafe")
	}
	return nil
}

func listenLoopback() (net.Listener, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port < 1 || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		_ = listener.Close()
		return nil, errors.New("listener did not bind to IPv4 loopback")
	}
	return listener, nil
}

func newControlServer(counters *requestCounters) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		payload, err := json.Marshal(counters.snapshot())
		if err != nil {
			http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(payload)
		}
	})
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func requestAuthorized(r *http.Request, verifier [sha256.Size]byte) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	parts := strings.SplitN(values[0], " ", 2)
	candidate := ""
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		candidate = parts[1]
	}
	candidateDigest := sha256.Sum256([]byte(candidate))
	digestMatches := subtle.ConstantTimeCompare(candidateDigest[:], verifier[:])
	return digestMatches == 1 && validBearer(candidate)
}

func validBearer(candidate string) bool {
	if len(candidate) != bearerLength || !strings.HasPrefix(candidate, bearerPrefix) {
		return false
	}
	var decoded [bearerRandomBytes]byte
	count, err := strictBearerEncoding.Decode(decoded[:], []byte(candidate[len(bearerPrefix):]))
	if err != nil || count != len(decoded) {
		return false
	}
	var distinct [256]bool
	distinctCount := 0
	for _, value := range decoded {
		if !distinct[value] {
			distinct[value] = true
			distinctCount++
		}
	}
	return distinctCount >= bearerMinDistinct
}

func requestHasCredentialQuery(rawQuery string) bool {
	for _, field := range strings.Split(rawQuery, "&") {
		name, _, _ := strings.Cut(field, "=")
		decodedName, err := percentDecodeQueryName(name)
		if err != nil {
			continue
		}
		switch strings.ToLower(decodedName) {
		case "token", "access_token", "authorization", "api_key", "apikey":
			return true
		}
	}
	return false
}

func percentDecodeQueryName(value string) (string, error) {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '+':
			builder.WriteByte(' ')
		case '%':
			if index+2 >= len(value) {
				return "", errors.New("invalid percent encoding")
			}
			var encoded [1]byte
			if _, err := hex.Decode(encoded[:], []byte(value[index+1:index+3])); err != nil {
				return "", err
			}
			builder.WriteByte(encoded[0])
			index += 2
		default:
			builder.WriteByte(value[index])
		}
	}
	return builder.String(), nil
}

func unexpectedServerResult(name string, err error) error {
	if err == nil {
		return fmt.Errorf("%s server stopped unexpectedly", name)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s server closed before shutdown", name)
	}
	return fmt.Errorf("%s server failed: %w", name, err)
}

func zeroBytes(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
