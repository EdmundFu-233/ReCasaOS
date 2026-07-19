/*
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package samba

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	InternalProbeArgument = "--internal-samba-probe"
	maxProbeInputBytes    = 4 << 10
	maxProbeOutputBytes   = 1 << 20
	maxProbeErrorBytes    = 64 << 10
	maxProbeShares        = 64
	maxProbeShareBytes    = 255
	defaultProbeTimeout   = 25 * time.Second
)

type probeRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type probeResponse struct {
	Shares []string `json:"shares,omitempty"`
	Error  string   `json:"error,omitempty"`
}

var (
	probeGate           = make(chan struct{}, 1)
	probeCommandFactory = defaultProbeCommand
	probeCommandMu      sync.RWMutex
	probeWallTimeout    = defaultProbeTimeout
)

func ConnectSambaService(host, port, username, password, directory string) error {
	if err := validateProbeShare(directory); err != nil {
		return err
	}
	names, err := GetSambaSharesList(host, port, username, password)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == directory {
			return nil
		}
	}
	return errors.New("Samba directory not found")
}

// GetSambaSharesList keeps every untrusted SMB parser and receive goroutine in
// a resource-limited child. A malformed server response can terminate only the
// probe, never the long-lived API/database process.
func GetSambaSharesList(host, port, username, password string) ([]string, error) {
	request := probeRequest{Host: host, Port: port, Username: username, Password: password}
	if err := validateProbeRequest(request); err != nil {
		return nil, err
	}
	input, err := json.Marshal(request)
	if err != nil || len(input) > maxProbeInputBytes {
		return nil, errors.New("invalid Samba probe request")
	}

	probeCommandMu.RLock()
	timeout := probeWallTimeout
	probeCommandMu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	select {
	case probeGate <- struct{}{}:
		defer func() { <-probeGate }()
	case <-ctx.Done():
		return nil, errors.New("Samba probe capacity timeout")
	}

	probeCommandMu.RLock()
	commandFactory := probeCommandFactory
	probeCommandMu.RUnlock()
	command, err := commandFactory(ctx)
	if err != nil {
		return nil, errors.New("start isolated Samba probe")
	}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "GOMEMLIMIT=128MiB", "GOMAXPROCS=1", "GOTRACEBACK=none"}
	stdout := &boundedProbeBuffer{limit: maxProbeOutputBytes}
	stderr := &boundedProbeBuffer{limit: maxProbeErrorBytes}
	command.Stderr = stderr
	if err := configureProbeCommand(command); err != nil {
		return nil, errors.New("secure isolated Samba probe")
	}
	stdinPipe, err := command.StdinPipe()
	if err != nil {
		return nil, errors.New("create isolated Samba probe input")
	}
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("create isolated Samba probe output")
	}
	if err := command.Start(); err != nil {
		return nil, errors.New("start isolated Samba probe")
	}
	ready := make([]byte, len("READY\n"))
	_, readyErr := io.ReadFull(stdoutPipe, ready)
	if readyErr != nil || string(ready) != "READY\n" {
		_ = stdinPipe.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errors.New("isolated Samba probe did not establish its sandbox")
	}
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(stdout, stdoutPipe)
		if copyErr != nil {
			// A child that keeps writing after crossing the bounded protocol
			// limit must not be allowed to block forever on a full pipe.
			_ = command.Process.Kill()
		}
		copyDone <- copyErr
	}()
	written, writeErr := stdinPipe.Write(input)
	closeInputErr := stdinPipe.Close()
	if writeErr != nil || written != len(input) || closeInputErr != nil {
		_ = command.Process.Kill()
		<-copyDone
		_ = command.Wait()
		return nil, errors.New("send isolated Samba probe request")
	}
	// os/exec requires callers using StdoutPipe to finish reading before Wait;
	// Wait is allowed to close the pipe and would otherwise lose a delayed JSON
	// tail. Context cancellation and output-limit failures both kill the child,
	// so this bounded read always eventually completes.
	copyErr := <-copyDone
	waitErr := command.Wait()
	if waitErr != nil || copyErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("isolated Samba probe timed out")
		}
		if errors.Is(stdout.err, errProbeOutputLimit) || errors.Is(stderr.err, errProbeOutputLimit) {
			return nil, errors.New("isolated Samba probe exceeded its output limit")
		}
		return nil, errors.New("isolated Samba probe failed")
	}

	var response probeResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.data))
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("isolated Samba probe returned an invalid response")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, fmt.Errorf("Samba probe rejected remote response: %s", response.Error)
	}
	if len(response.Shares) == 0 || len(response.Shares) > maxProbeShares {
		return nil, errors.New("isolated Samba probe returned an invalid share count")
	}
	for _, share := range response.Shares {
		if err := validateProbeShare(share); err != nil {
			return nil, errors.New("isolated Samba probe returned an invalid share name")
		}
	}
	return response.Shares, nil
}

func defaultProbeCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := probeExecutablePath()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, executable, InternalProbeArgument), nil
}

var errProbeOutputLimit = errors.New("Samba probe output limit exceeded")

type boundedProbeBuffer struct {
	data  []byte
	limit int
	err   error
}

func (b *boundedProbeBuffer) Write(data []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	remaining := b.limit - len(b.data)
	if remaining <= 0 || len(data) > remaining {
		written := 0
		if remaining > 0 {
			b.data = append(b.data, data[:remaining]...)
			written = remaining
		}
		b.err = errProbeOutputLimit
		return written, b.err
	}
	b.data = append(b.data, data...)
	return len(data), nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("isolated Samba probe returned trailing data")
	}
	return nil
}

func validateProbeRequest(request probeRequest) error {
	if request.Port != "445" || request.Host == "" || len(request.Host) > 255 || request.Username == "" || len(request.Username) > 255 || len(request.Password) > 1024 {
		return errors.New("invalid Samba probe fields")
	}
	if strings.HasPrefix(request.Host, ".") || strings.HasSuffix(request.Host, ".") || strings.Contains(request.Host, "..") {
		return errors.New("invalid Samba probe host")
	}
	for _, character := range request.Host {
		if character > unicode.MaxASCII || !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(".-_", character)) {
			return errors.New("invalid Samba probe host")
		}
	}
	for _, value := range []string{request.Username, request.Password} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, ",\x00\r\n") {
			return errors.New("invalid Samba probe credentials")
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return errors.New("invalid Samba probe credentials")
			}
		}
	}
	return nil
}

func validateProbeEnvironment() error {
	allowed := map[string]string{
		"PATH":        "/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG":        "C",
		"LC_ALL":      "C",
		"GOMEMLIMIT":  "128MiB",
		"GOMAXPROCS":  "1",
		"GOTRACEBACK": "none",
	}
	environment := os.Environ()
	if len(environment) != len(allowed) {
		return errors.New("invalid Samba probe environment")
	}
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || allowed[name] != value {
			return errors.New("invalid Samba probe environment")
		}
	}
	return nil
}

func validateProbeShare(share string) error {
	if share == "" || len(share) > maxProbeShareBytes || !utf8.ValidString(share) || strings.TrimSpace(share) != share || strings.ContainsAny(share, ",/\\\x00\r\n") || share == "." || share == ".." {
		return errors.New("invalid Samba share name")
	}
	for _, character := range share {
		if unicode.IsControl(character) {
			return errors.New("invalid Samba share name")
		}
	}
	return nil
}
