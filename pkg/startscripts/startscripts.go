// Package startscripts runs the scripts in /etc/casaos/start.d once the
// service is up.
//
// Replaces CasaOS-Common command.ExecuteScripts, which
//   - closed each script before reading its shebang: every script ran with /bin/sh
//   - had no timeout: one hanging script held the service before readiness
//   - discarded the output and stopped at the first failing script
package startscripts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxShebangBytes = 256
	maxOutputBytes  = 8 << 10
)

// Result of one script.
type Result struct {
	Path   string
	Output string // combined stdout/stderr, truncated to 8 KiB
	Err    error
}

// Run executes every script in dir, in name order, each with its own timeout.
// A failing script does not stop the others. Only regular files (or symlinks to
// them) owned by the service user and not writable by group or others are run.
func Run(ctx context.Context, dir string, timeout time.Duration) ([]Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var results []Result
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		output, err := runOne(ctx, path, timeout)
		results = append(results, Result{Path: path, Output: output, Err: err})
	}
	return results, nil
}

func runOne(ctx context.Context, path string, timeout time.Duration) (string, error) {
	// a symlink is judged by its target (e.g. a read-only package path)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("writable by group or others")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return "", errors.New("not owned by the service user")
	}
	interpreter, err := readInterpreter(path)
	if err != nil {
		return "", err
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, interpreter[0], append(interpreter[1:], path)...)
	output := &limitedBuffer{limit: maxOutputBytes}
	cmd.Stdout = output
	cmd.Stderr = output
	err = cmd.Run()
	if runCtx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return output.String(), err
}

// readInterpreter returns the shebang's interpreter and its arguments, or /bin/sh.
func readInterpreter(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(io.LimitReader(f, maxShebangBytes), maxShebangBytes).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if !strings.HasPrefix(line, "#!") {
		return []string{"/bin/sh"}, nil
	}
	fields := strings.Fields(line[2:])
	if len(fields) == 0 {
		return nil, errors.New("empty shebang")
	}
	return fields, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
