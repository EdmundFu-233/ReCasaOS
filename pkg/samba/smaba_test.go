package samba

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProbeParentAcceptsBoundedJSONAndKeepsSecretOutOfArgvAndEnv(t *testing.T) {
	const secret = "RECASAOS-PROBE-SECRET"
	restoreProbeTestCommand(t, "inspect", 2*time.Second)
	shares, err := GetSambaSharesList("nas.local", "445", "alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(shares, ",") != "Media,IPC$" {
		t.Fatalf("shares = %#v", shares)
	}
}

func TestProbeParentDrainsDelayedJSONTailBeforeWaiting(t *testing.T) {
	restoreProbeTestCommand(t, "delayed-tail", 2*time.Second)
	shares, err := GetSambaSharesList("nas.local", "445", "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(shares, ",") != "Media,Backups" {
		t.Fatalf("shares = %#v", shares)
	}
}

func TestProbeParentContainsCrashMalformedOutputLimitsAndTimeout(t *testing.T) {
	for _, mode := range []string{"panic-0", "panic-4", "panic-47", "panic-63", "malformed", "stdout-limit", "stderr-limit", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 2 * time.Second
			if mode == "sleep" {
				timeout = 100 * time.Millisecond
			}
			restoreProbeTestCommand(t, mode, timeout)
			if _, err := GetSambaSharesList("nas.local", "445", "alice", "secret"); err == nil {
				t.Fatalf("isolated probe mode %s unexpectedly succeeded", mode)
			}
		})
	}
	// Reaching a valid child after all crash modes proves the parent test process
	// and the single-probe gate both remain alive.
	restoreProbeTestCommand(t, "valid", 2*time.Second)
	if _, err := GetSambaSharesList("nas.local", "445", "alice", "secret"); err != nil {
		t.Fatalf("probe did not recover after isolated child failures: %v", err)
	}
}

func TestBoundedProbeBufferHardLimit(t *testing.T) {
	buffer := &boundedProbeBuffer{limit: 4}
	if written, err := buffer.Write([]byte("1234")); err != nil || written != 4 {
		t.Fatalf("exact-limit write = (%d, %v)", written, err)
	}
	if _, err := buffer.Write([]byte("5")); err == nil || len(buffer.data) != 4 {
		t.Fatalf("overflow write was not rejected: len=%d err=%v", len(buffer.data), err)
	}
}

func TestProbeValidationRejectsProtocolAndPathAmbiguity(t *testing.T) {
	for _, request := range []probeRequest{
		{Host: "nas.local", Port: "1445", Username: "alice"},
		{Host: "../nas", Port: "445", Username: "alice"},
		{Host: "nas.local", Port: "445", Username: "alice,uid=0"},
	} {
		if err := validateProbeRequest(request); err == nil {
			t.Fatalf("unsafe request unexpectedly accepted: %+v", request)
		}
	}
	for _, share := range []string{"", `foo\bar`, "../share", " share", strings.Repeat("x", maxProbeShareBytes+1)} {
		if err := validateProbeShare(share); err == nil {
			t.Fatalf("unsafe share %q unexpectedly accepted", share)
		}
	}
}

func TestProbeShareCountAccepts64AndRejects65(t *testing.T) {
	for count, wantError := range map[int]bool{64: false, 65: true} {
		mode := fmt.Sprintf("count-%d", count)
		restoreProbeTestCommand(t, mode, 2*time.Second)
		shares, err := GetSambaSharesList("nas.local", "445", "alice", "secret")
		if (err != nil) != wantError {
			t.Fatalf("count %d: shares=%d err=%v", count, len(shares), err)
		}
	}
}

func restoreProbeTestCommand(t *testing.T, mode string, timeout time.Duration) {
	t.Helper()
	probeCommandMu.Lock()
	previousFactory := probeCommandFactory
	previousTimeout := probeWallTimeout
	probeCommandFactory = func(ctx context.Context) (*exec.Cmd, error) {
		executable := os.Args[0]
		if runtime.GOOS == "linux" {
			// Root tests drop to nobody before exec. /proc/self/exe remains
			// executable even when Go's private build directory is mode 0700.
			executable = "/proc/self/exe"
		}
		return exec.CommandContext(ctx, executable, "-test.run=^TestSambaProbeHelperProcess$", "--", mode), nil
	}
	probeWallTimeout = timeout
	probeCommandMu.Unlock()
	t.Cleanup(func() {
		probeCommandMu.Lock()
		probeCommandFactory = previousFactory
		probeWallTimeout = previousTimeout
		probeCommandMu.Unlock()
	})
}

func TestSambaProbeHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	mode := os.Args[separator+1]
	if mode == "identity" {
		if err := applyProbeResourceLimits(); err != nil {
			os.Exit(2)
		}
		if err := verifyProbeSandbox(); err != nil || validateProbeEnvironment() != nil {
			os.Exit(2)
		}
		fmt.Fprint(os.Stdout, "READY\n")
		if !readHelperProbeInput() {
			os.Exit(2)
		}
		fmt.Fprint(os.Stdout, `{"shares":["Media"]}`)
		os.Exit(0)
	}
	fmt.Fprint(os.Stdout, "READY\n")
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxProbeInputBytes+1))
	if err != nil || len(input) == 0 || len(input) > maxProbeInputBytes {
		os.Exit(2)
	}
	switch mode {
	case "inspect":
		allProcessMetadata := strings.Join(append(append([]string{}, os.Args...), os.Environ()...), "\n")
		if strings.Contains(allProcessMetadata, "RECASAOS-PROBE-SECRET") {
			fmt.Fprint(os.Stderr, "secret leaked outside stdin")
			os.Exit(2)
		}
		if !strings.Contains(string(input), "RECASAOS-PROBE-SECRET") {
			fmt.Fprint(os.Stderr, "secret did not arrive over stdin after READY")
			os.Exit(2)
		}
		fallthrough
	case "valid":
		fmt.Fprint(os.Stdout, `{"shares":["Media","IPC$"]}`)
		os.Exit(0)
	case "delayed-tail":
		fmt.Fprint(os.Stdout, `{"shares":["Media",`)
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(os.Stdout, `"Backups"]}`)
		os.Exit(0)
	case "malformed":
		fmt.Fprint(os.Stdout, `{not-json`)
		os.Exit(0)
	case "stdout-limit":
		_, _ = os.Stdout.Write(make([]byte, maxProbeOutputBytes+1))
		os.Exit(0)
	case "stderr-limit":
		_, _ = os.Stderr.Write(make([]byte, maxProbeErrorBytes+1))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Second)
		os.Exit(0)
	default:
		if strings.HasPrefix(mode, "count-") {
			var count int
			_, _ = fmt.Sscanf(mode, "count-%d", &count)
			fmt.Fprint(os.Stdout, `{"shares":[`)
			for index := 0; index < count; index++ {
				if index != 0 {
					fmt.Fprint(os.Stdout, ",")
				}
				fmt.Fprintf(os.Stdout, `"Share%d"`, index)
			}
			fmt.Fprint(os.Stdout, `]}`)
			os.Exit(0)
		}
		if strings.HasPrefix(mode, "panic-") {
			panic("simulated truncated SMB response of length " + strings.TrimPrefix(mode, "panic-"))
		}
		os.Exit(2)
	}
}

func readHelperProbeInput() bool {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxProbeInputBytes+1))
	return err == nil && len(input) > 0 && len(input) <= maxProbeInputBytes
}
