package samba

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime/debug"
	"time"

	"github.com/EdmundFu-233/go-smb2"
)

// RunInternalProbe is invoked only by the hidden child mode in main. It owns
// the sole call path into go-smb2.
func RunInternalProbe() (exitCode int) {
	exitCode = 1
	encoder := json.NewEncoder(os.Stdout)
	defer func() {
		if recover() != nil {
			_ = encoder.Encode(probeResponse{Error: "protocol panic"})
		}
	}()
	debug.SetMemoryLimit(128 << 20)
	if err := applyProbeResourceLimits(); err != nil {
		_ = encoder.Encode(probeResponse{Error: "sandbox"})
		return 1
	}
	if err := verifyProbeSandbox(); err != nil || validateProbeEnvironment() != nil {
		_ = encoder.Encode(probeResponse{Error: "sandbox identity"})
		return 1
	}
	if _, err := os.Stdout.Write([]byte("READY\n")); err != nil {
		return 1
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxProbeInputBytes+1))
	if err != nil || len(input) > maxProbeInputBytes {
		_ = encoder.Encode(probeResponse{Error: "input"})
		return 1
	}
	var request probeRequest
	if err := json.Unmarshal(input, &request); err != nil || validateProbeRequest(request) != nil {
		_ = encoder.Encode(probeResponse{Error: "input"})
		return 1
	}
	names, err := getSambaSharesDirect(request)
	if err != nil {
		_ = encoder.Encode(probeResponse{Error: "protocol"})
		return 1
	}
	if len(names) == 0 || len(names) > maxProbeShares {
		_ = encoder.Encode(probeResponse{Error: "share limit"})
		return 1
	}
	for _, name := range names {
		if validateProbeShare(name) != nil {
			_ = encoder.Encode(probeResponse{Error: "share name"})
			return 1
		}
	}
	if err := encoder.Encode(probeResponse{Shares: names}); err != nil {
		return 1
	}
	return 0
}

func getSambaSharesDirect(request probeRequest) ([]string, error) {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(request.Host, request.Port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return nil, err
	}
	dialer := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator: &smb2.NTLMInitiator{
			User:     request.Username,
			Password: request.Password,
		},
	}
	session, err := dialer.Dial(connection)
	if err != nil {
		return nil, err
	}
	defer session.Logoff()
	names, err := session.ListSharenames()
	if err != nil {
		return nil, err
	}
	if len(names) > maxProbeShares {
		return nil, errors.New("remote Samba share count exceeds limit")
	}
	return names, nil
}
