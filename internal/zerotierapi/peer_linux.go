//go:build linux

package zerotierapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func zeroTierStateFileOwnedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

func verifyZeroTierPeer(ctx context.Context, connection net.Conn) error {
	client, clientOK := connection.LocalAddr().(*net.TCPAddr)
	server, serverOK := connection.RemoteAddr().(*net.TCPAddr)
	if !clientOK || !serverOK || server.IP.String() != "127.0.0.1" {
		return ErrZeroTierUntrustedPeer
	}

	for attempt := 0; attempt < 3; attempt++ {
		table, err := os.Open("/proc/self/net/tcp")
		if err != nil {
			return fmt.Errorf("inspect ZeroTier API peer: %w", err)
		}
		trusted, found, inspectErr := trustedZeroTierTCPPeer(table, server, client)
		closeErr := table.Close()
		if inspectErr != nil {
			return inspectErr
		}
		if closeErr != nil {
			return closeErr
		}
		if found {
			if trusted {
				return nil
			}
			return ErrZeroTierUntrustedPeer
		}
		if attempt == 2 {
			break
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ErrZeroTierUntrustedPeer
}

func trustedZeroTierTCPPeer(table io.Reader, server, client *net.TCPAddr) (trusted, found bool, result error) {
	serverAddress, err := encodeProcTCPAddress(server)
	if err != nil {
		return false, false, err
	}
	clientAddress, err := encodeProcTCPAddress(client)
	if err != nil {
		return false, false, err
	}

	scanner := bufio.NewScanner(io.LimitReader(table, 8<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != serverAddress || fields[2] != clientAddress || fields[3] != "01" {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return false, true, fmt.Errorf("parse ZeroTier API peer owner: %w", err)
		}
		return uid == 0, true, nil
	}
	if err := scanner.Err(); err != nil {
		return false, false, fmt.Errorf("inspect ZeroTier API peer: %w", err)
	}
	return false, false, nil
}

func encodeProcTCPAddress(address *net.TCPAddr) (string, error) {
	if address == nil || address.Port < 1 || address.Port > 65535 {
		return "", ErrZeroTierUntrustedPeer
	}
	ip := address.IP.To4()
	if ip == nil {
		return "", ErrZeroTierUntrustedPeer
	}
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], address.Port), nil
}
