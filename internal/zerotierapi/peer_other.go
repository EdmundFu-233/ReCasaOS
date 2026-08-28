//go:build !linux

package zerotierapi

import (
	"context"
	"net"
	"os"
)

func zeroTierStateFileOwnedByRoot(os.FileInfo) bool {
	return true
}

func verifyZeroTierPeer(context.Context, net.Conn) error {
	return ErrZeroTierPeerVerificationUnavailable
}
