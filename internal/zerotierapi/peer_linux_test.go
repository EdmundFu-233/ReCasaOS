//go:build linux

package zerotierapi

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTrustedZeroTierTCPPeerRequiresExactServerTupleAndRootOwner(t *testing.T) {
	server := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9993}
	client := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	tests := []struct {
		name        string
		table       string
		wantTrusted bool
		wantFound   bool
		wantError   bool
	}{
		{
			name:        "root server socket",
			table:       "  5: 0100007F:2709 0100007F:C350 01 00000000:00000000 00:00000000 00000000 0 0 12345 1 0000000000000000\n",
			wantTrusted: true,
			wantFound:   true,
		},
		{
			name:      "unprivileged server socket",
			table:     "  5: 0100007F:2709 0100007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000\n",
			wantFound: true,
		},
		{
			name:  "client direction is not server evidence",
			table: "  5: 0100007F:C350 0100007F:2709 01 00000000:00000000 00:00000000 00000000 0 0 12345 1 0000000000000000\n",
		},
		{
			name:  "non-established row is not evidence",
			table: "  5: 0100007F:2709 0100007F:C350 06 00000000:00000000 00:00000000 00000000 0 0 12345 1 0000000000000000\n",
		},
		{
			name:      "malformed matching owner fails closed",
			table:     "  5: 0100007F:2709 0100007F:C350 01 00000000:00000000 00:00000000 00000000 root 0 12345 1 0000000000000000\n",
			wantFound: true,
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trusted, found, err := trustedZeroTierTCPPeer(strings.NewReader("sl local_address rem_address st tx_queue rx_queue retrnsmt uid timeout inode\n"+test.table), server, client)
			if (err != nil) != test.wantError || trusted != test.wantTrusted || found != test.wantFound {
				t.Fatalf("trusted/found/error = %t, %t, %v", trusted, found, err)
			}
		})
	}
}

func TestEncodeProcTCPAddressIsCanonicalIPv4(t *testing.T) {
	encoded, err := encodeProcTCPAddress(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9993})
	if err != nil || encoded != "0100007F:2709" {
		t.Fatalf("encoded = %q, %v", encoded, err)
	}
	for _, address := range []*net.TCPAddr{
		nil,
		{IP: net.ParseIP("::1"), Port: 9993},
		{IP: net.ParseIP("127.0.0.1"), Port: 0},
		{IP: net.ParseIP("127.0.0.1"), Port: 65536},
	} {
		if _, err := encodeProcTCPAddress(address); !errors.Is(err, ErrZeroTierUntrustedPeer) {
			t.Fatalf("address %#v error = %v", address, err)
		}
	}
}

func TestUnprivilegedListenerReceivesNoBytesBeforePeerRejection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fixture needs a non-root listener owner")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	readResult := make(chan int, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			readResult <- -1
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		count, _ := connection.Read(buffer)
		readResult <- count
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := dialTrustedZeroTierPeer(ctx, "tcp", listener.Addr().String())
	if connection != nil {
		_ = connection.Close()
		t.Fatal("unprivileged listener was accepted")
	}
	if !errors.Is(err, ErrZeroTierUntrustedPeer) {
		t.Fatalf("dial error = %v", err)
	}
	select {
	case count := <-readResult:
		if count != 0 {
			t.Fatalf("untrusted listener received %d bytes", count)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("untrusted listener read did not finish")
	}
}
