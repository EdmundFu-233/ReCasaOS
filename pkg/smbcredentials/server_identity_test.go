package smbcredentials

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestPinNormalizesIdentity(t *testing.T) {
	pin, err := PinServerIdentity("FileServer.Example.COM.", 445, []string{"10.0.0.2", "10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if pin.Host() != "fileserver.example.com" || pin.Port() != 445 {
		t.Fatalf("not normalized: %+v", pin)
	}
	got := pin.Addresses()
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("addresses not deduped/sorted: %v", got)
	}
}

func TestPinRejectsMalformedInput(t *testing.T) {
	for name, tc := range map[string]struct {
		host      string
		port      int
		addresses []string
	}{
		"empty host":        {"", 445, []string{"10.0.0.1"}},
		"whitespace host":   {" file ", 445, []string{"10.0.0.1"}},
		"bad charset":       {"file_server!", 445, []string{"10.0.0.1"}},
		"empty label":       {"file..example", 445, []string{"10.0.0.1"}},
		"zero port":         {"file", 0, []string{"10.0.0.1"}},
		"huge port":         {"file", 65536, []string{"10.0.0.1"}},
		"no addresses":      {"file", 445, nil},
		"bad address":       {"file", 445, []string{"not-an-ip"}},
		"hostname address":  {"file", 445, []string{"other-host"}},
		"duplicate address": {"file", 445, []string{"10.0.0.1", "10.0.0.1"}},
	} {
		if _, err := PinServerIdentity(tc.host, tc.port, tc.addresses); !errors.Is(err, ErrInvalidServerIdentity) {
			t.Fatalf("%s: got %v, want ErrInvalidServerIdentity", name, err)
		}
	}
}

func TestVerifyAcceptsIdenticalReconnect(t *testing.T) {
	pin, err := PinServerIdentity("file", 445, []string{"10.0.0.2", "10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := pin.Verify("FILE", 445, []string{"10.0.0.1", "10.0.0.2"}); err != nil {
		t.Fatalf("identical reconnect must verify: %v", err)
	}
}

func TestVerifyRejectsSilentChanges(t *testing.T) {
	pin, err := PinServerIdentity("file.example", 445, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := pin.Verify("other.example", 445, []string{"10.0.0.1"}); !errors.Is(err, ErrServerIdentityChanged) {
		t.Fatalf("hostname change: got %v", err)
	}
	if err := pin.Verify("file.example", 1445, []string{"10.0.0.1"}); !errors.Is(err, ErrServerIdentityChanged) {
		t.Fatalf("port change: got %v", err)
	}
	// DNS rebinding: same name, attacker's address.
	if err := pin.Verify("file.example", 445, []string{"10.0.0.9"}); !errors.Is(err, ErrServerAddressChanged) {
		t.Fatalf("rebinding: got %v", err)
	}
	// Silent failover: extra address joins the set.
	if err := pin.Verify("file.example", 445, []string{"10.0.0.1", "10.0.0.2"}); !errors.Is(err, ErrServerAddressChanged) {
		t.Fatalf("failover: got %v", err)
	}
	// Unexpected server presenting the pinned name from a new address.
	if err := pin.Verify("file.example", 445, []string{"192.0.2.1"}); !errors.Is(err, ErrServerAddressChanged) {
		t.Fatalf("unexpected server: got %v", err)
	}
}

func TestRotateAddressesIsExplicit(t *testing.T) {
	pin, err := PinServerIdentity("file.example", 445, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	rotated, err := pin.RotateAddresses([]string{"10.0.0.2"})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := rotated.Verify("file.example", 445, []string{"10.0.0.2"}); err != nil {
		t.Fatalf("rotated pin must verify: %v", err)
	}
	if err := pin.Verify("file.example", 445, []string{"10.0.0.2"}); !errors.Is(err, ErrServerAddressChanged) {
		t.Fatalf("old pin must still reject: %v", err)
	}
	if _, err := pin.RotateAddresses(nil); !errors.Is(err, ErrInvalidServerIdentity) {
		t.Fatalf("empty rotation: got %v", err)
	}
}

func TestIdentityMarshalRoundTrip(t *testing.T) {
	pin, err := PinServerIdentity("file.example", 445, []string{"2001:db8::1", "10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	data, err := pin.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseServerIdentity(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Host() != pin.Host() || parsed.Port() != pin.Port() || !equalAddressSets(parsed.Addresses(), pin.Addresses()) {
		t.Fatalf("round trip mismatch")
	}
}

func TestIdentityMarshalTamperRejected(t *testing.T) {
	pin, err := PinServerIdentity("file.example", 445, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	data, err := pin.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mutations := map[string][]byte{
		"magic":     bytes.Clone(data),
		"version":   bytes.Clone(data),
		"host flip": bytes.Clone(data),
		"truncated": bytes.Clone(data[:len(data)-1]),
		"extended":  append(bytes.Clone(data), 0x00),
		"empty":     {},
	}
	mutations["magic"][0] ^= 0xff
	mutations["version"][8] ^= 0xff
	mutations["host flip"][13] ^= 0xff
	for name, mutated := range mutations {
		if _, err := ParseServerIdentity(mutated); !errors.Is(err, ErrInvalidServerIdentity) {
			t.Fatalf("%s: got %v, want rejection", name, err)
		}
	}
}

func TestIdentityErrorsCarryNoValues(t *testing.T) {
	pin, err := PinServerIdentity("secretfile.example", 445, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	err = pin.Verify("evil.example", 445, []string{"10.0.0.1"})
	if err == nil || strings.Contains(err.Error(), "evil") || strings.Contains(err.Error(), "secretfile") {
		t.Fatalf("verification error leaks identity: %v", err)
	}
}
