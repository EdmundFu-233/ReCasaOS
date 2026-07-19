package netsecurity

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestValidatePublicHTTPSURL(t *testing.T) {
	valid := []string{
		"https://example.com/search?q=test",
		"https://93.184.216.34/resource",
		"https://example.com:443/resource",
	}
	for _, candidate := range valid {
		if _, err := ValidatePublicHTTPSURL(candidate); err != nil {
			t.Errorf("ValidatePublicHTTPSURL(%q) = %v", candidate, err)
		}
	}

	invalid := []string{
		"http://example.com/",
		"https://user:secret@example.com/",
		"https://example.com:8443/",
		"https://localhost/",
		"https://service.internal/",
		"https://127.0.0.1/",
		"https://10.0.0.1/",
		"https://169.254.169.254/latest/meta-data/",
		"https://[::1]/",
		" https://example.com/",
	}
	for _, candidate := range invalid {
		if _, err := ValidatePublicHTTPSURL(candidate); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("ValidatePublicHTTPSURL(%q) error = %v, want ErrUnsafeURL", candidate, err)
		}
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, candidate := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1",
		"192.0.2.1", "198.18.0.1", "203.0.113.1", "::1", "fe80::1",
		"64:ff9b::a00:1", "64:ff9b:1::a00:1", "2001::a00:1", "2001:db8::1", "2002:0a00:0001::",
	} {
		if isPublicAddress(netip.MustParseAddr(candidate)) {
			t.Errorf("%s unexpectedly accepted", candidate)
		}
	}
	for _, candidate := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if !isPublicAddress(netip.MustParseAddr(candidate)) {
			t.Errorf("%s unexpectedly rejected", candidate)
		}
	}
}

func TestReadBodyLimited(t *testing.T) {
	content, err := ReadBodyLimited(strings.NewReader("safe"), 4)
	if err != nil || string(content) != "safe" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
	if _, err := ReadBodyLimited(strings.NewReader("oversized"), 4); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}
