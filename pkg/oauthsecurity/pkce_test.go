package oauthsecurity

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCodeVerifierAndChallengeRFC7636Vector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !ValidCodeVerifier(verifier) {
		t.Fatal("RFC 7636 appendix B verifier was rejected")
	}
	challenge, err := CodeChallengeS256(verifier)
	if err != nil || challenge != expectedChallenge {
		t.Fatalf("challenge = %q, err = %v, want %q", challenge, err, expectedChallenge)
	}
}

func TestCodeVerifierLengthBoundaries(t *testing.T) {
	minimum := strings.Repeat("a", MinCodeVerifierLength)
	maximum := strings.Repeat("a", MaxCodeVerifierLength)
	if !ValidCodeVerifier(minimum) {
		t.Fatal("minimum-length verifier was rejected")
	}
	if !ValidCodeVerifier(maximum) {
		t.Fatal("maximum-length verifier was rejected")
	}
	if ValidCodeVerifier(minimum[:len(minimum)-1]) {
		t.Fatal("below-minimum verifier was accepted")
	}
	if ValidCodeVerifier(maximum + "a") {
		t.Fatal("above-maximum verifier was accepted")
	}
}

func TestNewCodeVerifierShapeAndEntropy(t *testing.T) {
	first, err := NewCodeVerifier(bytes.NewReader(bytes.Repeat([]byte{0x5a}, codeVerifierBytes)))
	if err != nil {
		t.Fatalf("first verifier: %v", err)
	}
	second, err := NewCodeVerifier(bytes.NewReader(bytes.Repeat([]byte{0x6b}, codeVerifierBytes)))
	if err != nil {
		t.Fatalf("second verifier: %v", err)
	}
	if !ValidCodeVerifier(first) || !ValidCodeVerifier(second) {
		t.Fatalf("generated verifiers are invalid: %q, %q", first, second)
	}
	if first == second {
		t.Fatal("distinct entropy produced an identical verifier")
	}
	if _, err := NewCodeVerifier(nil); !errors.Is(err, ErrInvalidPKCE) {
		t.Fatalf("nil entropy error = %v, want ErrInvalidPKCE", err)
	}
	if _, err := NewCodeVerifier(bytes.NewReader([]byte{1})); !errors.Is(err, ErrInvalidPKCE) {
		t.Fatalf("short entropy error = %v, want ErrInvalidPKCE", err)
	}
}

func TestValidCodeVerifierRejectsNonCanonicalValues(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"space":        strings.Repeat("a", 42) + " ",
		"padding":      strings.Repeat("a", 42) + "=",
		"plus":         strings.Repeat("a", 42) + "+",
		"slash":        strings.Repeat("a", 42) + "/",
		"non ascii":    strings.Repeat("a", 42) + "é",
		"control byte": strings.Repeat("a", 42) + "\n",
	}
	for name, value := range cases {
		if ValidCodeVerifier(value) {
			t.Fatalf("%s verifier %q was accepted", name, value)
		}
		if _, err := CodeChallengeS256(value); !errors.Is(err, ErrInvalidPKCE) {
			t.Fatalf("%s challenge error = %v, want ErrInvalidPKCE", name, err)
		}
	}
}
