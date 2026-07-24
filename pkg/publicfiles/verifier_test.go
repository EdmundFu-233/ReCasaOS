package publicfiles

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testPublicBearer(rawByte byte) string {
	raw := make([]byte, publicBearerRandomBytes)
	for index := range raw {
		raw[index] = rawByte + byte(index)
	}
	return publicBearerPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func testEncodedPublicBearer(raw []byte) string {
	return publicBearerPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func serializeTestPublicVerifier(verifier [sha256.Size]byte) []byte {
	return []byte(publicVerifierPrefix + hex.EncodeToString(verifier[:]) + "\n")
}

func TestParsePublicVerifierAcceptsOnlyExactVersionedFormat(t *testing.T) {
	expected := sha256.Sum256([]byte("test-only verifier source"))
	serialized := serializeTestPublicVerifier(expected)
	if len(serialized) != publicVerifierFileMaxBytes {
		t.Fatalf("serialized verifier length = %d, want %d", len(serialized), publicVerifierFileMaxBytes)
	}

	got, err := parsePublicVerifier(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		t.Fatalf("parsed verifier = %x, want %x", got, expected)
	}
}

func TestParsePublicVerifierRejectsAmbiguousOrNoncanonicalInput(t *testing.T) {
	digest := sha256.Sum256([]byte("test-only verifier source"))
	hexDigest := hex.EncodeToString(digest[:])
	valid := publicVerifierPrefix + hexDigest + "\n"

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "legacy raw sixty-four characters", value: hexDigest},
		{name: "missing newline", value: strings.TrimSuffix(valid, "\n")},
		{name: "crlf", value: strings.TrimSuffix(valid, "\n") + "\r\n"},
		{name: "extra newline", value: valid + "\n"},
		{name: "leading whitespace", value: " " + valid},
		{name: "trailing whitespace", value: strings.TrimSuffix(valid, "\n") + " \n"},
		{name: "uppercase hex", value: publicVerifierPrefix + strings.ToUpper(hexDigest) + "\n"},
		{name: "unknown version", value: strings.Replace(valid, "-v1:", "-v2:", 1)},
		{name: "unknown algorithm", value: strings.Replace(valid, ":sha256:", ":sha512:", 1)},
		{name: "short digest", value: publicVerifierPrefix + hexDigest[:len(hexDigest)-2] + "\n"},
		{name: "long digest", value: publicVerifierPrefix + hexDigest + "00\n"},
		{name: "non-hex digest", value: publicVerifierPrefix + "g" + hexDigest[1:] + "\n"},
		{name: "embedded nul", value: publicVerifierPrefix + "\x00" + hexDigest[1:] + "\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parsePublicVerifier([]byte(test.value))
			if err == nil {
				t.Fatalf("parsePublicVerifier(%q) = %x, want error", test.value, parsed)
			}
			if parsed != ([sha256.Size]byte{}) {
				t.Fatalf("rejected verifier returned nonzero digest %x", parsed)
			}
		})
	}
}

func TestValidPublicBearerRequiresCanonicalRandomByteEncoding(t *testing.T) {
	valid := testPublicBearer(1)
	validDigest := digestPublicBearer(valid)
	if len(valid) != publicBearerLen {
		t.Fatalf("test bearer length = %d, want %d", len(valid), publicBearerLen)
	}
	const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lastIndex := strings.IndexByte(base64URLAlphabet, valid[len(valid)-1])
	if lastIndex < 0 || lastIndex&3 != 0 {
		t.Fatalf("test bearer has unexpected final base64url character %q", valid[len(valid)-1])
	}
	noncanonicalTrailingBits := valid[:len(valid)-1] + string(base64URLAlphabet[lastIndex+1])
	allZero := make([]byte, publicBearerRandomBytes)
	twoByteCycle := make([]byte, publicBearerRandomBytes)
	for index := range twoByteCycle {
		twoByteCycle[index] = byte(index % 2)
	}
	twelveByteCycle := make([]byte, publicBearerRandomBytes)
	for index := range twelveByteCycle {
		twelveByteCycle[index] = byte(index % 12)
	}

	tests := []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "valid", candidate: valid, want: true},
		{name: "empty"},
		{name: "missing prefix", candidate: strings.TrimPrefix(valid, publicBearerPrefix)},
		{name: "unknown prefix", candidate: "rc2_" + strings.TrimPrefix(valid, publicBearerPrefix)},
		{name: "short", candidate: valid[:len(valid)-1]},
		{name: "long", candidate: valid + "A"},
		{name: "padded", candidate: valid[:len(valid)-1] + "="},
		{name: "standard base64 alphabet", candidate: valid[:len(valid)-1] + "/"},
		{name: "noncanonical trailing bits", candidate: noncanonicalTrailingBits},
		{name: "all-zero low diversity", candidate: testEncodedPublicBearer(allZero)},
		{name: "two-byte low diversity cycle", candidate: testEncodedPublicBearer(twoByteCycle)},
		{name: "twelve-byte low diversity cycle", candidate: testEncodedPublicBearer(twelveByteCycle)},
		{name: "whitespace", candidate: valid[:len(valid)-1] + " "},
		{name: "newline", candidate: valid[:len(valid)-1] + "\n"},
		{name: "verifier file text", candidate: string(serializeTestPublicVerifier(validDigest))},
		{name: "hex digest", candidate: hex.EncodeToString(validDigest[:])},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validPublicBearer(test.candidate); got != test.want {
				t.Fatalf("validPublicBearer(%q) = %v, want %v", test.candidate, got, test.want)
			}
		})
	}
}

func TestDigestPublicBearerHashesEveryCandidate(t *testing.T) {
	candidates := []string{
		"",
		"malformed",
		testPublicBearer(7),
		string(serializeTestPublicVerifier(sha256.Sum256([]byte("not a bearer")))),
	}
	for _, candidate := range candidates {
		want := sha256.Sum256([]byte(candidate))
		if got := digestPublicBearer(candidate); got != want {
			t.Fatalf("digestPublicBearer(%q) = %x, want %x", candidate, got, want)
		}
	}
}

func TestVerifierCannotBeUsedAsBearer(t *testing.T) {
	bearer := testPublicBearer(19)
	verifier := digestPublicBearer(bearer)
	serializedVerifier := serializeTestPublicVerifier(verifier)
	encodedVerifier := publicBearerPrefix + base64.RawURLEncoding.EncodeToString(verifier[:])

	for _, candidate := range []string{
		string(serializedVerifier),
		hex.EncodeToString(verifier[:]),
		encodedVerifier,
	} {
		candidateDigest := digestPublicBearer(candidate)
		match := subtle.ConstantTimeCompare(candidateDigest[:], verifier[:])
		if validPublicBearer(candidate) && match == 1 {
			t.Fatalf("verifier-derived candidate %q authenticated as the bearer", candidate)
		}
	}
}
