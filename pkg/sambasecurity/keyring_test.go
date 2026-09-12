package sambasecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestKeyringSealOpenAndContextBinding(t *testing.T) {
	key := strings.Repeat("11", 32)
	keyring := parseTestKeyring(t, keyringText("active", key))
	context := []byte("recasaos-samba-credential-v1\x00alice\x00nas.local\x00445")
	envelope, err := keyring.Seal([]byte("correct horse battery staple"), context)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(envelope, "correct") || !strings.HasPrefix(envelope, envelopePrefix+":") {
		t.Fatalf("unexpected encrypted envelope: %q", envelope)
	}
	plaintext, rotate, err := keyring.Open(envelope, context)
	if err != nil || rotate || string(plaintext) != "correct horse battery staple" {
		t.Fatalf("Open() = %q, rotate=%v, err=%v", plaintext, rotate, err)
	}
	clear(plaintext)
	if plaintext, _, err := keyring.Open(envelope, append(context, 'x')); !errors.Is(err, ErrInvalidEnvelope) || plaintext != nil {
		t.Fatalf("modified context was accepted: plaintext=%q err=%v", plaintext, err)
	}

	tampered := envelope[:len(envelope)-1] + map[bool]string{true: "A", false: "B"}[envelope[len(envelope)-1] != 'A']
	if plaintext, _, err := keyring.Open(tampered, context); !errors.Is(err, ErrInvalidEnvelope) || plaintext != nil {
		t.Fatalf("tampered envelope was accepted: plaintext=%q err=%v", plaintext, err)
	}
}

func TestKeyringRotationUsesDecryptOnlyKey(t *testing.T) {
	oldKey := strings.Repeat("22", 32)
	newKey := strings.Repeat("33", 32)
	oldKeyring := parseTestKeyring(t, keyringText("active", oldKey))
	rotatingKeyring := parseTestKeyring(t,
		keyringHeader+"\n"+
			keyringLine("active", newKey)+"\n"+
			keyringLine("decrypt", oldKey)+"\n",
	)
	context := []byte("stable-context")
	oldEnvelope, err := oldKeyring.Seal([]byte("secret"), context)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, rotate, err := rotatingKeyring.Open(oldEnvelope, context)
	if err != nil || !rotate || string(plaintext) != "secret" {
		t.Fatalf("old envelope = %q, rotate=%v, err=%v", plaintext, rotate, err)
	}
	clear(plaintext)
	newEnvelope, err := rotatingKeyring.Seal([]byte("secret"), context)
	if err != nil {
		t.Fatal(err)
	}
	_, rotate, err = rotatingKeyring.Open(newEnvelope, context)
	if err != nil || rotate {
		t.Fatalf("active envelope rotate=%v err=%v", rotate, err)
	}
}

func TestParseKeyringRejectsMalformedAndAmbiguousInputs(t *testing.T) {
	key := strings.Repeat("ab", 32)
	id := testKeyID(t, key)
	valid := keyringText("active", key)
	for name, value := range map[string]string{
		"empty":            "",
		"missing final LF": strings.TrimSuffix(valid, "\n"),
		"CRLF":             strings.ReplaceAll(valid, "\n", "\r\n"),
		"wrong header":     "recasaos-samba-keyring-v2\n" + keyringLine("active", key) + "\n",
		"wrong key ID":     keyringHeader + "\nactive:0000000000000000:" + key + "\n",
		"uppercase key":    keyringHeader + "\nactive:" + id + ":" + strings.ToUpper(key) + "\n",
		"unknown role":     keyringHeader + "\nretired:" + id + ":" + key + "\n",
		"no active":        keyringHeader + "\n" + keyringLine("decrypt", key) + "\n",
		"duplicate key":    keyringHeader + "\n" + keyringLine("active", key) + "\n" + keyringLine("decrypt", key) + "\n",
		"two active":       keyringHeader + "\n" + keyringLine("active", key) + "\n" + keyringLine("active", strings.Repeat("55", 32)) + "\n",
		"extra field":      keyringHeader + "\n" + keyringLine("active", key) + ":extra\n",
		"embedded blank":   keyringHeader + "\n\n" + keyringLine("active", key) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKeyring([]byte(value)); !errors.Is(err, ErrInvalidKeyring) {
				t.Fatalf("ParseKeyring() error = %v", err)
			}
		})
	}
}

func TestOpenRejectsMalformedEnvelopesWithoutPanicking(t *testing.T) {
	keyring := parseTestKeyring(t, keyringText("active", strings.Repeat("66", 32)))
	valid, err := keyring.Seal([]byte("secret"), []byte("context"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ":")
	for name, value := range map[string]string{
		"empty":            "",
		"wrong prefix":     "wrong:" + strings.Join(parts[1:], ":"),
		"unknown key":      parts[0] + ":0000000000000000:" + parts[2] + ":" + parts[3],
		"padded nonce":     parts[0] + ":" + parts[1] + ":" + parts[2] + "=:" + parts[3],
		"short nonce":      parts[0] + ":" + parts[1] + ":AA:" + parts[3],
		"empty ciphertext": parts[0] + ":" + parts[1] + ":" + parts[2] + ":",
		"extra field":      valid + ":extra",
		"uppercase key ID": parts[0] + ":" + strings.ToUpper(parts[1]) + ":" + parts[2] + ":" + parts[3],
	} {
		t.Run(name, func(t *testing.T) {
			if plaintext, _, err := keyring.Open(value, []byte("context")); !errors.Is(err, ErrInvalidEnvelope) || plaintext != nil {
				t.Fatalf("Open() plaintext=%q error=%v", plaintext, err)
			}
		})
	}
}

func parseTestKeyring(t *testing.T, value string) *Keyring {
	t.Helper()
	keyring, err := ParseKeyring([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func keyringText(role, key string) string {
	return keyringHeader + "\n" + keyringLine(role, key) + "\n"
}

func keyringLine(role, key string) string {
	decoded, _ := hex.DecodeString(key)
	digest := sha256.Sum256(decoded)
	clear(decoded)
	return role + ":" + hex.EncodeToString(digest[:keyIDBytes]) + ":" + key
}

func testKeyID(t *testing.T, key string) string {
	t.Helper()
	line := keyringLine("active", key)
	return strings.Split(line, ":")[1]
}
