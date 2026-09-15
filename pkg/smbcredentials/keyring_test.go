package smbcredentials

import (
	"bytes"
	"errors"
	"testing"
)

func TestKeyringCanonicalRoundTripAndRotation(t *testing.T) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x11}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()
	encoded, err := keyring.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	reencoded, err := parsed.Marshal()
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatalf("canonical round trip mismatch: err=%v", err)
	}
	if parsed.ActiveID() != keyring.ActiveID() || len(parsed.KeyIDs()) != 1 {
		t.Fatalf("unexpected parsed IDs: active=%q ids=%v", parsed.ActiveID(), parsed.KeyIDs())
	}

	rotated, err := parsed.rotate(bytes.NewReader(bytes.Repeat([]byte{0x22}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Destroy()
	if rotated.ActiveID() == parsed.ActiveID() || len(rotated.KeyIDs()) != 2 {
		t.Fatalf("rotation did not retain old key and select a new key: active=%q ids=%v", rotated.ActiveID(), rotated.KeyIDs())
	}
	if parsed.ActiveID() != keyring.ActiveID() || len(parsed.KeyIDs()) != 1 {
		t.Fatal("rotation mutated its receiver")
	}

}

func TestPublicAPIUsesOperatingSystemCSPRNG(t *testing.T) {
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()

	envelope, err := keyring.Seal(testContext(), []byte("public CSPRNG smoke test"))
	if err != nil {
		t.Fatal(err)
	}
	secondEnvelope, err := keyring.Seal(testContext(), []byte("public CSPRNG smoke test"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(envelope, secondEnvelope) {
		t.Fatal("public Seal reused its per-envelope randomness")
	}
	rotated, err := keyring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Destroy()
	if rotated.ActiveID() == keyring.ActiveID() {
		t.Fatal("CSPRNG rotation reused the active key")
	}
	rewrapped, err := rotated.Rewrap(testContext(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if keyID, err := rotated.EnvelopeKeyID(testContext(), rewrapped); err != nil || keyID != rotated.ActiveID() || keyID == keyring.ActiveID() {
		t.Fatalf("rewrapped key ID=%q old=%q active=%q err=%v", keyID, keyring.ActiveID(), rotated.ActiveID(), err)
	}
	plaintext, err := rotated.Open(testContext(), rewrapped)
	if err != nil || string(plaintext) != "public CSPRNG smoke test" {
		t.Fatalf("public API round trip: plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)
}

func TestParseKeyringRejectsNonCanonicalAndTamperedInputs(t *testing.T) {
	first, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x31}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	keyring, err := first.rotate(bytes.NewReader(bytes.Repeat([]byte{0x72}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()
	valid, err := keyring.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	entryOffset := len(keyringMagic) + 1 + 1 + keyIDSize
	entrySize := keyIDSize + keySize

	tests := map[string]func([]byte) []byte{
		"empty":           func([]byte) []byte { return nil },
		"truncated":       func(value []byte) []byte { return value[:len(value)-1] },
		"trailing":        func(value []byte) []byte { return append(value, 0) },
		"magic":           func(value []byte) []byte { value[0] ^= 1; return value },
		"version":         func(value []byte) []byte { value[len(keyringMagic)] = 2; return value },
		"zero count":      func(value []byte) []byte { value[len(keyringMagic)+1] = 0; return value },
		"missing active":  func(value []byte) []byte { value[len(keyringMagic)+2] ^= 1; return value },
		"key id mismatch": func(value []byte) []byte { value[entryOffset] ^= 1; return value },
		"key mismatch":    func(value []byte) []byte { value[entryOffset+keyIDSize] ^= 1; return value },
		"unsorted": func(value []byte) []byte {
			firstEntry := bytes.Clone(value[entryOffset : entryOffset+entrySize])
			copy(value[entryOffset:entryOffset+entrySize], value[entryOffset+entrySize:entryOffset+2*entrySize])
			copy(value[entryOffset+entrySize:entryOffset+2*entrySize], firstEntry)
			return value
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(bytes.Clone(valid))
			if parsed, err := ParseKeyring(candidate); !errors.Is(err, ErrInvalidKeyring) {
				if parsed != nil {
					parsed.Destroy()
				}
				t.Fatalf("ParseKeyring() error = %v", err)
			}
		})
	}
}

func TestKeyringGenerationAndRotationFailClosed(t *testing.T) {
	if _, err := newKeyring(nil); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("nil random error = %v", err)
	}
	if _, err := newKeyring(bytes.NewReader(make([]byte, keySize-1))); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("short random error = %v", err)
	}
	keyring, err := newKeyring(bytes.NewReader(make([]byte, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()
	if _, err := keyring.rotate(bytes.NewReader(make([]byte, keySize*4))); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("duplicate random rotation error = %v", err)
	}
	if _, err := keyring.rotate(nil); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("nil rotation random error = %v", err)
	}
	if _, err := keyring.rotate(bytes.NewReader(make([]byte, keySize-1))); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("short rotation random error = %v", err)
	}

	full := keyring
	owned := []*Keyring{}
	for index := 1; index < maxKeys; index++ {
		rotated, rotateErr := full.rotate(bytes.NewReader(bytes.Repeat([]byte{byte(index)}, keySize)))
		if rotateErr != nil {
			t.Fatalf("rotation %d: %v", index, rotateErr)
		}
		owned = append(owned, rotated)
		full = rotated
	}
	defer func() {
		for _, item := range owned {
			item.Destroy()
		}
	}()
	if _, err := full.rotate(bytes.NewReader(bytes.Repeat([]byte{0xfe}, keySize))); !errors.Is(err, ErrKeyringFull) {
		t.Fatalf("full keyring rotation error = %v", err)
	}
	encoded, err := full.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if encoded[len(keyringMagic)+1] != maxKeys {
		t.Fatalf("marshaled key count = %d, want %d", encoded[len(keyringMagic)+1], maxKeys)
	}
	parsed, err := ParseKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	if len(parsed.KeyIDs()) != maxKeys || parsed.ActiveID() != full.ActiveID() {
		t.Fatalf("parsed full keyring: active=%q keys=%d", parsed.ActiveID(), len(parsed.KeyIDs()))
	}
}

func TestNilAndDestroyedKeyringsFailClosed(t *testing.T) {
	assertInvalid := func(t *testing.T, keyring *Keyring, envelope []byte) {
		t.Helper()
		if keyring.ActiveID() != "" || keyring.KeyIDs() != nil {
			t.Fatal("invalid keyring exposed key identifiers")
		}
		if _, err := keyring.Marshal(); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("Marshal error = %v", err)
		}
		if _, err := keyring.rotate(bytes.NewReader(bytes.Repeat([]byte{0xaa}, keySize))); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("Rotate error = %v", err)
		}
		if _, err := keyring.Rotate(); !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("public Rotate error = %v", err)
		}
		if _, err := keyring.seal(testContext(), nil, sealRandom(0xab)); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Seal error = %v", err)
		}
		if _, err := keyring.Seal(testContext(), nil); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("public Seal error = %v", err)
		}
		if plaintext, err := keyring.Open(testContext(), envelope); !errors.Is(err, ErrInvalidEnvelope) {
			clear(plaintext)
			t.Fatalf("Open error = %v", err)
		}
		if _, err := keyring.rewrap(testContext(), envelope, bytes.NewReader(bytes.Repeat([]byte{0xac}, chachaNonceSizeForTest))); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Rewrap error = %v", err)
		}
		if _, err := keyring.Rewrap(testContext(), envelope); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("public Rewrap error = %v", err)
		}
		if _, err := keyring.EnvelopeKeyID(testContext(), envelope); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("EnvelopeKeyID error = %v", err)
		}
		keyring.Destroy()
	}

	var nilKeyring *Keyring
	assertInvalid(t, nilKeyring, nil)
	assertInvalid(t, &Keyring{}, nil)

	destroyed, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0xad}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := destroyed.seal(testContext(), []byte("destroyed"), sealRandom(0xae))
	if err != nil {
		t.Fatal(err)
	}
	destroyed.Destroy()
	assertInvalid(t, destroyed, envelope)
}
