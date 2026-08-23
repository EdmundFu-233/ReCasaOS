package smbcredentials

import (
	"bytes"
	"testing"
)

func FuzzParseKeyringCanonical(f *testing.F) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x19}, keySize)))
	if err != nil {
		f.Fatal(err)
	}
	valid, err := keyring.Marshal()
	keyring.Destroy()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("RCSMBKEY"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, parseErr := ParseKeyring(data)
		if parseErr != nil {
			return
		}
		defer parsed.Destroy()
		canonical, marshalErr := parsed.Marshal()
		if marshalErr != nil {
			t.Fatalf("accepted keyring cannot be marshaled: %v", marshalErr)
		}
		if !bytes.Equal(canonical, data) {
			t.Fatal("accepted keyring was not canonical")
		}
	})
}

func FuzzEnvelopeOpenAndRewrap(f *testing.F) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x29}, keySize)))
	if err != nil {
		f.Fatal(err)
	}
	defer keyring.Destroy()
	valid, err := keyring.seal(testContext(), []byte("fuzz password"), sealRandom(0x39))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("RCSMBENV"))
	f.Fuzz(func(t *testing.T, data []byte) {
		plaintext, _ := keyring.Open(testContext(), data)
		clear(plaintext)
		rewrapped, rewrapErr := keyring.rewrap(testContext(), data, bytes.NewReader(bytes.Repeat([]byte{0x49}, chachaNonceSizeForTest)))
		if rewrapErr != nil {
			return
		}
		decrypted, openErr := keyring.Open(testContext(), rewrapped)
		clear(decrypted)
		if openErr != nil {
			t.Fatalf("rewrapped accepted envelope cannot be opened: %v", openErr)
		}
	})
}
