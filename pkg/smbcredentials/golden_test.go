package smbcredentials

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	keyringV1GoldenHex  = "5243534d424b4559010102d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc1111111111111111111111111111111111111111111111111111111111111111"
	envelopeV1GoldenHex = "5243534d42454e560101000002d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc222222222222222222222222222222222222222222222222a246c62d7d98c5b5c46c35ea9c5880c313b6e2f534bfdbc5416a57c650c17804c829ffeea3c49e59765b3241d26f3b3a232323232323232323232323232323232323232323232323001f3e2b09b88028d9a8de2f200444471f1f16cced7c17f973b47205d07f2b6e18"
)

func TestVersion1GoldenVectors(t *testing.T) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x11}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()
	encodedKeyring, err := keyring.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedKeyring)
	if got := hex.EncodeToString(encodedKeyring); got != keyringV1GoldenHex {
		t.Fatalf("keyring v1 changed:\n got %s\nwant %s", got, keyringV1GoldenHex)
	}
	goldenKeyring, err := hex.DecodeString(keyringV1GoldenHex)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(goldenKeyring)
	parsedKeyring, err := ParseKeyring(goldenKeyring)
	if err != nil {
		t.Fatalf("parse keyring v1 golden vector: %v", err)
	}
	parsedKeyring.Destroy()

	random := make([]byte, 0, keySize+2*chachaNonceSizeForTest)
	random = append(random, bytes.Repeat([]byte{0x21}, keySize)...)
	random = append(random, bytes.Repeat([]byte{0x22}, chachaNonceSizeForTest)...)
	random = append(random, bytes.Repeat([]byte{0x23}, chachaNonceSizeForTest)...)
	envelope, err := keyring.seal(testContext(), []byte("golden-password"), bytes.NewReader(random))
	clear(random)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope); got != envelopeV1GoldenHex {
		t.Fatalf("envelope v1 changed:\n got %s\nwant %s", got, envelopeV1GoldenHex)
	}
	goldenEnvelope, err := hex.DecodeString(envelopeV1GoldenHex)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keyring.Open(testContext(), goldenEnvelope)
	if err != nil || string(plaintext) != "golden-password" {
		t.Fatalf("open envelope v1 golden vector: plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)
}
