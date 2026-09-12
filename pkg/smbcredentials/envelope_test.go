package smbcredentials

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func testContext() Context {
	return Context{
		CredentialID: "18a6e26f-41c7-4f1e-8da8-94343e0cb9bf",
		Username:     "alice",
		Host:         "nas.local",
		Port:         "445",
		Directories:  "Media,Documents",
	}
}

func testKeyring(t *testing.T, fill byte) *Keyring {
	t.Helper()
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{fill}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keyring.Destroy)
	return keyring
}

func sealRandom(fill byte) *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{fill}, keySize+2*chachaNonceSizeForTest))
}

const chachaNonceSizeForTest = 24

func TestEnvelopeRoundTripEmptyAndRandomized(t *testing.T) {
	keyring := testKeyring(t, 0x17)
	for name, password := range map[string][]byte{
		"normal":  []byte("correct horse battery staple"),
		"empty":   {},
		"unicode": []byte("密碼-安全"),
	} {
		t.Run(name, func(t *testing.T) {
			envelope, err := keyring.seal(testContext(), password, sealRandom(0x31))
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := keyring.Open(testContext(), envelope)
			if err != nil || !bytes.Equal(plaintext, password) {
				t.Fatalf("Open() plaintext=%q err=%v", plaintext, err)
			}
			clear(plaintext)
			if id, err := keyring.EnvelopeKeyID(testContext(), envelope); err != nil || id != keyring.ActiveID() {
				t.Fatalf("EnvelopeKeyID()=%q err=%v", id, err)
			}
		})
	}

	first, err := keyring.seal(testContext(), []byte("same"), sealRandom(0x41))
	if err != nil {
		t.Fatal(err)
	}
	second, err := keyring.seal(testContext(), []byte("same"), sealRandom(0x42))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two independently randomized envelopes are identical")
	}
}

func TestEnvelopeAcceptsMaximumPasswordLength(t *testing.T) {
	keyring := testKeyring(t, 0x18)
	password := bytes.Repeat([]byte{0xf1}, maxPasswordBytes)
	envelope, err := keyring.seal(testContext(), password, sealRandom(0x32))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := keyring.Open(testContext(), envelope)
	if err != nil || !bytes.Equal(plaintext, password) {
		t.Fatalf("maximum-length password round trip: plaintext length=%d err=%v", len(plaintext), err)
	}
	clear(plaintext)
}

func TestEnvelopeRandomnessFailuresAreFailClosed(t *testing.T) {
	keyring := testKeyring(t, 0x19)
	for name, length := range map[string]int{
		"DEK":        keySize - 1,
		"wrap nonce": keySize + chachaNonceSizeForTest - 1,
		"data nonce": keySize + 2*chachaNonceSizeForTest - 1,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keyring.seal(testContext(), nil, bytes.NewReader(make([]byte, length))); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("short random error = %v", err)
			}
		})
	}
	if _, err := keyring.seal(testContext(), nil, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("nil seal random error = %v", err)
	}

	envelope, err := keyring.seal(testContext(), nil, sealRandom(0x33))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := keyring.rotate(bytes.NewReader(bytes.Repeat([]byte{0x34}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Destroy()
	if _, err := rotated.rewrap(testContext(), envelope, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("nil rewrap random error = %v", err)
	}
	if _, err := rotated.rewrap(testContext(), envelope, bytes.NewReader(make([]byte, chachaNonceSizeForTest-1))); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("short rewrap random error = %v", err)
	}
}

func TestOversizedEnvelopeIsRejectedBeforeAllocation(t *testing.T) {
	keyring := testKeyring(t, 0x1a)
	oversized := make([]byte, 8<<20)
	if len(oversized) <= maxEnvelopeBytes {
		t.Fatal("test input is not oversized")
	}

	operations := map[string]func() error{
		"Open": func() error {
			plaintext, err := keyring.Open(testContext(), oversized)
			clear(plaintext)
			return err
		},
		"Rewrap": func() error {
			result, err := keyring.Rewrap(testContext(), oversized)
			clear(result)
			return err
		},
		"EnvelopeKeyID": func() error {
			_, err := keyring.EnvelopeKeyID(testContext(), oversized)
			return err
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			var operationErr error
			allocations := testing.AllocsPerRun(10, func() {
				operationErr = operation()
			})
			if !errors.Is(operationErr, ErrInvalidEnvelope) {
				t.Fatalf("oversized envelope error = %v", operationErr)
			}
			if allocations != 0 {
				t.Fatalf("oversized envelope caused %.0f allocations before rejection", allocations)
			}
		})
	}
}

func TestEnvelopeRejectsTamperingTruncationTrailingAndUnknownKey(t *testing.T) {
	keyring := testKeyring(t, 0x21)
	envelope, err := keyring.seal(testContext(), []byte("do-not-leak-this-password"), sealRandom(0x51))
	if err != nil {
		t.Fatal(err)
	}
	keyIDOffset := 12
	wrapNonceOffset := keyIDOffset + keyIDSize
	wrappedDEKOffset := wrapNonceOffset + chachaNonceSizeForTest
	dataNonceOffset := wrappedDEKOffset + keySize + 16
	lengthOffset := dataNonceOffset + chachaNonceSizeForTest
	ciphertextOffset := lengthOffset + 2
	tests := map[string]func([]byte) []byte{
		"truncated":   func(value []byte) []byte { return value[:len(value)-1] },
		"trailing":    func(value []byte) []byte { return append(value, 0) },
		"magic":       func(value []byte) []byte { value[0] ^= 1; return value },
		"version":     func(value []byte) []byte { value[8] = 2; return value },
		"algorithm":   func(value []byte) []byte { value[9] = 2; return value },
		"reserved":    func(value []byte) []byte { value[10] = 1; return value },
		"unknown key": func(value []byte) []byte { value[keyIDOffset] ^= 1; return value },
		"wrap nonce":  func(value []byte) []byte { value[wrapNonceOffset] ^= 1; return value },
		"wrapped DEK": func(value []byte) []byte { value[wrappedDEKOffset] ^= 1; return value },
		"data nonce":  func(value []byte) []byte { value[dataNonceOffset] ^= 1; return value },
		"length":      func(value []byte) []byte { value[lengthOffset] ^= 1; return value },
		"ciphertext":  func(value []byte) []byte { value[ciphertextOffset] ^= 1; return value },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(bytes.Clone(envelope))
			plaintext, openErr := keyring.Open(testContext(), candidate)
			clear(plaintext)
			if openErr == nil {
				t.Fatal("tampered envelope authenticated")
			}
		})
	}

	other := testKeyring(t, 0x22)
	if plaintext, err := other.Open(testContext(), envelope); !errors.Is(err, ErrUnknownKey) {
		clear(plaintext)
		t.Fatalf("unknown-key error = %v", err)
	}
}

func TestEnvelopeBindsEveryContextField(t *testing.T) {
	keyring := testKeyring(t, 0x25)
	context := testContext()
	envelope, err := keyring.seal(context, []byte("bound secret"), sealRandom(0x61))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(Context) Context{
		"credential ID": func(value Context) Context { value.CredentialID = "11a6e26f-41c7-4f1e-8da8-94343e0cb9bf"; return value },
		"username":      func(value Context) Context { value.Username = "mallory"; return value },
		"host":          func(value Context) Context { value.Host = "other.local"; return value },
		"port":          func(value Context) Context { value.Port = "1445"; return value },
		"directories":   func(value Context) Context { value.Directories = "Media"; return value },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plaintext, openErr := keyring.Open(mutate(context), envelope)
			clear(plaintext)
			if openErr == nil {
				t.Fatal("envelope authenticated with mutated context")
			}
		})
	}
}

func TestEnvelopeRewrapAuthenticatesAndPreservesPasswordCiphertext(t *testing.T) {
	oldKeyring := testKeyring(t, 0x33)
	envelope, err := oldKeyring.seal(testContext(), []byte("rotate me"), sealRandom(0x71))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := oldKeyring.rotate(bytes.NewReader(bytes.Repeat([]byte{0x44}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Destroy()
	before, err := parseEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := rotated.rewrap(testContext(), envelope, bytes.NewReader(bytes.Repeat([]byte{0x81}, chachaNonceSizeForTest)))
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseEnvelope(rewrapped)
	if err != nil {
		t.Fatal(err)
	}
	if after.keyID == before.keyID || !bytes.Equal(after.dataNonce, before.dataNonce) || !bytes.Equal(after.ciphertext, before.ciphertext) {
		t.Fatal("rewrap changed the password layer or did not select the active key")
	}
	plaintext, err := rotated.Open(testContext(), rewrapped)
	if err != nil || string(plaintext) != "rotate me" {
		t.Fatalf("open rewrapped envelope: plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)
	if plaintext, err := oldKeyring.Open(testContext(), rewrapped); !errors.Is(err, ErrUnknownKey) {
		clear(plaintext)
		t.Fatalf("old-only keyring error = %v", err)
	}

	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 1
	if _, err := rotated.rewrap(testContext(), tampered, bytes.NewReader(bytes.Repeat([]byte{0x82}, chachaNonceSizeForTest))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("rewrap tampered envelope error = %v", err)
	}
}

func TestEnvelopeRewrapWithActiveKeyIsAuthenticatedNoOp(t *testing.T) {
	keyring := testKeyring(t, 0x35)
	envelope, err := keyring.seal(testContext(), []byte("already active"), sealRandom(0x72))
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := keyring.rewrap(testContext(), envelope, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewrapped, envelope) {
		t.Fatal("same-active rewrap changed an authenticated envelope")
	}
	original := bytes.Clone(envelope)
	rewrapped[0] ^= 1
	if !bytes.Equal(envelope, original) {
		t.Fatal("same-active rewrap aliased the caller's envelope")
	}
	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 1
	if _, err := keyring.rewrap(testContext(), tampered, bytes.NewReader(bytes.Repeat([]byte{0x83}, chachaNonceSizeForTest))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("same-active tampered envelope error = %v", err)
	}
}

type reentrantMutationReader struct {
	target []byte
	fill   byte
	once   sync.Once
}

type callbackReader struct {
	callback func()
	fill     byte
	once     sync.Once
}

func (r *callbackReader) Read(destination []byte) (int, error) {
	r.once.Do(r.callback)
	for index := range destination {
		destination[index] = r.fill
	}
	return len(destination), nil
}

func (r *reentrantMutationReader) Read(destination []byte) (int, error) {
	r.once.Do(func() {
		if len(r.target) > 0 {
			r.target[len(r.target)-1] ^= 1
		}
	})
	for index := range destination {
		destination[index] = r.fill
	}
	return len(destination), nil
}

func TestEnvelopeSnapshotsCallerBuffersBeforeRandomReaderReentry(t *testing.T) {
	oldKeyring := testKeyring(t, 0x34)
	password := []byte("snapshot this password")
	passwordBefore := bytes.Clone(password)
	sealReader := &reentrantMutationReader{target: password, fill: 0x73}
	envelope, err := oldKeyring.seal(testContext(), password, sealReader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := oldKeyring.Open(testContext(), envelope)
	if err != nil || !bytes.Equal(plaintext, passwordBefore) {
		t.Fatalf("Seal used caller memory after random-reader reentry: plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)

	rotated, err := oldKeyring.rotate(bytes.NewReader(bytes.Repeat([]byte{0x45}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Destroy()
	originalEnvelope := bytes.Clone(envelope)
	rewrapReader := &reentrantMutationReader{target: envelope, fill: 0x83}
	rewrapped, err := rotated.rewrap(testContext(), envelope, rewrapReader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(envelope, originalEnvelope) {
		t.Fatal("reentrant reader did not exercise caller-buffer mutation")
	}
	plaintext, err = rotated.Open(testContext(), rewrapped)
	if err != nil || !bytes.Equal(plaintext, passwordBefore) {
		t.Fatalf("Rewrap aliased caller memory after authentication: plaintext=%q err=%v", plaintext, err)
	}
	clear(plaintext)
}

func TestKeyringDestroyFailsClosedDuringConcurrentCredentialOperations(t *testing.T) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x57}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := keyring.seal(testContext(), []byte("concurrent password"), sealRandom(0x68))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	done := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				plaintext, _ := keyring.Open(testContext(), envelope)
				clear(plaintext)
				sealed, _ := keyring.seal(testContext(), nil, sealRandom(byte(iteration+1)))
				clear(sealed)
				marshaled, _ := keyring.Marshal()
				clear(marshaled)
			}
		}()
	}
	close(start)
	go func() {
		keyring.Destroy()
		close(done)
	}()
	workers.Wait()
	<-done
	if plaintext, err := keyring.Open(testContext(), envelope); !errors.Is(err, ErrInvalidEnvelope) {
		clear(plaintext)
		t.Fatalf("Open after Destroy error = %v", err)
	}
	if _, err := keyring.Marshal(); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("Marshal after Destroy error = %v", err)
	}
}

func TestCopiedKeyringSharesLifecycleSynchronization(t *testing.T) {
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x58}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	copyValue := *keyring
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for iteration := 0; iteration < 1000; iteration++ {
			encoded, _ := keyring.Marshal()
			clear(encoded)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		copyValue.Destroy()
	}()
	close(start)
	workers.Wait()
	if _, err := keyring.Marshal(); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("original copy remained usable after shared Destroy: %v", err)
	}
}

func TestRandomReadersCannotDeadlockKeyringLifecycle(t *testing.T) {
	run := func(t *testing.T, operation func() error) error {
		t.Helper()
		result := make(chan error, 1)
		go func() { result <- operation() }()
		select {
		case err := <-result:
			return err
		case <-time.After(time.Second):
			t.Fatal("credential operation deadlocked in a reentrant random reader")
			return nil
		}
	}

	t.Run("Seal", func(t *testing.T) {
		keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x91}, keySize)))
		if err != nil {
			t.Fatal(err)
		}
		reader := &callbackReader{fill: 0x92, callback: keyring.Destroy}
		err = run(t, func() error {
			_, sealErr := keyring.seal(testContext(), nil, reader)
			return sealErr
		})
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Seal after reentrant Destroy error = %v", err)
		}
	})

	t.Run("Rotate", func(t *testing.T) {
		keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0xa1}, keySize)))
		if err != nil {
			t.Fatal(err)
		}
		reader := &callbackReader{fill: 0xa2, callback: keyring.Destroy}
		err = run(t, func() error {
			_, rotateErr := keyring.rotate(reader)
			return rotateErr
		})
		if !errors.Is(err, ErrInvalidKeyring) {
			t.Fatalf("Rotate after reentrant Destroy error = %v", err)
		}
	})

	t.Run("Rewrap", func(t *testing.T) {
		oldKeyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0xb1}, keySize)))
		if err != nil {
			t.Fatal(err)
		}
		defer oldKeyring.Destroy()
		envelope, err := oldKeyring.seal(testContext(), nil, sealRandom(0xb2))
		if err != nil {
			t.Fatal(err)
		}
		rotated, err := oldKeyring.rotate(bytes.NewReader(bytes.Repeat([]byte{0xb3}, keySize)))
		if err != nil {
			t.Fatal(err)
		}
		reader := &callbackReader{fill: 0xb4, callback: rotated.Destroy}
		err = run(t, func() error {
			_, rewrapErr := rotated.rewrap(testContext(), envelope, reader)
			return rewrapErr
		})
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("Rewrap after reentrant Destroy error = %v", err)
		}
	})
}

var _ io.Reader = (*reentrantMutationReader)(nil)
var _ io.Reader = (*callbackReader)(nil)

func TestCredentialErrorsNeverContainSensitiveMaterial(t *testing.T) {
	keyring := testKeyring(t, 0x56)
	password := []byte("sentinel-password-never-log")
	envelope, err := keyring.seal(testContext(), password, sealRandom(0x91))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 1
	_, openErr := keyring.Open(testContext(), tampered)
	_, parseErr := ParseKeyring(append([]byte("sentinel-keyring-never-log"), envelope...))
	combined := openErr.Error() + " " + parseErr.Error()
	for _, secret := range []string{string(password), "sentinel-keyring-never-log", string(envelope)} {
		if strings.Contains(combined, secret) {
			t.Fatalf("error disclosed sensitive material: %q", combined)
		}
	}
}

func TestEnvelopeRejectsOversizedAndInvalidContext(t *testing.T) {
	keyring := testKeyring(t, 0x67)
	if _, err := keyring.seal(testContext(), make([]byte, maxPasswordBytes+1), sealRandom(0xa1)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("oversized password error = %v", err)
	}
	context := testContext()
	context.CredentialID = strings.ToUpper(context.CredentialID)
	if _, err := keyring.seal(context, nil, sealRandom(0xa2)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("noncanonical credential ID error = %v", err)
	}
	for _, invalidID := range []string{
		"00000000-0000-0000-0000-000000000000",
		"18a6e26f-41c7-1f1e-8da8-94343e0cb9bf",
		"18a6e26f-41c7-4f1e-0da8-94343e0cb9bf",
	} {
		context = testContext()
		context.CredentialID = invalidID
		if _, err := keyring.seal(context, nil, sealRandom(0xa3)); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("credential ID %q error = %v", invalidID, err)
		}
	}
}
