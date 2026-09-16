package oauthsecurity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

type counterReader struct {
	next byte
}

func (r *counterReader) Read(buffer []byte) (int, error) {
	for i := range buffer {
		buffer[i] = r.next
		r.next++
	}
	return len(buffer), nil
}

func testTokenRing(t *testing.T) *TokenKeyring {
	t.Helper()
	ring, err := newTokenKeyring(&counterReader{})
	if err != nil {
		t.Fatalf("newTokenKeyring: %v", err)
	}
	return ring
}

func TestTokenSealOpenRoundTrip(t *testing.T) {
	ring := testTokenRing(t)
	refresh := []byte("refresh-token-value-123")
	defer clear(refresh)
	envelope, err := ring.seal("google", 7, refresh, &counterReader{next: 100})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := ring.Open("google", 7, envelope)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer clear(opened)
	if !bytes.Equal(opened, refresh) {
		t.Fatalf("round trip mismatch")
	}
}

func TestTokenBindingRejectsCrossUse(t *testing.T) {
	ring := testTokenRing(t)
	envelope, err := ring.seal("google", 7, []byte("tok"), &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for name, tc := range map[string]struct {
		provider  string
		principal int
	}{
		"other provider": {"dropbox", 7},
		"other user":     {"google", 8},
		"bad provider":   {"GOOGLE", 7},
		"zero principal": {"google", 0},
	} {
		if _, err := ring.Open(tc.provider, tc.principal, envelope); !errors.Is(err, ErrInvalidTokenEnvelope) {
			t.Fatalf("%s: got %v, want ErrInvalidTokenEnvelope", name, err)
		}
	}
}

func TestTokenTamperRejected(t *testing.T) {
	ring := testTokenRing(t)
	envelope, err := ring.seal("google", 7, []byte("tok"), &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	header := 8 + 1 + tokenKeyIDSize + 24
	mutations := map[string][]byte{
		"magic":      bytes.Clone(envelope),
		"version":    bytes.Clone(envelope),
		"key id":     bytes.Clone(envelope),
		"nonce":      bytes.Clone(envelope),
		"ciphertext": bytes.Clone(envelope),
		"truncated":  bytes.Clone(envelope[:len(envelope)-1]),
		"extended":   append(bytes.Clone(envelope), 0x00),
		"empty":      {},
	}
	mutations["magic"][0] ^= 0xff
	mutations["version"][8] ^= 0xff
	mutations["key id"][9] ^= 0xff
	mutations["nonce"][9+tokenKeyIDSize] ^= 0xff
	mutations["ciphertext"][header] ^= 0xff
	for name, mutated := range mutations {
		if _, err := ring.Open("google", 7, mutated); !errors.Is(err, ErrInvalidTokenEnvelope) && !errors.Is(err, ErrUnknownTokenKey) {
			t.Fatalf("%s: got %v, want envelope rejection", name, err)
		}
	}
}

func TestTokenUnknownKey(t *testing.T) {
	a := testTokenRing(t)
	b, err := newTokenKeyring(&counterReader{next: 200})
	if err != nil {
		t.Fatalf("second ring: %v", err)
	}
	envelope, err := a.seal("google", 7, []byte("tok"), &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := b.Open("google", 7, envelope); !errors.Is(err, ErrUnknownTokenKey) {
		t.Fatalf("got %v, want ErrUnknownTokenKey", err)
	}
}

func TestTokenRotationKeepsOldEnvelopes(t *testing.T) {
	ring := testTokenRing(t)
	reader := &counterReader{}
	old, err := ring.seal("google", 7, []byte("tok"), reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ring.rotateKeyTo(t, reader); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	opened, err := ring.Open("google", 7, old)
	if err != nil {
		t.Fatalf("old envelope must still open: %v", err)
	}
	clear(opened)
	fresh, err := ring.seal("google", 7, []byte("tok2"), reader)
	if err != nil {
		t.Fatalf("seal after rotate: %v", err)
	}
	opened, err = ring.Open("google", 7, fresh)
	if err != nil {
		t.Fatalf("fresh envelope must open: %v", err)
	}
	clear(opened)
}

func (k *TokenKeyring) rotateKeyTo(t *testing.T, random *counterReader) error {
	t.Helper()
	_, err := k.rotateKey(random)
	return err
}

func TestTokenKeyEviction(t *testing.T) {
	ring := testTokenRing(t)
	reader := &counterReader{next: 50}
	first, err := ring.seal("google", 7, []byte("tok"), reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for range maxTokenKeys {
		if _, err := ring.rotateKey(reader); err != nil {
			t.Fatalf("rotate: %v", err)
		}
	}
	if _, err := ring.Open("google", 7, first); !errors.Is(err, ErrUnknownTokenKey) {
		t.Fatalf("evicted key must be unknown, got %v", err)
	}
}

func TestTokenRevoke(t *testing.T) {
	ring := testTokenRing(t)
	envelope, err := ring.seal("google", 7, []byte("tok"), &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ring.Revoke("google", 7, envelope); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := ring.Open("google", 7, envelope); !errors.Is(err, ErrRevokedToken) {
		t.Fatalf("got %v, want ErrRevokedToken", err)
	}
	if err := ring.Revoke("google", 7, envelope); err != nil {
		t.Fatalf("double revoke must be idempotent: %v", err)
	}
	if err := ring.Revoke("google", 7, []byte("garbage")); !errors.Is(err, ErrInvalidTokenEnvelope) {
		t.Fatalf("revoke garbage: got %v", err)
	}
}

func TestTokenRotateToken(t *testing.T) {
	ring := testTokenRing(t)
	reader := &counterReader{}
	old, err := ring.seal("google", 7, []byte("tok"), reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := ring.rotateKey(reader); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	fresh, err := ring.rotateToken("google", 7, old, reader)
	if err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	if _, err := ring.Open("google", 7, old); !errors.Is(err, ErrRevokedToken) {
		t.Fatalf("old must be revoked, got %v", err)
	}
	opened, err := ring.Open("google", 7, fresh)
	if err != nil {
		t.Fatalf("fresh must open: %v", err)
	}
	defer clear(opened)
	if string(opened) != "tok" {
		t.Fatalf("rotated value mismatch")
	}
}

func TestTokenRetainedKey(t *testing.T) {
	a := testTokenRing(t)
	reader := &counterReader{}
	envelope, err := a.seal("google", 7, []byte("tok"), reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	b, err := newTokenKeyring(&counterReader{next: 200})
	if err != nil {
		t.Fatalf("second ring: %v", err)
	}
	if err := b.AddRetainedKey(a.state.active, a.state.keys[a.state.active]); err != nil {
		t.Fatalf("import retained key: %v", err)
	}
	opened, err := b.Open("google", 7, envelope)
	if err != nil {
		t.Fatalf("retained key must open: %v", err)
	}
	clear(opened)
}

func TestTokenSealBounds(t *testing.T) {
	ring := testTokenRing(t)
	big := bytes.Repeat([]byte("a"), maxTokenFieldBytes+1)
	for name, tc := range map[string]struct {
		provider  string
		principal int
		refresh   []byte
	}{
		"empty provider": {"", 7, []byte("tok")},
		"empty refresh":  {"google", 7, []byte{}},
		"oversize":       {"google", 7, big},
		"bad bytes":      {"google", 7, []byte("tok\x00en")},
		"zero principal": {"google", 0, []byte("tok")},
		"huge principal": {"google", maxPrincipalID + 1, []byte("tok")},
	} {
		if _, err := ring.seal(tc.provider, tc.principal, tc.refresh, &counterReader{}); !errors.Is(err, ErrInvalidTokenEnvelope) {
			t.Fatalf("%s: got %v, want rejection", name, err)
		}
	}
}

func TestTokenErrorsCarryNoSecrets(t *testing.T) {
	ring := testTokenRing(t)
	secret := []byte("super-secret-refresh-value")
	envelope, err := ring.seal("google", 7, secret, &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	clear(secret)
	mutated := bytes.Clone(envelope)
	mutated[len(mutated)-1] ^= 0xff
	_, err = ring.Open("google", 7, mutated)
	if err == nil {
		t.Fatalf("tampered envelope must fail")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func TestTokenConcurrentSealOpen(t *testing.T) {
	ring := testTokenRing(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			envelope, err := ring.Seal("google", i+1, []byte("tok"))
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			opened, err := ring.Open("google", i+1, envelope)
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			if string(opened) != "tok" {
				t.Errorf("mismatch")
			}
			clear(opened)
		}()
	}
	wg.Wait()
}

func TestLoadTokenKeyFromEnvironment(t *testing.T) {
	lookup := func(key string) (string, bool) {
		if key == tokenKeyEnvVariable {
			return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true
		}
		return "", false
	}
	material, id, err := loadTokenKey(lookup, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer clear(material[:])
	var zero [tokenKeySize]byte
	if material == zero {
		t.Fatalf("material must be set")
	}
	var zeroID [tokenKeyIDSize]byte
	if id == zeroID {
		t.Fatalf("id must be set")
	}
}

func TestLoadTokenKeyRejects(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]map[string]string{
		"none":         {},
		"both":         {tokenKeyEnvVariable: good, tokenKeyFileEnvVariable: "/x"},
		"short":        {tokenKeyEnvVariable: "abcd"},
		"non hex":      {tokenKeyEnvVariable: strings.Repeat("z", 64)},
		"zero key":     {tokenKeyEnvVariable: strings.Repeat("0", 64)},
		"missing file": {tokenKeyFileEnvVariable: "/nonexistent/key"},
	}
	for name, env := range cases {
		lookup := func(key string) (string, bool) {
			value, ok := env[key]
			return value, ok
		}
		if _, _, err := loadTokenKey(lookup, readCredentialFile); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s: got %v, want ErrInvalidConfiguration", name, err)
		}
	}
}

func TestTokenRevokeRequiresLiveEnvelope(t *testing.T) {
	ring := testTokenRing(t)
	envelope, err := ring.seal("google", 7, []byte("tok"), &counterReader{})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// A well-formed forgery that never decrypted must not consume a slot.
	forged := bytes.Clone(envelope)
	forged[len(forged)-1] ^= 0xff
	forged[len(forged)-2] ^= 0xff
	for range 16 {
		if err := ring.Revoke("google", 7, forged); err == nil {
			t.Fatalf("forged envelope must never revoke")
		}
	}
	// The genuine envelope still revokes afterwards: no exhaustion.
	if err := ring.Revoke("google", 7, envelope); err != nil {
		t.Fatalf("genuine revoke after forgeries: %v", err)
	}
}

func TestTokenKeyIDSurvivesReload(t *testing.T) {
	lookup := func(key string) (string, bool) {
		if key == tokenKeyEnvVariable {
			return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true
		}
		return "", false
	}
	first, firstID, err := loadTokenKey(lookup, nil)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	defer clear(first[:])
	second, secondID, err := loadTokenKey(lookup, nil)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	defer clear(second[:])
	if firstID != secondID {
		t.Fatalf("same key must reload the same ID")
	}
	// Full restart story: ring1 seals under its active key; the operator
	// persists that key material; a fresh ring reimports the reloaded key
	// and opens the pre-restart envelope.
	ring1, err := newTokenKeyring(&counterReader{})
	if err != nil {
		t.Fatalf("ring1: %v", err)
	}
	idA := ring1.state.active
	matA := ring1.state.keys[idA]
	envelope, err := ring1.seal("google", 7, []byte("tok"), &counterReader{next: 200})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	operatorHex := hex.EncodeToString(matA[:])
	clear(matA[:])
	reloaded, reloadedID, err := loadTokenKey(func(key string) (string, bool) {
		if key == tokenKeyEnvVariable {
			return operatorHex, true
		}
		return "", false
	}, nil)
	if err != nil {
		t.Fatalf("reload persisted key: %v", err)
	}
	defer clear(reloaded[:])
	if reloadedID != idA {
		t.Fatalf("reloaded ID must match the sealing key ID")
	}
	ring2, err := newTokenKeyring(&counterReader{next: 100})
	if err != nil {
		t.Fatalf("ring2: %v", err)
	}
	if err := ring2.AddRetainedKey(reloadedID, reloaded); err != nil {
		t.Fatalf("reimport: %v", err)
	}
	clear(reloaded[:])
	opened, err := ring2.Open("google", 7, envelope)
	if err != nil {
		t.Fatalf("pre-restart envelope must open after reload: %v", err)
	}
	clear(opened)
}

func TestTokenConcurrentHammer(t *testing.T) {
	ring := testTokenRing(t)
	envelope, err := ring.Seal("google", 7, []byte("tok"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			principal := n + 1
			sealed, err := ring.Seal("google", principal, []byte("tok"))
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			opened, err := ring.Open("google", principal, sealed)
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			clear(opened)
			_, _ = ring.RotateToken("google", principal, sealed)
			_ = ring.Revoke("google", principal, sealed)
		}(i)
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ring.RotateKey()
			_, _ = ring.Open("google", 7, envelope)
		}()
	}
	wg.Wait()
}
