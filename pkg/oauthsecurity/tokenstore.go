package oauthsecurity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	tokenKeyEnvVariable     = "RECASAOS_OAUTH_TOKEN_KEY"
	tokenKeyFileEnvVariable = "RECASAOS_OAUTH_TOKEN_KEY_FILE"
	tokenKeyHexBytes        = 64
	tokenKeySize            = 32
	tokenKeyIDSize          = 16
	maxTokenKeys            = 8
	maxRevocations          = 8192
	maxPrincipalID          = 1<<31 - 1

	tokenEnvelopeVersion = 1
	tokenAADPurpose      = 1
)

var (
	tokenEnvelopeMagic = [8]byte{'R', 'C', 'O', 'A', 'U', 'T', 'H', '1'}
	tokenAADMagic      = [8]byte{'R', 'C', 'O', 'A', 'U', 'A', 'A', 'D'}

	// ErrInvalidTokenEnvelope reports a malformed sealed refresh token.
	ErrInvalidTokenEnvelope = errors.New("invalid sealed OAuth refresh token")
	// ErrUnknownTokenKey reports that the sealing key is unavailable. It
	// never reveals which key was expected.
	ErrUnknownTokenKey = errors.New("OAuth token sealing key is unavailable")
	// ErrRevokedToken reports a revoked refresh token without revealing why
	// or when it was revoked.
	ErrRevokedToken = errors.New("OAuth refresh token is revoked")
)

// TokenKeyring holds host-protected key-encryption keys for sealed refresh
// tokens. Keys enter only from the process environment or a root-owned 0600
// credential file; the keyring never logs key material. Every method is safe
// for concurrent use: seal/open race rotation and revocation instead of
// crashing on the underlying maps.
type TokenKeyring struct {
	state *tokenKeyringState
}

type tokenKeyringState struct {
	mu      sync.RWMutex
	keys    map[[tokenKeyIDSize]byte][tokenKeySize]byte
	active  [tokenKeyIDSize]byte
	order   [][tokenKeyIDSize]byte
	revoked map[[sha256.Size]byte]struct{}
}

// NewTokenKeyring generates one active sealing key from the CSPRNG.
func NewTokenKeyring() (*TokenKeyring, error) {
	return newTokenKeyring(rand.Reader)
}

func newTokenKeyring(random io.Reader) (*TokenKeyring, error) {
	ring := &TokenKeyring{state: &tokenKeyringState{
		keys:    make(map[[tokenKeyIDSize]byte][tokenKeySize]byte),
		revoked: make(map[[sha256.Size]byte]struct{}),
	}}
	if _, err := ring.rotateKey(random); err != nil {
		return nil, err
	}
	return ring, nil
}

// RotateKey generates a new active key and retains the previous keys (up to
// maxTokenKeys) so envelopes sealed before rotation still open. Retired keys
// are evicted oldest-first, never the active key.
func (k *TokenKeyring) RotateKey() error {
	_, err := k.rotateKey(rand.Reader)
	return err
}

func (k *TokenKeyring) rotateKey(random io.Reader) ([tokenKeyIDSize]byte, error) {
	if k == nil || k.state == nil || random == nil {
		return [tokenKeyIDSize]byte{}, ErrInvalidTokenEnvelope
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	for attempts := 0; attempts < 4; attempts++ {
		var material [tokenKeySize]byte
		if _, err := io.ReadFull(random, material[:]); err != nil {
			return [tokenKeyIDSize]byte{}, ErrInvalidTokenEnvelope
		}
		// The identifier derives from the material itself (like the SMB
		// keyring), so a reloaded key reproduces its identifier and old
		// envelopes keep opening across restarts. Random per-load
		// identifiers would orphan every sealed token on restart.
		id := deriveTokenKeyID(material)
		var zeroKey [tokenKeySize]byte
		if material == zeroKey {
			continue
		}
		if _, exists := k.state.keys[id]; exists {
			clear(material[:])
			continue
		}
		k.state.keys[id] = material
		clear(material[:])
		k.state.order = append(k.state.order, id)
		k.state.active = id
		for len(k.state.order) > maxTokenKeys {
			victim := k.state.order[0]
			k.state.order = k.state.order[1:]
			if victim != k.state.active {
				delete(k.state.keys, victim)
			}
		}
		return id, nil
	}
	return [tokenKeyIDSize]byte{}, ErrInvalidTokenEnvelope
}

// AddRetainedKey imports one previously generated key so envelopes sealed
// before a restart or rotation still open. Duplicate imports are rejected.
// The caller must clear material after a successful import; the keyring
// copies it.
func (k *TokenKeyring) AddRetainedKey(id [tokenKeyIDSize]byte, material [tokenKeySize]byte) error {
	if k == nil || k.state == nil {
		return ErrInvalidTokenEnvelope
	}
	var zeroID [tokenKeyIDSize]byte
	var zeroKey [tokenKeySize]byte
	if id == zeroID || material == zeroKey {
		return ErrInvalidTokenEnvelope
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	if _, duplicate := k.state.keys[id]; duplicate {
		return ErrInvalidTokenEnvelope
	}
	if len(k.state.keys) >= maxTokenKeys {
		return ErrInvalidTokenEnvelope
	}
	k.state.keys[id] = material
	k.state.order = append(k.state.order, id)
	return nil
}

// Seal encrypts one refresh token. The envelope binds the provider,
// principal, and sealing key ID as associated data so a sealed token cannot
// move across providers, users, or keys. The provider and principal must
// come from the authenticated session, never from caller-supplied token
// content. Callers must clear the refresh slice after Seal returns.
func (k *TokenKeyring) Seal(provider string, principalID int, refresh []byte) ([]byte, error) {
	return k.seal(provider, principalID, refresh, rand.Reader)
}

func (k *TokenKeyring) seal(provider string, principalID int, refresh []byte, random io.Reader) ([]byte, error) {
	if k == nil || k.state == nil || random == nil {
		return nil, ErrInvalidTokenEnvelope
	}
	if !ValidProviderName(provider) || principalID < 1 || principalID > maxPrincipalID {
		return nil, ErrInvalidTokenEnvelope
	}
	if len(refresh) < 1 || len(refresh) > maxTokenFieldBytes || !validTokenField(string(refresh)) {
		return nil, ErrInvalidTokenEnvelope
	}
	snapshot := bytes.Clone(refresh)
	defer clear(snapshot)

	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, ErrInvalidTokenEnvelope
	}
	defer clear(nonce[:])

	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	key, ok := k.state.keys[k.state.active]
	if !ok {
		return nil, ErrUnknownTokenKey
	}
	aead, err := chacha20poly1305.NewX(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidTokenEnvelope
	}
	aad, err := tokenAAD(provider, principalID, k.state.active)
	if err != nil {
		return nil, err
	}
	defer clear(aad)

	envelope := make([]byte, 0, 8+1+tokenKeyIDSize+chacha20poly1305.NonceSizeX+len(snapshot)+chacha20poly1305.Overhead)
	envelope = append(envelope, tokenEnvelopeMagic[:]...)
	envelope = append(envelope, tokenEnvelopeVersion)
	envelope = append(envelope, k.state.active[:]...)
	envelope = append(envelope, nonce[:]...)
	envelope = aead.Seal(envelope, nonce[:], snapshot, aad)
	return envelope, nil
}

// Open decrypts one sealed refresh token for the expected provider and
// principal. Both bindings are verified as associated data, so a sealed
// token cannot move across providers or users. Revoked envelopes are
// rejected before decryption so revocation status cannot be probed through
// decryption oracles. Callers must clear the returned refresh slice.
func (k *TokenKeyring) Open(provider string, principalID int, envelope []byte) ([]byte, error) {
	if k == nil || k.state == nil {
		return nil, ErrInvalidTokenEnvelope
	}
	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	return k.openLocked(provider, principalID, envelope)
}

func (k *TokenKeyring) openLocked(provider string, principalID int, envelope []byte) ([]byte, error) {
	if !ValidProviderName(provider) || principalID < 1 || principalID > maxPrincipalID {
		return nil, ErrInvalidTokenEnvelope
	}
	parsed, err := parseTokenEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(envelope)
	if _, revoked := k.state.revoked[digest]; revoked {
		return nil, ErrRevokedToken
	}
	key, ok := k.state.keys[parsed.keyID]
	if !ok {
		return nil, ErrUnknownTokenKey
	}
	aead, err := chacha20poly1305.NewX(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidTokenEnvelope
	}
	aad, err := tokenAAD(provider, principalID, parsed.keyID)
	if err != nil {
		return nil, err
	}
	defer clear(aad)
	refresh, err := aead.Open(nil, parsed.nonce, parsed.ciphertext, aad)
	if err != nil {
		clear(refresh)
		return nil, ErrInvalidTokenEnvelope
	}
	return refresh, nil
}

// Revoke records one sealed envelope as revoked. The envelope must decrypt
// under the given bindings first: revocation without key access would let
// anyone forge unparseable-but-well-formed envelopes and exhaust the bounded
// revocation set. Revoking an already-revoked envelope succeeds silently.
func (k *TokenKeyring) Revoke(provider string, principalID int, envelope []byte) error {
	if k == nil || k.state == nil {
		return ErrInvalidTokenEnvelope
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	if _, err := k.openLocked(provider, principalID, envelope); err != nil {
		if errors.Is(err, ErrRevokedToken) {
			return nil
		}
		return err
	}
	if len(k.state.revoked) >= maxRevocations {
		return ErrInvalidTokenEnvelope
	}
	digest := sha256.Sum256(envelope)
	k.state.revoked[digest] = struct{}{}
	return nil
}

// RotateToken re-seals one live envelope under the active key and revokes the
// old envelope, so a rotated refresh token has exactly one valid sealed form.
// The whole rotation holds the write lock: concurrent rotations of the same
// envelope serialize instead of minting two live forms.
func (k *TokenKeyring) RotateToken(provider string, principalID int, envelope []byte) ([]byte, error) {
	return k.rotateToken(provider, principalID, envelope, rand.Reader)
}

func (k *TokenKeyring) rotateToken(provider string, principalID int, envelope []byte, random io.Reader) ([]byte, error) {
	if k == nil || k.state == nil || random == nil {
		return nil, ErrInvalidTokenEnvelope
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	refresh, err := k.openLocked(provider, principalID, envelope)
	if err != nil {
		return nil, err
	}
	defer clear(refresh)
	resealed, err := k.sealLocked(provider, principalID, refresh, random)
	if err != nil {
		return nil, err
	}
	if len(k.state.revoked) >= maxRevocations {
		clear(resealed)
		return nil, ErrInvalidTokenEnvelope
	}
	digest := sha256.Sum256(envelope)
	k.state.revoked[digest] = struct{}{}
	return resealed, nil
}

// sealLocked seals while the caller holds the state lock.
func (k *TokenKeyring) sealLocked(provider string, principalID int, refresh []byte, random io.Reader) ([]byte, error) {
	snapshot := bytes.Clone(refresh)
	defer clear(snapshot)

	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, ErrInvalidTokenEnvelope
	}
	defer clear(nonce[:])

	key, ok := k.state.keys[k.state.active]
	if !ok {
		return nil, ErrUnknownTokenKey
	}
	aead, err := chacha20poly1305.NewX(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidTokenEnvelope
	}
	aad, err := tokenAAD(provider, principalID, k.state.active)
	if err != nil {
		return nil, err
	}
	defer clear(aad)

	envelope := make([]byte, 0, 8+1+tokenKeyIDSize+chacha20poly1305.NonceSizeX+len(snapshot)+chacha20poly1305.Overhead)
	envelope = append(envelope, tokenEnvelopeMagic[:]...)
	envelope = append(envelope, tokenEnvelopeVersion)
	envelope = append(envelope, k.state.active[:]...)
	envelope = append(envelope, nonce[:]...)
	envelope = aead.Seal(envelope, nonce[:], snapshot, aad)
	return envelope, nil
}

type parsedTokenEnvelope struct {
	keyID      [tokenKeyIDSize]byte
	nonce      []byte
	ciphertext []byte
}

// The envelope header carries only the key ID: provider and principal are
// authenticated as associated data supplied by the caller of Open, so no
// binding metadata leaks from the sealed bytes themselves.
func parseTokenEnvelope(envelope []byte) (parsedTokenEnvelope, error) {
	var parsed parsedTokenEnvelope
	header := 8 + 1 + tokenKeyIDSize + chacha20poly1305.NonceSizeX
	minimum := header + chacha20poly1305.Overhead + 1
	maximum := header + maxTokenFieldBytes + chacha20poly1305.Overhead
	if len(envelope) < minimum || len(envelope) > maximum {
		return parsed, ErrInvalidTokenEnvelope
	}
	if !bytes.Equal(envelope[:8], tokenEnvelopeMagic[:]) || envelope[8] != tokenEnvelopeVersion {
		return parsed, ErrInvalidTokenEnvelope
	}
	offset := 9
	copy(parsed.keyID[:], envelope[offset:offset+tokenKeyIDSize])
	offset += tokenKeyIDSize
	parsed.nonce = envelope[offset : offset+chacha20poly1305.NonceSizeX]
	offset += chacha20poly1305.NonceSizeX
	parsed.ciphertext = envelope[offset:]
	return parsed, nil
}

func tokenAAD(provider string, principalID int, keyID [tokenKeyIDSize]byte) ([]byte, error) {
	if !ValidProviderName(provider) || principalID < 1 || principalID > maxPrincipalID {
		return nil, ErrInvalidTokenEnvelope
	}
	aad := make([]byte, 0, 8+1+2+len(provider)+8+tokenKeyIDSize)
	aad = append(aad, tokenAADMagic[:]...)
	aad = append(aad, tokenAADPurpose)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(provider)))
	aad = append(aad, provider...)
	aad = binary.BigEndian.AppendUint64(aad, uint64(principalID))
	aad = append(aad, keyID[:]...)
	return aad, nil
}

// deriveTokenKeyID binds the key identifier to the key material itself, so a
// restarted process reloads the same identifier for the same key and
// previously sealed envelopes keep opening. Random per-load identifiers
// would orphan every sealed token on restart.
func deriveTokenKeyID(material [tokenKeySize]byte) [tokenKeyIDSize]byte {
	digest := sha256.Sum256(material[:])
	var id [tokenKeyIDSize]byte
	copy(id[:], digest[:tokenKeyIDSize])
	clear(digest[:])
	return id
}

// LoadTokenKey loads the 32-byte token sealing key from exactly one source:
// RECASAOS_OAUTH_TOKEN_KEY (64 hex characters) or
// RECASAOS_OAUTH_TOKEN_KEY_FILE (a root-owned 0600 file with the same
// content). The returned material must be cleared by the caller after the
// keyring takes ownership.
func LoadTokenKey() ([tokenKeySize]byte, [tokenKeyIDSize]byte, error) {
	return loadTokenKey(os.LookupEnv, readCredentialFile)
}

func loadTokenKey(lookup func(string) (string, bool), readCredential func(string) ([]byte, error)) ([tokenKeySize]byte, [tokenKeyIDSize]byte, error) {
	var material [tokenKeySize]byte
	var id [tokenKeyIDSize]byte
	inline, inlinePresent := lookup(tokenKeyEnvVariable)
	file, filePresent := lookup(tokenKeyFileEnvVariable)
	if inlinePresent == filePresent {
		return material, id, ErrInvalidConfiguration
	}
	var raw string
	if inlinePresent {
		raw = strings.TrimSpace(inline)
	} else {
		content, err := readCredential(file)
		if err != nil {
			return material, id, ErrInvalidConfiguration
		}
		defer clear(content)
		raw = strings.TrimSpace(string(content))
	}
	if len(raw) != tokenKeyHexBytes {
		return material, id, ErrInvalidConfiguration
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != tokenKeySize {
		clear(decoded)
		return material, id, ErrInvalidConfiguration
	}
	copy(material[:], decoded)
	clear(decoded)
	var zero [tokenKeySize]byte
	if material == zero {
		clear(material[:])
		return material, id, ErrInvalidConfiguration
	}
	return material, deriveTokenKeyID(material), nil
}
