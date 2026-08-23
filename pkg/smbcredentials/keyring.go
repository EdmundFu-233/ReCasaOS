package smbcredentials

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"sync"
)

const (
	CredentialName = "recasaos-smb-keyring"
	keySize        = 32
	keyIDSize      = sha256.Size
	maxKeys        = 8
)

var (
	keyringMagic = [8]byte{'R', 'C', 'S', 'M', 'B', 'K', 'E', 'Y'}

	ErrInvalidKeyring = errors.New("invalid ReCasaOS SMB keyring")
	ErrKeyringFull    = errors.New("ReCasaOS SMB keyring is full")
)

type keyID [keyIDSize]byte
type keyMaterial [keySize]byte

type keyringState struct {
	mu     sync.RWMutex
	active keyID
	keys   map[keyID]keyMaterial
}

// Keyring is an immutable, bounded collection of key-encryption keys. Copies
// share one synchronized state, so a copied value cannot bypass Destroy or
// race the underlying map through an independent mutex. The active key
// encrypts new envelopes; retained keys decrypt during a staged rotation.
// Destroy waits for operations holding shared key state. Operations still in
// a pre-key phase fail closed when they later try to acquire that state, and
// every shared copy becomes unusable.
type Keyring struct {
	state *keyringState
}

// NewKeyring creates a one-key keyring from the operating system CSPRNG.
func NewKeyring() (*Keyring, error) {
	return newKeyring(rand.Reader)
}

func newKeyring(random io.Reader) (*Keyring, error) {
	if random == nil {
		return nil, ErrInvalidKeyring
	}
	var key keyMaterial
	if _, err := io.ReadFull(random, key[:]); err != nil {
		clear(key[:])
		return nil, ErrInvalidKeyring
	}
	id := deriveKeyID(&key)
	keys := map[keyID]keyMaterial{id: key}
	clear(key[:])
	return &Keyring{state: &keyringState{active: id, keys: keys}}, nil
}

// ParseKeyring accepts only the canonical binary v1 format emitted by Marshal.
// It copies key material and cannot clear the caller-owned input; callers must
// clear that input as soon as it is no longer needed.
func ParseKeyring(data []byte) (*Keyring, error) {
	const fixedSize = len(keyringMagic) + 1 + 1 + keyIDSize
	if len(data) < fixedSize || !bytes.Equal(data[:len(keyringMagic)], keyringMagic[:]) || data[len(keyringMagic)] != 1 {
		return nil, ErrInvalidKeyring
	}
	count := int(data[len(keyringMagic)+1])
	if count < 1 || count > maxKeys || len(data) != fixedSize+count*(keyIDSize+keySize) {
		return nil, ErrInvalidKeyring
	}
	var active keyID
	copy(active[:], data[len(keyringMagic)+2:fixedSize])
	keys := make(map[keyID]keyMaterial, count)
	offset := fixedSize
	var previous keyID
	for index := 0; index < count; index++ {
		var id keyID
		var key keyMaterial
		copy(id[:], data[offset:offset+keyIDSize])
		offset += keyIDSize
		copy(key[:], data[offset:offset+keySize])
		offset += keySize
		if id != deriveKeyID(&key) || index > 0 && bytes.Compare(previous[:], id[:]) >= 0 {
			clear(key[:])
			destroyKeyMap(keys)
			return nil, ErrInvalidKeyring
		}
		if _, exists := keys[id]; exists {
			clear(key[:])
			destroyKeyMap(keys)
			return nil, ErrInvalidKeyring
		}
		keys[id] = key
		clear(key[:])
		previous = id
	}
	if _, exists := keys[active]; !exists {
		destroyKeyMap(keys)
		return nil, ErrInvalidKeyring
	}
	return &Keyring{state: &keyringState{active: active, keys: keys}}, nil
}

// Marshal returns the one canonical representation: version 1, active key ID,
// and entries sorted by their derived IDs. The returned buffer contains raw
// keys and must be cleared immediately after its bounded use.
func (k *Keyring) Marshal() ([]byte, error) {
	if k == nil || k.state == nil {
		return nil, ErrInvalidKeyring
	}
	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if err := k.validateLocked(); err != nil {
		return nil, err
	}
	ids := k.sortedIDs()
	data := make([]byte, len(keyringMagic)+1+1+keyIDSize+len(ids)*(keyIDSize+keySize))
	copy(data, keyringMagic[:])
	data[len(keyringMagic)] = 1
	data[len(keyringMagic)+1] = byte(len(ids))
	copy(data[len(keyringMagic)+2:], k.state.active[:])
	offset := len(keyringMagic) + 2 + keyIDSize
	for _, id := range ids {
		key := k.state.keys[id]
		copy(data[offset:], id[:])
		offset += keyIDSize
		copy(data[offset:], key[:])
		offset += keySize
		clear(key[:])
	}
	return data, nil
}

// Rotate returns a new keyring with a fresh CSPRNG-generated active key and
// every existing key retained for decryption. The receiver is not modified.
func (k *Keyring) Rotate() (*Keyring, error) {
	return k.rotate(rand.Reader)
}

func (k *Keyring) rotate(random io.Reader) (*Keyring, error) {
	if k == nil || k.state == nil || random == nil {
		return nil, ErrInvalidKeyring
	}
	for attempts := 0; attempts < 4; attempts++ {
		var key keyMaterial
		if _, err := io.ReadFull(random, key[:]); err != nil {
			clear(key[:])
			return nil, ErrInvalidKeyring
		}
		id := deriveKeyID(&key)
		k.state.mu.RLock()
		if err := k.validateLocked(); err != nil {
			k.state.mu.RUnlock()
			clear(key[:])
			return nil, ErrInvalidKeyring
		}
		if len(k.state.keys) >= maxKeys {
			k.state.mu.RUnlock()
			clear(key[:])
			return nil, ErrKeyringFull
		}
		if _, exists := k.state.keys[id]; exists {
			k.state.mu.RUnlock()
			clear(key[:])
			continue
		}
		keys := cloneKeyMap(k.state.keys)
		keys[id] = key
		clear(key[:])
		rotated := &Keyring{state: &keyringState{active: id, keys: keys}}
		k.state.mu.RUnlock()
		return rotated, nil
	}
	return nil, ErrInvalidKeyring
}

func (k *Keyring) ActiveID() string {
	if k == nil || k.state == nil {
		return ""
	}
	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if k.validateLocked() != nil {
		return ""
	}
	return hex.EncodeToString(k.state.active[:])
}

func (k *Keyring) KeyIDs() []string {
	if k == nil || k.state == nil {
		return nil
	}
	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if k.validateLocked() != nil {
		return nil
	}
	ids := k.sortedIDs()
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		result = append(result, hex.EncodeToString(id[:]))
	}
	return result
}

func (k *Keyring) Destroy() {
	if k == nil || k.state == nil {
		return
	}
	k.state.mu.Lock()
	defer k.state.mu.Unlock()
	destroyKeyMap(k.state.keys)
	clear(k.state.active[:])
	k.state.keys = nil
}

func (k *Keyring) validateLocked() error {
	if k == nil || k.state == nil || len(k.state.keys) < 1 || len(k.state.keys) > maxKeys {
		return ErrInvalidKeyring
	}
	if _, exists := k.state.keys[k.state.active]; !exists {
		return ErrInvalidKeyring
	}
	for id, key := range k.state.keys {
		valid := id == deriveKeyID(&key)
		clear(key[:])
		if !valid {
			return ErrInvalidKeyring
		}
	}
	return nil
}

func (k *Keyring) sortedIDs() []keyID {
	ids := make([]keyID, 0, len(k.state.keys))
	for id := range k.state.keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	return ids
}

func deriveKeyID(key *keyMaterial) keyID {
	return keyID(sha256.Sum256(key[:]))
}

func encodeKeyID(id keyID) string {
	return hex.EncodeToString(id[:])
}

func cloneKeyMap(source map[keyID]keyMaterial) map[keyID]keyMaterial {
	result := make(map[keyID]keyMaterial, len(source))
	for id, key := range source {
		result[id] = key
		clear(key[:])
	}
	return result
}

func destroyKeyMap(keys map[keyID]keyMaterial) {
	for id, key := range keys {
		clear(key[:])
		keys[id] = key
		delete(keys, id)
	}
}

func appendUint16(destination []byte, value int) ([]byte, error) {
	if value < 0 || value > int(^uint16(0)) {
		return nil, ErrInvalidEnvelope
	}
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], uint16(value))
	return append(destination, encoded[:]...), nil
}
