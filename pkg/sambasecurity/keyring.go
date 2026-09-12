package sambasecurity

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyringHeader   = "recasaos-samba-keyring-v1"
	envelopePrefix  = "recasaos-samba-password-v1"
	keyIDBytes      = 8
	maximumKeyCount = 8
	maximumKeyring  = 4096
	maximumSecret   = 1024
	maximumContext  = 1024
	maximumEnvelope = 4096
	activeKeyRole   = "active"
	decryptKeyRole  = "decrypt"
)

var (
	ErrInvalidKeyring  = errors.New("invalid Samba credential keyring")
	ErrInvalidEnvelope = errors.New("invalid encrypted Samba credential")
)

// Keyring holds one active encryption key and a bounded set of decrypt-only
// keys. It is immutable after parsing and is therefore safe for concurrent use.
// Key material is retained only inside the AEAD implementations.
type Keyring struct {
	activeID string
	active   cipher.AEAD
	keys     map[string]cipher.AEAD
}

// ParseKeyring accepts a deliberately small, exact text format:
//
//	recasaos-samba-keyring-v1
//	active:<16 lowercase hex key ID>:<64 lowercase hex key bytes>
//	decrypt:<16 lowercase hex key ID>:<64 lowercase hex key bytes>
//
// The key ID is the first eight bytes of SHA-256(key), encoded as lowercase
// hexadecimal. Requiring that derivation catches accidental key/ID mismatches
// during rotation without exposing the key itself.
func ParseKeyring(data []byte) (*Keyring, error) {
	if len(data) == 0 || len(data) > maximumKeyring || data[len(data)-1] != '\n' ||
		strings.ContainsRune(string(data), '\r') || strings.ContainsRune(string(data), '\x00') {
		return nil, ErrInvalidKeyring
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) < 2 || len(lines) > maximumKeyCount+1 || lines[0] != keyringHeader {
		return nil, ErrInvalidKeyring
	}

	result := &Keyring{keys: make(map[string]cipher.AEAD, len(lines)-1)}
	for _, line := range lines[1:] {
		fields := strings.Split(line, ":")
		if len(fields) != 3 || fields[0] != activeKeyRole && fields[0] != decryptKeyRole ||
			!isLowerHex(fields[1], keyIDBytes*2) || !isLowerHex(fields[2], chacha20poly1305.KeySize*2) {
			return nil, ErrInvalidKeyring
		}
		key, err := hex.DecodeString(fields[2])
		if err != nil || len(key) != chacha20poly1305.KeySize {
			clear(key)
			return nil, ErrInvalidKeyring
		}
		digest := sha256.Sum256(key)
		expectedID := hex.EncodeToString(digest[:keyIDBytes])
		if fields[1] != expectedID {
			clear(key)
			return nil, ErrInvalidKeyring
		}
		if _, duplicate := result.keys[fields[1]]; duplicate {
			clear(key)
			return nil, ErrInvalidKeyring
		}
		aead, err := chacha20poly1305.NewX(key)
		clear(key)
		if err != nil {
			return nil, ErrInvalidKeyring
		}
		result.keys[fields[1]] = aead
		if fields[0] == activeKeyRole {
			if result.active != nil {
				return nil, ErrInvalidKeyring
			}
			result.activeID = fields[1]
			result.active = aead
		}
	}
	if result.active == nil || len(result.keys) == 0 {
		return nil, ErrInvalidKeyring
	}
	return result, nil
}

// Seal encrypts one database field with the active key. Context is authenticated
// but not stored; callers should bind it to stable, canonical row attributes.
func (k *Keyring) Seal(plaintext, context []byte) (string, error) {
	if k == nil || k.active == nil || len(k.activeID) != keyIDBytes*2 ||
		len(plaintext) > maximumSecret || len(context) == 0 || len(context) > maximumContext {
		return "", ErrInvalidEnvelope
	}
	nonce := make([]byte, k.active.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New("generate encrypted Samba credential nonce")
	}
	ciphertext := k.active.Seal(nil, nonce, plaintext, context)
	return strings.Join([]string{
		envelopePrefix,
		k.activeID,
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(ciphertext),
	}, ":"), nil
}

// Open authenticates and decrypts one database field. needsRotation is true
// when a decrypt-only key was used, allowing startup migration to re-encrypt
// the row under the active key before an old key is retired.
func (k *Keyring) Open(envelope string, context []byte) (plaintext []byte, needsRotation bool, err error) {
	if k == nil || len(envelope) == 0 || len(envelope) > maximumEnvelope ||
		len(context) == 0 || len(context) > maximumContext {
		return nil, false, ErrInvalidEnvelope
	}
	fields := strings.Split(envelope, ":")
	if len(fields) != 4 || fields[0] != envelopePrefix || !isLowerHex(fields[1], keyIDBytes*2) {
		return nil, false, ErrInvalidEnvelope
	}
	aead, ok := k.keys[fields[1]]
	if !ok {
		return nil, false, ErrInvalidEnvelope
	}
	nonce, err := decodeCanonicalBase64(fields[2], aead.NonceSize(), aead.NonceSize())
	if err != nil {
		return nil, false, ErrInvalidEnvelope
	}
	ciphertext, err := decodeCanonicalBase64(fields[3], aead.Overhead(), maximumSecret+aead.Overhead())
	if err != nil {
		return nil, false, ErrInvalidEnvelope
	}
	plaintext, err = aead.Open(nil, nonce, ciphertext, context)
	if err != nil || len(plaintext) > maximumSecret {
		clear(plaintext)
		return nil, false, ErrInvalidEnvelope
	}
	return plaintext, fields[1] != k.activeID, nil
}

func decodeCanonicalBase64(value string, minimum, maximum int) ([]byte, error) {
	if value == "" || strings.ContainsRune(value, '=') {
		return nil, ErrInvalidEnvelope
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, ErrInvalidEnvelope
	}
	return decoded, nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
