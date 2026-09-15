package smbcredentials

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EnvelopeFormat       = "recasaos-smb-envelope-v1"
	maxPasswordBytes     = 1024
	maxDirectoriesBytes  = 16 << 10
	envelopeFixedSize    = 8 + 1 + 1 + 2 + keyIDSize + chacha20poly1305.NonceSizeX + (keySize + chacha20poly1305.Overhead) + chacha20poly1305.NonceSizeX + 2
	minEnvelopeBytes     = envelopeFixedSize + chacha20poly1305.Overhead
	maxEnvelopeBytes     = envelopeFixedSize + maxPasswordBytes + chacha20poly1305.Overhead
	envelopeAlgorithmV1  = 1
	envelopeVersionV1    = 1
	aadPurposeWrappedDEK = 1
	aadPurposePassword   = 2
)

var (
	envelopeMagic = [8]byte{'R', 'C', 'S', 'M', 'B', 'E', 'N', 'V'}
	aadMagic      = [8]byte{'R', 'C', 'S', 'M', 'B', 'A', 'A', 'D'}

	ErrInvalidEnvelope = errors.New("invalid ReCasaOS SMB credential envelope")
	ErrUnknownKey      = errors.New("ReCasaOS SMB credential key is unavailable")
	ErrAuthentication  = errors.New("ReCasaOS SMB credential authentication failed")
)

type Context struct {
	CredentialID string
	Username     string
	Host         string
	Port         string
	Directories  string
}

type parsedEnvelope struct {
	keyID      keyID
	wrapNonce  []byte
	wrappedDEK []byte
	dataNonce  []byte
	ciphertext []byte
}

// Seal creates a two-layer envelope using the operating system CSPRNG: a
// random per-row DEK encrypts the password, and the active key-encryption key
// wraps only that DEK. Rotation can therefore rewrap the DEK without
// re-encrypting the password payload.
func (k *Keyring) Seal(context Context, password []byte) ([]byte, error) {
	return k.seal(context, password, rand.Reader)
}

func (k *Keyring) seal(context Context, password []byte, random io.Reader) ([]byte, error) {
	if k == nil || k.state == nil || random == nil || len(password) > maxPasswordBytes {
		return nil, ErrInvalidEnvelope
	}
	passwordSnapshot := bytes.Clone(password)
	defer clear(passwordSnapshot)
	var dek keyMaterial
	wrapNonce := make([]byte, chacha20poly1305.NonceSizeX)
	dataNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, dek[:]); err != nil {
		clear(dek[:])
		clear(wrapNonce)
		clear(dataNonce)
		return nil, ErrInvalidEnvelope
	}
	if _, err := io.ReadFull(random, wrapNonce); err != nil {
		clear(dek[:])
		clear(wrapNonce)
		clear(dataNonce)
		return nil, ErrInvalidEnvelope
	}
	if _, err := io.ReadFull(random, dataNonce); err != nil {
		clear(dek[:])
		clear(wrapNonce)
		clear(dataNonce)
		return nil, ErrInvalidEnvelope
	}
	defer clear(dek[:])
	defer clear(wrapNonce)
	defer clear(dataNonce)

	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if err := k.validateLocked(); err != nil {
		return nil, ErrInvalidEnvelope
	}
	dataAAD, err := contextAAD(context, aadPurposePassword, keyID{})
	if err != nil {
		return nil, err
	}
	wrapAAD, err := contextAAD(context, aadPurposeWrappedDEK, k.state.active)
	if err != nil {
		clear(dataAAD)
		return nil, err
	}
	defer clear(dataAAD)
	defer clear(wrapAAD)

	dataAEAD, err := chacha20poly1305.NewX(dek[:])
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	key := k.state.keys[k.state.active]
	wrapAEAD, err := chacha20poly1305.NewX(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidEnvelope
	}

	wrappedDEK := wrapAEAD.Seal(nil, wrapNonce, dek[:], wrapAAD)
	ciphertext := dataAEAD.Seal(nil, dataNonce, passwordSnapshot, dataAAD)
	result, err := marshalEnvelope(k.state.active, wrapNonce, wrappedDEK, dataNonce, ciphertext)
	clear(wrappedDEK)
	clear(ciphertext)
	return result, err
}

// Open authenticates both layers and returns a caller-owned plaintext buffer.
// The caller must clear the returned slice immediately after its bounded use.
func (k *Keyring) Open(context Context, envelope []byte) ([]byte, error) {
	if k == nil || k.state == nil || !validEnvelopeLength(envelope) {
		return nil, ErrInvalidEnvelope
	}
	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if err := k.validateLocked(); err != nil {
		return nil, ErrInvalidEnvelope
	}
	envelopeSnapshot := bytes.Clone(envelope)
	defer clear(envelopeSnapshot)
	return k.openLocked(context, envelopeSnapshot)
}

func (k *Keyring) openLocked(context Context, envelope []byte) ([]byte, error) {
	parsed, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	key, exists := k.state.keys[parsed.keyID]
	if !exists {
		return nil, ErrUnknownKey
	}
	wrapAAD, err := contextAAD(context, aadPurposeWrappedDEK, parsed.keyID)
	if err != nil {
		clear(key[:])
		return nil, err
	}
	wrapAEAD, err := chacha20poly1305.NewX(key[:])
	clear(key[:])
	if err != nil {
		clear(wrapAAD)
		return nil, ErrInvalidEnvelope
	}
	dek, err := wrapAEAD.Open(nil, parsed.wrapNonce, parsed.wrappedDEK, wrapAAD)
	clear(wrapAAD)
	if err != nil || len(dek) != keySize {
		clear(dek)
		return nil, ErrAuthentication
	}
	defer clear(dek)
	dataAEAD, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	dataAAD, err := contextAAD(context, aadPurposePassword, keyID{})
	if err != nil {
		return nil, err
	}
	plaintext, err := dataAEAD.Open(nil, parsed.dataNonce, parsed.ciphertext, dataAAD)
	clear(dataAAD)
	if err != nil || len(plaintext) > maxPasswordBytes {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// Rewrap authenticates the complete envelope and uses the operating system
// CSPRNG to wrap its DEK with the active key. The password ciphertext and its
// nonce remain byte-for-byte unchanged.
func (k *Keyring) Rewrap(context Context, envelope []byte) ([]byte, error) {
	return k.rewrap(context, envelope, rand.Reader)
}

func (k *Keyring) rewrap(context Context, envelope []byte, random io.Reader) ([]byte, error) {
	if k == nil || k.state == nil || random == nil || !validEnvelopeLength(envelope) {
		return nil, ErrInvalidEnvelope
	}
	envelopeSnapshot := bytes.Clone(envelope)
	defer clear(envelopeSnapshot)
	parsed, err := parseEnvelope(envelopeSnapshot)
	if err != nil {
		return nil, err
	}

	// An already-active envelope is an authenticated no-op and does not consume
	// entropy. For a real rewrap, release the lifecycle lock before calling the
	// external test reader, then revalidate after reacquiring it. Production
	// callers always use crypto/rand.Reader through Rewrap.
	k.state.mu.RLock()
	if err := k.validateLocked(); err != nil {
		k.state.mu.RUnlock()
		return nil, ErrInvalidEnvelope
	}
	if parsed.keyID == k.state.active {
		plaintext, openErr := k.openLocked(context, envelopeSnapshot)
		clear(plaintext)
		if openErr != nil {
			k.state.mu.RUnlock()
			return nil, openErr
		}
		result := bytes.Clone(envelopeSnapshot)
		k.state.mu.RUnlock()
		return result, nil
	}
	k.state.mu.RUnlock()

	newNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(random, newNonce); err != nil {
		clear(newNonce)
		return nil, ErrInvalidEnvelope
	}
	defer clear(newNonce)

	k.state.mu.RLock()
	defer k.state.mu.RUnlock()
	if err := k.validateLocked(); err != nil {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := k.openLocked(context, envelopeSnapshot)
	if err != nil {
		return nil, err
	}
	clear(plaintext)
	oldKey, exists := k.state.keys[parsed.keyID]
	if !exists {
		return nil, ErrUnknownKey
	}
	oldAAD, err := contextAAD(context, aadPurposeWrappedDEK, parsed.keyID)
	if err != nil {
		clear(oldKey[:])
		return nil, err
	}
	oldAEAD, err := chacha20poly1305.NewX(oldKey[:])
	clear(oldKey[:])
	if err != nil {
		clear(oldAAD)
		return nil, ErrInvalidEnvelope
	}
	dek, err := oldAEAD.Open(nil, parsed.wrapNonce, parsed.wrappedDEK, oldAAD)
	clear(oldAAD)
	if err != nil || len(dek) != keySize {
		clear(dek)
		return nil, ErrAuthentication
	}
	defer clear(dek)

	newKey := k.state.keys[k.state.active]
	newAEAD, err := chacha20poly1305.NewX(newKey[:])
	clear(newKey[:])
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	newAAD, err := contextAAD(context, aadPurposeWrappedDEK, k.state.active)
	if err != nil {
		return nil, err
	}
	defer clear(newAAD)
	wrappedDEK := newAEAD.Seal(nil, newNonce, dek, newAAD)
	result, err := marshalEnvelope(k.state.active, newNonce, wrappedDEK, parsed.dataNonce, parsed.ciphertext)
	clear(wrappedDEK)
	return result, err
}

// EnvelopeKeyID authenticates the complete envelope before returning its
// non-secret wrapping-key identifier. It is safe for rotation status checks.
func (k *Keyring) EnvelopeKeyID(context Context, envelope []byte) (string, error) {
	if !validEnvelopeLength(envelope) {
		return "", ErrInvalidEnvelope
	}
	envelopeSnapshot := bytes.Clone(envelope)
	defer clear(envelopeSnapshot)
	plaintext, err := k.Open(context, envelopeSnapshot)
	if err != nil {
		return "", err
	}
	clear(plaintext)
	parsed, err := parseEnvelope(envelopeSnapshot)
	if err != nil {
		return "", err
	}
	return encodeKeyID(parsed.keyID), nil
}

func marshalEnvelope(id keyID, wrapNonce, wrappedDEK, dataNonce, ciphertext []byte) ([]byte, error) {
	if len(wrapNonce) != chacha20poly1305.NonceSizeX || len(wrappedDEK) != keySize+chacha20poly1305.Overhead || len(dataNonce) != chacha20poly1305.NonceSizeX || len(ciphertext) < chacha20poly1305.Overhead || len(ciphertext) > maxPasswordBytes+chacha20poly1305.Overhead {
		return nil, ErrInvalidEnvelope
	}
	result := make([]byte, envelopeFixedSize+len(ciphertext))
	copy(result, envelopeMagic[:])
	result[8] = envelopeVersionV1
	result[9] = envelopeAlgorithmV1
	copy(result[12:12+keyIDSize], id[:])
	offset := 12 + keyIDSize
	copy(result[offset:], wrapNonce)
	offset += len(wrapNonce)
	copy(result[offset:], wrappedDEK)
	offset += len(wrappedDEK)
	copy(result[offset:], dataNonce)
	offset += len(dataNonce)
	binary.BigEndian.PutUint16(result[offset:offset+2], uint16(len(ciphertext)))
	offset += 2
	copy(result[offset:], ciphertext)
	return result, nil
}

func parseEnvelope(data []byte) (parsedEnvelope, error) {
	var result parsedEnvelope
	if !validEnvelopeLength(data) || !bytes.Equal(data[:8], envelopeMagic[:]) || data[8] != envelopeVersionV1 || data[9] != envelopeAlgorithmV1 || data[10] != 0 || data[11] != 0 {
		return result, ErrInvalidEnvelope
	}
	copy(result.keyID[:], data[12:12+keyIDSize])
	offset := 12 + keyIDSize
	result.wrapNonce = data[offset : offset+chacha20poly1305.NonceSizeX]
	offset += chacha20poly1305.NonceSizeX
	result.wrappedDEK = data[offset : offset+keySize+chacha20poly1305.Overhead]
	offset += keySize + chacha20poly1305.Overhead
	result.dataNonce = data[offset : offset+chacha20poly1305.NonceSizeX]
	offset += chacha20poly1305.NonceSizeX
	ciphertextLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if ciphertextLength < chacha20poly1305.Overhead || ciphertextLength > maxPasswordBytes+chacha20poly1305.Overhead || len(data) != offset+ciphertextLength {
		return parsedEnvelope{}, ErrInvalidEnvelope
	}
	result.ciphertext = data[offset:]
	return result, nil
}

func validEnvelopeLength(data []byte) bool {
	return len(data) >= minEnvelopeBytes && len(data) <= maxEnvelopeBytes
}

func contextAAD(context Context, purpose byte, id keyID) ([]byte, error) {
	parsedID, err := uuid.Parse(context.CredentialID)
	if err != nil || parsedID == uuid.Nil || parsedID.Version() != 4 || parsedID.Variant() != uuid.RFC4122 || parsedID.String() != context.CredentialID || context.Username == "" || len(context.Username) > 255 || context.Host == "" || len(context.Host) > 255 || context.Port != "445" || context.Directories == "" || len(context.Directories) > maxDirectoriesBytes {
		return nil, ErrInvalidEnvelope
	}
	for _, value := range []string{context.Username, context.Host, context.Port, context.Directories} {
		if !utf8.ValidString(value) {
			return nil, ErrInvalidEnvelope
		}
	}
	result := make([]byte, 0, len(aadMagic)+2+16+keyIDSize+len(context.Username)+len(context.Host)+len(context.Port)+len(context.Directories)+8)
	result = append(result, aadMagic[:]...)
	result = append(result, envelopeVersionV1, purpose)
	result = append(result, parsedID[:]...)
	if purpose == aadPurposeWrappedDEK {
		result = append(result, id[:]...)
	} else if purpose != aadPurposePassword {
		return nil, ErrInvalidEnvelope
	}
	for _, value := range []string{context.Username, context.Host, context.Port, context.Directories} {
		result, err = appendUint16(result, len(value))
		if err != nil {
			clear(result)
			return nil, ErrInvalidEnvelope
		}
		result = append(result, value...)
	}
	return result, nil
}
