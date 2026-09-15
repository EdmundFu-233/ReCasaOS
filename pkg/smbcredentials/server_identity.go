package smbcredentials

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
)

const (
	maxServerHostBytes = 253
	maxServerAddresses = 16
	minServerPort      = 1
	maxServerPort      = 65535

	serverIdentityVersion = 1
)

var (
	serverIdentityMagic = [8]byte{'R', 'C', 'S', 'M', 'B', 'S', 'I', 'D'}

	// ErrInvalidServerIdentity reports a malformed host, port, address, or
	// serialized pin. It never carries the offending value.
	ErrInvalidServerIdentity = errors.New("invalid ReCasaOS SMB server identity")
	// ErrServerIdentityChanged reports a hostname or port that differs from
	// the pin. Reconnecting under a changed identity is rejected; the
	// operator must pin the new server explicitly.
	ErrServerIdentityChanged = errors.New("ReCasaOS SMB server identity changed")
	// ErrServerAddressChanged reports a resolved address set that differs
	// from the pin. DNS rebinding and silent failover are rejected; address
	// changes require explicit rotation.
	ErrServerAddressChanged = errors.New("ReCasaOS SMB server address set changed")
)

// ServerIdentity is a trust-on-first-use pin for one SMB server. The pin
// binds the normalized hostname, port, and the full resolved address set
// observed at pin time. It is deliberately not a certificate or Kerberos
// principal: see docs/smb-server-identity.md for the trust anchor it does
// and does not provide.
type ServerIdentity struct {
	host      string
	port      uint16
	addresses []string
}

// PinServerIdentity records the operator-verified identity of one SMB
// server. Host is normalized to lowercase without a trailing dot; addresses
// are deduplicated, sorted text forms of parsed IPs. The pin carries no
// timestamp: freshness comes from Verify at every reconnect, not from age.
func PinServerIdentity(host string, port int, addresses []string) (ServerIdentity, error) {
	normalizedHost, err := normalizeServerHost(host)
	if err != nil {
		return ServerIdentity{}, err
	}
	if port < minServerPort || port > maxServerPort {
		return ServerIdentity{}, ErrInvalidServerIdentity
	}
	normalizedAddresses, err := normalizeServerAddresses(addresses)
	if err != nil {
		return ServerIdentity{}, err
	}
	return ServerIdentity{
		host:      normalizedHost,
		port:      uint16(port),
		addresses: normalizedAddresses,
	}, nil
}

// Host reports the normalized pinned hostname.
func (pin ServerIdentity) Host() string { return pin.host }

// Port reports the pinned port.
func (pin ServerIdentity) Port() int { return int(pin.port) }

// Addresses reports a copy of the pinned address set in sorted order.
func (pin ServerIdentity) Addresses() []string {
	return append([]string(nil), pin.addresses...)
}

// Verify rejects any reconnect whose hostname, port, or resolved address set
// differs from the pin. Address order is insignificant; address set changes
// are not.
func (pin ServerIdentity) Verify(host string, port int, addresses []string) error {
	normalizedHost, err := normalizeServerHost(host)
	if err != nil {
		return err
	}
	if normalizedHost != pin.host || port != int(pin.port) {
		return ErrServerIdentityChanged
	}
	normalizedAddresses, err := normalizeServerAddresses(addresses)
	if err != nil {
		return err
	}
	if !equalAddressSets(normalizedAddresses, pin.addresses) {
		return ErrServerAddressChanged
	}
	return nil
}

// RotateAddresses returns a pin for the same host and port with an explicitly
// adopted address set. Failover and DNS changes are operator actions, never
// silent adaptations: the caller presents the new set after out-of-band
// verification.
func (pin ServerIdentity) RotateAddresses(addresses []string) (ServerIdentity, error) {
	if pin.host == "" || pin.port == 0 || len(pin.addresses) == 0 {
		return ServerIdentity{}, ErrInvalidServerIdentity
	}
	normalizedAddresses, err := normalizeServerAddresses(addresses)
	if err != nil {
		return ServerIdentity{}, err
	}
	return ServerIdentity{
		host:      pin.host,
		port:      pin.port,
		addresses: normalizedAddresses,
	}, nil
}

// Marshal returns the canonical serialization: magic, version, port,
// host, and address count followed by length-prefixed entries. It contains
// no secret and is safe to store beside the keyring backup.
func (pin ServerIdentity) Marshal() ([]byte, error) {
	if pin.host == "" || pin.port == 0 || len(pin.addresses) == 0 {
		return nil, ErrInvalidServerIdentity
	}
	data := make([]byte, 0, 64)
	data = append(data, serverIdentityMagic[:]...)
	data = append(data, serverIdentityVersion)
	data = binary.BigEndian.AppendUint16(data, pin.port)
	var err error
	if data, err = appendUint16(data, len(pin.host)); err != nil {
		return nil, ErrInvalidServerIdentity
	}
	data = append(data, pin.host...)
	if data, err = appendUint16(data, len(pin.addresses)); err != nil {
		return nil, ErrInvalidServerIdentity
	}
	for _, address := range pin.addresses {
		if data, err = appendUint16(data, len(address)); err != nil {
			return nil, ErrInvalidServerIdentity
		}
		data = append(data, address...)
	}
	return data, nil
}

// ParseServerIdentity accepts only the canonical Marshal format.
func ParseServerIdentity(data []byte) (ServerIdentity, error) {
	var pin ServerIdentity
	if len(data) < 8+1+2+2 || !bytes.Equal(data[:8], serverIdentityMagic[:]) || data[8] != serverIdentityVersion {
		return pin, ErrInvalidServerIdentity
	}
	offset := 9
	port := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	hostLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if hostLength < 1 || hostLength > maxServerHostBytes || offset+hostLength+2 > len(data) {
		return pin, ErrInvalidServerIdentity
	}
	host := string(data[offset : offset+hostLength])
	offset += hostLength
	count := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if count < 1 || count > maxServerAddresses {
		return pin, ErrInvalidServerIdentity
	}
	addresses := make([]string, 0, count)
	for range count {
		if offset+2 > len(data) {
			return ServerIdentity{}, ErrInvalidServerIdentity
		}
		length := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if length < 1 || offset+length > len(data) {
			return ServerIdentity{}, ErrInvalidServerIdentity
		}
		addresses = append(addresses, string(data[offset:offset+length]))
		offset += length
	}
	if offset != len(data) {
		return ServerIdentity{}, ErrInvalidServerIdentity
	}
	return PinServerIdentity(host, port, addresses)
}

func normalizeServerHost(host string) (string, error) {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if trimmed == "" || len(trimmed) > maxServerHostBytes || strings.TrimSpace(host) != host {
		return "", ErrInvalidServerIdentity
	}
	if parsed := net.ParseIP(trimmed); parsed != nil {
		return parsed.String(), nil
	}
	labels := strings.Split(trimmed, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidServerIdentity
		}
		for i := 0; i < len(label); i++ {
			switch character := label[i]; {
			case character >= 'a' && character <= 'z',
				character >= '0' && character <= '9',
				character == '-':
			default:
				return "", ErrInvalidServerIdentity
			}
		}
	}
	return trimmed, nil
}

func normalizeServerAddresses(addresses []string) ([]string, error) {
	if len(addresses) < 1 || len(addresses) > maxServerAddresses {
		return nil, ErrInvalidServerIdentity
	}
	seen := make(map[string]struct{}, len(addresses))
	normalized := make([]string, 0, len(addresses))
	for _, raw := range addresses {
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if parsed == nil {
			return nil, ErrInvalidServerIdentity
		}
		text := parsed.String()
		if _, duplicate := seen[text]; duplicate {
			return nil, ErrInvalidServerIdentity
		}
		seen[text] = struct{}{}
		normalized = append(normalized, text)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func equalAddressSets(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
