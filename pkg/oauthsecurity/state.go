package oauthsecurity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultStateTTL bounds how long an initiated authorization may complete.
	DefaultStateTTL = 10 * time.Minute
	// DefaultMaxRecords bounds concurrent in-flight authorizations.
	DefaultMaxRecords = 256
	stateBytes        = 32
	// maxStateLength is the accepted wire length of a state parameter.
	maxStateLength = 128
	maxProviderLen = 32
)

var (
	// ErrInvalidRequest reports malformed initiation or callback input.
	ErrInvalidRequest = errors.New("invalid OAuth request")
	// ErrInvalidState reports an unknown, expired, replayed, or mismatched
	// state. Callers must not distinguish these cases to clients.
	ErrInvalidState = errors.New("invalid OAuth state")
	// ErrStoreFull reports the bounded in-flight capacity limit.
	ErrStoreFull = errors.New("too many pending OAuth authorizations")
)

// Record is the server-side authorization context belonging to one state.
type Record struct {
	Provider     string
	PrincipalID  int
	RedirectURI  string
	CreatedAt    time.Time
	CodeVerifier string
}

// Challenge is the material an initiation response needs.
type Challenge struct {
	State         string
	CodeVerifier  string
	CodeChallenge string
}

// StoreOptions configures a Store. RedirectURIs is the exact allowlist of
// callback values that may be bound to a state.
type StoreOptions struct {
	RedirectURIs []string
	TTL          time.Duration
	MaxRecords   int
	Now          func() time.Time
	Random       io.Reader
}

// Store keeps single-use authorization states. Values are never persisted or
// logged, and only their SHA-256 digests are held in memory.
type Store struct {
	mu           sync.Mutex
	redirectURIs map[string]struct{}
	ttl          time.Duration
	maxRecords   int
	now          func() time.Time
	random       io.Reader
	records      map[[sha256.Size]byte]Record
}

// NewStore creates a bounded state store. It fails closed on any missing or
// malformed option; there is no default redirect allowlist.
func NewStore(options StoreOptions) (*Store, error) {
	if len(options.RedirectURIs) == 0 || len(options.RedirectURIs) > 16 {
		return nil, ErrInvalidRequest
	}
	allowlist := make(map[string]struct{}, len(options.RedirectURIs))
	for _, redirect := range options.RedirectURIs {
		if _, err := ParsePublicHTTPSURL(redirect); err != nil {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := allowlist[redirect]; duplicate {
			return nil, ErrInvalidRequest
		}
		allowlist[redirect] = struct{}{}
	}
	ttl := options.TTL
	if ttl == 0 {
		ttl = DefaultStateTTL
	}
	if ttl < time.Minute || ttl > time.Hour {
		return nil, ErrInvalidRequest
	}
	maxRecords := options.MaxRecords
	if maxRecords == 0 {
		maxRecords = DefaultMaxRecords
	}
	if maxRecords < 1 || maxRecords > 4096 {
		return nil, ErrInvalidRequest
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	return &Store{
		redirectURIs: allowlist,
		ttl:          ttl,
		maxRecords:   maxRecords,
		now:          now,
		random:       random,
		records:      make(map[[sha256.Size]byte]Record),
	}, nil
}

// Begin issues a fresh S256 challenge and registers its single-use state.
func (s *Store) Begin(provider string, principalID int, redirectURI string) (Challenge, error) {
	if s == nil || !ValidProviderName(provider) || principalID < 1 {
		return Challenge{}, ErrInvalidRequest
	}
	if _, allowed := s.redirectURIs[redirectURI]; !allowed {
		return Challenge{}, ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	if len(s.records) >= s.maxRecords {
		return Challenge{}, ErrStoreFull
	}

	stateBuffer := make([]byte, stateBytes)
	if _, err := io.ReadFull(s.random, stateBuffer); err != nil {
		clear(stateBuffer)
		return Challenge{}, ErrInvalidRequest
	}
	state := base64.RawURLEncoding.EncodeToString(stateBuffer)
	clear(stateBuffer)
	verifier, err := newCodeVerifier(s.random)
	if err != nil {
		return Challenge{}, ErrInvalidRequest
	}
	challenge, err := CodeChallengeS256(verifier)
	if err != nil {
		return Challenge{}, ErrInvalidRequest
	}
	stateDigest := sha256.Sum256([]byte(state))
	s.records[stateDigest] = Record{
		Provider:     provider,
		PrincipalID:  principalID,
		RedirectURI:  redirectURI,
		CreatedAt:    s.now(),
		CodeVerifier: verifier,
	}
	return Challenge{State: state, CodeVerifier: verifier, CodeChallenge: challenge}, nil
}

// Consume validates and atomically removes the state belonging to provider.
// Every failure mode returns ErrInvalidState: unknown, expired, replayed, and
// provider-mismatched states are indistinguishable to callers.
func (s *Store) Consume(provider, state string) (Record, error) {
	if s == nil || !ValidProviderName(provider) || len(state) < MinCodeVerifierLength || len(state) > maxStateLength {
		return Record{}, ErrInvalidState
	}
	for i := 0; i < len(state); i++ {
		switch character := state[i]; {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '-', character == '_':
		default:
			return Record{}, ErrInvalidState
		}
	}
	stateDigest := sha256.Sum256([]byte(state))
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[stateDigest]
	if !exists {
		return Record{}, ErrInvalidState
	}
	// Single use: the record is removed even when it is expired or bound to a
	// different provider, so a stolen state cannot be retried.
	delete(s.records, stateDigest)
	now := s.now()
	if now.Sub(record.CreatedAt) < 0 || now.Sub(record.CreatedAt) > s.ttl {
		return Record{}, ErrInvalidState
	}
	if record.Provider != provider {
		return Record{}, ErrInvalidState
	}
	return record, nil
}

// Pending reports the number of live records. It is intended for tests and
// metrics only.
func (s *Store) Pending() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *Store) pruneLocked(now time.Time) {
	for digest, record := range s.records {
		if now.Sub(record.CreatedAt) < 0 || now.Sub(record.CreatedAt) > s.ttl {
			delete(s.records, digest)
		}
	}
}

// ValidProviderName reports whether a provider identifier is a bounded
// lowercase token. Provider identifiers become environment-variable suffixes
// and route parameters, so only this alphabet is accepted.
func ValidProviderName(provider string) bool {
	if len(provider) < 1 || len(provider) > maxProviderLen {
		return false
	}
	for i := 0; i < len(provider); i++ {
		switch character := provider[i]; {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '_', character == '-':
		default:
			return false
		}
	}
	return !strings.HasPrefix(provider, "-") && !strings.HasPrefix(provider, "_")
}
