package oauthsecurity

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRedirect = "https://casaos.example.com/api/v1/recover/GoogleDrive"

func newTestStore(t *testing.T, options StoreOptions) *Store {
	t.Helper()
	if len(options.RedirectURIs) == 0 {
		options.RedirectURIs = []string{testRedirect}
	}
	store, err := NewStore(options)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestStoreBeginConsumeHappyPath(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	store := newTestStore(t, StoreOptions{Now: func() time.Time { return clock }})
	challenge, err := store.Begin("google_drive", 7, testRedirect)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !ValidCodeVerifier(challenge.CodeVerifier) {
		t.Fatalf("verifier %q is invalid", challenge.CodeVerifier)
	}
	expectedChallenge, err := CodeChallengeS256(challenge.CodeVerifier)
	if err != nil || expectedChallenge != challenge.CodeChallenge {
		t.Fatalf("challenge = %q, err = %v", challenge.CodeChallenge, err)
	}
	if len(challenge.State) != 43 {
		t.Fatalf("state length = %d, want 43", len(challenge.State))
	}
	if store.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", store.Pending())
	}

	record, err := store.Consume("google_drive", challenge.State)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if record.Provider != "google_drive" || record.PrincipalID != 7 || record.RedirectURI != testRedirect {
		t.Fatalf("record = %+v", record)
	}
	if record.CodeVerifier != challenge.CodeVerifier {
		t.Fatal("consumed verifier differs from the issued verifier")
	}
	if !record.CreatedAt.Equal(clock) {
		t.Fatalf("created at %v, want %v", record.CreatedAt, clock)
	}
	if store.Pending() != 0 {
		t.Fatal("consumed state was retained")
	}

	// Replay must fail and must not resurrect the record.
	if _, err := store.Consume("google_drive", challenge.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replay error = %v, want ErrInvalidState", err)
	}
	if store.Pending() != 0 {
		t.Fatal("replay recreated a record")
	}
}

func TestStoreConsumeFailureModesAreIndistinguishable(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	store := newTestStore(t, StoreOptions{TTL: time.Minute, Now: func() time.Time { return clock }})
	challenge, err := store.Begin("google_drive", 3, testRedirect)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if _, err := store.Consume("google_drive", strings.Repeat("z", 43)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown state error = %v", err)
	}
	if _, err := store.Consume("GoogleDrive", challenge.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid provider error = %v", err)
	}
	if _, err := store.Consume("google_drive", "short"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("short state error = %v", err)
	}
	if _, err := store.Consume("google_drive", strings.Repeat("a", 43)+"!"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("non-canonical state error = %v", err)
	}
	if _, err := store.Consume("google_drive", strings.Repeat("a", maxStateLength+1)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("oversized state error = %v", err)
	}

	// A provider mismatch consumes the state: the failed attempt is the last.
	otherStore := newTestStore(t, StoreOptions{TTL: time.Minute, Now: func() time.Time { return clock }})
	otherChallenge, err := otherStore.Begin("google_drive", 3, testRedirect)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := otherStore.Consume("onedrive", otherChallenge.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("provider mismatch error = %v", err)
	}
	if _, err := otherStore.Consume("google_drive", otherChallenge.State); !errors.Is(err, ErrInvalidState) {
		t.Fatal("provider-mismatched state was not consumed")
	}

	// Expiry: the record is rejected and removed once the TTL has passed.
	if _, err := store.Consume("google_drive", challenge.State); err != nil {
		t.Fatalf("in-window consume: %v", err)
	}
	expiring, err := store.Begin("google_drive", 3, testRedirect)
	if err != nil {
		t.Fatalf("Begin expiring: %v", err)
	}
	clock = clock.Add(time.Minute + time.Second)
	if _, err := store.Consume("google_drive", expiring.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expired state error = %v", err)
	}
	if store.Pending() != 0 {
		t.Fatal("expired state was retained")
	}
}

func TestStoreBeginRejectsUnlistedRedirectAndInvalidProvider(t *testing.T) {
	store := newTestStore(t, StoreOptions{})
	if _, err := store.Begin("google_drive", 1, "https://evil.example.com/callback"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unlisted redirect error = %v", err)
	}
	if _, err := store.Begin("google_drive", 1, testRedirect+"?x=1"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("query redirect error = %v", err)
	}
	for _, provider := range []string{"", "GoogleDrive", "google drive", "google/drive", strings.Repeat("a", maxProviderLen+1), "-leading"} {
		if _, err := store.Begin(provider, 1, testRedirect); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("provider %q error = %v", provider, err)
		}
	}
	if _, err := store.Begin("google_drive", 0, testRedirect); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero principal error = %v", err)
	}
}

func TestNewStoreOptionValidation(t *testing.T) {
	if _, err := NewStore(StoreOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty allowlist error = %v", err)
	}
	if _, err := NewStore(StoreOptions{RedirectURIs: []string{"http://casaos.example.com/callback"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("http redirect error = %v", err)
	}
	if _, err := NewStore(StoreOptions{RedirectURIs: []string{testRedirect, testRedirect}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate redirect error = %v", err)
	}
	if _, err := NewStore(StoreOptions{RedirectURIs: []string{testRedirect}, TTL: time.Second}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("below-minimum TTL error = %v", err)
	}
	if _, err := NewStore(StoreOptions{RedirectURIs: []string{testRedirect}, TTL: 2 * time.Hour}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("above-maximum TTL error = %v", err)
	}
	if _, err := NewStore(StoreOptions{RedirectURIs: []string{testRedirect}, MaxRecords: -1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative capacity error = %v", err)
	}
}

func TestStoreCapacityFailsClosedAndExpiredRecordsArePruned(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	store := newTestStore(t, StoreOptions{
		TTL:        time.Minute,
		MaxRecords: 2,
		Now:        func() time.Time { return clock },
	})
	if _, err := store.Begin("google_drive", 1, testRedirect); err != nil {
		t.Fatalf("first begin: %v", err)
	}
	if _, err := store.Begin("google_drive", 1, testRedirect); err != nil {
		t.Fatalf("second begin: %v", err)
	}
	if _, err := store.Begin("google_drive", 1, testRedirect); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("capacity error = %v, want ErrStoreFull", err)
	}
	clock = clock.Add(time.Minute + time.Second)
	if _, err := store.Begin("google_drive", 1, testRedirect); err != nil {
		t.Fatalf("begin after expiry: %v", err)
	}
}

func TestStoreConcurrentConsumeHasOneWinner(t *testing.T) {
	store := newTestStore(t, StoreOptions{})
	const attempts = 32
	winners := 0
	var mutex sync.Mutex
	var waitGroup sync.WaitGroup
	for i := 0; i < attempts; i++ {
		challenge, err := store.Begin("google_drive", 1, testRedirect)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		waitGroup.Add(attempts)
		for j := 0; j < attempts; j++ {
			go func(state string) {
				defer waitGroup.Done()
				if _, err := store.Consume("google_drive", state); err == nil {
					mutex.Lock()
					winners++
					mutex.Unlock()
				}
			}(challenge.State)
		}
		waitGroup.Wait()
	}
	if winners != attempts {
		t.Fatalf("winners = %d, want exactly %d", winners, attempts)
	}
	if store.Pending() != 0 {
		t.Fatal("records were retained after concurrent consumption")
	}
}

func TestStoreIssuesIndependentUnpredictableStates(t *testing.T) {
	store := newTestStore(t, StoreOptions{Random: nil})
	first, err := store.Begin("google_drive", 1, testRedirect)
	if err != nil {
		t.Fatalf("first begin: %v", err)
	}
	second, err := store.Begin("google_drive", 1, testRedirect)
	if err != nil {
		t.Fatalf("second begin: %v", err)
	}
	if first.State == second.State || first.CodeVerifier == second.CodeVerifier {
		t.Fatal("independent authorizations reused state or verifier material")
	}
	altered := first.State[:len(first.State)-1] + "A"
	if altered == first.State {
		altered = first.State[:len(first.State)-1] + "B"
	}
	if _, err := store.Consume("google_drive", altered); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("altered state error = %v, want ErrInvalidState", err)
	}
}

func TestValidProviderName(t *testing.T) {
	for _, valid := range []string{"google_drive", "onedrive", "dropbox", "p1", "a-b"} {
		if !ValidProviderName(valid) {
			t.Fatalf("provider %q was rejected", valid)
		}
	}
	for _, invalid := range []string{"", "A", "a b", "a.b", "a/b", "_a", "-a", strings.Repeat("a", maxProviderLen+1)} {
		if ValidProviderName(invalid) {
			t.Fatalf("provider %q was accepted", invalid)
		}
	}
}
