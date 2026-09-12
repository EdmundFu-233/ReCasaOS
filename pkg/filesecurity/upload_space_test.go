package filesecurity

import (
	"errors"
	"sync"
	"testing"
)

func TestUploadSpaceAdmissionReservesAndReleasesAtomically(t *testing.T) {
	var mu sync.Mutex
	available := uint64(1_000)
	checker := func(*ManagedRoots, string) (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		return available, nil
	}
	admission := NewUploadSpaceAdmission(checker)

	firstRelease, err := admission.Reserve(&ManagedRoots{}, "/managed", 400, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Reserve(&ManagedRoots{}, "/managed", 501, 100); !errors.Is(err, ErrUploadSpaceInsufficient) {
		t.Fatalf("second reservation error = %v, want insufficient space", err)
	}

	firstRelease()
	secondRelease, err := admission.Reserve(&ManagedRoots{}, "/managed", 501, 100)
	if err != nil {
		t.Fatal(err)
	}
	secondRelease()
	secondRelease()
	if admission.reserved != 0 {
		t.Fatalf("reserved bytes = %d, want 0", admission.reserved)
	}
}

func TestUploadSpaceAdmissionFailsClosedWhenSpaceCannotBeChecked(t *testing.T) {
	injected := errors.New("injected statfs failure")
	admission := NewUploadSpaceAdmission(func(*ManagedRoots, string) (uint64, error) {
		return 0, injected
	})

	if _, err := admission.Reserve(&ManagedRoots{}, "/managed", 1, 0); !errors.Is(err, ErrUploadSpaceUnavailable) || !errors.Is(err, injected) {
		t.Fatalf("space-check error = %v, want unavailable wrapping injected error", err)
	}
}

func TestUploadSpaceAdmissionRejectsInvalidCapacityAndOverflow(t *testing.T) {
	admission := NewUploadSpaceAdmission(func(*ManagedRoots, string) (uint64, error) {
		return ^uint64(0), nil
	})

	if _, err := admission.Reserve(nil, "/managed", 1, 0); !errors.Is(err, ErrUploadSpaceUnavailable) {
		t.Fatalf("nil roots error = %v, want unavailable", err)
	}

	admission.reserved = ^uint64(0) - 1
	if _, err := admission.Reserve(&ManagedRoots{}, "/managed", 2, 0); !errors.Is(err, ErrUploadSpaceInsufficient) {
		t.Fatalf("reservation overflow error = %v, want insufficient", err)
	}
}

func TestUploadSpaceAdmissionSerializesConcurrentReservations(t *testing.T) {
	admission := NewUploadSpaceAdmission(func(*ManagedRoots, string) (uint64, error) {
		return 1_000, nil
	})

	const callers = 16
	var wait sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	releases := make([]func(), 0, callers)
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			release, err := admission.Reserve(&ManagedRoots{}, "/managed", 100, 0)
			if err != nil {
				return
			}
			mu.Lock()
			accepted++
			releases = append(releases, release)
			mu.Unlock()
		}()
	}
	wait.Wait()
	if accepted != 10 {
		t.Fatalf("accepted reservations = %d, want 10", accepted)
	}
	for _, release := range releases {
		release()
	}
	if admission.reserved != 0 {
		t.Fatalf("reserved bytes after release = %d, want 0", admission.reserved)
	}
}
