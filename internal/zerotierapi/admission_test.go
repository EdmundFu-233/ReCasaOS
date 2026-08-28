package zerotierapi

import (
	"errors"
	"strings"
	"testing"
)

func TestZeroTierPublicRequestAdmissionIsNonBlockingAndBounded(t *testing.T) {
	releases := make([]func(), 0, zeroTierMaximumConcurrentPublicRequests+1)
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
	})

	for index := 0; index < zeroTierMaximumConcurrentPublicRequests; index++ {
		release, admitted := TryAcquirePublicRequest()
		if !admitted || release == nil {
			t.Fatalf("request %d was not admitted", index)
		}
		releases = append(releases, release)
	}
	if release, admitted := TryAcquirePublicRequest(); admitted || release != nil {
		t.Fatal("request above the concurrency bound was admitted")
	}

	releases[0]()
	releases[0]() // release is intentionally idempotent
	release, admitted := TryAcquirePublicRequest()
	if !admitted || release == nil {
		t.Fatal("released capacity was not reusable")
	}
	releases = append(releases, release)
}

func TestZeroTierFailureClassNeverIncludesRawErrorText(t *testing.T) {
	const secret = "token-at-sensitive-state-path"
	classification := FailureClass(errors.New(secret))
	if classification != "upstream_error" || strings.Contains(classification, secret) {
		t.Fatalf("failure class = %q", classification)
	}
}
