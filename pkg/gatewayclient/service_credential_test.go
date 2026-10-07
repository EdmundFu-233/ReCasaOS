package gatewayclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceAuthorizationCarriesTheToken(t *testing.T) {
	runtimePath := plantRuntime(t, "", testServiceToken)
	authorization, err := ServiceAuthorization(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer "+testServiceToken {
		t.Fatalf("authorization = %q", authorization)
	}
}

func TestServiceAuthorizationFailsWithoutToken(t *testing.T) {
	if _, err := ServiceAuthorization(plantRuntime(t, "", "")); err == nil {
		t.Fatal("expected an error without a token file")
	}
}

func TestServiceAuthorizationMatches(t *testing.T) {
	runtimePath := plantRuntime(t, "", testServiceToken)
	for _, tc := range []struct {
		authorization string
		want          bool
	}{
		{"Bearer " + testServiceToken, true},
		{testServiceToken, true},
		{"", false},
		{"Bearer ", false},
		{"Bearer " + testServiceToken[:len(testServiceToken)-1] + "0", false},
		{"Bearer " + testServiceToken + "0", false},
		{"Internal " + testServiceToken, false},
	} {
		if got := ServiceAuthorizationMatches(runtimePath, tc.authorization); got != tc.want {
			t.Errorf("ServiceAuthorizationMatches(%q) = %v, want %v", tc.authorization, got, tc.want)
		}
	}
}

func TestServiceAuthorizationMatchesNothingWithoutToken(t *testing.T) {
	runtimePath := plantRuntime(t, "", "")
	if ServiceAuthorizationMatches(runtimePath, "") || ServiceAuthorizationMatches(runtimePath, "Bearer ") {
		t.Fatal("an absent credential must never match")
	}
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, ServiceTokenFilename), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ServiceAuthorizationMatches(empty, "") || ServiceAuthorizationMatches(empty, "Bearer ") {
		t.Fatal("an empty credential must never match")
	}
}

func TestServiceRequestEditor(t *testing.T) {
	runtimePath := plantRuntime(t, "", testServiceToken)
	edit := ServiceRequestEditor(runtimePath)

	authorizationFor := func(url, preset string) string {
		request := httptest.NewRequest(http.MethodPost, url, nil)
		if preset != "" {
			request.Header.Set("Authorization", preset)
		}
		if err := edit(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		return request.Header.Get("Authorization")
	}

	if got := authorizationFor("http://127.0.0.1:4000/v2/message_bus/event_type", ""); got != "Bearer "+testServiceToken {
		t.Errorf("IPv4 loopback: %q", got)
	}
	if got := authorizationFor("http://[::1]:4000/v2/message_bus/event_type", ""); got != "Bearer "+testServiceToken {
		t.Errorf("IPv6 loopback: %q", got)
	}
	if got := authorizationFor("http://192.0.2.10:4000/v2/message_bus/event_type", ""); got != "" {
		t.Errorf("non-loopback destination got the credential: %q", got)
	}
	if got := authorizationFor("http://localhost.example.org:4000/", ""); got != "" {
		t.Errorf("a host name got the credential: %q", got)
	}
	if got := authorizationFor("http://127.0.0.1:4000/", "Bearer user-token"); got != "Bearer user-token" {
		t.Errorf("an existing Authorization header was replaced: %q", got)
	}

	missing := ServiceRequestEditor(plantRuntime(t, "", ""))
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4000/", nil)
	if err := missing(context.Background(), request); err != nil {
		t.Fatalf("a missing credential must not fail the request: %v", err)
	}
	if got := request.Header.Get("Authorization"); got != "" {
		t.Errorf("missing credential: %q", got)
	}
}
