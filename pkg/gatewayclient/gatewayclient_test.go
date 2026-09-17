package gatewayclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/model"
)

const testServiceToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func plantRuntime(t *testing.T, address, token string) string {
	t.Helper()
	runtimePath := t.TempDir()
	if address != "" {
		if err := os.WriteFile(filepath.Join(runtimePath, "management.url"), []byte(address), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if token != "" {
		if err := os.WriteFile(filepath.Join(runtimePath, ServiceTokenFilename), []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return runtimePath
}

func TestManagementRequestsCarryTheServiceToken(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/ping" && r.Header.Get("Authorization") != "Bearer "+testServiceToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/ping":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/gateway/routes":
			body, _ := io.ReadAll(r.Body)
			var route model.Route
			if err := json.Unmarshal(body, &route); err != nil || route.Path != "/v1/file" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/gateway/port":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/gateway/port":
			_, _ = w.Write([]byte(`{"success":200,"data":"8080"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, testServiceToken)
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if err := client.ChangePort(&model.ChangePortRequest{Port: "8080"}); err != nil {
		t.Fatalf("ChangePort: %v", err)
	}
	getErr, body := client.GetPort()
	if getErr != nil {
		t.Fatalf("GetPort: %v", getErr)
	}
	if body != `{"success":200,"data":"8080"}` {
		t.Fatalf("GetPort body = %q", body)
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("management requests = %d, want 4", got)
	}
}

func TestManagementRequestsFailClosedWithoutToken(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, "")
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("CreateRoute without a service token unexpectedly succeeded")
	}
	if err := client.ChangePort(&model.ChangePortRequest{Port: "8080"}); err == nil {
		t.Fatal("ChangePort without a service token unexpectedly succeeded")
	}
	if requests.Load() != 1 {
		t.Fatalf("requests reached the server without a token: %d", requests.Load())
	}
}

func TestManagementRequestsRejectWrongToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, "wrong-token")
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("CreateRoute with a rejected token unexpectedly succeeded")
	}
}

func TestNewFailsClosedWithoutAddressOrPing(t *testing.T) {
	previousAttempts, previousDelay := addressRetryAttempts, addressRetryDelay
	addressRetryAttempts, addressRetryDelay = 1, 0
	t.Cleanup(func() { addressRetryAttempts, addressRetryDelay = previousAttempts, previousDelay })

	if _, err := New(plantRuntime(t, "", testServiceToken)); err == nil {
		t.Fatal("missing management address was accepted")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	if _, err := New(plantRuntime(t, server.URL, testServiceToken)); err == nil {
		t.Fatal("unreachable management service was accepted")
	}

	if _, err := New(""); err == nil {
		t.Fatal("empty runtime path was accepted")
	}
}

func TestGetPortRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, testServiceToken)
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if getErr, _ := client.GetPort(); getErr == nil {
		t.Fatal("oversized port response was accepted")
	}
}

func TestNewUsesBoundedRetryDelay(t *testing.T) {
	previousAttempts, previousDelay := addressRetryAttempts, addressRetryDelay
	addressRetryAttempts, addressRetryDelay = 2, time.Millisecond
	t.Cleanup(func() { addressRetryAttempts, addressRetryDelay = previousAttempts, previousDelay })

	start := time.Now()
	if _, err := New(plantRuntime(t, "", testServiceToken)); err == nil {
		t.Fatal("missing management address was accepted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("retry delay was not bounded: %v", elapsed)
	}
}

func TestClientRejectsNonLoopbackManagementAddress(t *testing.T) {
	for _, address := range []string{
		"http://example.com:8080",
		"http://10.0.0.1:8080",
		"https://127.0.0.1:8080",
		"http://127.0.0.1",
		"http://user@127.0.0.1:8080",
		"http://127.0.0.1:8080/v1",
	} {
		if _, err := New(plantRuntime(t, address, testServiceToken)); err == nil {
			t.Fatalf("management address %q was accepted", address)
		}
	}
}

func TestClientDoesNotForwardCredentialOnRedirect(t *testing.T) {
	var redirectedRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, target.URL+"/v1/gateway/routes", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client, err := New(plantRuntime(t, redirector.URL, testServiceToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("redirected management request unexpectedly succeeded")
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("service credential reached the redirect target %d times", redirectedRequests.Load())
	}
}

func TestClientPicksUpRotatedToken(t *testing.T) {
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("Authorization") == "Bearer rotated-token" {
			accepted.Add(1)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, testServiceToken)
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("stale token unexpectedly accepted")
	}
	if err := os.WriteFile(filepath.Join(runtimePath, ServiceTokenFilename), []byte("rotated-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err != nil {
		t.Fatalf("rotated token was not picked up: %v", err)
	}
	if accepted.Load() != 1 {
		t.Fatalf("rotated token accepted %d times, want 1", accepted.Load())
	}
}

func TestClientRejectsSymlinkedAndOversizedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	runtimePath := plantRuntime(t, server.URL, "")
	realToken := filepath.Join(runtimePath, "real.token")
	if err := os.WriteFile(realToken, []byte(testServiceToken), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(runtimePath, ServiceTokenFilename)
	if err := os.Symlink(realToken, tokenPath); err != nil {
		t.Fatal(err)
	}
	client, err := New(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("symlinked service token was accepted")
	}

	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, make([]byte, maxCredentialFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := client.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}); err == nil {
		t.Fatal("oversized service token was accepted")
	}
}
