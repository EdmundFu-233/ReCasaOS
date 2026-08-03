//go:build linux && recasaos_publicfiles_browser_test

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerDiagnosticsTracksOnlySafeCategories(t *testing.T) {
	diagnostics := &serverDiagnostics{}
	handler := &diagnosticPortal{
		diagnostics: diagnostics,
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	for _, path := range []string{
		"/public-files/",
		"/public-files/style.css",
		"/public-files/api/list?path=private",
		"/not-allowlisted?token=secret",
	} {
		request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("response code = %d, want 204", response.Code)
		}
	}

	snapshot := diagnostics.snapshot()
	if snapshot.ActiveRequests != 0 || snapshot.StartedRequests != 4 ||
		snapshot.CompletedRequests != 4 {
		t.Fatalf("request totals = %+v", snapshot)
	}
	if snapshot.PortalDocumentsStarted != 1 || snapshot.PortalDocumentsCompleted != 1 ||
		snapshot.StaticAssetsStarted != 1 || snapshot.StaticAssetsCompleted != 1 ||
		snapshot.APIRequestsStarted != 1 || snapshot.APIRequestsCompleted != 1 ||
		snapshot.OtherRequestsStarted != 1 || snapshot.OtherRequestsCompleted != 1 {
		t.Fatalf("request categories = %+v", snapshot)
	}
}

func TestServerDiagnosticsTracksConnectionAndErrorClasses(t *testing.T) {
	diagnostics := &serverDiagnostics{}
	diagnostics.connectionState(nil, http.StateNew)
	diagnostics.connectionState(nil, http.StateActive)
	diagnostics.connectionState(nil, http.StateIdle)
	diagnostics.connectionState(nil, http.StateClosed)

	logger := &diagnosticServerLog{diagnostics: diagnostics}
	if _, err := logger.Write([]byte("TLS handshake error from test peer")); err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Write([]byte("generic server error")); err != nil {
		t.Fatal(err)
	}

	snapshot := diagnostics.snapshot()
	if snapshot.AcceptedConnections != 1 || snapshot.ActiveConnectionChanges != 1 ||
		snapshot.IdleConnectionChanges != 1 || snapshot.ClosedConnections != 1 ||
		snapshot.OpenConnections != 0 || snapshot.ServerErrors != 2 ||
		snapshot.TLSHandshakeErrors != 1 {
		t.Fatalf("connection diagnostics = %+v", snapshot)
	}
}

func TestControlDiagnosticsEndpointReturnsExactSnapshot(t *testing.T) {
	counters := &requestCounters{}
	diagnostics := &serverDiagnostics{}
	diagnostics.startedRequests.Store(7)
	server := newControlServer(counters, diagnostics)

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/diagnostics", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response code = %d, want 200", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var snapshot serverDiagnosticsSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.StartedRequests != 7 {
		t.Fatalf("started requests = %d, want 7", snapshot.StartedRequests)
	}

	post := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/diagnostics", nil)
	postResponse := httptest.NewRecorder()
	server.Handler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST response code = %d, want 405", postResponse.Code)
	}
}
