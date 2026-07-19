package v1

import (
	"encoding/json"
	"testing"
)

func TestCenterHandlerTryAddIsAtomic(t *testing.T) {
	handler := &CenterHandler{clients: make(map[string]*Client)}
	first := &Client{ID: "first"}
	second := &Client{ID: "second"}
	if !handler.tryAdd(first, 1) {
		t.Fatal("first client was not added")
	}
	if handler.tryAdd(second, 1) {
		t.Fatal("client limit was bypassed")
	}
	if handler.count() != 1 {
		t.Fatalf("client count = %d, want 1", handler.count())
	}
}

func TestNormalizeClientPeerMessageOverwritesSender(t *testing.T) {
	typeName, target, normalized, err := normalizeClientPeerMessage([]byte(`{"type":"offer","to":"peer-2","sender":"spoofed","sdp":"value"}`), "peer-1")
	if err != nil {
		t.Fatal(err)
	}
	if typeName != "offer" || target != "peer-2" {
		t.Fatalf("type = %q, target = %q", typeName, target)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(normalized, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["sender"] != "peer-1" {
		t.Fatalf("sender = %#v", decoded["sender"])
	}
	if _, exists := decoded["to"]; exists {
		t.Fatal("normalized peer message retained target")
	}
}

func TestNormalizeClientPeerMessageRejectsServerControls(t *testing.T) {
	for _, message := range []string{
		`{"type":"peer-left","peerId":"victim"}`,
		`{"type":"peers","peers":[]}`,
		`{"type":"offer","to":42}`,
		`{"sender":"missing-type"}`,
	} {
		if _, _, _, err := normalizeClientPeerMessage([]byte(message), "peer-1"); err == nil {
			t.Errorf("message %s unexpectedly accepted", message)
		}
	}
}
