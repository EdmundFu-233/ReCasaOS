package httper

import (
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/config"
)

func TestLegacyHTTPHelpersRejectMalformedURLWithoutPanic(t *testing.T) {
	const malformedURL = "http://[::1"

	tests := []struct {
		name string
		call func() bool
	}{
		{
			name: "Get with headers",
			call: func() bool {
				return Get(malformedURL, map[string]string{"X-Test": "value"}) == ""
			},
		},
		{
			name: "PersonGet",
			call: func() bool {
				return PersonGet(malformedURL) == ""
			},
		},
		{
			name: "Post",
			call: func() bool {
				return Post(malformedURL, []byte(`{"test":true}`), "application/json", nil) == ""
			},
		},
		{
			name: "ZeroTierGet",
			call: func() bool {
				content, code := ZeroTierGet(malformedURL, map[string]string{"X-Test": "value"})
				return content == "" && code == 0
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("helper panicked for malformed URL: %v", recovered)
				}
			}()
			if !test.call() {
				t.Fatal("helper did not return its documented zero value")
			}
		})
	}
}

func TestOasisGetRejectsMalformedConfiguredURLWithoutPanic(t *testing.T) {
	previousServerAPI := config.ServerInfo.ServerApi
	config.ServerInfo.ServerApi = "http://[::1"
	t.Cleanup(func() { config.ServerInfo.ServerApi = previousServerAPI })

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("OasisGet panicked for malformed configured URL: %v", recovered)
		}
	}()
	if response := OasisGet("http://[::1"); response != "" {
		t.Fatalf("OasisGet response = %q, want empty", response)
	}
}

func TestZeroTierGetReturnsZeroValuesOnTransportError(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ZeroTierGet panicked for transport error: %v", recovered)
		}
	}()
	content, code := ZeroTierGet("unsupported://device.test", nil)
	if content != "" || code != 0 {
		t.Fatalf("ZeroTierGet = (%q, %d), want empty zero values", content, code)
	}
}
