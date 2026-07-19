package version

import (
	"testing"

	"github.com/IceWhaleTech/CasaOS/model"
)

func TestIsNeedUpdateUsesSemanticVersions(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "newer upstream", version: "0.4.18", want: true},
		{name: "older upstream", version: "0.4.16", want: false},
		{name: "same upstream base", version: "0.4.17", want: false},
		{name: "same fork", version: "v0.4.17-recasaos.1", want: false},
		{name: "newer fork revision", version: "v0.4.17-recasaos.2", want: true},
		{name: "newer legacy fourth component", version: "0.4.17.1", want: true},
		{name: "older legacy fourth component", version: "0.4.16.99", want: false},
		{name: "historical four component", version: "0.3.7.1", want: false},
		{name: "older prerelease", version: "0.4.17-alpha1", want: false},
		{name: "invalid fails closed", version: "latest", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := IsNeedUpdate(model.Version{Version: test.version})
			if got != test.want {
				t.Fatalf("IsNeedUpdate(%q) = %v, want %v", test.version, got, test.want)
			}
		})
	}
}

func TestCanonicalVersion(t *testing.T) {
	if got := canonicalVersion(" 0.4.17-recasaos.1 "); got != "v0.4.17-recasaos.1" {
		t.Fatalf("canonicalVersion = %q", got)
	}
	if got := canonicalVersion("not-a-version"); got != "" {
		t.Fatalf("invalid canonicalVersion = %q", got)
	}
}
