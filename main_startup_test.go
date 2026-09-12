package main

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/samba"
	"github.com/IceWhaleTech/CasaOS/pkg/smbcredentials"
)

func TestAdmitStartupSMBCredentialDestroysValidatedKeyringImmediately(t *testing.T) {
	keyring, err := smbcredentials.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	validated, err := admitStartupSMBCredential(func() (*smbcredentials.Keyring, error) {
		return keyring, nil
	})
	if err != nil || !validated {
		t.Fatalf("admission validated=%t err=%v", validated, err)
	}
	if keyring.ActiveID() != "" {
		t.Fatal("validated startup keyring remained usable after admission")
	}
}

func TestAdmitStartupSMBCredentialAllowsOnlyExplicitNotProvidedResult(t *testing.T) {
	validated, err := admitStartupSMBCredential(func() (*smbcredentials.Keyring, error) {
		return nil, smbcredentials.ErrSystemdCredentialNotProvided
	})
	if err != nil || validated {
		t.Fatalf("legacy admission validated=%t err=%v", validated, err)
	}

	injected := errors.New("configured credential failure")
	for name, failure := range map[string]error{
		"ordinary error":   injected,
		"wrapped sentinel": fmt.Errorf("indeterminate: %w", smbcredentials.ErrSystemdCredentialNotProvided),
		"joined sentinel":  errors.Join(smbcredentials.ErrSystemdCredentialNotProvided, injected),
	} {
		t.Run(name, func(t *testing.T) {
			validated, err := admitStartupSMBCredential(func() (*smbcredentials.Keyring, error) {
				return nil, failure
			})
			if validated || err == nil {
				t.Fatalf("configured failure validated=%t err=%v", validated, err)
			}
		})
	}
}

func TestAdmitStartupSMBCredentialDestroysKeyringOnInconsistentLoaderError(t *testing.T) {
	injected := errors.New("inconsistent loader failure")
	for name, failure := range map[string]error{
		"ordinary error": injected,
		"sentinel":       smbcredentials.ErrSystemdCredentialNotProvided,
	} {
		t.Run(name, func(t *testing.T) {
			keyring, err := smbcredentials.NewKeyring()
			if err != nil {
				t.Fatal(err)
			}
			validated, err := admitStartupSMBCredential(func() (*smbcredentials.Keyring, error) {
				return keyring, failure
			})
			if validated || err == nil {
				t.Fatalf("inconsistent admission validated=%t err=%v", validated, err)
			}
			if keyring.ActiveID() != "" {
				t.Fatal("keyring returned beside a loader error was not destroyed")
			}
		})
	}
}

func TestAdmitStartupSMBCredentialRejectsInvalidLoaderContract(t *testing.T) {
	for name, load := range map[string]func() (*smbcredentials.Keyring, error){
		"nil loader":  nil,
		"nil success": func() (*smbcredentials.Keyring, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			validated, err := admitStartupSMBCredential(load)
			if validated || err == nil {
				t.Fatalf("invalid loader contract validated=%t err=%v", validated, err)
			}
		})
	}
}

func TestInternalSambaProbeInvocationRequiresExactArgumentVector(t *testing.T) {
	originalArguments := os.Args
	t.Cleanup(func() { os.Args = originalArguments })
	for _, testCase := range []struct {
		name      string
		arguments []string
		want      bool
	}{
		{name: "exact", arguments: []string{"casaos", samba.InternalProbeArgument}, want: true},
		{name: "missing", arguments: []string{"casaos"}},
		{name: "extra", arguments: []string{"casaos", samba.InternalProbeArgument, "unexpected"}},
		{name: "similar", arguments: []string{"casaos", "internal-samba-probe"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			os.Args = testCase.arguments
			if got := isInternalSambaProbeInvocation(); got != testCase.want {
				t.Fatalf("isInternalSambaProbeInvocation()=%t want=%t", got, testCase.want)
			}
		})
	}
}
