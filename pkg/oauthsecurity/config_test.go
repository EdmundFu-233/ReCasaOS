package oauthsecurity

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func environmentLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, present := values[key]
		return value, present
	}
}

func validProviderEnvironment() map[string]string {
	return map[string]string{
		providersEnvironmentVariable:                "google_drive",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_URL":      "https://accounts.google.com/o/oauth2/v2/auth",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL":     "https://oauth2.googleapis.com/token",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_ID":     "1234567890.apps.googleusercontent.com",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET": "s3cret-value",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_REDIRECT_URI":  "https://casaos.example.com/api/v1/recover/GoogleDrive",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_SCOPES":        "drive.readonly openid",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_PKCE":          "true",
		"RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_STYLE":    "basic",
	}
}

func TestLoadProvidersHappyPath(t *testing.T) {
	providers, err := loadProviders(environmentLookup(validProviderEnvironment()), nil)
	if err != nil {
		t.Fatalf("loadProviders: %v", err)
	}
	provider, present := providers["google_drive"]
	if !present {
		t.Fatal("provider was not loaded")
	}
	if provider.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" ||
		provider.TokenURL != "https://oauth2.googleapis.com/token" ||
		provider.ClientID != "1234567890.apps.googleusercontent.com" ||
		provider.ClientSecret != "s3cret-value" ||
		provider.AuthStyle != AuthStyleBasic {
		t.Fatalf("provider = %+v", provider)
	}
	if !reflect.DeepEqual(provider.Scopes, []string{"drive.readonly", "openid"}) {
		t.Fatalf("scopes = %v", provider.Scopes)
	}
	if redirects := RedirectURIs(providers); len(redirects) != 1 || redirects[0] != provider.RedirectURI {
		t.Fatalf("redirects = %v", redirects)
	}
}

func TestLoadProvidersUnsetIsEmptyAndNotAnError(t *testing.T) {
	providers, err := loadProviders(environmentLookup(nil), nil)
	if err != nil || len(providers) != 0 {
		t.Fatalf("providers = %v, err = %v", providers, err)
	}
	providers, err = loadProviders(environmentLookup(map[string]string{providersEnvironmentVariable: "  "}), nil)
	if err != nil || len(providers) != 0 {
		t.Fatalf("blank list providers = %v, err = %v", providers, err)
	}
}

func TestLoadProvidersRejectsIncompleteOrUnsafeConfiguration(t *testing.T) {
	mutations := map[string]func(map[string]string){
		"missing auth url":  func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_URL") },
		"missing token url": func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL") },
		"missing client id": func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_ID") },
		"missing redirect":  func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_REDIRECT_URI") },
		"missing scopes":    func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_SCOPES") },
		"pkce missing":      func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_PKCE") },
		"pkce false":        func(values map[string]string) { values["RECASAOS_OAUTH_GOOGLE_DRIVE_PKCE"] = "false" },
		"both secrets": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET_FILE"] = "/etc/recasaos/secret"
		},
		"neither secret": func(values map[string]string) { delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET") },
		"http auth url": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_URL"] = "http://accounts.google.com/o/oauth2/v2/auth"
		},
		"ip literal token url": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL"] = "https://142.250.72.14/token"
		},
		"userinfo token url": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL"] = "https://user:pass@oauth2.googleapis.com/token"
		},
		"query auth url": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_URL"] = "https://accounts.google.com/o/oauth2/v2/auth?x=1"
		},
		"uppercase host": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL"] = "https://OAuth2.Googleapis.com/token"
		},
		"explicit port": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL"] = "https://oauth2.googleapis.com:8443/token"
		},
		"trailing dot host": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_TOKEN_URL"] = "https://oauth2.googleapis.com./token"
		},
		"localhost redirect": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_REDIRECT_URI"] = "https://localhost/callback"
		},
		"internal redirect": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_REDIRECT_URI"] = "https://auth.internal/callback"
		},
		"empty scope token": func(values map[string]string) { values["RECASAOS_OAUTH_GOOGLE_DRIVE_SCOPES"] = "drive,,openid" },
		"too many scopes": func(values map[string]string) {
			values["RECASAOS_OAUTH_GOOGLE_DRIVE_SCOPES"] = strings.Repeat("a ", 32)
		},
		"secret with newline":   func(values map[string]string) { values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET"] = "line\nbreak" },
		"secret with space":     func(values map[string]string) { values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET"] = " padded " },
		"bad auth style":        func(values map[string]string) { values["RECASAOS_OAUTH_GOOGLE_DRIVE_AUTH_STYLE"] = "header" },
		"invalid provider name": func(values map[string]string) { values["RECASAOS_OAUTH_PROVIDERS"] = "Google_Drive" },
		"duplicate provider":    func(values map[string]string) { values["RECASAOS_OAUTH_PROVIDERS"] = "google_drive,google_drive" },
	}
	for name, mutate := range mutations {
		values := validProviderEnvironment()
		mutate(values)
		if _, err := loadProviders(environmentLookup(values), nil); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s error = %v, want ErrInvalidConfiguration", name, err)
		}
	}
}

func TestLoadProvidersReadsCredentialFileThroughInjectedReader(t *testing.T) {
	values := validProviderEnvironment()
	delete(values, "RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET")
	values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET_FILE"] = "/run/credentials/casaos.service/oauth-google"
	var requested string
	providers, err := loadProviders(environmentLookup(values), func(path string) ([]byte, error) {
		requested = path
		return []byte("credential-secret"), nil
	})
	if err != nil {
		t.Fatalf("loadProviders: %v", err)
	}
	if requested != "/run/credentials/casaos.service/oauth-google" {
		t.Fatalf("credential path = %q", requested)
	}
	if providers["google_drive"].ClientSecret != "credential-secret" {
		t.Fatal("credential secret was not used")
	}

	values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET_FILE"] = "/run/credentials/casaos.service/oauth-google"
	values["RECASAOS_OAUTH_GOOGLE_DRIVE_CLIENT_SECRET"] = "inline"
	if _, err := loadProviders(environmentLookup(values), func(string) ([]byte, error) {
		return []byte("credential-secret"), nil
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("dual source error = %v", err)
	}
}

func TestReadCredentialFileEnforcesOwnershipAndMode(t *testing.T) {
	directory := t.TempDir()
	good := filepath.Join(directory, "good")
	if err := os.WriteFile(good, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, err := readCredentialFile(good); err != nil || string(content) != "secret" {
		t.Fatalf("good credential = %q, err = %v", content, err)
	}
	if err := os.Chmod(good, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(good); err != nil {
		t.Fatalf("0400 credential rejected: %v", err)
	}

	worldReadable := filepath.Join(directory, "world")
	if err := os.WriteFile(worldReadable, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(worldReadable); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("0644 credential error = %v", err)
	}

	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(good, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialFile(symlink); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("symlink credential error = %v", err)
	}

	if _, err := readCredentialFile("relative/path"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("relative credential error = %v", err)
	}
	if _, err := readCredentialFile(filepath.Join(directory, "missing")); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing credential error = %v", err)
	}
	if _, err := readCredentialFile(directory); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("directory credential error = %v", err)
	}
}

func TestParsePublicHTTPSURLRejectsUnsafeShapes(t *testing.T) {
	valid := []string{
		"https://oauth2.googleapis.com/token",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://login.microsoftonline.com/common/oauth2/v2.0/token",
		"https://example.com/",
	}
	for _, value := range valid {
		if _, err := ParsePublicHTTPSURL(value); err != nil {
			t.Fatalf("valid URL %q rejected: %v", value, err)
		}
	}
	invalid := []string{
		"",
		"https://",
		"http://example.com/x",
		"https://example.com:443/x",
		"https://user@example.com/x",
		"https://example.com/x#fragment",
		"https://example.com/x?query=1",
		"https://-bad.example.com/x",
		"https://bad-.example.com/x",
		"https://exa mple.com/x",
		"https://example.com\\x",
		"ftp://example.com/x",
		"https://127.0.0.1/token",
		"https://[::1]/token",
		" https://example.com/x",
	}
	for _, value := range invalid {
		if _, err := ParsePublicHTTPSURL(value); err == nil {
			t.Fatalf("unsafe URL %q was accepted", value)
		}
	}
}
