package oauthsecurity

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	providersEnvironmentVariable = "RECASAOS_OAUTH_PROVIDERS"
	providerEnvironmentPrefix    = "RECASAOS_OAUTH_"
	maxClientSecretBytes         = 4096
	maxScopes                    = 16
	maxScopeBytes                = 64
	maxURLLength                 = 2048
)

// ErrInvalidConfiguration reports incomplete or unsafe runtime provider
// configuration. It never carries secret values.
var ErrInvalidConfiguration = errors.New("invalid OAuth provider configuration")

// AuthStyle selects where the client secret is presented.
type AuthStyle uint8

const (
	// AuthStyleBody sends client_id and client_secret in the form body.
	AuthStyleBody AuthStyle = iota + 1
	// AuthStyleBasic sends the client secret with HTTP Basic authentication.
	AuthStyleBasic
)

// Provider is one fully configured OAuth provider. It is only constructed by
// LoadProvidersFromEnvironment, which enforces the runtime secret boundary.
type Provider struct {
	Name         string
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	AuthStyle    AuthStyle
}

// ParsePublicHTTPSURL validates a canonical bare HTTPS URL: lowercase ASCII
// DNS host, no userinfo, no fragment, no query, and no explicit non-443 port.
// The returned URL is always freshly parsed from the accepted input.
func ParsePublicHTTPSURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxURLLength || strings.TrimSpace(raw) != raw || strings.IndexByte(raw, 0) >= 0 {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" {
		return nil, ErrInvalidConfiguration
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" {
		return nil, ErrInvalidConfiguration
	}
	if parsed.Host != strings.ToLower(parsed.Host) || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, ErrInvalidConfiguration
	}
	// The default port must not be spelled explicitly so the configured value
	// is the single canonical form compared at exchange time.
	if parsed.Port() != "" {
		return nil, ErrInvalidConfiguration
	}
	host := parsed.Hostname()
	if host != strings.TrimSuffix(host, ".") || net.ParseIP(host) != nil {
		return nil, ErrInvalidConfiguration
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return nil, ErrInvalidConfiguration
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return nil, ErrInvalidConfiguration
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return nil, ErrInvalidConfiguration
		}
		for i := 0; i < len(label); i++ {
			switch character := label[i]; {
			case character >= 'a' && character <= 'z',
				character >= '0' && character <= '9',
				character == '-':
			default:
				return nil, ErrInvalidConfiguration
			}
		}
	}
	if parsed.Path != "" && !strings.HasPrefix(parsed.Path, "/") {
		return nil, ErrInvalidConfiguration
	}
	return url.Parse(raw)
}

func validClientID(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validClientSecret(value string) bool {
	if value == "" || len(value) > maxClientSecretBytes || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func parseScopes(value string) ([]string, error) {
	if value == "" {
		return nil, ErrInvalidConfiguration
	}
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields) > maxScopes {
		return nil, ErrInvalidConfiguration
	}
	scopes := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if len(field) > maxScopeBytes || !validScopeToken(field) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := seen[field]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		seen[field] = struct{}{}
		scopes = append(scopes, field)
	}
	return scopes, nil
}

func validScopeToken(value string) bool {
	for i := 0; i < len(value); i++ {
		switch character := value[i]; {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '.', character == '_', character == '~',
			character == ':', character == '/', character == '-':
		default:
			return false
		}
	}
	return true
}

// LoadProvidersFromEnvironment parses the runtime provider configuration.
// Only providers listed in RECASAOS_OAUTH_PROVIDERS are returned, and each
// must be complete: a partially configured provider is a hard error so a
// typo cannot silently disable or half-enable a flow.
func LoadProvidersFromEnvironment() (map[string]Provider, error) {
	return loadProviders(os.LookupEnv, readCredentialFile)
}

func loadProviders(lookup func(string) (string, bool), readCredential func(string) ([]byte, error)) (map[string]Provider, error) {
	listValue, present := lookup(providersEnvironmentVariable)
	if !present || strings.TrimSpace(listValue) == "" {
		return map[string]Provider{}, nil
	}
	names := strings.Split(listValue, ",")
	if len(names) > 16 {
		return nil, ErrInvalidConfiguration
	}
	providers := make(map[string]Provider, len(names))
	for _, rawName := range names {
		name := strings.TrimSpace(rawName)
		if !ValidProviderName(name) {
			return nil, ErrInvalidConfiguration
		}
		if _, duplicate := providers[name]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		provider, err := loadProvider(lookup, readCredential, name)
		if err != nil {
			return nil, err
		}
		providers[name] = provider
	}
	return providers, nil
}

func loadProvider(lookup func(string) (string, bool), readCredential func(string) ([]byte, error), name string) (Provider, error) {
	prefix := providerEnvironmentPrefix + strings.ToUpper(name) + "_"
	required := func(suffix string) (string, error) {
		value, present := lookup(prefix + suffix)
		if !present || value == "" {
			return "", fmt.Errorf("%w: %s is missing", ErrInvalidConfiguration, strings.ToLower(suffix))
		}
		return value, nil
	}

	authURLValue, err := required("AUTH_URL")
	if err != nil {
		return Provider{}, err
	}
	tokenURLValue, err := required("TOKEN_URL")
	if err != nil {
		return Provider{}, err
	}
	clientID, err := required("CLIENT_ID")
	if err != nil {
		return Provider{}, err
	}
	redirectURI, err := required("REDIRECT_URI")
	if err != nil {
		return Provider{}, err
	}
	scopeValue, err := required("SCOPES")
	if err != nil {
		return Provider{}, err
	}
	if _, err := ParsePublicHTTPSURL(authURLValue); err != nil {
		return Provider{}, fmt.Errorf("%w: auth url", ErrInvalidConfiguration)
	}
	if _, err := ParsePublicHTTPSURL(tokenURLValue); err != nil {
		return Provider{}, fmt.Errorf("%w: token url", ErrInvalidConfiguration)
	}
	if _, err := ParsePublicHTTPSURL(redirectURI); err != nil {
		return Provider{}, fmt.Errorf("%w: redirect uri", ErrInvalidConfiguration)
	}
	if !validClientID(clientID) {
		return Provider{}, fmt.Errorf("%w: client id", ErrInvalidConfiguration)
	}
	scopes, err := parseScopes(scopeValue)
	if err != nil {
		return Provider{}, fmt.Errorf("%w: scopes", ErrInvalidConfiguration)
	}

	// PKCE is mandatory: a provider that cannot use it stays unsupported.
	pkce, present := lookup(prefix + "PKCE")
	if !present || strings.ToLower(strings.TrimSpace(pkce)) != "true" {
		return Provider{}, fmt.Errorf("%w: pkce must be true", ErrInvalidConfiguration)
	}

	inlineSecret, inlinePresent := lookup(prefix + "CLIENT_SECRET")
	secretFile, filePresent := lookup(prefix + "CLIENT_SECRET_FILE")
	if inlinePresent == filePresent {
		return Provider{}, fmt.Errorf("%w: exactly one client secret source is required", ErrInvalidConfiguration)
	}
	var secret string
	if inlinePresent {
		if !validClientSecret(inlineSecret) {
			return Provider{}, fmt.Errorf("%w: client secret", ErrInvalidConfiguration)
		}
		secret = inlineSecret
	} else {
		secretBytes, err := readCredential(secretFile)
		if err != nil {
			return Provider{}, fmt.Errorf("%w: client secret credential", ErrInvalidConfiguration)
		}
		if !validClientSecret(string(secretBytes)) {
			clear(secretBytes)
			return Provider{}, fmt.Errorf("%w: client secret credential", ErrInvalidConfiguration)
		}
		secret = string(secretBytes)
		clear(secretBytes)
	}

	authStyle := AuthStyleBody
	if style, present := lookup(prefix + "AUTH_STYLE"); present {
		switch strings.ToLower(strings.TrimSpace(style)) {
		case "body":
			authStyle = AuthStyleBody
		case "basic":
			authStyle = AuthStyleBasic
		default:
			return Provider{}, fmt.Errorf("%w: auth style", ErrInvalidConfiguration)
		}
	}

	return Provider{
		Name:         name,
		AuthURL:      authURLValue,
		TokenURL:     tokenURLValue,
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
		AuthStyle:    authStyle,
	}, nil
}

// readCredentialFile loads a systemd-credential-style secret file: absolute
// path, no symlinks, root-owned regular file with 0600 or 0400 permissions,
// and a bounded size. It never includes file content in errors.
func readCredentialFile(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidConfiguration
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidConfiguration
	}
	if info.Size() < 1 || info.Size() > maxClientSecretBytes {
		return nil, ErrInvalidConfiguration
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 && permissions != 0o400 {
		return nil, ErrInvalidConfiguration
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrInvalidConfiguration
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) < 1 || len(content) > maxClientSecretBytes {
		clear(content)
		return nil, ErrInvalidConfiguration
	}
	return content, nil
}

// RedirectURIs returns the sorted exact allowlist of configured redirects.
func RedirectURIs(providers map[string]Provider) []string {
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		seen[provider.RedirectURI] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for redirect := range seen {
		result = append(result, redirect)
	}
	sort.Strings(result)
	return result
}
