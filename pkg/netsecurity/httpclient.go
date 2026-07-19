package netsecurity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUnsafeURL        = errors.New("outbound URL is not allowed")
	ErrResponseTooLarge = errors.New("outbound response is too large")
	// canonicalPublicHTTPSURL rejects ambiguous URL spellings before the
	// structured and DNS-aware checks below. In particular, the authority is
	// ASCII-only and paths/queries must use RFC 3986 characters or percent
	// encoding; raw Unicode, fragments, backslashes, and trailing-dot hosts are
	// not accepted.
	canonicalPublicHTTPSURL = regexp.MustCompile(`^https://[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?(?::443)?(?:[/?](?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*)?$`)

	blockedOutboundPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),      // current host / software source addresses
		netip.MustParsePrefix("100.64.0.0/10"),  // shared carrier-grade NAT
		netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),   // documentation
		netip.MustParsePrefix("192.88.99.0/24"), // deprecated 6to4 relay anycast
		netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
		netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use prefix
		netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments
		netip.MustParsePrefix("2001:db8::/32"),  // documentation
		netip.MustParsePrefix("2002::/16"),      // 6to4 IPv4 tunneling
		netip.MustParsePrefix("3fff::/20"),      // documentation
	}
	allocatedIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")
)

type FetchCapability uint8

const (
	SearchSuggestionsCapability FetchCapability = iota + 1
	StaticAssetCapability

	maximumResponseHeaderBytes = 64 << 10
)

type capabilityTransport struct {
	capability FetchCapability
	base       http.RoundTripper
}

func (transport capabilityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || (request.Body != nil && request.Body != http.NoBody) {
		return nil, ErrUnsafeURL
	}
	if _, err := ValidatePublicHTTPSURL(request.URL.String(), transport.capability); err != nil {
		return nil, err
	}
	return transport.base.RoundTrip(request)
}

// ValidatePublicHTTPSURL permits only the exact hosts assigned to capability,
// over canonical HTTPS on the default port. The transport repeats IP checks
// after DNS resolution, so authorized names cannot resolve to private services.
func ValidatePublicHTTPSURL(rawURL string, capability FetchCapability) (*url.URL, error) {
	if strings.TrimSpace(rawURL) != rawURL || len(rawURL) == 0 || len(rawURL) > 4096 || strings.IndexByte(rawURL, 0) >= 0 {
		return nil, ErrUnsafeURL
	}
	if !canonicalPublicHTTPSURL.MatchString(rawURL) {
		return nil, ErrUnsafeURL
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrUnsafeURL
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, ErrUnsafeURL
	}
	if parsed.RawPath != "" || parsed.ForceQuery || parsed.EscapedPath() != parsed.Path || !capabilityAllowsURL(parsed, capability) {
		return nil, ErrUnsafeURL
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return nil, ErrUnsafeURL
	}
	if address, err := netip.ParseAddr(host); err == nil && !isPublicAddress(address) {
		return nil, ErrUnsafeURL
	}
	return parsed, nil
}

func capabilityAllowsURL(parsed *url.URL, capability FetchCapability) bool {
	host := parsed.Hostname()
	switch capability {
	case SearchSuggestionsCapability:
		switch host {
		case "www.bing.com":
			return parsed.Path == "/osjson.aspx" && hasExactSearchQuery(parsed, "query", nil)
		case "www.google.com":
			return parsed.Path == "/complete/search" && hasExactSearchQuery(parsed, "q", map[string]string{
				"authuser": "0",
				"client":   "gws-wiz",
				"dpr":      "1",
				"hl":       "en-US",
				"xssi":     "t",
			})
		case "www.baidu.com":
			return parsed.Path == "/sugrec" && hasExactSearchQuery(parsed, "wd", map[string]string{
				"json": "1",
				"prod": "pc",
			})
		case "duckduckgo.com":
			return parsed.Path == "/ac/" && hasExactSearchQuery(parsed, "q", map[string]string{"type": "list"})
		case "www.startpage.com":
			return parsed.Path == "/suggestions" && hasExactSearchQuery(parsed, "q", map[string]string{
				"lui":     "english",
				"segment": "startpage.udog",
			})
		}
	case StaticAssetCapability:
		if parsed.RawQuery != "" {
			return false
		}
		switch host {
		case "files.codelife.cc":
			switch parsed.Path {
			case "/itab/search/bing.svg", "/itab/search/google.svg", "/itab/search/baidu.svg", "/itab/search/duckduckgo.svg":
				return true
			}
		case "www.startpage.com":
			return parsed.Path == "/sp/cdn/favicons/apple-touch-icon-60x60--default.png"
		}
	}
	return false
}

func hasExactSearchQuery(parsed *url.URL, termKey string, fixed map[string]string) bool {
	if parsed.RawQuery == "" {
		return false
	}
	for _, pair := range strings.Split(parsed.RawQuery, "&") {
		key, _, found := strings.Cut(pair, "=")
		if !found || key == "" || strings.ContainsAny(key, "%+") {
			return false
		}
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != len(fixed)+1 {
		return false
	}
	term, ok := query[termKey]
	if !ok || len(term) != 1 || !validSearchTerm(term[0]) {
		return false
	}
	for key, expected := range fixed {
		values, ok := query[key]
		if !ok || len(values) != 1 || values[0] != expected {
			return false
		}
	}
	return true
}

func validSearchTerm(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// NewPublicHTTPSClient creates a capability-bound direct client that does not
// honor ambient proxy variables. Every connection resolves the hostname and
// rejects the entire result set if any address is non-public. Redirects are
// revalidated against the same capability.
func NewPublicHTTPSClient(capability FetchCapability, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: capabilityTransport{capability: capability, base: sharedPublicHTTPSTransport},
		Timeout:   timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			_, err := ValidatePublicHTTPSURL(request.URL.String(), capability)
			return err
		},
	}
}

var sharedPublicHTTPSTransport = newPublicHTTPSTransport()

func newPublicHTTPSTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: maximumResponseHeaderBytes,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           20,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, ErrUnsafeURL
			}
			addresses, err := resolvePublicAddresses(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, resolved := range addresses {
				connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
				if err == nil {
					return connection, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func GetPublicHTTPS(ctx context.Context, capability FetchCapability, rawURL string, timeout time.Duration) (*http.Response, error) {
	parsed, err := ValidatePublicHTTPSURL(rawURL, capability)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, ErrUnsafeURL
	}
	request.Header.Set("Accept", "application/json, text/plain, image/*;q=0.8, */*;q=0.1")
	return NewPublicHTTPSClient(capability, timeout).Do(request)
}

func ReadBodyLimited(body io.Reader, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, ErrResponseTooLarge
	}
	limited := io.LimitReader(body, maximum+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, ErrResponseTooLarge
	}
	return content, nil
}

func resolvePublicAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		address = address.Unmap()
		if !isPublicAddress(address) {
			return nil, ErrUnsafeURL
		}
		return []netip.Addr{address}, nil
	}

	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("outbound host has no addresses")
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
		if !isPublicAddress(addresses[index]) {
			return nil, ErrUnsafeURL
		}
	}
	return addresses, nil
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedOutboundPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	// Go's IsGlobalUnicast intentionally returns true for IPv6 ranges outside
	// IANA's currently allocated 2000::/3 space. Outbound authorization is more
	// conservative: only presently allocated global-unicast space is eligible.
	if address.Is6() && !allocatedIPv6GlobalUnicast.Contains(address) {
		return false
	}
	return true
}
