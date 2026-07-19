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
		netip.MustParsePrefix("100.64.0.0/10"), // shared carrier-grade NAT
		netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),  // documentation
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
		netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use prefix
		netip.MustParsePrefix("2001::/32"),      // Teredo IPv4 tunneling
		netip.MustParsePrefix("2001:db8::/32"),  // documentation
		netip.MustParsePrefix("2002::/16"),      // 6to4 IPv4 tunneling
	}
)

type FetchCapability uint8

const (
	SearchSuggestionsCapability FetchCapability = iota + 1
	StaticAssetCapability

	maximumResponseHeaderBytes = 64 << 10
)

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
	switch capability {
	case SearchSuggestionsCapability:
		switch parsed.Hostname() {
		case "www.bing.com", "www.google.com", "www.baidu.com", "duckduckgo.com", "www.startpage.com":
		default:
			return nil, ErrUnsafeURL
		}
	case StaticAssetCapability:
		switch parsed.Hostname() {
		case "files.codelife.cc", "www.startpage.com":
		default:
			return nil, ErrUnsafeURL
		}
	default:
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

// NewPublicHTTPSClient creates a capability-bound direct client that does not
// honor ambient proxy variables. Every connection resolves the hostname and
// rejects the entire result set if any address is non-public. Redirects are
// revalidated against the same capability.
func NewPublicHTTPSClient(capability FetchCapability, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
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
	return &http.Client{
		Transport: transport,
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
	return true
}
