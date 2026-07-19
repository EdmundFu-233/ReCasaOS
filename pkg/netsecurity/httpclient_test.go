package netsecurity

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestValidatePublicHTTPSURLAllowsEachCapabilityHost(t *testing.T) {
	tests := []struct {
		name       string
		capability FetchCapability
		url        string
	}{
		{name: "bing suggestions", capability: SearchSuggestionsCapability, url: "https://www.bing.com/osjson.aspx?query=test"},
		{name: "google suggestions", capability: SearchSuggestionsCapability, url: "https://www.google.com/complete/search?client=gws-wiz&xssi=t&hl=en-US&authuser=0&dpr=1&q=hello+world"},
		{name: "baidu suggestions", capability: SearchSuggestionsCapability, url: "https://www.baidu.com/sugrec?json=1&prod=pc&wd=test"},
		{name: "duckduckgo suggestions", capability: SearchSuggestionsCapability, url: "https://duckduckgo.com/ac/?type=list&q=test"},
		{name: "startpage suggestions", capability: SearchSuggestionsCapability, url: "https://www.startpage.com:443/suggestions?segment=startpage.udog&lui=english&q=test"},
		{name: "codelife asset", capability: StaticAssetCapability, url: "https://files.codelife.cc/itab/search/bing.svg"},
		{name: "startpage asset", capability: StaticAssetCapability, url: "https://www.startpage.com/sp/cdn/favicons/apple-touch-icon-60x60--default.png"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidatePublicHTTPSURL(test.url, test.capability); err != nil {
				t.Fatalf("ValidatePublicHTTPSURL(%q) = %v", test.url, err)
			}
		})
	}
}

func TestValidatePublicHTTPSURLRejectsUnauthorizedAndAmbiguousTargets(t *testing.T) {
	invalid := []struct {
		capability FetchCapability
		url        string
	}{
		{SearchSuggestionsCapability, "https://www.bing.com.evil.example/osjson.aspx"},
		{SearchSuggestionsCapability, "https://evil-www.google.com/complete/search"},
		{SearchSuggestionsCapability, "https://www.baidu.com.attacker.example/sugrec"},
		{SearchSuggestionsCapability, "https://duckduckgo.com.evil.example/ac/"},
		{SearchSuggestionsCapability, "https://www.startpage.com.attacker.example/suggestions"},
		{SearchSuggestionsCapability, "https://files.codelife.cc/itab/search/bing.svg"},
		{StaticAssetCapability, "https://files.codelife.cc.evil.example/itab/search/bing.svg"},
		{StaticAssetCapability, "https://www.startpage.com.attacker.example/sp/cdn/icon.png"},
		{StaticAssetCapability, "https://www.google.com/complete/search?q=test"},
		{StaticAssetCapability, "https://files.codelife.cc/"},
		{StaticAssetCapability, "https://files.codelife.cc/itab/search/bing.svg?"},
		{StaticAssetCapability, "https://files.codelife.cc/itab/search/bing.svg?download=1"},
		{StaticAssetCapability, "https://www.startpage.com/sp/cdn/favicons/other.png"},
		{SearchSuggestionsCapability, "https://www.bing.com/search?q=test"},
		{SearchSuggestionsCapability, "https://www.bing.com/osjson.aspx?other=test"},
		{SearchSuggestionsCapability, "https://www.bing.com/osjson.aspx?query="},
		{SearchSuggestionsCapability, "https://www.bing.com/osjson.aspx?query=one&query=two"},
		{SearchSuggestionsCapability, "https://www.google.com/complete/search?client=gws-wiz&q=test"},
		{SearchSuggestionsCapability, "https://www.baidu.com/sugrec?json=1&wd=test"},
		{SearchSuggestionsCapability, "https://www.startpage.com/suggestions?segment=startpage.udog&lui=english&q=test%0aheader"},
		{SearchSuggestionsCapability, "https://www.bing.com/%6fsjson.aspx?query=test"},
		{SearchSuggestionsCapability, "https://www.bing.com/osjson.aspx?%71uery=test"},
		{FetchCapability(255), "https://files.codelife.cc/itab/search/bing.svg"},
		{SearchSuggestionsCapability, "http://www.bing.com/"},
		{SearchSuggestionsCapability, "https://user:secret@www.bing.com/"},
		{SearchSuggestionsCapability, "https://www.bing.com:8443/"},
		{SearchSuggestionsCapability, "https://localhost/"},
		{SearchSuggestionsCapability, "https://service.internal/"},
		{SearchSuggestionsCapability, "https://127.0.0.1/"},
		{SearchSuggestionsCapability, "https://10.0.0.1/"},
		{SearchSuggestionsCapability, "https://169.254.169.254/latest/meta-data/"},
		{SearchSuggestionsCapability, "https://[::1]/"},
		{SearchSuggestionsCapability, "HTTPS://www.bing.com/"},
		{SearchSuggestionsCapability, "https://www.bing.com./"},
		{SearchSuggestionsCapability, "https://www.bing.com/raw unicode"},
		{SearchSuggestionsCapability, "https://www.bing.com/搜索"},
		{SearchSuggestionsCapability, "https://www.bing.com/path\\segment"},
		{SearchSuggestionsCapability, "https://www.bing.com/<script>"},
		{SearchSuggestionsCapability, "https://www.bing.com/%invalid"},
		{SearchSuggestionsCapability, "https://[2606:4700:4700::1111%25eth0]/"},
		{SearchSuggestionsCapability, " https://www.bing.com/"},
	}
	for _, test := range invalid {
		if _, err := ValidatePublicHTTPSURL(test.url, test.capability); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("ValidatePublicHTTPSURL(%q, %d) error = %v, want ErrUnsafeURL", test.url, test.capability, err)
		}
	}
}

func TestRedirectRevalidatesCapabilityHost(t *testing.T) {
	tests := []struct {
		name       string
		capability FetchCapability
		redirect   string
		wantError  bool
	}{
		{name: "search stays on suggestion host", capability: SearchSuggestionsCapability, redirect: "https://www.google.com/complete/search?client=gws-wiz&xssi=t&hl=en-US&authuser=0&dpr=1&q=test"},
		{name: "asset stays on codelife", capability: StaticAssetCapability, redirect: "https://files.codelife.cc/itab/search/google.svg"},
		{name: "search cannot redirect to asset host", capability: SearchSuggestionsCapability, redirect: "https://files.codelife.cc/itab/search/google.svg", wantError: true},
		{name: "asset cannot redirect to search host", capability: StaticAssetCapability, redirect: "https://www.google.com/complete/search?q=test", wantError: true},
		{name: "similar search host rejected", capability: SearchSuggestionsCapability, redirect: "https://www.google.com.evil.example/complete/search", wantError: true},
		{name: "external redirect rejected", capability: StaticAssetCapability, redirect: "https://evil.example/asset.png", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, test.redirect, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = NewPublicHTTPSClient(test.capability, time.Second).CheckRedirect(request, nil)
			if test.wantError && !errors.Is(err, ErrUnsafeURL) {
				t.Fatalf("redirect error = %v, want ErrUnsafeURL", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("redirect error = %v", err)
			}
		})
	}
}

func TestPublicHTTPSClientIsDirectAndBounded(t *testing.T) {
	client := NewPublicHTTPSClient(StaticAssetCapability, time.Second)
	boundTransport, ok := client.Transport.(capabilityTransport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	transport, ok := boundTransport.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport type = %T", boundTransport.base)
	}
	if transport.Proxy != nil {
		t.Fatal("public HTTPS client must not honor ambient proxy configuration")
	}
	if transport.MaxResponseHeaderBytes != maximumResponseHeaderBytes {
		t.Fatalf("MaxResponseHeaderBytes = %d, want %d", transport.MaxResponseHeaderBytes, maximumResponseHeaderBytes)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("public HTTPS client must require TLS 1.2 or newer")
	}
	second := NewPublicHTTPSClient(SearchSuggestionsCapability, 2*time.Second)
	secondBoundTransport, ok := second.Transport.(capabilityTransport)
	if !ok || secondBoundTransport.base != boundTransport.base {
		t.Fatal("capability clients must share one bounded connection pool")
	}
}

func TestPublicHTTPSClientValidatesInitialRequest(t *testing.T) {
	client := NewPublicHTTPSClient(StaticAssetCapability, time.Second)
	request, err := http.NewRequest(http.MethodGet, "https://files.codelife.cc/unauthorized", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("initial request error = %v, want ErrUnsafeURL", err)
	}

	request, err = http.NewRequest(http.MethodPost, "https://files.codelife.cc/itab/search/bing.svg", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("non-GET request error = %v, want ErrUnsafeURL", err)
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, candidate := range []string{
		"0.0.0.1", "127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1",
		"192.0.2.1", "192.88.99.1", "198.18.0.1", "203.0.113.1", "::1", "100::1", "fec0::1", "fe80::1",
		"64:ff9b::a00:1", "64:ff9b:1::a00:1", "2001::a00:1", "2001:2::1", "2001:10::1", "2001:20::1", "2001:db8::1", "2002:0a00:0001::", "3fff::1", "4000::1",
	} {
		if isPublicAddress(netip.MustParseAddr(candidate)) {
			t.Errorf("%s unexpectedly accepted", candidate)
		}
	}
	for _, candidate := range []string{"93.184.216.34", "2606:4700:4700::1111"} {
		if !isPublicAddress(netip.MustParseAddr(candidate)) {
			t.Errorf("%s unexpectedly rejected", candidate)
		}
	}
}

func TestReadBodyLimited(t *testing.T) {
	content, err := ReadBodyLimited(strings.NewReader("safe"), 4)
	if err != nil || string(content) != "safe" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
	if _, err := ReadBodyLimited(strings.NewReader("oversized"), 4); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}
