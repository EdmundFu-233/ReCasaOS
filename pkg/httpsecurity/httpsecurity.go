// Package httpsecurity contains the HTTP trust-boundary checks shared by the
// API routers and their WebSocket endpoints.
package httpsecurity

import (
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	// AllowedOriginsEnv is a comma-separated list of exact HTTP(S) origins that
	// may access the API across origins.
	AllowedOriginsEnv = "RECASAOS_ALLOWED_ORIGINS"
	// TrustLoopbackAuthBypassEnv enables the legacy loopback JWT bypass only
	// when it is set to the exact value "1".
	TrustLoopbackAuthBypassEnv = "RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS"

	allowedMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	allowedHeaders = "Authorization, Content-Length, Content-Type, X-CSRF-Token, X-Requested-With"
	exposedHeaders = "Content-Length"
)

var allowedMethodSet = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodPatch:   {},
	http.MethodDelete:  {},
	http.MethodOptions: {},
}

// IsDirectLoopbackRequest reports whether the request's socket peer is a
// loopback address. Forwarding headers are deliberately ignored because they
// are supplied by the requester unless a trusted proxy policy says otherwise.
func IsDirectLoopbackRequest(r *http.Request) bool {
	return r != nil && IsDirectLoopback(r.RemoteAddr)
}

// LoopbackAuthBypassAllowed reports whether the legacy local authentication
// bypass was explicitly enabled and the direct socket peer is loopback.
func LoopbackAuthBypassAllowed(r *http.Request) bool {
	return os.Getenv(TrustLoopbackAuthBypassEnv) == "1" && IsDirectLoopbackRequest(r)
}

// IsDirectLoopback reports whether remoteAddr is a literal loopback IP, with
// or without a port. Hostnames such as "localhost" are intentionally rejected.
func IsDirectLoopback(remoteAddr string) bool {
	if addrPort, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return addrPort.Addr().Unmap().IsLoopback()
	}

	addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(remoteAddr, "["), "]"))
	return err == nil && addr.Unmap().IsLoopback()
}

// AllowedOriginsFromEnv returns the valid, canonical origins configured in
// RECASAOS_ALLOWED_ORIGINS. Invalid entries and duplicates are ignored.
func AllowedOriginsFromEnv() []string {
	return ParseAllowedOrigins(os.Getenv(AllowedOriginsEnv))
}

// ParseAllowedOrigins parses a comma-separated list of exact HTTP(S) origins.
func ParseAllowedOrigins(value string) []string {
	origins := make([]string, 0)
	seen := make(map[string]struct{})

	for _, candidate := range strings.Split(value, ",") {
		origin, ok := NormalizeOrigin(candidate)
		if !ok {
			continue
		}
		if _, exists := seen[origin]; exists {
			continue
		}

		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}

	return origins
}

// NormalizeOrigin returns the canonical serialization of an HTTP(S) origin.
// Paths, queries, fragments, user information, wildcards, and invalid ports
// are rejected because they do not identify an exact web origin.
func NormalizeOrigin(value string) (string, bool) {
	raw := strings.TrimSpace(value)
	if raw == "" || strings.ContainsAny(raw, "?#") {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	if u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", false
	}

	authority, ok := normalizeAuthority(u.Host, scheme)
	if !ok {
		return "", false
	}

	return scheme + "://" + authority, true
}

// WebSocketOriginAllowed accepts non-browser clients without Origin, browser
// clients whose Origin matches the connection scheme and request Host, and
// explicitly allowed cross-origin clients.
func WebSocketOriginAllowed(r *http.Request) bool {
	if r == nil {
		return false
	}

	originHeader, singleOriginHeader := requestOriginHeader(r)
	if !singleOriginHeader {
		return false
	}
	if originHeader == "" {
		return true
	}

	origin, ok := NormalizeOrigin(originHeader)
	if !ok {
		return false
	}
	if originMatchesRequest(origin, r) {
		return true
	}

	for _, allowed := range AllowedOriginsFromEnv() {
		if origin == allowed {
			return true
		}
	}

	return false
}

// WithCORS enforces same-origin access by default and permits only the supplied
// exact origins for cross-origin requests. Requests without Origin are accepted
// for compatibility with non-browser clients.
func WithCORS(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, candidate := range allowedOrigins {
		if origin, ok := NormalizeOrigin(candidate); ok {
			allowed[origin] = struct{}{}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHeader, singleOriginHeader := requestOriginHeader(r)
		if originHeader == "" {
			if !singleOriginHeader {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		appendVary(w.Header(), "Origin")
		if !singleOriginHeader {
			http.Error(w, "cross-origin request denied", http.StatusForbidden)
			return
		}
		origin, valid := NormalizeOrigin(originHeader)
		_, explicitlyAllowed := allowed[origin]
		if !valid || (!originMatchesRequest(origin, r) && !explicitlyAllowed) {
			http.Error(w, "cross-origin request denied", http.StatusForbidden)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", exposedHeaders)

		if isPreflight(r) {
			appendVary(w.Header(), "Access-Control-Request-Method")
			appendVary(w.Header(), "Access-Control-Request-Headers")
			requestedMethod := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
			if _, ok := allowedMethodSet[requestedMethod]; !ok {
				http.Error(w, "cross-origin method denied", http.StatusForbidden)
				return
			}

			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
			w.Header().Set("Access-Control-Max-Age", "172800")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// WithSecurityHeaders adds browser hardening headers to every API response,
// including middleware-generated error and preflight responses.
func WithSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		next.ServeHTTP(w, r)
	})
}

func originMatchesRequest(origin string, r *http.Request) bool {
	if r == nil {
		return false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestOrigin, ok := NormalizeOrigin(scheme + "://" + strings.TrimSpace(r.Host))
	return ok && origin == requestOrigin
}

func normalizeAuthority(authority, scheme string) (string, bool) {
	if authority == "" || strings.ContainsAny(authority, "@/?#") || strings.HasSuffix(authority, ":") {
		return "", false
	}

	u, err := url.Parse("//" + authority)
	if err != nil || u.Host != authority || u.User != nil {
		return "", false
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || strings.Contains(hostname, "%") {
		return "", false
	}
	if ip, err := netip.ParseAddr(hostname); err == nil {
		hostname = ip.String()
	} else {
		if strings.HasPrefix(authority, "[") {
			return "", false
		}
		for _, character := range hostname {
			if !isHostnameCharacter(character) {
				return "", false
			}
		}
	}

	port := u.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", false
		}
		port = strconv.Itoa(portNumber)
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			port = ""
		}
	}

	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port != "" {
		return hostname + ":" + port, true
	}
	return hostname, true
}

func isHostnameCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		character == '.' || character == '-' || character == '_'
}

func requestOriginHeader(r *http.Request) (string, bool) {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 {
		return "", false
	}
	return strings.TrimSpace(values[0]), true
}

func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}

func appendVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		for _, token := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(token), value) {
				return
			}
		}
	}
	header.Add("Vary", value)
}
