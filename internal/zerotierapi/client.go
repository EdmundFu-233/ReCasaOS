package zerotierapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	zeroTierPortFile              = "/var/lib/zerotier-one/zerotier-one.port"
	zeroTierAuthTokenFile         = "/var/lib/zerotier-one/authtoken.secret"
	zeroTierRequestTimeout        = 10 * time.Second
	zeroTierDialTimeout           = 2 * time.Second
	zeroTierResponseHeaderTimeout = 5 * time.Second
	zeroTierMaximumRequestBytes   = 1 << 20
	zeroTierMaximumResponseBytes  = 16 << 20
	zeroTierMaximumHeaderBytes    = 64 << 10
	zeroTierMaximumPortFileBytes  = 16
	zeroTierMaximumTokenFileBytes = 256
	zeroTierMaximumEndpointBytes  = 4096
	zeroTierMaximumContentType    = 4096
)

var (
	ErrZeroTierUnsafeEndpoint              = errors.New("unsafe ZeroTier endpoint")
	ErrZeroTierRequestTooLarge             = errors.New("ZeroTier request is too large")
	ErrZeroTierResponseTooLarge            = errors.New("ZeroTier response is too large")
	ErrZeroTierRedirect                    = errors.New("ZeroTier API redirect is forbidden")
	ErrZeroTierUntrustedPeer               = errors.New("ZeroTier API peer is not trusted")
	ErrZeroTierPeerVerificationUnavailable = errors.New("ZeroTier API peer verification is unavailable")
)

type zeroTierStateReader func(path string, maximum int64, secret bool) ([]byte, error)

type zeroTierAPI struct {
	client   *http.Client
	readFile zeroTierStateReader
	timeout  time.Duration
}

// ZeroTierResponse contains only the response metadata that may cross the
// local management boundary. In particular, arbitrary daemon headers are not
// exposed to browser clients.
type ZeroTierResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
}

var defaultZeroTierAPI = &zeroTierAPI{
	client:   newZeroTierHTTPClient(),
	readFile: readZeroTierStateFile,
	timeout:  zeroTierRequestTimeout,
}

func newZeroTierHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialTrustedZeroTierPeer,
		DisableCompression:     true,
		ResponseHeaderTimeout:  zeroTierResponseHeaderTimeout,
		MaxResponseHeaderBytes: zeroTierMaximumHeaderBytes,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        30 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   zeroTierRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func dialTrustedZeroTierPeer(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, ErrZeroTierUntrustedPeer
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return nil, ErrZeroTierUntrustedPeer
	}
	if _, err := parseZeroTierPort(port); err != nil {
		return nil, ErrZeroTierUntrustedPeer
	}

	dialer := net.Dialer{Timeout: zeroTierDialTimeout, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, err
	}
	if err := verifyZeroTierPeer(ctx, connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

// Request performs one bounded request to the root-authenticated local
// ZeroTier API. Callers provide only a method, endpoint, and body;
// authentication, representation headers, and transport selection remain
// owned here.
func Request(ctx context.Context, method, endpoint string, body []byte) (*ZeroTierResponse, error) {
	return defaultZeroTierAPI.request(ctx, method, endpoint, body)
}

func (api *zeroTierAPI) request(ctx context.Context, method, endpoint string, body []byte) (*ZeroTierResponse, error) {
	if ctx == nil || api == nil || api.client == nil || api.readFile == nil || api.timeout <= 0 {
		return nil, errors.New("invalid ZeroTier client configuration")
	}
	if !allowedZeroTierMethod(method) {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	if len(body) > zeroTierMaximumRequestBytes {
		return nil, ErrZeroTierRequestTooLarge
	}
	target, err := parseZeroTierEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	boundedContext, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	if err := boundedContext.Err(); err != nil {
		return nil, err
	}

	portBytes, err := api.readFile(zeroTierPortFile, zeroTierMaximumPortFileBytes, false)
	if err != nil {
		return nil, fmt.Errorf("read ZeroTier port state: %w", err)
	}
	if err := boundedContext.Err(); err != nil {
		return nil, err
	}
	port, err := parseZeroTierPort(strings.TrimSpace(string(portBytes)))
	if err != nil {
		return nil, err
	}
	target.Scheme = "http"
	target.Host = net.JoinHostPort("127.0.0.1", port)

	tokenBytes, err := api.readFile(zeroTierAuthTokenFile, zeroTierMaximumTokenFileBytes, true)
	if err != nil {
		return nil, fmt.Errorf("read ZeroTier authentication state: %w", err)
	}
	if err := boundedContext.Err(); err != nil {
		return nil, err
	}
	token, err := validateZeroTierToken(tokenBytes)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(boundedContext, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	request.Header.Set("X-ZT1-AUTH", token)
	request.Header.Set("User-Agent", "ReCasaOS/zerotier-local-api")
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost || method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := api.client.Do(request)
	if err != nil {
		return nil, sanitizeZeroTierRequestError(boundedContext, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 {
		return nil, errors.New("invalid ZeroTier API response status")
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return nil, ErrZeroTierRedirect
	}

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, zeroTierMaximumResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read ZeroTier API response: %w", err)
	}
	if len(responseBody) > zeroTierMaximumResponseBytes {
		return nil, ErrZeroTierResponseTooLarge
	}
	responseContentType := safeZeroTierContentType(response.Header.Get("Content-Type"))
	return &ZeroTierResponse{
		StatusCode:  response.StatusCode,
		ContentType: responseContentType,
		Body:        responseBody,
	}, nil
}

func sanitizeZeroTierRequestError(ctx context.Context, err error) error {
	if ctx != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
	}
	for _, stableError := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		ErrZeroTierUnsafeEndpoint,
		ErrZeroTierRequestTooLarge,
		ErrZeroTierResponseTooLarge,
		ErrZeroTierRedirect,
		ErrZeroTierUntrustedPeer,
		ErrZeroTierPeerVerificationUnavailable,
	} {
		if errors.Is(err, stableError) {
			return stableError
		}
	}
	return errors.New("call ZeroTier API failed")
}

func allowedZeroTierMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func safeZeroTierContentType(value string) string {
	if len(value) == 0 || len(value) > zeroTierMaximumContentType {
		return "application/octet-stream"
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil {
		return "application/octet-stream"
	}
	switch mediaType {
	case "application/json":
		if charset, ok := parameters["charset"]; ok && !strings.EqualFold(charset, "utf-8") {
			return "application/octet-stream"
		}
		return "application/json"
	case "text/plain":
		if charset, ok := parameters["charset"]; ok && !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "us-ascii") {
			return "application/octet-stream"
		}
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func parseZeroTierPort(raw string) (string, error) {
	if raw == "" || len(raw) > 5 {
		return "", ErrZeroTierUnsafeEndpoint
	}
	parsed, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != raw {
		return "", ErrZeroTierUnsafeEndpoint
	}
	return raw, nil
}

func parseZeroTierEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" || len(endpoint) > zeroTierMaximumEndpointBytes || endpoint[0] != '/' || strings.HasPrefix(endpoint, "//") || strings.ContainsAny(endpoint, "#\\\x00\r\n") {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	if strings.HasPrefix(parsed.Path, "//") || zeroTierPathContainsUnsafeByte(parsed.Path) || zeroTierPathHasDotSegment(parsed.Path) {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, ErrZeroTierUnsafeEndpoint
	}
	for key := range query {
		if key != "jsonp" {
			return nil, ErrZeroTierUnsafeEndpoint
		}
	}
	return parsed, nil
}

func zeroTierPathContainsUnsafeByte(path string) bool {
	for index := 0; index < len(path); index++ {
		character := path[index]
		if character < 0x20 || character == 0x7f || character == '\\' || character == '#' {
			return true
		}
	}
	return false
}

func zeroTierPathHasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func validateZeroTierToken(raw []byte) (string, error) {
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > zeroTierMaximumTokenFileBytes {
		return "", errors.New("invalid ZeroTier authentication state")
	}
	for index := 0; index < len(token); index++ {
		if token[index] < 0x21 || token[index] > 0x7e {
			return "", errors.New("invalid ZeroTier authentication state")
		}
	}
	return token, nil
}

func readZeroTierStateFile(path string, maximum int64, secret bool) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("untrusted ZeroTier state file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) || !zeroTierStateFileOwnedByRoot(info) {
		return nil, errors.New("untrusted ZeroTier state file")
	}
	permissions := info.Mode().Perm()
	if (secret && permissions&0077 != 0) || (!secret && permissions&0022 != 0) {
		return nil, errors.New("unsafe ZeroTier state file permissions")
	}

	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, errors.New("ZeroTier state file is too large")
	}
	return content, nil
}

func Get(endpoint string) ([]byte, error) {
	return GetContext(context.Background(), endpoint)
}

func GetContext(ctx context.Context, endpoint string) ([]byte, error) {
	return defaultZeroTierAPI.get(ctx, endpoint)
}

func (api *zeroTierAPI) get(ctx context.Context, endpoint string) ([]byte, error) {
	response, err := api.request(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("ZeroTier API returned HTTP %d", response.StatusCode)
	}
	return response.Body, nil
}

func Post(endpoint string, body string) ([]byte, error) {
	return PostContext(context.Background(), endpoint, body)
}

func PostContext(ctx context.Context, endpoint, body string) ([]byte, error) {
	return defaultZeroTierAPI.post(ctx, endpoint, body)
}

func (api *zeroTierAPI) post(ctx context.Context, endpoint, body string) ([]byte, error) {
	response, err := api.request(ctx, http.MethodPost, endpoint, []byte(body))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("ZeroTier API returned HTTP %d", response.StatusCode)
	}
	return response.Body, nil
}
