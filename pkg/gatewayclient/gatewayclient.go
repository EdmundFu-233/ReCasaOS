// Package gatewayclient talks to the local CasaOS-Gateway management listener
// with the gateway's per-start service credential. It replaces the inherited
// CasaOS-Common client, which sends no Authorization header and therefore
// cannot manage routes on a gateway that requires authentication.
package gatewayclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS-Common/model"
)

const (
	// ServiceTokenFilename is the owner-only credential the gateway writes
	// into its runtime directory on every start.
	ServiceTokenFilename = "gateway.token"

	maxResponseBytes       = 64 << 10
	maxCredentialFileBytes = 1 << 10
)

var (
	addressRetryAttempts = 10
	addressRetryDelay    = time.Second
	pingTimeout          = 30 * time.Second
	requestTimeout       = 30 * time.Second
)

// Client is an external.ManagementService that authenticates with the local
// gateway service credential. Every call re-reads the address and token files
// so a gateway restart or port change is picked up without a root restart.
type Client struct {
	runtimePath string
	httpClient  *http.Client
}

// New waits for the gateway management address file, proves the management
// listener answers, and returns the authenticated client. It mirrors the
// inherited client's startup contract so callers keep their retry semantics.
func New(runtimePath string) (*Client, error) {
	if strings.TrimSpace(runtimePath) == "" {
		return nil, errors.New("gateway runtime path is empty")
	}
	client := &Client{
		runtimePath: runtimePath,
		httpClient: &http.Client{
			Timeout: requestTimeout,
			// A management redirect must never forward the service credential
			// to another listener; the caller sees the redirect response and
			// fails closed.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	address, err := client.waitForAddress()
	if err != nil {
		return nil, err
	}
	if err := client.ping(address); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) waitForAddress() (string, error) {
	addressFile := filepath.Join(c.runtimePath, external.ManagementURLFilename)
	for attempt := 0; attempt < addressRetryAttempts; attempt++ {
		if _, err := os.Stat(addressFile); err == nil {
			break
		}
		time.Sleep(addressRetryDelay)
	}
	return c.address()
}

// readBoundedFile reads one owner-controlled runtime file with a size bound
// and symlink refusal. The file is opened and re-checked against its lstat
// identity so a replacement between the two steps fails closed.
func (c *Client) readBoundedFile(name string, limit int64) (string, error) {
	path := filepath.Join(c.runtimePath, name)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return "", fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, opened) {
		return "", fmt.Errorf("%s changed while opening", name)
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > limit {
		return "", fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	value := strings.TrimSpace(string(raw))
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%s contains a NUL byte", name)
	}
	return value, nil
}

func (c *Client) address() (string, error) {
	value, err := c.readBoundedFile(external.ManagementURLFilename, maxCredentialFileBytes)
	if err != nil {
		return "", fmt.Errorf("read gateway management address: %w", err)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("gateway management address is not a plain http loopback URL")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || port == "" {
		return "", errors.New("gateway management address must include an explicit port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("gateway management address must be a loopback IP")
	}
	return value, nil
}

func (c *Client) serviceToken() (string, error) {
	value, err := c.readBoundedFile(ServiceTokenFilename, maxCredentialFileBytes)
	if err != nil {
		return "", fmt.Errorf("read gateway service token: %w", err)
	}
	if value == "" {
		return "", errors.New("gateway service token is empty")
	}
	return value, nil
}

func (c *Client) ping(address string) error {
	request, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(address, "/")+"/ping", nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: pingTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("ping gateway management service: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway management service answered %d", response.StatusCode)
	}
	return nil
}

// CreateRoute registers a route under the gateway service owner.
func (c *Client) CreateRoute(route *model.Route) error {
	if route == nil {
		return errors.New("gateway route is required")
	}
	body, err := json.Marshal(route)
	if err != nil {
		return err
	}
	response, err := c.do(http.MethodPost, external.APIGatewayRoutes, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create route (status code: %d)", response.StatusCode)
	}
	return nil
}

// ChangePort asks the gateway to bind the requested port.
func (c *Client) ChangePort(request *model.ChangePortRequest) error {
	if request == nil {
		return errors.New("gateway port change request is required")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	response, err := c.do(http.MethodPut, external.APIGatewayPort, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to change port (status code: %d)", response.StatusCode)
	}
	return nil
}

// GetPort returns the raw management response body. The caller parses the
// documented "data" field, preserving the inherited client's contract.
func (c *Client) GetPort() (error, string) {
	response, err := c.do(http.MethodGet, external.APIGatewayPort, nil)
	if err != nil {
		return err, ""
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return readErr, ""
	}
	if len(body) > maxResponseBytes {
		return errors.New("gateway port response is too large"), ""
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to read port (status code: %d)", response.StatusCode), ""
	}
	return nil, string(body)
}

func (c *Client) do(method, path string, body []byte) (*http.Response, error) {
	address, err := c.address()
	if err != nil {
		return nil, err
	}
	token, err := c.serviceToken()
	if err != nil {
		return nil, err
	}
	url := strings.TrimSuffix(address, "/") + "/" + strings.TrimPrefix(path, "/")
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("gateway management request failed: %w", err)
	}
	return response, nil
}
