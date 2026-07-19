package httper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MountList struct {
	MountPoints []MountPoints `json:"mountPoints"`
}
type MountPoints struct {
	MountPoint string `json:"MountPoint"`
	Fs         string `json:"Fs"`
	// FsPath is the path after rclone's remote-name colon. ReCasaOS-managed
	// mounts require it to be empty (remote:), while unrelated remote:subdir
	// mounts remain parseable without being mistaken for our mount.
	FsPath string `json:"-"`
	Icon   string `json:"Icon"`
	Name   string `json:"Name"`
}
type MountPoint struct {
	MountPoint string `json:"mount_point"`
	Fs         string `json:"fs"`
	Icon       string `json:"icon"`
	Name       string `json:"name"`
}
type MountResult struct {
	Error string `json:"error"`
	Input struct {
		Fs         string `json:"fs"`
		MountPoint string `json:"mountPoint"`
	} `json:"input"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type RemotesResult struct {
	Remotes []string `json:"remotes"`
}

const (
	rcloneUnixSocket       = "/var/run/rclone/rclone.sock"
	maxRcloneResponseBytes = 1 << 20
	maxRcloneListEntries   = 4096
	maxRcloneConfigEntries = 256
)

var UserAgent = "ReCasaOS/rclone-rc"
var DefaultTimeout = time.Second * 30

var rcloneHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", rcloneUnixSocket)
		},
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     30 * time.Second,
	},
	Timeout: DefaultTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		// A 307/308 redirect would replay a mutating POST. The local Unix-socket
		// RC API has no legitimate redirect flow, so return the original response
		// and let callRclone reject its non-200 status.
		return http.ErrUseLastResponse
	},
}

// callRclone performs exactly one RC request. Mutating rclone operations are
// not generally idempotent, so transport retries belong in the service state
// machine where their effects can be reconciled explicitly.
func callRclone(endpoint string, form url.Values) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, "http://localhost"+endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", UserAgent)
	response, err := rcloneHTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("rclone RC %s: %w", endpoint, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxRcloneResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read rclone RC %s response: %w", endpoint, err)
	}
	if len(body) > maxRcloneResponseBytes {
		return nil, fmt.Errorf("rclone RC %s response exceeds %d bytes", endpoint, maxRcloneResponseBytes)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rclone RC %s returned HTTP %d", endpoint, response.StatusCode)
	}
	return body, nil
}

func GetMountList() (MountList, error) {
	var result MountList
	body, err := callRclone("/mount/listmounts", url.Values{})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("decode mount list: %w", err)
	}
	if len(result.MountPoints) > maxRcloneListEntries {
		return MountList{}, fmt.Errorf("rclone mount list exceeds %d entries", maxRcloneListEntries)
	}
	for i := 0; i < len(result.MountPoints); i++ {
		normalizeRcloneMountFilesystem(&result.MountPoints[i])
	}
	return result, nil
}

func normalizeRcloneMountFilesystem(mounted *MountPoints) {
	if mounted == nil {
		return
	}
	remote, remotePath, ok := splitRcloneFilesystem(mounted.Fs)
	if !ok {
		// Keep the record so callers can still detect an occupied mount point,
		// but never let an unparsed local/malformed Fs compare equal to a managed
		// remote name.
		mounted.Fs = ""
		mounted.FsPath = ""
		return
	}
	mounted.Fs = remote
	mounted.FsPath = remotePath
}

func rcloneRemoteFromFilesystem(filesystem string) (string, bool) {
	remote, _, ok := splitRcloneFilesystem(filesystem)
	return remote, ok
}

func splitRcloneFilesystem(filesystem string) (string, string, bool) {
	separator := strings.IndexByte(filesystem, ':')
	if separator <= 0 {
		return "", "", false
	}
	return filesystem[:separator], filesystem[separator+1:], true
}

func Mount(mountPoint string, filesystem string) error {
	_, err := callRclone("/mount/mount", url.Values{
		"mountPoint": []string{mountPoint},
		"fs":         []string{filesystem},
		"mountOpt":   []string{`{"AllowOther": true}`},
		"vfsOpt":     []string{`{"CacheMode": 3}`},
	})
	return err
}

func Unmount(mountPoint string) error {
	_, err := callRclone("/mount/unmount", url.Values{"mountPoint": []string{mountPoint}})
	return err
}

func CreateConfig(data map[string]string, name, t string) error {
	parameters := make(map[string]string, len(data)+1)
	for key, value := range data {
		parameters[key] = value
	}
	parameters["config_is_local"] = "false"
	dataStr, err := json.Marshal(parameters)
	if err != nil {
		return fmt.Errorf("encode rclone config: %w", err)
	}
	_, err = callRclone("/config/create", url.Values{
		"name":       []string{name},
		"parameters": []string{string(dataStr)},
		"type":       []string{t},
	})
	return err
}

func GetConfigByName(name string) (map[string]string, error) {
	body, err := callRclone("/config/get", url.Values{"name": []string{name}})
	if err != nil {
		return nil, err
	}
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode rclone config: %w", err)
	}
	if len(result) > maxRcloneConfigEntries {
		return nil, fmt.Errorf("rclone config exceeds %d fields", maxRcloneConfigEntries)
	}
	return result, nil
}

func GetAllConfigName() (RemotesResult, error) {
	var result RemotesResult
	body, err := callRclone("/config/listremotes", url.Values{})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("decode rclone remotes: %w", err)
	}
	if len(result.Remotes) > maxRcloneListEntries {
		return RemotesResult{}, fmt.Errorf("rclone remote list exceeds %d entries", maxRcloneListEntries)
	}
	return result, nil
}

func DeleteConfigByName(name string) error {
	_, err := callRclone("/config/delete", url.Values{"name": []string{name}})
	return err
}
