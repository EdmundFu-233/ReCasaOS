package httper

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRcloneRemoteFromFilesystemSupportsSubdirectories(t *testing.T) {
	for filesystem, expected := range map[string]string{
		"remote:":             "remote",
		"remote:subdir":       "remote",
		"john+home:backups/a": "john+home",
	} {
		remote, ok := rcloneRemoteFromFilesystem(filesystem)
		if !ok || remote != expected {
			t.Fatalf("rcloneRemoteFromFilesystem(%q) = %q, %t; want %q, true", filesystem, remote, ok, expected)
		}
	}
	for _, filesystem := range []string{"", ":", "/local/path"} {
		if remote, ok := rcloneRemoteFromFilesystem(filesystem); ok || remote != "" {
			t.Fatalf("rcloneRemoteFromFilesystem(%q) = %q, %t; want invalid", filesystem, remote, ok)
		}
	}
	remote, remotePath, ok := splitRcloneFilesystem("remote:subdir/child")
	if !ok || remote != "remote" || remotePath != "subdir/child" {
		t.Fatalf("splitRcloneFilesystem() = %q, %q, %t", remote, remotePath, ok)
	}
}

func TestNormalizeRcloneMountFilesystemDoesNotTrustMissingColon(t *testing.T) {
	invalid := MountPoints{MountPoint: "/mnt/cloud", Fs: "cloud"}
	normalizeRcloneMountFilesystem(&invalid)
	if invalid.Fs != "" || invalid.FsPath != "" {
		t.Fatalf("invalid filesystem normalized as managed remote: %+v", invalid)
	}

	valid := MountPoints{MountPoint: "/mnt/cloud", Fs: "cloud:"}
	normalizeRcloneMountFilesystem(&valid)
	if valid.Fs != "cloud" || valid.FsPath != "" {
		t.Fatalf("valid filesystem normalization = %+v", valid)
	}
}

func TestCallRcloneDoesNotRetryTransportErrors(t *testing.T) {
	original := rcloneHTTPClient
	t.Cleanup(func() { rcloneHTTPClient = original })
	calls := 0
	rcloneHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("ambiguous transport failure")
	})}

	if _, err := callRclone("/mount/mount", nil); err == nil {
		t.Fatal("callRclone() unexpectedly ignored transport failure")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want exactly one", calls)
	}
}

func TestCallRcloneBoundsResponseAndDoesNotExposeErrorBody(t *testing.T) {
	original := rcloneHTTPClient
	t.Cleanup(func() { rcloneHTTPClient = original })

	rcloneHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxRcloneResponseBytes+1))),
			Header:     make(http.Header),
		}, nil
	})}
	if _, err := callRclone("/config/get", nil); err == nil {
		t.Fatal("oversized rclone response was accepted")
	}

	const secret = "refresh-token-must-not-leak"
	rcloneHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader(secret)),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := callRclone("/config/get", nil)
	if err == nil {
		t.Fatal("non-200 rclone response was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("rclone error exposed response body: %v", err)
	}
}

func TestCallRcloneDoesNotReplayRedirectedPost(t *testing.T) {
	original := rcloneHTTPClient
	t.Cleanup(func() { rcloneHTTPClient = original })
	calls := 0
	rcloneHTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Body:       io.NopCloser(strings.NewReader("redirect forbidden")),
				Header:     http.Header{"Location": []string{"http://localhost/replayed"}},
			}, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	if _, err := callRclone("/config/delete", nil); err == nil {
		t.Fatal("redirected mutating RC request was accepted")
	}
	if calls != 1 {
		t.Fatalf("transport calls = %d, want exactly one", calls)
	}
}

func TestMountDoesNotExposeCloudFilesToOtherLocalUsers(t *testing.T) {
	original := rcloneHTTPClient
	t.Cleanup(func() { rcloneHTTPClient = original })
	rcloneHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/mount/mount" {
			t.Fatalf("request path = %q", request.URL.Path)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if mountOptions := request.PostForm.Get("mountOpt"); mountOptions != `{"AllowOther": false}` {
			t.Fatalf("mount options = %q", mountOptions)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}, nil
	})}

	if err := Mount("/var/lib/casaos/storage/cloud", "cloud:"); err != nil {
		t.Fatal(err)
	}
}
