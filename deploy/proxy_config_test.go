package deploy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryFile(t *testing.T, relativePath string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate proxy configuration test source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), ".."))
	content, err := os.ReadFile(filepath.Join(repositoryRoot, relativePath))
	if err != nil {
		t.Fatalf("read %s: %v", relativePath, err)
	}
	return string(content)
}

func normalizedText(content string) string {
	return strings.Join(strings.Fields(content), " ")
}

func TestCaddyConfigPreservesClientCancellation(t *testing.T) {
	config := repositoryFile(t, "deploy/caddy/Caddyfile.example")
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "flush_interval") {
			t.Fatalf("Caddy config must leave flush_interval unset, found %q", trimmed)
		}
	}
	for _, required := range []string{
		"default response buffering and cancellation behavior",
		"negative flush_interval",
		"client disconnects",
		"lets cancellation propagate",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("Caddy cancellation guidance is missing %q", required)
		}
	}
}

func TestDeploymentGuideStatesProxyTimeoutAndVerificationBoundaries(t *testing.T) {
	guide := normalizedText(repositoryFile(t, "docs/deployment/public-access.md"))
	for _, required := range []string{
		"not evidence of a live public deployment",
		"has not verified any real public hostname",
		"`flush_interval -1`",
		"between two successive read operations",
		"not to the total response duration",
		"`proxy_ignore_client_abort`",
		"Passing repository static tests does not satisfy this target-host matrix",
	} {
		if !strings.Contains(guide, required) {
			t.Errorf("deployment guide is missing %q", required)
		}
	}
}
