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

func uncommentedConfiguration(content string) string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func braceBlockAt(t *testing.T, content string, openingBrace int) string {
	t.Helper()
	if openingBrace < 0 || openingBrace >= len(content) || content[openingBrace] != '{' {
		t.Fatal("locate configuration block opening brace")
	}
	depth := 0
	for i := openingBrace; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[openingBrace : i+1]
			}
		}
	}
	t.Fatal("configuration block has no closing brace")
	return ""
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

func TestPublicPortalProxyCSPAllowsOnlyRequiredWorkerSource(t *testing.T) {
	for _, path := range []string{"deploy/caddy/Caddyfile.example", "deploy/nginx/recasaos.conf.example"} {
		config := repositoryFile(t, path)
		for _, required := range []string{"default-src 'none'", "worker-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(config, required) {
				t.Errorf("%s CSP is missing %q", path, required)
			}
		}
		if strings.Contains(config, "unsafe-inline") || strings.Contains(config, "unsafe-eval") {
			t.Errorf("%s CSP contains an unsafe script allowance", path)
		}
	}
}

func TestPublicPortalRuntimeLogsDoNotRecordFullRequestURI(t *testing.T) {
	caddyConfig := strings.TrimSpace(uncommentedConfiguration(
		repositoryFile(t, "deploy/caddy/Caddyfile.example"),
	))
	caddyGlobalBlock := normalizedText(braceBlockAt(t, caddyConfig, 0))
	if !strings.Contains(caddyGlobalBlock, "log { format filter { request>uri delete } }") {
		t.Error("Caddy global runtime logger must delete request.uri")
	}

	nginxConfig := uncommentedConfiguration(
		repositoryFile(t, "deploy/nginx/recasaos.conf.example"),
	)
	const serverMarker = "server {"
	serverCount := 0
	for searchFrom := 0; ; {
		relativeStart := strings.Index(nginxConfig[searchFrom:], serverMarker)
		if relativeStart < 0 {
			break
		}
		blockStart := searchFrom + relativeStart + len("server ")
		serverBlock := braceBlockAt(t, nginxConfig, blockStart)
		if !strings.Contains(normalizedText(serverBlock), "error_log /dev/null;") {
			t.Errorf("Nginx public server block %d must discard request-scoped error logs", serverCount+1)
		}
		serverCount++
		searchFrom = blockStart + len(serverBlock)
	}
	if serverCount != 2 {
		t.Fatalf("expected two Nginx public server blocks, found %d", serverCount)
	}

	for _, line := range strings.Split(nginxConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "error_log ") && trimmed != "error_log /dev/null;" {
			t.Errorf("Nginx public template retains an error log sink: %q", trimmed)
		}
	}
}

func TestPublicPortalHTTPRedirectDropsRequestURI(t *testing.T) {
	tests := []struct {
		path      string
		forbidden string
		required  string
	}{
		{
			path:      "deploy/caddy/Caddyfile.example",
			forbidden: "{uri}",
			required:  "redir https://recasaos.example.invalid/public-files/ 308",
		},
		{
			path:      "deploy/nginx/recasaos.conf.example",
			forbidden: "$request_uri",
			required:  "return 308 https://recasaos.example.invalid/public-files/;",
		},
	}
	for _, test := range tests {
		config := uncommentedConfiguration(repositoryFile(t, test.path))
		if strings.Contains(config, test.forbidden) {
			t.Errorf("%s HTTP redirect retains request URI with query", test.path)
		}
		if !strings.Contains(config, test.required) {
			t.Errorf("%s HTTP redirect is not pinned to the HTTPS portal root", test.path)
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
