package publicfiles

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// BasePath is deliberately separate from the administrative CasaOS APIs.
	BasePath = "/public-files"

	DefaultMaxDirectoryEntries = 1_000
	DefaultMaxActiveDownloads  = 64
)

var (
	ErrUnsupported = errors.New("public file portal requires Linux openat2 and statx mount-ID support")
	errEntryLimit  = errors.New("directory entry limit exceeded")
)

// Config contains the complete public-file security boundary. Root and
// VerifierFile must be absolute paths. The host loads only a SHA-256 verifier;
// the raw bearer must never be written to the portal host.
type Config struct {
	Root         string
	VerifierFile string
	MaxEntries   int
	MaxDownloads int
}

// Entry is the minimal metadata exposed by the directory-list endpoint.
// Host paths, ownership, permissions, inode numbers and timestamps are never
// returned.
type Entry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// Portal is a read-only http.Handler rooted at a directory descriptor.
type Portal struct {
	storage        storageBackend
	bearerVerifier [sha256.Size]byte
	maxEntries     int
	downloadSlots  chan struct{}
}

// New preserves the embeddable portal API and performs descriptor-relative
// share operations in the calling process. It is suitable for trusted,
// in-process integrations but not for the Internet-facing standalone service,
// where a stalled filesystem syscall must not block the long-lived HTTP
// coordinator. That service must use NewIsolated.
func New(config Config) (*Portal, error) {
	validated, err := validatePortalConfig(config)
	if err != nil {
		return nil, err
	}
	bearerVerifier, err := readVerifierFileSecure(validated.verifierPath)
	if err != nil {
		return nil, fmt.Errorf("public file verifier file is unsafe: %w", err)
	}
	storage, err := newLocalStorageBackend(validated.rootPath)
	if err != nil {
		return nil, fmt.Errorf("public file root is unsafe: %w", err)
	}
	return newPortalWithStorage(validated, storage, bearerVerifier), nil
}

// NewIsolated creates the standalone Internet-facing portal. On Linux it
// keeps every share open, stat, list and read in disposable subprocesses.
// The embedding executable must dispatch InternalStorageWorkerArgument to
// RunInternalStorageWorker before performing any normal application startup.
func NewIsolated(config Config) (*Portal, error) {
	validated, err := validatePortalConfig(config)
	if err != nil {
		return nil, err
	}
	storage, bearerVerifier, err := newIsolatedStorage(
		validated.rootPath,
		validated.verifierPath,
	)
	if err != nil {
		return nil, err
	}
	return newPortalWithStorage(validated, storage, bearerVerifier), nil
}

type validatedPortalConfig struct {
	rootPath     string
	verifierPath string
	maxEntries   int
	maxDownloads int
}

func validatePortalConfig(config Config) (validatedPortalConfig, error) {
	var validated validatedPortalConfig
	rootPath, err := validateAbsoluteConfigPath(config.Root, false)
	if err != nil {
		return validated, fmt.Errorf("public file root is invalid: %w", err)
	}
	verifierPath, err := validateAbsoluteConfigPath(config.VerifierFile, true)
	if err != nil {
		return validated, fmt.Errorf("public file verifier file is invalid: %w", err)
	}

	maxEntries := config.MaxEntries
	if maxEntries == 0 {
		maxEntries = DefaultMaxDirectoryEntries
	}
	if maxEntries < 1 || maxEntries > DefaultMaxDirectoryEntries {
		return validated, fmt.Errorf("public file directory limit must be between 1 and %d", DefaultMaxDirectoryEntries)
	}
	maxDownloads := config.MaxDownloads
	if maxDownloads == 0 {
		maxDownloads = DefaultMaxActiveDownloads
	}
	if maxDownloads < 1 || maxDownloads > DefaultMaxActiveDownloads {
		return validated, fmt.Errorf("public file download limit must be between 1 and %d", DefaultMaxActiveDownloads)
	}

	return validatedPortalConfig{
		rootPath:     rootPath,
		verifierPath: verifierPath,
		maxEntries:   maxEntries,
		maxDownloads: maxDownloads,
	}, nil
}

func newPortalWithStorage(
	config validatedPortalConfig,
	storage storageBackend,
	bearerVerifier [sha256.Size]byte,
) *Portal {
	return &Portal{
		storage:        storage,
		bearerVerifier: bearerVerifier,
		maxEntries:     config.maxEntries,
		downloadSlots:  make(chan struct{}, config.maxDownloads),
	}
}

func validateAbsoluteConfigPath(value string, allowFile bool) (string, error) {
	if value == "" ||
		strings.IndexByte(value, 0) >= 0 ||
		!utf8.ValidString(value) ||
		!filepath.IsAbs(value) {
		return "", errors.New("an absolute path is required")
	}
	clean := filepath.Clean(value)
	if clean != value {
		return "", errors.New("the path must already be clean")
	}
	if clean == string(filepath.Separator) {
		if allowFile {
			return "", errors.New("the filesystem root is not a file")
		}
		return "", errors.New("the filesystem root cannot be shared")
	}
	return clean, nil
}

// Close releases the storage manager and its pinned root descriptor. Call it
// only after the HTTP server has stopped accepting requests.
func (p *Portal) Close() error {
	if p == nil || p.storage == nil {
		return nil
	}
	return p.storage.close()
}

func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	allowSameOriginFraming := r.URL.Path == BasePath+"/download-frame"
	w = &securityResponseWriter{
		ResponseWriter:         w,
		allowSameOriginFraming: allowSameOriginFraming,
	}
	setSecurityHeaders(w.Header(), allowSameOriginFraming)

	switch r.URL.Path {
	case BasePath:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		http.Redirect(w, r, BasePath+"/", http.StatusPermanentRedirect)
	case BasePath + "/":
		p.serveAsset(w, r, "text/html; charset=utf-8", portalHTML)
	case BasePath + "/app.js":
		p.serveAsset(w, r, "text/javascript; charset=utf-8", portalJavaScript)
	case BasePath + "/download-frame":
		p.serveAsset(w, r, "text/html; charset=utf-8", downloadFrameHTML)
	case BasePath + "/download-frame.js":
		p.serveAsset(w, r, "text/javascript; charset=utf-8", downloadFrameJavaScript)
	case BasePath + "/download-worker.js":
		w.Header().Set("Service-Worker-Allowed", BasePath+"/")
		p.serveAsset(w, r, "text/javascript; charset=utf-8", downloadWorkerJavaScript)
	case BasePath + "/style.css":
		p.serveAsset(w, r, "text/css; charset=utf-8", portalCSS)
	case BasePath + "/api/list":
		p.serveList(w, r)
	case BasePath + "/api/file":
		p.serveFile(w, r)
	default:
		writeError(w, r, http.StatusNotFound, "not found")
	}
}

// securityResponseWriter reapplies the portal policy at the actual header
// commit boundary. This is required because helpers such as http.ServeContent
// may delete caching headers while constructing an error response.
type securityResponseWriter struct {
	http.ResponseWriter
	allowSameOriginFraming bool
}

func (w *securityResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *securityResponseWriter) WriteHeader(status int) {
	setSecurityHeaders(w.Header(), w.allowSameOriginFraming)
	w.ResponseWriter.WriteHeader(status)
}

func (w *securityResponseWriter) Write(payload []byte) (int, error) {
	setSecurityHeaders(w.Header(), w.allowSameOriginFraming)
	return w.ResponseWriter.Write(payload)
}

func setSecurityHeaders(header http.Header, allowSameOriginFraming bool) {
	header.Set("Cache-Control", "no-store")
	if allowSameOriginFraming {
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'")
		header.Set("X-Frame-Options", "SAMEORIGIN")
	} else {
		header.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		header.Set("X-Frame-Options", "DENY")
	}
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
}

func (p *Portal) serveAsset(w http.ResponseWriter, r *http.Request, contentType, content string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(content)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(content))
	}
}

func (p *Portal) serveList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !p.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ReCasaOS public files"`)
		writeError(w, r, http.StatusUnauthorized, "authorization required")
		return
	}
	query, err := parseSafeQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid query")
		return
	}
	relativePath, err := validateRelativePath(query.Get("path"), true)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid relative path")
		return
	}

	entries, err := p.storage.list(r.Context(), relativePath, p.maxEntries)
	if err != nil {
		if errors.Is(err, errStorageCapacity) || errors.Is(err, errStorageTimeout) {
			w.Header().Set("Retry-After", "5")
			writeError(w, r, http.StatusServiceUnavailable, "storage capacity unavailable")
			return
		}
		if errors.Is(err, errEntryLimit) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "directory entry limit exceeded")
			return
		}
		if isHiddenFilesystemError(err) {
			writeError(w, r, http.StatusNotFound, "not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "unable to list directory")
		return
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type == "directory"
		}
		return entries[i].Name < entries[j].Name
	})
	writeJSON(w, r, http.StatusOK, struct {
		Path    string  `json:"path"`
		Entries []Entry `json:"entries"`
	}{Path: relativePath, Entries: entries})
}

func (p *Portal) serveFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !p.authorized(r) {
		// A controlled portal or same-origin child-frame download navigation
		// normally receives its Authorization header from the scoped Service Worker.
		// If that Worker is
		// replaced or bypassed after the page has prepared the navigation, return
		// an empty response instead of rendering an error document in either
		// context. Sec-Fetch-* is only a UX/fail-closed signal here; it never grants
		// access and non-navigation clients retain the normal 401.
		destination := r.Header.Get("Sec-Fetch-Dest")
		if r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate" && (destination == "document" || destination == "iframe") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="ReCasaOS public files"`)
		writeError(w, r, http.StatusUnauthorized, "authorization required")
		return
	}
	query, err := parseSafeQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid query")
		return
	}
	relativePath, err := validateRelativePath(query.Get("path"), false)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid relative path")
		return
	}
	if storageWorkerSystemdTestEnabled {
		reportStorageWorkerSystemdTestEvent(
			systemdStorageWorkerTestHandlerEntered,
		)
	}
	select {
	case p.downloadSlots <- struct{}{}:
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(
				systemdStorageWorkerTestDownloadSlotAcquired,
			)
		}
		defer func() { <-p.downloadSlots }()
	default:
		if storageWorkerSystemdTestEnabled {
			reportStorageWorkerSystemdTestEvent(
				systemdStorageWorkerTestDownloadSlotRejected,
			)
		}
		w.Header().Set("Retry-After", "5")
		writeError(w, r, http.StatusServiceUnavailable, "download capacity reached")
		return
	}

	file, info, err := p.storage.openRegular(r.Context(), relativePath)
	if err != nil {
		if errors.Is(err, errStorageCapacity) || errors.Is(err, errStorageTimeout) {
			w.Header().Set("Retry-After", "5")
			writeError(w, r, http.StatusServiceUnavailable, "storage capacity unavailable")
			return
		}
		if isHiddenFilesystemError(err) {
			writeError(w, r, http.StatusNotFound, "not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "unable to open file")
		return
	}
	defer file.Close()
	// Multi-range work is intentionally rejected even when If-Range might make
	// the standard library ignore it. The public boundary supports one bounded
	// byte range only and does not construct multipart responses.
	if ranges := r.Header.Values("Range"); len(ranges) > 1 || (len(ranges) == 1 && strings.Contains(ranges[0], ",")) {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", info.Size()))
		writeError(w, r, http.StatusRequestedRangeNotSatisfiable, "multiple ranges are not supported")
		return
	}

	filename := pathpkg.Base(relativePath)
	w.Header().Set("Content-Disposition", formatDownloadContentDisposition(filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	// The storage protocol does not provide a strong representation
	// validator. Passing the filesystem modification time to ServeContent
	// would make it accept date-based If-Range values at one-second
	// precision. A same-second replacement could then let a client splice a
	// cached prefix from one representation onto a 206 suffix from another.
	//
	// A zero modification time keeps ordinary single-range requests working,
	// but makes every If-Range request fall back to a complete 200 response
	// until the portal can prove an immutable representation identity.
	http.ServeContent(w, r, filename, time.Time{}, file)
	if source, ok := file.(storageSourceError); ok && source.sourceError() != nil {
		panic(http.ErrAbortHandler)
	}
}

func parseSafeQuery(rawQuery string) (url.Values, error) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, err
	}
	for key := range query {
		switch strings.ToLower(key) {
		case "token", "access_token", "authorization", "api_key", "apikey":
			return nil, errors.New("credentials are not accepted in the query string")
		}
		if key != "path" || len(query[key]) != 1 {
			return nil, errors.New("only one path query parameter is accepted")
		}
	}
	return query, nil
}

func validateRelativePath(value string, allowRoot bool) (string, error) {
	if value == "" {
		if allowRoot {
			return "", nil
		}
		return "", errors.New("a file path is required")
	}
	if len(value) > 4_096 || strings.IndexByte(value, 0) >= 0 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", errors.New("path must be relative")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if !isSafeVisibleName(part) || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return "", errors.New("path contains a forbidden component")
		}
	}
	if pathpkg.Clean(value) != value {
		return "", errors.New("path must already be clean")
	}
	return value, nil
}

func isSafeVisibleName(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func formatDownloadContentDisposition(filename string) string {
	if !isSafeVisibleName(filename) {
		return "attachment"
	}
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	if disposition == "" {
		return "attachment"
	}
	return disposition
}

func (p *Portal) authorized(r *http.Request) bool {
	candidate := ""
	values := r.Header.Values("Authorization")
	if len(values) == 1 {
		parts := strings.SplitN(values[0], " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			candidate = parts[1]
		}
	}
	candidateDigest := digestPublicBearer(candidate)
	digestMatches := subtle.ConstantTimeCompare(candidateDigest[:], p.bearerVerifier[:])
	candidateIsValid := validPublicBearer(candidate)
	return digestMatches == 1 && candidateIsValid
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "unable to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(payload)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	payload, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: message})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(payload)
	}
}

// fileInfo is the subset used by http.ServeContent and keeps the platform
// implementation private.
type fileInfo interface {
	Name() string
	Size() int64
	Mode() os.FileMode
	ModTime() time.Time
	IsDir() bool
	Sys() any
}
