package publicfiles

import (
	"encoding/base64"
	"encoding/hex"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateRelativePath(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		allowRoot bool
		want      string
		wantError bool
	}{
		{name: "root", value: "", allowRoot: true, want: ""},
		{name: "file", value: "folder/report 2026.pdf", want: "folder/report 2026.pdf"},
		{name: "unicode", value: "photos/旅行.jpg", want: "photos/旅行.jpg"},
		{name: "empty file", value: "", wantError: true},
		{name: "absolute", value: "/etc/passwd", wantError: true},
		{name: "parent traversal", value: "../secret", wantError: true},
		{name: "embedded parent", value: "safe/../secret", wantError: true},
		{name: "hidden", value: "safe/.secret", wantError: true},
		{name: "empty component", value: "safe//file", wantError: true},
		{name: "backslash", value: `safe\file`, wantError: true},
		{name: "control", value: "safe/file\nname", wantError: true},
		{name: "bidi override", value: "safe/report\u202efdp.exe", wantError: true},
		{name: "zero width space", value: "safe/zero\u200bwidth.txt", wantError: true},
		{name: "zero width joiner", value: "safe/join\u200der.txt", wantError: true},
		{name: "invalid utf8", value: string([]byte{0xff}), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateRelativePath(test.value, test.allowRoot)
			if (err != nil) != test.wantError {
				t.Fatalf("validateRelativePath(%q) error = %v, wantError=%v", test.value, err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("validateRelativePath(%q) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestValidatePortalConfigRejectsInvalidUTF8Paths(t *testing.T) {
	invalidPath := string([]byte{'/', 't', 'm', 'p', '/', 0xff})
	tests := []Config{
		{Root: invalidPath, VerifierFile: "/tmp/verifier"},
		{Root: "/tmp/share", VerifierFile: invalidPath},
	}
	for _, config := range tests {
		if _, err := validatePortalConfig(config); err == nil {
			t.Fatalf("invalid UTF-8 configuration path was accepted: %#v", config)
		}
	}
}

func TestIsSafeVisibleNameRejectsUnicodeFormatCharacters(t *testing.T) {
	tests := []struct {
		name      string
		character rune
	}{
		{name: "soft hyphen", character: '\u00ad'},
		{name: "arabic letter mark", character: '\u061c'},
		{name: "zero width space", character: '\u200b'},
		{name: "zero width non-joiner", character: '\u200c'},
		{name: "zero width joiner", character: '\u200d'},
		{name: "left-to-right mark", character: '\u200e'},
		{name: "right-to-left mark", character: '\u200f'},
		{name: "left-to-right embedding", character: '\u202a'},
		{name: "right-to-left embedding", character: '\u202b'},
		{name: "pop directional formatting", character: '\u202c'},
		{name: "left-to-right override", character: '\u202d'},
		{name: "right-to-left override", character: '\u202e'},
		{name: "left-to-right isolate", character: '\u2066'},
		{name: "right-to-left isolate", character: '\u2067'},
		{name: "first strong isolate", character: '\u2068'},
		{name: "pop directional isolate", character: '\u2069'},
		{name: "byte order mark", character: '\ufeff'},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := "report" + string(test.character) + ".pdf"
			if isSafeVisibleName(value) {
				t.Fatalf("isSafeVisibleName(%q) = true for Unicode format character U+%04X", value, test.character)
			}
		})
	}
}

func TestIsSafeVisibleNameAllowsLegitimateUnicode(t *testing.T) {
	for _, value := range []string{
		"旅行.jpg",
		"résumé.pdf",
		"Cafe\u0301.txt",
		"invoice-счёт.pdf",
		"photo-📷.png",
	} {
		t.Run(value, func(t *testing.T) {
			if !isSafeVisibleName(value) {
				t.Fatalf("isSafeVisibleName(%q) = false for legitimate Unicode", value)
			}
		})
	}
}

func TestDownloadContentDispositionRoundTripsFilename(t *testing.T) {
	for _, filename := range []string{
		"report.pdf",
		"2026 旅行 说明.pdf",
		`quarterly "final" report.pdf`,
		`archive\windows-style.txt`,
		`unicode "旅行"\copy.txt`,
	} {
		t.Run(filename, func(t *testing.T) {
			disposition := formatDownloadContentDisposition(filename)
			if strings.ContainsAny(disposition, "\r\n") {
				t.Fatalf("Content-Disposition contains CR/LF: %q", disposition)
			}

			mediaType, parameters, err := mime.ParseMediaType(disposition)
			if err != nil {
				t.Fatalf("mime.ParseMediaType(%q): %v", disposition, err)
			}
			if mediaType != "attachment" {
				t.Fatalf("media type = %q, want attachment", mediaType)
			}
			if got := parameters["filename"]; got != filename {
				t.Fatalf("filename round trip = %q, want %q (header %q)", got, filename, disposition)
			}
		})
	}
}

func TestDownloadContentDispositionDropsFilenamesWithCRLF(t *testing.T) {
	for _, filename := range []string{
		"report\rname.pdf",
		"report\nname.pdf",
		"report\r\nX-Injected: true.pdf",
	} {
		t.Run(filename, func(t *testing.T) {
			disposition := formatDownloadContentDisposition(filename)
			if disposition != "attachment" {
				t.Fatalf("unsafe filename produced Content-Disposition %q, want attachment fallback", disposition)
			}
			if strings.ContainsAny(disposition, "\r\n") {
				t.Fatalf("Content-Disposition contains CR/LF: %q", disposition)
			}
		})
	}
}

func TestParseSafeQueryIsStrictAndRejectsCredentials(t *testing.T) {
	tests := []struct {
		query     string
		wantPath  string
		wantError bool
	}{
		{query: "", wantPath: ""},
		{query: "path=folder%2Ffile", wantPath: "folder/file"},
		{query: "path=one&path=two", wantError: true},
		{query: "path=file&nonce=not-a-server-credential", wantError: true},
		{query: "unknown=value", wantError: true},
		{query: "token=secret", wantError: true},
		{query: "ACCESS_TOKEN=secret", wantError: true},
		{query: "authorization=Bearer", wantError: true},
		{query: "%zz", wantError: true},
	}
	for _, test := range tests {
		values, err := parseSafeQuery(test.query)
		if (err != nil) != test.wantError {
			t.Errorf("parseSafeQuery(%q) error = %v, wantError=%v", test.query, err, test.wantError)
			continue
		}
		if err == nil && values.Get("path") != test.wantPath {
			t.Errorf("parseSafeQuery(%q) path = %q, want %q", test.query, values.Get("path"), test.wantPath)
		}
	}
}

func TestBearerAuthorizationRequiresOneExactHeaderToken(t *testing.T) {
	token := testPublicBearer(31)
	otherToken := testPublicBearer(99)
	verifier := digestPublicBearer(token)
	portal := &Portal{bearerVerifier: verifier}
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{name: "valid", headers: []string{"Bearer " + token}, want: true},
		{name: "case-insensitive scheme", headers: []string{"bearer " + token}, want: true},
		{name: "missing"},
		{name: "wrong canonical bearer", headers: []string{"Bearer " + otherToken}},
		{name: "malformed bearer", headers: []string{"Bearer wrong"}},
		{name: "basic", headers: []string{"Basic " + token}},
		{name: "space in token", headers: []string{"Bearer " + token + " extra"}},
		{name: "multiple", headers: []string{"Bearer " + token, "Bearer " + token}},
		{name: "serialized verifier", headers: []string{"Bearer " + strings.TrimSuffix(string(serializeTestPublicVerifier(verifier)), "\n")}},
		{name: "hex verifier", headers: []string{"Bearer " + hex.EncodeToString(verifier[:])}},
		{name: "encoded verifier", headers: []string{"Bearer " + publicBearerPrefix + base64.RawURLEncoding.EncodeToString(verifier[:])}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, BasePath+"/api/list", nil)
			for _, header := range test.headers {
				request.Header.Add("Authorization", header)
			}
			if got := portal.authorized(request); got != test.want {
				t.Fatalf("authorized() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBearerAuthorizationRejectsObviousLowDiversityBearerEvenWhenDigestMatches(t *testing.T) {
	for _, raw := range [][]byte{
		make([]byte, publicBearerRandomBytes),
		func() []byte {
			value := make([]byte, publicBearerRandomBytes)
			for index := range value {
				value[index] = byte(index % 2)
			}
			return value
		}(),
		func() []byte {
			value := make([]byte, publicBearerRandomBytes)
			for index := range value {
				value[index] = byte(index % 12)
			}
			return value
		}(),
	} {
		candidate := testEncodedPublicBearer(raw)
		portal := &Portal{bearerVerifier: digestPublicBearer(candidate)}
		request := httptest.NewRequest(http.MethodGet, BasePath+"/api/list", nil)
		request.Header.Set("Authorization", "Bearer "+candidate)
		if portal.authorized(request) {
			t.Fatalf("obvious low-diversity bearer %q authenticated despite input policy", candidate)
		}
	}
}

func TestPublicAssetsRequireNoCredentialAndContainNoInlineScript(t *testing.T) {
	portal := &Portal{}
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("asset status = %d, want 200", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "<script>") || !strings.Contains(recorder.Body.String(), `src="app.js"`) {
		t.Fatal("HTML must load only the same-origin external script")
	}
	if strings.Contains(recorder.Body.String(), `name="token"`) || !strings.Contains(recorder.Body.String(), `autocomplete="off"`) {
		t.Fatal("token input can be serialized or lacks autocomplete suppression")
	}
	for _, required := range []string{
		`minlength="47"`,
		`maxlength="47"`,
		`pattern="rc1_[A-Za-z0-9_-]{43}"`,
	} {
		if !strings.Contains(recorder.Body.String(), required) {
			t.Errorf("HTML bearer input is missing %q", required)
		}
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "worker-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("unsafe CSP: %q", csp)
	}
}

func TestPublicStylesHonorHiddenState(t *testing.T) {
	portal := &Portal{}
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/style.css", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("style.css status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "[hidden]{display:none!important}") {
		t.Fatal("portal CSS can override the hidden attribute")
	}
}

func TestPublicDownloadClientKeepsCredentialsEphemeralAndFallbackBounded(t *testing.T) {
	portal := &Portal{}
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/app.js", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("app.js status = %d, want 200", recorder.Code)
	}
	script := recorder.Body.String()
	for _, forbidden := range []string{
		"sessionStorage",
		"localStorage",
		"indexedDB",
		"caches.",
		"document.cookie",
		"history.pushState",
		"history.replaceState",
		"BroadcastChannel",
		"response.blob(",
		"response.arrayBuffer(",
		"searchParams.set('token'",
		"searchParams.set('navigationProof'",
		"frameProof",
		"download-frame",
		"window.location.assign(",
		"window.stop()",
		"state.frame.src=",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("app.js contains forbidden credential or buffering primitive %q", forbidden)
		}
	}
	for _, required := range []string{
		"const protocolVersion=2",
		"const fallbackByteLimit=32*1024*1024",
		"response.body.getReader()",
		"received>fallbackByteLimit",
		"setTimeout(()=>revokeFallbackObjectURL(objectURL),60000)",
		"Response security policy is missing",
		"Download response policy is invalid",
		"redirect:'error'",
		"credentials:'omit'",
		"referrerPolicy:'no-referrer'",
		"Download handed to the browser",
		"Download stream completed",
		"recasaos-download-prepare",
		"recasaos-download-cancel",
		"state.navigationProof",
		"state.navigationProof=''",
		"submitNativeDownload(state)",
		"form.method='post'",
		"form.action=state.requestURL",
		"proof.name='proof'",
		"proof.value=state.navigationProof",
		"form.submit()",
		"handed:false",
		"state.handed&&status.status==='completed'",
		"boundedDownload(path,entry).catch(showError);",
		"Token forgotten after page restore",
		"const bearerPattern=/^rc1_[A-Za-z0-9_-]{43}$/",
		"bearerPattern.test(candidate)",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("app.js is missing %q", required)
		}
	}
}

func TestDownloadWorkerIsNarrowNoStoreAsset(t *testing.T) {
	portal := &Portal{}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		recorder := httptest.NewRecorder()
		portal.ServeHTTP(recorder, httptest.NewRequest(method, BasePath+"/download-worker.js", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s worker status = %d, want 200", method, recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Fatalf("worker Content-Type = %q", got)
		}
		if got := recorder.Header().Get("Service-Worker-Allowed"); got != BasePath+"/" {
			t.Fatalf("worker scope header = %q", got)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("worker Cache-Control = %q", got)
		}
		if method == http.MethodHead && recorder.Body.Len() != 0 {
			t.Fatal("HEAD worker response included a body")
		}
	}

	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/download-worker.js", nil))
	script := recorder.Body.String()
	for _, forbidden := range []string{
		"caches.",
		"indexedDB",
		"localStorage",
		"sessionStorage",
		"console.",
		"BroadcastChannel",
		"clients.matchAll",
		"new Blob(",
		".blob(",
		".arrayBuffer(",
		".clone(",
		".tee(",
		"frameProof",
		"frameClientId",
		"download-frame",
		"canonicalFrameClient",
		"event.clientId",
		"replacesClientId",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("download worker contains persistent storage or logging primitive %q", forbidden)
		}
	}
	for _, required := range []string{
		"const protocolVersion=2",
		"const filePath=basePath+'/api/file'",
		"request.method!=='POST'",
		"request.mode==='navigate'",
		"request.destination==='document'||request.destination==='iframe'",
		"pendingDownloads.get(download.nonce)",
		"activeDownloads.get(data.nonce)",
		"activeDownloads.has(data.nonce)",
		"navigationProof:data.navigationProof",
		"exactNavigationProof(event.request,prepared)",
		"request.text()",
		"prepared.navigationProof=''",
		"self.clients.get(prepared.clientId)",
		"headers.set('Authorization','Bearer '+authorization.token)",
		"const bearerPattern=/^rc1_[A-Za-z0-9_-]{43}$/",
		"!bearerPattern.test(data.token)",
		"credentials:'omit'",
		"redirect:'error'",
		"event.request.signal.removeEventListener('abort',abortFromNavigation)",
		"/^attachment(?:\\s*;|$)/i.test(disposition)",
		"contentType==='application/octet-stream'",
		"contentEncoding===null",
		"/^(?:0|[1-9][0-9]*)$/.test(contentLength)",
		"cacheDirectives.includes('no-store')",
		"X-Content-Type-Options",
		"Accept-Ranges",
		"const reader=response.body.getReader()",
		"const body=new ReadableStream({",
		"finishActiveDownload(download,active,'completed')",
		"active.cancelRequested=true;active.controller.abort()",
		"sendStatus(active.port,download,'handed',active.httpStatus,false)",
		"controller.abort()",
		"status:204",
		"respondToDownload(download,event)",
		"return monitored",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("download worker is missing %q", required)
		}
	}

	recorder = httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, BasePath+"/download-worker.js", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("worker POST response = %d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestDownloadWorkerChecksNavigationProofBeforeConsumingReservation(t *testing.T) {
	portal := &Portal{}
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BasePath+"/download-worker.js", nil))
	script := recorder.Body.String()

	preparedIndex := strings.Index(script, "const prepared=pendingDownloads.get(download.nonce);")
	if preparedIndex < 0 {
		t.Fatal("download worker does not look up the prepared reservation")
	}
	proofCheckIndex := strings.Index(script, "exactNavigationProof(event.request,prepared)")
	if proofCheckIndex < preparedIndex {
		t.Fatal("download worker navigation proof is missing from the consume path")
	}
	deleteIndex := strings.Index(script, "pendingDownloads.delete(download.nonce);")
	if deleteIndex < 0 || proofCheckIndex > deleteIndex {
		t.Fatal("download worker consumes a reservation before validating its navigation proof")
	}
}

func TestUnauthenticatedFileNavigationFailsClosedWithoutReplacingPortal(t *testing.T) {
	portal := &Portal{}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, destination := range []string{"document", "iframe"} {
			request := httptest.NewRequest(method, BasePath+"/api/file?path=report.pdf", strings.NewReader("proof=untrusted"))
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Dest", destination)
			recorder := httptest.NewRecorder()
			portal.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("%s %s navigation status = %d, want 204", method, destination, recorder.Code)
			}
			if recorder.Body.Len() != 0 {
				t.Fatalf("%s %s navigation failure returned a body: %q", method, destination, recorder.Body.String())
			}
			if recorder.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("%s %s navigation failure unexpectedly requested browser authentication", method, destination)
			}
			if recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s navigation failure is cacheable", method, destination)
			}
		}
	}

	request := httptest.NewRequest(http.MethodGet, BasePath+"/api/file?path=report.pdf", nil)
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "object")
	recorder := httptest.NewRecorder()
	portal.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsupported navigation destination status = %d, want 401", recorder.Code)
	}
}
