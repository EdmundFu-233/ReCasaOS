package route

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/oapi-codegen/echo-middleware"
)

func TestV2OpenAPIAuthenticationRequiresMatchingEchoRequest(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")

	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	input := newV2OpenAPIAuthenticationInput(t, request)

	if err := v2OpenAPIAuthentication(context.Background(), input); err != echo.ErrUnauthorized {
		t.Fatalf("missing Echo context error = %v, want echo.ErrUnauthorized", err)
	}
	if err := v2OpenAPIAuthentication(context.Background(), nil); err != echo.ErrUnauthorized {
		t.Fatalf("nil authentication input error = %v, want echo.ErrUnauthorized", err)
	}

	otherRequest := httptest.NewRequest(http.MethodGet, request.URL.String(), nil)
	otherRequest.RemoteAddr = request.RemoteAddr
	echoContext, validationContext := newV2OpenAPIEchoContext(otherRequest)
	v2JWTConfig().SuccessHandler(echoContext)
	if err := v2OpenAPIAuthentication(validationContext, input); err != echo.ErrUnauthorized {
		t.Fatalf("mismatched request error = %v, want echo.ErrUnauthorized", err)
	}
}

func TestV2OpenAPIAuthenticationRejectsForgedRequestSignals(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")

	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	request.Header.Set(echo.HeaderAuthorization, "Bearer attacker-controlled")
	request.Header.Set("user_id", "1")
	request.Header.Set("Forwarded", "for=127.0.0.1")
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("X-Real-IP", "::1")

	echoContext, validationContext := newV2OpenAPIEchoContext(request)
	echoContext.Set("user", "attacker-controlled")
	echoContext.Set(v2OpenAPIJWTVerifiedContextKey, true)

	if err := v2OpenAPIAuthentication(validationContext, newV2OpenAPIAuthenticationInput(t, request)); err != echo.ErrUnauthorized {
		t.Fatalf("forged request signals error = %v, want echo.ErrUnauthorized", err)
	}
}

func TestV2OpenAPIAuthenticationRejectsMarkerFromAnotherRequest(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")

	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	otherRequest := httptest.NewRequest(http.MethodGet, request.URL.String(), nil)
	otherRequest.RemoteAddr = request.RemoteAddr
	echoContext, validationContext := newV2OpenAPIEchoContext(request)
	echoContext.Set(v2OpenAPIJWTVerifiedContextKey, v2OpenAPIJWTVerification{
		request: otherRequest,
	})

	if err := v2OpenAPIAuthentication(validationContext, newV2OpenAPIAuthenticationInput(t, request)); err != echo.ErrUnauthorized {
		t.Fatalf("marker from another request error = %v, want echo.ErrUnauthorized", err)
	}
}

func TestV2OpenAPIAuthenticationAcceptsJWTSuccessMarker(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")

	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	echoContext, validationContext := newV2OpenAPIEchoContext(request)

	config := v2JWTConfig()
	if config.SuccessHandler == nil {
		t.Fatal("v2 JWT middleware has no success handler")
	}
	config.SuccessHandler(echoContext)

	if err := v2OpenAPIAuthentication(validationContext, newV2OpenAPIAuthenticationInput(t, request)); err != nil {
		t.Fatalf("JWT success marker rejected: %v", err)
	}
}

func TestV2OpenAPIValidationSkipperIsUploadSpecific(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		want        bool
	}{
		{
			name:        "upload multipart",
			method:      http.MethodPost,
			path:        V2APIPath + "/file/upload",
			contentType: "multipart/form-data; boundary=test-boundary",
			want:        true,
		},
		{
			name:        "upload GET",
			method:      http.MethodGet,
			path:        V2APIPath + "/file/upload",
			contentType: "multipart/form-data; boundary=test-boundary",
		},
		{
			name:        "other route",
			method:      http.MethodPost,
			path:        V2APIPath + "/health/services",
			contentType: "multipart/form-data; boundary=test-boundary",
		},
		{
			name:        "substring media type",
			method:      http.MethodPost,
			path:        V2APIPath + "/file/upload",
			contentType: "text/plain; note=multipart/form-data",
		},
		{
			name:        "malformed media type",
			method:      http.MethodPost,
			path:        V2APIPath + "/file/upload",
			contentType: "multipart/form-data; boundary",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://device.test"+test.path, nil)
			request.Header.Set(echo.HeaderContentType, test.contentType)
			echoContext := echo.New().NewContext(request, httptest.NewRecorder())

			if got := v2OpenAPIValidationSkipper(echoContext); got != test.want {
				t.Fatalf("v2OpenAPIValidationSkipper() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestV2OpenAPIAuthenticationAllowsOnlyExplicitDirectLoopbackBypass(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "127.0.0.1:43120"
	_, validationContext := newV2OpenAPIEchoContext(request)
	input := newV2OpenAPIAuthenticationInput(t, request)

	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")
	if err := v2OpenAPIAuthentication(validationContext, input); err != echo.ErrUnauthorized {
		t.Fatalf("default loopback error = %v, want echo.ErrUnauthorized", err)
	}

	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "true")
	if err := v2OpenAPIAuthentication(validationContext, input); err != echo.ErrUnauthorized {
		t.Fatalf("non-exact opt-in error = %v, want echo.ErrUnauthorized", err)
	}

	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")
	if err := v2OpenAPIAuthentication(validationContext, input); err != nil {
		t.Fatalf("explicit direct-loopback bypass rejected: %v", err)
	}
}

func TestV2OpenAPIAuthenticationRejectsSecuritySchemeDrift(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")

	request := httptest.NewRequest(http.MethodGet, "http://device.test"+V2APIPath+"/health/services", nil)
	request.RemoteAddr = "198.51.100.20:43120"
	echoContext, validationContext := newV2OpenAPIEchoContext(request)
	v2JWTConfig().SuccessHandler(echoContext)

	tests := map[string]func(*openapi3filter.AuthenticationInput){
		"unknown name": func(input *openapi3filter.AuthenticationInput) {
			input.SecuritySchemeName = "future_auth"
		},
		"wrong type": func(input *openapi3filter.AuthenticationInput) {
			scheme := *input.SecurityScheme
			scheme.Type = "http"
			input.SecurityScheme = &scheme
		},
		"wrong location": func(input *openapi3filter.AuthenticationInput) {
			scheme := *input.SecurityScheme
			scheme.In = "query"
			input.SecurityScheme = &scheme
		},
		"wrong header": func(input *openapi3filter.AuthenticationInput) {
			scheme := *input.SecurityScheme
			scheme.Name = "X-API-Key"
			input.SecurityScheme = &scheme
		},
		"unexpected scope": func(input *openapi3filter.AuthenticationInput) {
			input.Scopes = []string{"admin"}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := newV2OpenAPIAuthenticationInput(t, request)
			mutate(input)
			if err := v2OpenAPIAuthentication(validationContext, input); err != echo.ErrUnauthorized {
				t.Fatalf("scheme drift error = %v, want echo.ErrUnauthorized", err)
			}
		})
	}
}

func TestInitV2RouterAuthenticatesBeforeOpenAPIValidation(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")

	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
	}{
		{
			name:   "invalid query",
			method: http.MethodGet,
			target: "http://device.test" + V2APIPath + "/file/upload",
		},
		{
			name:        "multipart skipper",
			method:      http.MethodPost,
			target:      "http://device.test" + V2APIPath + "/file/upload",
			contentType: "multipart/form-data; boundary=test-boundary",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, nil)
			request.RemoteAddr = "198.51.100.20:43120"
			request.Header.Set("user_id", "1")
			request.Header.Set("Forwarded", "for=127.0.0.1")
			request.Header.Set("X-Forwarded-For", "127.0.0.1")
			if test.contentType != "" {
				request.Header.Set(echo.HeaderContentType, test.contentType)
			}
			response := httptest.NewRecorder()

			InitV2Router().ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
		})
	}
}

func TestInitV2RouterRejectsRepeatedScalarQueryValues(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "1")

	query := url.Values{}
	query.Add("path", "/DATA/first")
	query.Add("path", "/DATA/second")
	query.Set("relativePath", "/DATA/first")
	query.Set("filename", "first")
	query.Set("chunkNumber", "1")
	query.Set("totalChunks", "1")

	request := httptest.NewRequest(
		http.MethodGet,
		"http://device.test"+V2APIPath+"/file/upload?"+query.Encode(),
		nil,
	)
	request.RemoteAddr = "127.0.0.1:43120"
	response := httptest.NewRecorder()

	InitV2Router().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "multiple values for single value parameter 'path'") {
		t.Fatalf("response did not prove the generated scalar binder rejected duplicates: %s", response.Body.String())
	}
}

func newV2OpenAPIAuthenticationInput(t *testing.T, request *http.Request) *openapi3filter.AuthenticationInput {
	t.Helper()

	if _swagger == nil || _swagger.Components == nil {
		t.Fatal("v2 OpenAPI document has no components")
	}
	schemeRef := _swagger.Components.SecuritySchemes[v2OpenAPISecuritySchemeName]
	if schemeRef == nil || schemeRef.Value == nil {
		t.Fatalf("v2 OpenAPI document has no %q security scheme", v2OpenAPISecuritySchemeName)
	}

	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: request},
		SecuritySchemeName:     v2OpenAPISecuritySchemeName,
		SecurityScheme:         schemeRef.Value,
	}
}

func newV2OpenAPIEchoContext(request *http.Request) (echo.Context, context.Context) {
	echoContext := echo.New().NewContext(request, httptest.NewRecorder())
	validationContext := context.WithValue(context.Background(), echomiddleware.EchoContextKey, echoContext)
	return echoContext, validationContext
}
