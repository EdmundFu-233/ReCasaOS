package route

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS/pkg/authsecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func TestManagementJWTConfigurationsRequireBearerHeader(t *testing.T) {
	t.Setenv(httpsecurity.TrustLoopbackAuthBypassEnv, "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token, err := commonjwt.GetAccessToken("transport-test", key, 42)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := commonjwt.GetRefreshToken("transport-test", key, 42)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []struct {
		name   string
		config echojwt.Config
	}{
		{name: "v1", config: v1JWTConfig()},
		{name: "v2", config: v2JWTConfig()},
	} {
		for _, test := range []struct {
			name    string
			headers []string
			query   string
			status  int
		}{
			{name: "bearer", headers: []string{"Bearer " + token}, status: http.StatusOK},
			{name: "case insensitive scheme", headers: []string{"bEaReR " + token}, status: http.StatusOK},
			{name: "bare JWT", headers: []string{token}, status: http.StatusUnauthorized},
			{name: "missing header", status: http.StatusUnauthorized},
			{name: "wrong scheme", headers: []string{"Basic " + token}, status: http.StatusUnauthorized},
			{name: "extra space", headers: []string{"Bearer  " + token}, status: http.StatusUnauthorized},
			{name: "refresh token", headers: []string{"Bearer " + refresh}, status: http.StatusUnauthorized},
			{name: "query token", query: "token=" + token, status: http.StatusBadRequest},
			{name: "header plus query token", headers: []string{"Bearer " + token}, query: "token=" + token, status: http.StatusBadRequest},
			{name: "duplicate headers", headers: []string{"Bearer " + token, "Bearer " + token}, status: http.StatusBadRequest},
		} {
			t.Run(version.name+"/"+test.name, func(t *testing.T) {
				configuration := version.config
				parseCalls := 0
				// Keep the production extractor and real issuer/signature checks;
				// only supply an in-memory key instead of fetching UserService.
				configuration.ParseTokenFunc = func(_ echo.Context, raw string) (interface{}, error) {
					parseCalls++
					return authsecurity.ValidateAccessToken(raw, func() (*ecdsa.PublicKey, error) {
						return &key.PublicKey, nil
					})
				}
				router := echo.New()
				router.Use(rejectCredentialTransport())
				router.Use(echojwt.WithConfig(configuration))
				reachedHandler := false
				router.GET("/protected", func(context echo.Context) error {
					reachedHandler = true
					return context.NoContent(http.StatusOK)
				})
				request := httptest.NewRequest(http.MethodGet, "/protected?"+test.query, nil)
				request.RemoteAddr = "198.51.100.20:43120"
				for _, header := range test.headers {
					request.Header.Add(echo.HeaderAuthorization, header)
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code != test.status || reachedHandler != (test.status == http.StatusOK) {
					t.Fatalf("status=%d, handler=%v, want status=%d", response.Code, reachedHandler, test.status)
				}
				if test.status == http.StatusBadRequest && parseCalls != 0 {
					t.Fatal("ambiguous credential transport reached JWT parsing")
				}
			})
		}
	}
}
