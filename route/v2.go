package route

import (
	"context"
	"crypto/ecdsa"
	"log"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IceWhaleTech/CasaOS/codegen"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/file"

	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS/pkg/authsecurity"
	v2Route "github.com/IceWhaleTech/CasaOS/route/v2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
	"github.com/oapi-codegen/echo-middleware"
)

var (
	_swagger *openapi3.T

	V2APIPath  string
	V2DocPath  string
	V3FilePath string
)

const (
	v2OpenAPIJWTVerifiedContextKey = "recasaos/v2-openapi-jwt-verified"
	v2OpenAPISecuritySchemeName    = "access_token"
)

// v2OpenAPIJWTVerification binds the OpenAPI handoff to the exact request
// which echo-jwt authenticated. Request headers and generic Echo context
// values are not authentication evidence.
type v2OpenAPIJWTVerification struct {
	request *http.Request
}

func init() {
	swagger, err := codegen.GetSwagger()
	if err != nil {
		panic(err)
	}

	_swagger = swagger

	u, err := url.Parse(_swagger.Servers[0].URL)
	if err != nil {
		panic(err)
	}

	V2APIPath = strings.TrimRight(u.Path, "/")
	V2DocPath = "/doc" + V2APIPath
	V3FilePath = "/v3/file"
}

func InitV2Router() http.Handler {
	appManagement := v2Route.NewCasaOS()

	e := echo.New()

	e.Use(rejectCredentialTransport())
	e.Use(echo_middleware.Gzip())

	e.Use(safeRequestLogger())

	e.Use(echojwt.WithConfig(v2JWTConfig()))
	e.Use(privateNoStoreResponses())

	e.Use(echomiddleware.OapiRequestValidatorWithOptions(_swagger, &echomiddleware.Options{
		Skipper: v2OpenAPIValidationSkipper,
		Options: openapi3filter.Options{AuthenticationFunc: v2OpenAPIAuthentication},
	}))

	codegen.RegisterHandlersWithBaseURL(e, appManagement, V2APIPath)

	return httpsecurity.WithSecurityHeaders(httpsecurity.WithCORS(e, httpsecurity.AllowedOriginsFromEnv()))
}

func v2JWTConfig() echojwt.Config {
	return echojwt.Config{
		Skipper: func(c echo.Context) bool {
			return httpsecurity.LoopbackAuthBypassAllowed(c.Request())
		},
		SuccessHandler: func(c echo.Context) {
			c.Set(v2OpenAPIJWTVerifiedContextKey, v2OpenAPIJWTVerification{
				request: c.Request(),
			})
		},
		ParseTokenFunc: func(c echo.Context, token string) (interface{}, error) {
			claims, err := authsecurity.ValidateAccessToken(token, func() (*ecdsa.PublicKey, error) { return external.GetPublicKey(config.CommonInfo.RuntimePath) })
			if err != nil {
				return nil, echo.ErrUnauthorized
			}
			c.Request().Header.Set("user_id", strconv.Itoa(claims.ID))

			return claims, nil
		},
		TokenLookup: "header:Authorization",
	}
}

func v2OpenAPIValidationSkipper(c echo.Context) bool {
	request := c.Request()
	if request == nil ||
		request.URL == nil ||
		request.Method != http.MethodPost ||
		request.URL.Path != V2APIPath+"/file/upload" {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(request.Header.Get(echo.HeaderContentType))
	return err == nil && mediaType == "multipart/form-data"
}

func v2OpenAPIAuthentication(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	if input == nil ||
		input.RequestValidationInput == nil ||
		input.RequestValidationInput.Request == nil ||
		input.SecuritySchemeName != v2OpenAPISecuritySchemeName ||
		input.SecurityScheme == nil ||
		input.SecurityScheme.Type != "apiKey" ||
		input.SecurityScheme.In != "header" ||
		input.SecurityScheme.Name != echo.HeaderAuthorization ||
		len(input.Scopes) != 0 {
		return echo.ErrUnauthorized
	}

	echoContext := echomiddleware.GetEchoContext(ctx)
	if echoContext == nil ||
		echoContext.Request() == nil ||
		echoContext.Request() != input.RequestValidationInput.Request {
		return echo.ErrUnauthorized
	}

	verification, ok := echoContext.Get(v2OpenAPIJWTVerifiedContextKey).(v2OpenAPIJWTVerification)
	if ok && verification.request == echoContext.Request() {
		return nil
	}
	if httpsecurity.LoopbackAuthBypassAllowed(echoContext.Request()) {
		return nil
	}
	return echo.ErrUnauthorized
}

func InitV2DocRouter(docHTML string, docYAML string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == V2DocPath {
			if _, err := w.Write([]byte(docHTML)); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		if r.URL.Path == V2DocPath+"/openapi.yaml" {
			if _, err := w.Write([]byte(docYAML)); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	})
}

func InitFile() http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		token, ok := accessTokenFromRequest(r)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if _, err := authsecurity.ValidateAccessToken(token, func() (*ecdsa.PublicKey, error) { return external.GetPublicKey(config.CommonInfo.RuntimePath) }); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		filePath := r.URL.Query().Get("path")
		if strings.TrimSpace(filePath) == "" || strings.IndexByte(filePath, 0) >= 0 {
			http.NotFound(w, r)
			return
		}
		roots, err := filesecurity.ManagementFileRoots()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		opened, err := roots.OpenRegular(filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer opened.Close()
		info, err := opened.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}

		fileName := filepath.Base(filePath)
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", "attachment; filename*=utf-8''"+url.PathEscape(fileName))
		http.ServeContent(w, r, fileName, info.ModTime(), opened)
	})
	return httpsecurity.WithSecurityHeaders(rejectCredentialTransportHTTP(handler))
}

func accessTokenFromRequest(r *http.Request) (string, bool) {
	const maxTokenLength = 16 << 10

	if r == nil || hasCredentialQueryParameter(r) {
		return "", false
	}
	authorization := r.Header.Values(echo.HeaderAuthorization)
	if len(authorization) > 0 {
		if len(authorization) != 1 {
			return "", false
		}
		scheme, token, found := strings.Cut(strings.TrimSpace(authorization[0]), " ")
		token = strings.TrimSpace(token)
		if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenLength || strings.ContainsAny(token, " \t\r\n") {
			return "", false
		}
		return token, true
	}

	return "", false
}

func InitDir() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := accessTokenFromRequest(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "token not found"}`))
			return
		}

		if _, err := authsecurity.ValidateAccessToken(token, func() (*ecdsa.PublicKey, error) { return external.GetPublicKey(config.CommonInfo.RuntimePath) }); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "validation failure"}`))
			return
		}
		t := r.URL.Query().Get("format")
		files := r.URL.Query().Get("files")

		if len(files) == 0 {
			// w.JSON(common_err.CLIENT_ERROR, model.Result{
			// 	Success: common_err.INVALID_PARAMS,
			// 	Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			// })
			return
		}
		list := strings.Split(files, ",")
		roots, err := filesecurity.ManagementFileRoots()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		for _, v := range list {
			if _, err := roots.Stat(v); err != nil {
				// return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
				// 	Success: common_err.FILE_DOES_NOT_EXIST,
				// 	Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
				// })
				return
			}
		}
		w.Header().Add("Content-Type", "application/octet-stream")
		w.Header().Add("Content-Transfer-Encoding", "binary")
		w.Header().Add("Cache-Control", "no-cache")
		// handles only single files not folders and multiple files
		//		if len(list) == 1 {

		// filePath := list[0]
		//			info, err := os.Stat(filePath)
		//			if err != nil {

		// w.JSON(http.StatusOK, model.Result{
		// 	Success: common_err.FILE_DOES_NOT_EXIST,
		// 	Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
		// })
		//return
		//			}
		//}

		extension, ar, err := file.GetCompressionAlgorithm(t)
		if err != nil {
			// w.JSON(common_err.CLIENT_ERROR, model.Result{
			// 	Success: common_err.INVALID_PARAMS,
			// 	Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			// })
			return
		}

		err = ar.Create(w)
		if err != nil {
			//  return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			// 	Success: common_err.SERVICE_ERROR,
			// 	Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			// 	Data:    err.Error(),
			// })
			return
		}
		defer ar.Close()
		commonDir := file.CommonPrefix(filepath.Separator, list...)

		currentPath := filepath.Base(commonDir)

		name := "_" + currentPath
		name += extension
		w.Header().Add("Content-Disposition", "attachment; filename*=utf-8''"+url.PathEscape(name))
		for _, fname := range list {
			err = file.AddManagedFile(ar, roots, fname, commonDir)
			if err != nil {
				log.Printf("Failed to archive %s: %v", fname, err)
			}
		}
	})
}
