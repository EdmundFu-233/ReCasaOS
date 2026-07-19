package v1

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// GetRecoverStorage intentionally disables the legacy cloud OAuth callback.
//
// The original flow accepted an unauthenticated authorization code without a
// one-time state value or PKCE verifier and immediately wrote a root-owned
// rclone configuration. That allowed cross-site OAuth code injection. Cloud
// recovery must remain unavailable until every provider uses a locally-issued,
// single-use state record bound to the initiating user and PKCE verifier.
func GetRecoverStorage(ctx echo.Context) error {
	ctx.Response().Header().Set("Cache-Control", "no-store")
	return ctx.JSON(http.StatusGone, map[string]string{
		"error": "cloud OAuth recovery is disabled pending state and PKCE support",
	})
}
