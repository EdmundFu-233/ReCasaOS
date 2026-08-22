package v2

import (
	"errors"
	"net/http"
	"strconv"

	commonjwt "github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS/codegen"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

func (c *CasaOS) CheckUploadChunk(ctx echo.Context, params codegen.CheckUploadChunkParams) error {
	principalID, err := authenticatedUploadPrincipalID(ctx)
	if err != nil {
		return err
	}
	identifier := ctx.QueryParam("identifier")
	chunkNumber, err := strconv.ParseInt(ctx.QueryParam("chunkNumber"), 10, 64)
	if err != nil {
		return ctx.NoContent(http.StatusBadRequest)
	}

	err = c.fileUploadService.TestChunk(ctx, principalID, identifier, chunkNumber)
	if err != nil {
		return ctx.NoContent(http.StatusNoContent)
	}
	return ctx.NoContent(http.StatusOK)
}

func (c *CasaOS) PostUploadFile(ctx echo.Context) error {
	principalID, err := authenticatedUploadPrincipalID(ctx)
	if err != nil {
		return err
	}
	const multipartOverheadAllowance int64 = 1 << 20
	const multipartMemory = 32 << 20
	requestLimit := filesecurity.MaxUploadChunkSize + multipartOverheadAllowance
	request := ctx.Request()
	request.Body = http.MaxBytesReader(ctx.Response().Writer, request.Body, requestLimit)
	if request.ContentLength > requestLimit {
		return ctx.JSON(http.StatusRequestEntityTooLarge, map[string]string{"message": "upload request exceeds 256 MiB"})
	}
	if err := request.ParseMultipartForm(multipartMemory); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return ctx.JSON(http.StatusRequestEntityTooLarge, map[string]string{"message": "upload request exceeds 256 MiB"})
		}
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "invalid multipart request"})
	}
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}

	path := ctx.FormValue("path")

	// handle the request
	chunkNumber, err := strconv.ParseInt(ctx.FormValue("chunkNumber"), 10, 64)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}
	chunkSize, err := strconv.ParseInt(ctx.FormValue("chunkSize"), 10, 64)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}
	currentChunkSize, err := strconv.ParseInt(ctx.FormValue("currentChunkSize"), 10, 64)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}
	totalChunks, err := strconv.ParseInt(ctx.FormValue("totalChunks"), 10, 64)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}
	totalSize, err := strconv.ParseInt(ctx.FormValue("totalSize"), 10, 64)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}

	identifier := ctx.FormValue("identifier")
	fileName := ctx.FormValue("filename")
	relativePath := ctx.FormValue("relativePath")
	bin, err := ctx.FormFile("file")

	if err != nil {
		return ctx.JSON(http.StatusBadRequest, err)
	}

	err = c.fileUploadService.UploadFile(
		ctx,
		principalID,
		path,
		chunkNumber,
		chunkSize,
		currentChunkSize,
		totalChunks,
		totalSize,
		identifier,
		relativePath,
		fileName,
		bin,
	)
	if err != nil {
		return respondUploadMutationFailure(ctx, err)
	}
	return ctx.NoContent(http.StatusOK)
}

// authenticatedUploadPrincipalID accepts only the typed claims installed by
// echo-jwt after access-token validation. Request headers are deliberately not
// authentication evidence, and the optional loopback bypass has no principal
// to bind a resumable upload to, so both cases fail closed here.
func authenticatedUploadPrincipalID(ctx echo.Context) (int, error) {
	if ctx == nil {
		return 0, echo.ErrUnauthorized
	}
	claims, ok := ctx.Get("user").(*commonjwt.Claims)
	if !ok || claims == nil || claims.ID < 1 {
		return 0, echo.ErrUnauthorized
	}
	return claims.ID, nil
}

func respondUploadMutationFailure(ctx echo.Context, err error) error {
	status := "FAILED"
	if filesecurity.ManagedMutationChanged(err) {
		status = "PARTIAL"
	}
	return ctx.JSON(http.StatusInternalServerError, map[string]interface{}{
		"status":             status,
		"changed":            filesecurity.ManagedMutationChanged(err),
		"durability_unknown": filesecurity.ManagedMutationDurabilityUnknown(err),
		"error":              err.Error(),
	})
}
