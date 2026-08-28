package v1

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	url2 "net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/httpsecurity"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/robfig/cron/v3"

	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/file"
	"github.com/IceWhaleTech/CasaOS/service"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"

	"github.com/google/uuid"

	"github.com/h2non/filetype"
)

type ListReq struct {
	model.PageReq
	Path string `json:"path" form:"path"`
	// Refresh bool   `json:"refresh"`
}

type ObjResp struct {
	Name       string                 `json:"name"`
	Size       int64                  `json:"size"`
	IsDir      bool                   `json:"is_dir"`
	Modified   time.Time              `json:"modified"`
	Sign       string                 `json:"sign"`
	Thumb      string                 `json:"thumb"`
	Type       int                    `json:"type"`
	Path       string                 `json:"path"`
	Date       time.Time              `json:"date"`
	Extensions map[string]interface{} `json:"extensions"`
}
type FsListResp struct {
	Content  []ObjResp `json:"content"`
	Total    int64     `json:"total"`
	Readme   string    `json:"readme,omitempty"`
	Write    bool      `json:"write,omitempty"`
	Provider string    `json:"provider,omitempty"`
	Index    int       `json:"index"`
	Size     int       `json:"size"`
}

var (
	// 升级成 WebSocket 协议
	upgraderFile = websocket.Upgrader{
		CheckOrigin:      httpsecurity.WebSocketOriginAllowed,
		HandshakeTimeout: 5 * time.Second,
	}
)

const (
	maxManagedTextFileSize              int64 = 16 << 20
	maxManagedTextUpdateRequestBodySize int64 = 17 << 20
	maxFileOperationRequestBodySize     int64 = 256 << 10
	maxSmallFileJSONRequestBodySize     int64 = 64 << 10
	maxFileDeleteItems                        = 16
	// Path-only legacy UI callers expect a complete list and ignore pagination.
	// The service bounds this compatibility mode at its raw scan limit; explicit
	// pagination remains capped at ManagedDirectoryPageLimit.
	defaultManagedDirectoryPageSize = service.ManagedDirectoryLegacyPageSize
	managedDirectoryLimitMessage    = "directory listing exceeds the safe entry limit"
	managedDirectoryBusyMessage     = "directory listing capacity is temporarily busy"
)

var errInvalidManagedDirectoryPagination = errors.New("invalid managed directory pagination")

type filePathRequest struct {
	Path string `json:"path"`
}

type fileRenameRequest struct {
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
}

func bindBoundedFileJSON(ctx echo.Context, destination interface{}, maximum int64) error {
	request := ctx.Request()
	request.Body = http.MaxBytesReader(ctx.Response().Writer, request.Body, maximum)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validManagedRequestPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && strings.IndexByte(path, 0) < 0
}

func parseManagedDirectoryPagination(rawQuery string) (int, int, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return 0, 0, errInvalidManagedDirectoryPagination
	}
	_, hasIndex := values["index"]
	_, hasSize := values["size"]
	if hasIndex != hasSize {
		return 0, 0, errInvalidManagedDirectoryPagination
	}
	if !hasIndex {
		return 1, defaultManagedDirectoryPageSize, nil
	}
	index, err := parseManagedDirectoryPositiveInt(values, "index", 1)
	if err != nil {
		return 0, 0, err
	}
	size, err := parseManagedDirectoryPositiveInt(values, "size", defaultManagedDirectoryPageSize)
	if err != nil || size > service.ManagedDirectoryPageLimit {
		return 0, 0, errInvalidManagedDirectoryPagination
	}
	maxInt := int(^uint(0) >> 1)
	if index-1 > maxInt/size {
		return 0, 0, errInvalidManagedDirectoryPagination
	}
	return index, size, nil
}

func parseManagedDirectoryPositiveInt(values url.Values, name string, defaultValue int) (int, error) {
	provided, ok := values[name]
	if !ok {
		return defaultValue, nil
	}
	if len(provided) != 1 || provided[0] == "" {
		return 0, errInvalidManagedDirectoryPagination
	}
	for index := range provided[0] {
		if provided[0][index] < '0' || provided[0][index] > '9' {
			return 0, errInvalidManagedDirectoryPagination
		}
	}
	parsed, err := strconv.Atoi(provided[0])
	if err != nil || parsed <= 0 {
		return 0, errInvalidManagedDirectoryPagination
	}
	return parsed, nil
}

func managedDirectoryNeedsMountedExtensions(path string) bool {
	return path == "/mnt" || strings.HasPrefix(path, "/mnt/") || path == "/media" || strings.HasPrefix(path, "/media/")
}

func managedRoutePathsOverlap(first, second string) bool {
	return first == second ||
		strings.HasPrefix(first, second+string(filepath.Separator)) ||
		strings.HasPrefix(second, first+string(filepath.Separator))
}

func managedDeleteFailureStatus(result filesecurity.ManagedBatchMutationResult, err error) string {
	if result.Changed || filesecurity.ManagedMutationChanged(err) {
		return "PARTIAL"
	}
	return "FAILED"
}

func managedDeleteFailureData(result filesecurity.ManagedBatchMutationResult, err error) map[string]interface{} {
	return map[string]interface{}{
		"completed":          result.Completed,
		"changed":            result.Changed || filesecurity.ManagedMutationChanged(err),
		"durability_unknown": filesecurity.ManagedMutationDurabilityUnknown(err),
		"status":             managedDeleteFailureStatus(result, err),
		"error":              err.Error(),
	}
}

func managedMutationFailureStatus(err error) string {
	if filesecurity.ManagedMutationChanged(err) {
		return "PARTIAL"
	}
	return "FAILED"
}

func respondManagedMutationFailure(ctx echo.Context, err error) error {
	status := managedMutationFailureStatus(err)
	return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
		Success: common_err.SERVICE_ERROR,
		Message: status,
		Data: map[string]interface{}{
			"status":             status,
			"changed":            filesecurity.ManagedMutationChanged(err),
			"durability_unknown": filesecurity.ManagedMutationDurabilityUnknown(err),
			"error":              err.Error(),
		},
	})
}

func respondV1UploadFailure(ctx echo.Context, err error) error {
	if !filesecurity.ManagedMutationChanged(err) && errors.Is(err, errUploadTooLarge) {
		return ctx.JSON(http.StatusRequestEntityTooLarge, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: errUploadTooLarge.Error(),
			Data: map[string]interface{}{
				"status":             "FAILED",
				"changed":            false,
				"durability_unknown": false,
				"error":              err.Error(),
			},
		})
	}
	return respondManagedMutationFailure(ctx, err)
}

func changedV1UploadError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &filesecurity.ManagedMutationError{
		Operation:         operation,
		Changed:           true,
		DurabilityUnknown: filesecurity.ManagedMutationDurabilityUnknown(err),
		Err:               err,
	}
}

// @Summary 读取文件
// @Produce  application/json
// @Accept application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path query string true "路径"
// @Success 200 {string} string "ok"
// @Router /file/read [get]
func GetFilerContent(ctx echo.Context) error {
	filePath := ctx.QueryParam("path")
	if len(filePath) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	opened, err := roots.OpenRegular(filePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    err.Error(),
		})
	}
	defer opened.Close()
	info, err := io.ReadAll(io.LimitReader(opened, maxManagedTextFileSize+1))
	if err != nil || int64(len(info)) > maxManagedTextFileSize {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_READ_ERROR, Message: common_err.GetMsg(common_err.FILE_READ_ERROR)})
	}
	result := string(info)

	return ctx.JSON(common_err.SUCCESS, model.Result{
		Success: common_err.SUCCESS,
		Message: common_err.GetMsg(common_err.SUCCESS),
		Data:    result,
	})
}

func GetLocalFile(ctx echo.Context) error {
	filePath := ctx.QueryParam("path")
	if len(filePath) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	opened, err := roots.OpenRegular(filePath)
	if err != nil {
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.FILE_DOES_NOT_EXIST,
			Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
		})
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_READ_ERROR, Message: common_err.GetMsg(common_err.FILE_READ_ERROR)})
	}
	http.ServeContent(ctx.Response().Writer, ctx.Request(), filepath.Base(filePath), info.ModTime(), opened)
	return nil
}

// @Summary download
// @Produce  application/json
// @Accept application/json
// @Tags file
// @Security ApiKeyAuth
// @Param format query string false "Compression format" Enums(zip,tar,targz)
// @Param files query string true "file list eg: filename1,filename2,filename3 "
// @Success 200 {string} string "ok"
// @Router /file/download [get]
func GetDownloadFile(ctx echo.Context) error {
	t := ctx.QueryParam("format")

	files := ctx.QueryParam("files")

	if len(files) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	list := strings.Split(files, ",")
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	for _, v := range list {
		if strings.TrimSpace(v) == "" {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
				Success: common_err.INVALID_PARAMS,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
		}
		info, err := roots.Stat(v)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
				Success: common_err.FILE_DOES_NOT_EXIST,
				Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
				Data:    err.Error(),
			})
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
				Success: common_err.INVALID_PARAMS,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
		}
	}
	// handles only single files not folders and multiple files
	if len(list) == 1 {
		filePath := list[0]
		fileHandle, err := roots.OpenPath(filePath)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
				Success: common_err.FILE_DOES_NOT_EXIST,
				Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
				Data:    err.Error(),
			})
		}
		defer fileHandle.Close()

		info, err := fileHandle.Stat()
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
				Success: common_err.FILE_READ_ERROR,
				Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
				Data:    err.Error(),
			})
		}
		if info.Mode().IsRegular() {
			fileName := path.Base(filePath)
			responseHeader := ctx.Response().Header()
			responseHeader.Set("Content-Transfer-Encoding", "binary")
			responseHeader.Set("Cache-Control", "private, no-store")
			responseHeader.Set("X-Content-Type-Options", "nosniff")
			responseHeader.Set("Content-Type", "application/octet-stream")
			responseHeader.Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(fileName))
			http.ServeContent(ctx.Response().Writer, ctx.Request(), fileName, info.ModTime(), fileHandle)
			return nil
		}
		if !info.IsDir() {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
	}

	extension, ar, err := file.GetCompressionAlgorithm(t)
	if err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	responseHeader := ctx.Response().Header()
	responseHeader.Set("Content-Transfer-Encoding", "binary")
	responseHeader.Set("Cache-Control", "private, no-store")
	responseHeader.Set("X-Content-Type-Options", "nosniff")
	responseHeader.Set("Content-Type", archiveContentType(extension))

	commonDir := file.CommonPrefix(filepath.Separator, list...)
	currentPath := filepath.Base(filepath.Clean(commonDir))
	if currentPath == "." || currentPath == string(filepath.Separator) || currentPath == "" {
		currentPath = "download"
	}
	name := "_" + currentPath + extension
	responseHeader.Set("Content-Disposition", "attachment; filename*=utf-8''"+url.PathEscape(name))

	if err = ar.Create(ctx.Response().Writer); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			Data:    err.Error(),
		})
	}
	for _, fname := range list {
		err = file.AddManagedFile(ar, roots, fname, commonDir)
		if err != nil {
			_ = ar.Close()
			return fmt.Errorf("archive %s: %w", fname, err)
		}
	}
	return ar.Close()
}

func GetDownloadSingleFile(ctx echo.Context) error {
	filePath := ctx.QueryParam("path")
	if len(filePath) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	fileName := path.Base(filePath)

	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	fi, err := roots.OpenRegular(filePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_DOES_NOT_EXIST,
			Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
			Data:    err.Error(),
		})
	}
	defer fi.Close()

	node, err := fi.Stat()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    err.Error(),
		})
	}
	if !node.Mode().IsRegular() {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}

	// We only have to pass the file header = first 261 bytes
	buffer := make([]byte, 261)
	n, readErr := fi.Read(buffer)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    readErr.Error(),
		})
	}
	if _, err := fi.Seek(0, io.SeekStart); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    err.Error(),
		})
	}

	responseHeader := ctx.Response().Header()
	responseHeader.Set("Content-Disposition", "attachment; filename*=utf-8''"+url2.PathEscape(fileName))
	responseHeader.Set("Content-Type", "application/octet-stream")
	responseHeader.Set("X-Content-Type-Options", "nosniff")
	kind, _ := filetype.Match(buffer[:n])
	if kind != filetype.Unknown {
		responseHeader.Set("Content-Type", kind.MIME.Value)
	}
	// Set the Last-Modified header to the timestamp
	responseHeader.Set("Last-Modified", node.ModTime().UTC().Format(http.TimeFormat))

	knownSize := node.Size() >= 0
	if knownSize {
		responseHeader.Set("Content-Length", strconv.FormatInt(node.Size(), 10))
	}
	http.ServeContent(ctx.Response().Writer, ctx.Request(), fileName, node.ModTime(), fi)
	return nil
}

func archiveContentType(extension string) string {
	switch extension {
	case ".zip":
		return "application/zip"
	case ".tar":
		return "application/x-tar"
	case ".tar.gz":
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}

// @Summary 获取目录列表
// @Produce  application/json
// @Accept application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path query string false "路径"
// @Success 200 {string} string "ok"
// @Router /file/dirpath [get]
func DirPath(ctx echo.Context) error {
	var req ListReq
	index, size, err := parseManagedDirectoryPagination(ctx.Request().URL.RawQuery)
	if err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	release, err := service.AcquireManagedDirectoryListing(ctx.Request().Context())
	if err != nil {
		return respondManagedDirectoryListingFailure(ctx, err)
	}
	defer release()
	req.Path = ctx.QueryParam("path")
	req.Index = index
	req.Size = size
	info, total, err := service.MyService.System().GetDirPathPage(ctx.Request().Context(), req.Path, req.Index, req.Size)
	if err != nil {
		return respondManagedDirectoryListingFailure(ctx, err)
	}
	if err := ctx.Request().Context().Err(); err != nil {
		return err
	}
	shares := service.MyService.Shares().GetSharesList()
	if err := ctx.Request().Context().Err(); err != nil {
		return err
	}
	sharesMap := make(map[string]string)
	for _, v := range shares {
		sharesMap[v.Path] = fmt.Sprint(v.ID)
	}
	for i := range info {
		if v, ok := sharesMap[info[i].Path]; ok {
			ex := info[i].Extensions
			if ex == nil {
				ex = make(map[string]interface{})
			}
			shareEx := make(map[string]string)
			shareEx["shared"] = "true"
			shareEx["id"] = v
			ex["share"] = shareEx
			if _, exists := ex["mounted"]; !exists {
				ex["mounted"] = false
			}
			info[i].Extensions = ex
		}
	}
	if managedDirectoryNeedsMountedExtensions(req.Path) {
		if err := ctx.Request().Context().Err(); err != nil {
			return err
		}
		mountedPaths := service.DirectoryListingMountedPaths()
		if err := ctx.Request().Context().Err(); err != nil {
			return err
		}
		for i := range info {
			ex := info[i].Extensions
			if ex == nil {
				ex = make(map[string]interface{})
			}
			_, mounted := mountedPaths[info[i].Path]
			ex["mounted"] = mounted
			info[i].Extensions = ex
		}
	}
	pathList := []ObjResp{}
	for i := range info {
		t := ObjResp{}
		t.IsDir = info[i].IsDir
		t.Name = info[i].Name
		t.Modified = info[i].Date
		t.Date = info[i].Date
		t.Size = info[i].Size
		t.Path = info[i].Path
		t.Extensions = info[i].Extensions
		pathList = append(pathList, t)
	}
	flist := FsListResp{
		Content: pathList,
		Total:   total,
		// Readme:   "",
		// Write:    true,
		// Provider: "local",
		Index: req.Index,
		Size:  req.Size,
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: flist})
}

func respondManagedDirectoryListingFailure(ctx echo.Context, err error) error {
	switch {
	case errors.Is(err, service.ErrManagedDirectoryScanLimit):
		return ctx.JSON(http.StatusUnprocessableEntity, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    managedDirectoryLimitMessage,
		})
	case errors.Is(err, service.ErrManagedDirectoryListingBusy):
		ctx.Response().Header().Set("Retry-After", "1")
		return ctx.JSON(http.StatusServiceUnavailable, model.Result{
			Success: common_err.SERVICE_ERROR,
			Message: common_err.GetMsg(common_err.SERVICE_ERROR),
			Data:    managedDirectoryBusyMessage,
		})
	case errors.Is(err, service.ErrInvalidManagedDirectoryPage):
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	default:
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
}

// @Summary rename file or dir
// @Produce  application/json
// @Accept application/json
// @Tags file
// @Security ApiKeyAuth
// @Param oldpath body string true "path of old"
// @Param newpath body string true "path of new"
// @Success 200 {string} string "ok"
// @Router /file/rename [put]
func RenamePath(ctx echo.Context) error {
	request := fileRenameRequest{}
	if err := bindBoundedFileJSON(ctx, &request, maxSmallFileJSONRequestBodySize); err != nil || !validManagedRequestPath(request.OldPath) || !validManagedRequestPath(request.NewPath) || request.OldPath == request.NewPath {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	mounted := service.IsMounted(request.OldPath)
	if mounted {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
	}

	success, err := service.MyService.System().RenameFile(request.OldPath, request.NewPath)
	if err != nil {
		return respondManagedMutationFailure(ctx, err)
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: success, Message: common_err.GetMsg(success), Data: err})
}

// @Summary create folder
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path body string true "path of folder"
// @Success 200 {string} string "ok"
// @Router /file/mkdir [post]
func MkdirAll(ctx echo.Context) error {
	request := filePathRequest{}
	var code int
	if err := bindBoundedFileJSON(ctx, &request, maxSmallFileJSONRequestBodySize); err != nil || !validManagedRequestPath(request.Path) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	// decodedPath, err := url.QueryUnescape(path)
	// if err != nil {
	// 	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	// 	return
	// }
	code, err := service.MyService.System().MkdirAll(request.Path)
	if err != nil {
		return respondManagedMutationFailure(ctx, err)
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: code, Message: common_err.GetMsg(code)})
}

// @Summary create file
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path body string true "path of folder (path need to url encode)"
// @Success 200 {string} string "ok"
// @Router /file/create [post]
func PostCreateFile(ctx echo.Context) error {
	request := filePathRequest{}
	var code int
	if err := bindBoundedFileJSON(ctx, &request, maxSmallFileJSONRequestBodySize); err != nil || !validManagedRequestPath(request.Path) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	// decodedPath, err := url.QueryUnescape(path)
	// if err != nil {
	// 	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	// 	return
	// }
	code, err := service.MyService.System().CreateFile(request.Path)
	if err != nil {
		return respondManagedMutationFailure(ctx, err)
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: code, Message: common_err.GetMsg(code)})
}

// @Summary upload file
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path formData string false "file path"
// @Param file formData file true "file"
// @Success 200 {string} string "ok"
// @Router /file/upload [get]
func GetFileUpload(ctx echo.Context) error {
	relative := ctx.QueryParam("relativePath")
	fileName := ctx.QueryParam("filename")
	totalChunks, chunkNumber, err := parseUploadChunks(ctx.QueryParam("totalChunks"), ctx.QueryParam("chunkNumber"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}

	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(http.StatusServiceUnavailable, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	paths, err := buildV1UploadPaths(roots, ctx.QueryParam("path"), relative, fileName, totalChunks, chunkNumber)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	if completed, ok, err := v1UploadSessions.lockCompleted(paths, totalChunks); err != nil {
		return respondV1UploadFailure(ctx, err)
	} else if ok {
		verifyErr := verifyCompletedV1Upload(completed, roots)
		completionErr := completed.completionErr
		completed.lastActivity = time.Now()
		completed.lock.Unlock()
		if verifyErr != nil {
			return respondV1UploadFailure(ctx, verifyErr)
		}
		if completionErr != nil {
			return respondV1UploadFailure(ctx, completionErr)
		}
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
	}
	if _, err := roots.Stat(paths.target); err == nil {
		return ctx.JSON(http.StatusConflict, model.Result{Success: http.StatusConflict, Message: common_err.GetMsg(common_err.FILE_ALREADY_EXISTS)})
	} else if !os.IsNotExist(err) {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if _, err := roots.Stat(paths.chunk); err == nil {
		return ctx.JSON(200, model.Result{Success: 200, Message: common_err.GetMsg(common_err.FILE_ALREADY_EXISTS)})
	} else if !os.IsNotExist(err) {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}

	return ctx.NoContent(http.StatusNoContent)
}

// @Summary upload file
// @Produce  application/json
// @Accept  multipart/form-data
// @Tags file
// @Security ApiKeyAuth
// @Param path formData string false "file path"
// @Param file formData file true "file"
// @Success 200 {string} string "ok"
// @Router /file/upload [post]
func PostFileUpload(ctx echo.Context) error {
	const multipartOverheadAllowance int64 = 1 << 20
	request := ctx.Request()
	request.Body = http.MaxBytesReader(ctx.Response().Writer, request.Body, filesecurity.MaxUploadChunkSize+multipartOverheadAllowance)
	if request.ContentLength > filesecurity.MaxUploadChunkSize+multipartOverheadAllowance {
		return ctx.JSON(http.StatusRequestEntityTooLarge, model.Result{Success: common_err.INVALID_PARAMS, Message: "upload request exceeds 256 MiB"})
	}

	f, fileHeader, err := request.FormFile("file")
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return ctx.JSON(http.StatusRequestEntityTooLarge, model.Result{Success: common_err.INVALID_PARAMS, Message: "upload request exceeds 256 MiB"})
		}
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	defer f.Close()
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	if fileHeader == nil || fileHeader.Size < 0 || fileHeader.Size > filesecurity.MaxUploadChunkSize {
		return ctx.JSON(http.StatusRequestEntityTooLarge, model.Result{Success: common_err.INVALID_PARAMS, Message: "upload chunk exceeds 256 MiB"})
	}

	relative := ctx.FormValue("relativePath")
	fileName := ctx.FormValue("filename")
	totalChunks, chunkNumber, err := parseUploadChunks(ctx.FormValue("totalChunks"), ctx.FormValue("chunkNumber"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	base := ctx.FormValue("path")
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(http.StatusServiceUnavailable, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	paths, err := buildV1UploadPaths(roots, base, relative, fileName, totalChunks, chunkNumber)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	uploadSession, err := v1UploadSessions.acquire(paths, totalChunks)
	if err != nil {
		if filesecurity.ManagedMutationChanged(err) {
			return respondV1UploadFailure(ctx, err)
		}
		return ctx.JSON(http.StatusTooManyRequests, model.Result{Success: http.StatusTooManyRequests, Message: err.Error()})
	}
	sessionFinished := false
	defer func() {
		if !sessionFinished {
			uploadSession.lock.Unlock()
		}
	}()
	if uploadSession.completed {
		verifyErr := verifyCompletedV1Upload(uploadSession, roots)
		completionErr := uploadSession.completionErr
		uploadSession.lastActivity = time.Now()
		uploadSession.lock.Unlock()
		sessionFinished = true
		if verifyErr != nil {
			return respondV1UploadFailure(ctx, verifyErr)
		}
		if completionErr != nil {
			return respondV1UploadFailure(ctx, completionErr)
		}
		return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
	}

	if err := roots.MkdirAll(filepath.Dir(paths.target), 0o750); err != nil {
		return respondV1UploadFailure(ctx, err)
	}
	namespaceMayHaveChanged := true
	if err := roots.MkdirAll(paths.tempDir, 0o700); err != nil {
		return respondV1UploadFailure(ctx, changedV1UploadErrorIf(namespaceMayHaveChanged, "target parent created before upload staging creation failed", err))
	}
	uploadSession.stagingClean = false
	// Recheck after creating parents so a pre-existing symlink cannot turn a
	// previously missing prefix into an escape.
	if checked, err := roots.MatchChild(base, relative); err != nil || checked.Canonical != paths.target {
		if err == nil {
			err = filesecurity.ErrUnsafePath
		}
		return respondV1UploadFailure(ctx, changedV1UploadErrorIf(namespaceMayHaveChanged, "upload path changed after directory creation", err))
	}

	if err := writeUploadChunk(roots, paths.chunk, f); err != nil {
		return respondV1UploadFailure(ctx, changedV1UploadErrorIf(namespaceMayHaveChanged, "upload directories may have changed before chunk publication failed", err))
	}

	complete, err := allV1ChunksPresent(roots, base, paths.tempRelative, totalChunks)
	if err != nil {
		return respondV1UploadFailure(ctx, changedV1UploadError("upload chunk published before chunk-set validation failed", err))
	}
	if complete {
		assemblyResult, assemblyErr := assembleV1Upload(roots, base, relative, paths.tempRelative, paths.assembly, paths.target, totalChunks)
		if assemblyResult.TargetPublished {
			uploadSession.completed = true
			uploadSession.completedAt = time.Now()
			uploadSession.completionDigest = assemblyResult.Digest
			uploadSession.completionSize = assemblyResult.Size
			uploadSession.completionIdentity = assemblyResult.Identity
			uploadSession.completionErr = assemblyErr
		}
		if assemblyErr != nil {
			cleanupErr := v1UploadSessions.finishSession(paths.tempDir, uploadSession, true)
			sessionFinished = true
			return respondV1UploadFailure(ctx, changedV1UploadError("upload chunk published before assembly failed", errors.Join(assemblyErr, cleanupErr)))
		}
		if !assemblyResult.TargetPublished {
			cleanupErr := v1UploadSessions.finishSession(paths.tempDir, uploadSession, true)
			sessionFinished = true
			return respondV1UploadFailure(ctx, changedV1UploadError("upload assembly completed without publishing its target", cleanupErr))
		}
		cleanupErr := v1UploadSessions.finishSession(paths.tempDir, uploadSession, true)
		sessionFinished = true
		if cleanupErr != nil {
			// The completed tombstone owns cleanup retry. Returning failure would
			// make the client resend a target that was already committed durably.
			return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
		}
	}
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

var errUploadTooLarge = errors.New("upload chunk exceeds 256 MiB")

type v1UploadPaths struct {
	target       string
	tempDir      string
	tempRelative string
	chunk        string
	assembly     string
}

const (
	maxActiveV1UploadSessions      = 16
	maxCompletedV1UploadTombstones = 128
	v1UploadSessionTTL             = 6 * time.Hour
	v1UploadCompletionTTL          = 10 * time.Minute
)

type v1UploadSession struct {
	lock               sync.Mutex
	closed             bool
	target             string
	tempDir            string
	totalChunks        int64
	lastActivity       time.Time
	cleanupErr         error
	completed          bool
	completedAt        time.Time
	completionDigest   [sha256.Size]byte
	completionSize     int64
	completionIdentity filesecurity.ManagedFileIdentity
	completionErr      error
	stagingClean       bool
}

type v1UploadAssemblyResult struct {
	TargetPublished bool
	Digest          [sha256.Size]byte
	Size            int64
	Identity        filesecurity.ManagedFileIdentity
}

type v1CompletedUploadIdentityVerifier interface {
	VerifyRegularIdentity(string, filesecurity.ManagedFileIdentity) error
}

type v1UploadSessionRegistry struct {
	mu         sync.Mutex
	sessions   map[string]*v1UploadSession
	removeTree func(string) error
}

var v1UploadSessions = v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession), removeTree: filesecurity.RemoveManagementTree}

func (r *v1UploadSessionRegistry) acquire(paths v1UploadPaths, totalChunks int64) (*v1UploadSession, error) {
	now := time.Now()
	r.cleanup(now)
	r.mu.Lock()
	session := r.sessions[paths.tempDir]
	if session == nil {
		r.pruneCompletedLocked(now)
		active := 0
		for _, existing := range r.sessions {
			if existing == nil {
				continue
			}
			if !existing.lock.TryLock() {
				// Treat an in-flight generation as active without blocking every
				// other key behind the registry mutex.
				active++
				continue
			}
			closed := existing.closed
			existing.lock.Unlock()
			if !closed {
				active++
			}
		}
		if active >= maxActiveV1UploadSessions {
			r.mu.Unlock()
			return nil, errors.New("too many active upload sessions")
		}
		if len(r.sessions) >= maxActiveV1UploadSessions+maxCompletedV1UploadTombstones {
			r.mu.Unlock()
			return nil, errors.New("too many retained upload sessions")
		}
		session = &v1UploadSession{target: paths.target, tempDir: paths.tempDir, totalChunks: totalChunks, lastActivity: now}
		r.sessions[paths.tempDir] = session
		cleanupErr := r.removeUploadTree(paths.tempDir)
		if cleanupErr != nil {
			session.closed = true
			session.cleanupErr = cleanupErr
			r.mu.Unlock()
			return nil, cleanupErr
		}
		session.stagingClean = true
	}
	r.mu.Unlock()

	session.lock.Lock()
	if session.target != paths.target || session.tempDir != paths.tempDir || session.totalChunks != totalChunks {
		session.lock.Unlock()
		return nil, errors.New("upload session metadata changed")
	}
	if session.closed && !session.completed {
		cleanupErr := session.cleanupErr
		session.lock.Unlock()
		if cleanupErr != nil {
			return nil, cleanupErr
		}
		return nil, errors.New("upload session cleanup is pending")
	}
	session.lastActivity = now
	return session, nil
}

// lockCompleted returns a matching completed generation with its session lock
// held. A busy active generation is left to the existing chunk probe path;
// registry-wide reads never wait on a slow upload.
func (r *v1UploadSessionRegistry) lockCompleted(paths v1UploadPaths, totalChunks int64) (*v1UploadSession, bool, error) {
	r.cleanup(time.Now())
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[paths.tempDir]
	if session == nil || !session.lock.TryLock() {
		return nil, false, nil
	}
	if session.target != paths.target || session.tempDir != paths.tempDir || session.totalChunks != totalChunks {
		session.lock.Unlock()
		return nil, false, errors.New("upload session metadata changed")
	}
	if !session.completed {
		session.lock.Unlock()
		return nil, false, nil
	}
	return session, true, nil
}

func (r *v1UploadSessionRegistry) finish(key string, session *v1UploadSession) {
	_ = r.finishSession(key, session, false)
}

func (r *v1UploadSessionRegistry) finishSession(key string, session *v1UploadSession, requestChanged bool) error {
	if session == nil {
		return nil
	}
	session.closed = true
	completed := session.completed
	session.lock.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[key] == session {
		cleanupErr := r.removeUploadTree(session.tempDir)
		if cleanupErr != nil {
			if requestChanged {
				cleanupErr = changedV1UploadError("upload staging cleanup remains incomplete", cleanupErr)
			}
			if session.lock.TryLock() {
				session.cleanupErr = cleanupErr
				session.lock.Unlock()
			}
			return cleanupErr
		}
		if session.lock.TryLock() {
			session.stagingClean = true
			session.cleanupErr = nil
			session.lock.Unlock()
		}
		if !completed {
			delete(r.sessions, key)
		}
		r.pruneCompletedLocked(time.Now())
	}
	return nil
}

func (r *v1UploadSessionRegistry) cleanup(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, session := range r.sessions {
		if session == nil || !session.lock.TryLock() {
			continue
		}
		if session.completed && session.stagingClean {
			expired := !session.completedAt.IsZero() && now.Sub(session.completedAt) > v1UploadCompletionTTL
			session.lock.Unlock()
			if expired && r.sessions[key] == session {
				delete(r.sessions, key)
			}
			continue
		}
		expired := !session.closed && !session.lastActivity.IsZero() && now.Sub(session.lastActivity) > v1UploadSessionTTL
		if expired {
			session.closed = true
		}
		terminal := session.closed
		completed := session.completed
		requestChanged := completed || filesecurity.ManagedMutationChanged(session.cleanupErr)
		session.lock.Unlock()
		if terminal && r.sessions[key] == session {
			cleanupErr := r.removeUploadTree(session.tempDir)
			if cleanupErr != nil {
				if requestChanged {
					cleanupErr = changedV1UploadError("upload staging cleanup remains incomplete", cleanupErr)
				}
				if session.lock.TryLock() {
					session.cleanupErr = cleanupErr
					session.lock.Unlock()
				}
				continue
			}
			if completed {
				if session.lock.TryLock() {
					session.stagingClean = true
					session.cleanupErr = nil
					session.lock.Unlock()
				}
			} else {
				delete(r.sessions, key)
			}
		}
	}
	r.pruneCompletedLocked(now)
}

func (r *v1UploadSessionRegistry) removeUploadTree(path string) error {
	if r.removeTree == nil {
		return errors.New("upload staging cleanup is unavailable")
	}
	err := r.removeTree(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (r *v1UploadSessionRegistry) pruneCompletedLocked(now time.Time) {
	type cleanCompletion struct {
		key         string
		completedAt time.Time
	}
	clean := make([]cleanCompletion, 0)
	completedCount := 0
	for key, session := range r.sessions {
		if session == nil {
			delete(r.sessions, key)
			continue
		}
		if !session.lock.TryLock() {
			continue
		}
		completed := session.completed
		stagingClean := session.stagingClean
		completedAt := session.completedAt
		session.lock.Unlock()
		if !completed {
			continue
		}
		if stagingClean && !completedAt.IsZero() && now.Sub(completedAt) > v1UploadCompletionTTL {
			delete(r.sessions, key)
			continue
		}
		completedCount++
		if stagingClean {
			clean = append(clean, cleanCompletion{key: key, completedAt: completedAt})
		}
	}
	if completedCount <= maxCompletedV1UploadTombstones {
		return
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].completedAt.Before(clean[j].completedAt) })
	for _, candidate := range clean {
		if completedCount <= maxCompletedV1UploadTombstones {
			break
		}
		session := r.sessions[candidate.key]
		if session == nil {
			continue
		}
		if !session.lock.TryLock() {
			continue
		}
		eligible := session.completed && session.stagingClean
		session.lock.Unlock()
		if eligible {
			delete(r.sessions, candidate.key)
			completedCount--
		}
	}
}

func parseUploadChunks(totalValue, chunkValue string) (int64, int64, error) {
	totalChunks, err := strconv.ParseInt(totalValue, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid totalChunks: %w", err)
	}
	chunkNumber, err := strconv.ParseInt(chunkValue, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid chunkNumber: %w", err)
	}
	if err := filesecurity.ValidateChunk(totalChunks, chunkNumber); err != nil {
		return 0, 0, err
	}
	return totalChunks, chunkNumber, nil
}

func buildV1UploadPaths(roots *filesecurity.ManagedRoots, base, relative, fileName string, totalChunks, chunkNumber int64) (v1UploadPaths, error) {
	if roots == nil {
		return v1UploadPaths{}, errors.New("management file roots are unavailable")
	}
	if fileName == "" || fileName == "." || fileName == ".." || filepath.Base(fileName) != fileName {
		return v1UploadPaths{}, fmt.Errorf("invalid filename")
	}
	if err := filesecurity.ValidateRelativePath(relative); err != nil {
		return v1UploadPaths{}, err
	}
	cleanRelative := filepath.Clean(relative)
	if filepath.Base(cleanRelative) != fileName {
		return v1UploadPaths{}, fmt.Errorf("filename does not match relativePath")
	}
	if err := filesecurity.ValidateChunk(totalChunks, chunkNumber); err != nil {
		return v1UploadPaths{}, err
	}

	targetLocation, err := roots.MatchChild(base, cleanRelative)
	if err != nil {
		return v1UploadPaths{}, err
	}
	target := targetLocation.Canonical
	uploadHash := v1UploadNamespaceHash([]byte(cleanRelative + "\x00" + fileName))
	tempRelative := filepath.Join(".temp", "upload-"+uploadHash+"-"+strconv.FormatInt(totalChunks, 10), filepath.Dir(cleanRelative))
	tempLocation, err := roots.MatchChild(base, tempRelative)
	if err != nil {
		return v1UploadPaths{}, err
	}
	tempDir := tempLocation.Canonical
	chunkLocation, err := roots.MatchChild(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
	if err != nil {
		return v1UploadPaths{}, err
	}
	chunk := chunkLocation.Canonical
	assemblyLocation, err := roots.MatchChild(base, filepath.Join(tempRelative, ".complete"))
	if err != nil {
		return v1UploadPaths{}, err
	}
	assembly := assemblyLocation.Canonical

	return v1UploadPaths{target: target, tempDir: tempDir, tempRelative: tempRelative, chunk: chunk, assembly: assembly}, nil
}

func v1UploadNamespaceHash(content []byte) string {
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest[:])
}

func writeUploadChunk(roots *filesecurity.ManagedRoots, destination string, source io.Reader) error {
	return writeUploadChunkWithLimit(roots, destination, source, filesecurity.MaxUploadChunkSize)
}

func writeUploadChunkWithLimit(roots *filesecurity.ManagedRoots, destination string, source io.Reader, limit int64) error {
	out, err := roots.CreateExclusive(destination, 0o600)
	if err != nil {
		return err
	}
	defer out.Abort()
	written, copyErr := io.Copy(out, io.LimitReader(source, limit+1))
	if copyErr != nil {
		return errors.Join(copyErr, out.Abort())
	}
	if written > limit {
		return errors.Join(errUploadTooLarge, out.Abort())
	}
	if err := out.Sync(); err != nil {
		return errors.Join(err, out.Abort())
	}
	if err := out.Close(); err != nil {
		return err
	}
	return nil
}

func allV1ChunksPresent(roots *filesecurity.ManagedRoots, base, tempRelative string, totalChunks int64) (bool, error) {
	for chunkNumber := int64(1); chunkNumber <= totalChunks; chunkNumber++ {
		chunkLocation, err := roots.MatchChild(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			return false, err
		}
		info, err := roots.Stat(chunkLocation.Canonical)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() || info.Size() > filesecurity.MaxUploadChunkSize {
			return false, fmt.Errorf("invalid upload chunk %d", chunkNumber)
		}
	}
	return true, nil
}

func verifyCompletedV1Upload(session *v1UploadSession, roots v1CompletedUploadIdentityVerifier) error {
	if session == nil || !session.completed || session.completionSize < 0 {
		return errors.New("invalid completed upload state")
	}
	if roots == nil {
		return errors.New("management file roots are unavailable")
	}
	return roots.VerifyRegularIdentity(session.target, session.completionIdentity)
}

func assembleV1Upload(roots *filesecurity.ManagedRoots, base, targetRelative, tempRelative, assemblyPath, targetPath string, totalChunks int64, beforeCommit ...func() error) (result v1UploadAssemblyResult, resultErr error) {
	namespaceChanged := false
	if err := roots.Remove(assemblyPath); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return result, err
		}
	} else {
		namespaceChanged = true
	}
	out, err := roots.CreateExclusive(assemblyPath, 0o600)
	if err != nil {
		return result, changedV1UploadErrorIf(namespaceChanged, "old upload assembly removed before recreation failed", err)
	}
	writerFinished := false
	defer func() {
		if !writerFinished {
			resultErr = errors.Join(resultErr, out.Abort())
		}
		resultErr = changedV1UploadErrorIf(namespaceChanged, "upload assembly namespace changed before failure", resultErr)
	}()

	completionDigest := sha256.New()
	var totalWritten int64
	for chunkNumber := int64(1); chunkNumber <= totalChunks; chunkNumber++ {
		chunkLocation, err := roots.MatchChild(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			return result, err
		}
		chunk, err := roots.OpenRegular(chunkLocation.Canonical)
		if err != nil {
			return result, err
		}
		written, copyErr := io.Copy(io.MultiWriter(out, completionDigest), io.LimitReader(chunk, filesecurity.MaxUploadChunkSize+1))
		closeErr := chunk.Close()
		if copyErr != nil {
			return result, copyErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		if written > filesecurity.MaxUploadChunkSize {
			return result, fmt.Errorf("upload chunk %d exceeds 256 MiB", chunkNumber)
		}
		if totalWritten > filesecurity.MaxUploadTotalSize-written {
			return result, errors.New("assembled upload size overflow")
		}
		totalWritten += written
	}
	result.Size = totalWritten
	copy(result.Digest[:], completionDigest.Sum(nil))
	checkedTarget, err := roots.MatchChild(base, targetRelative)
	if err != nil {
		return result, err
	}
	if checkedTarget.Canonical != targetPath {
		return result, filesecurity.ErrUnsafePath
	}
	if err := out.Sync(); err != nil {
		return result, err
	}
	if err := out.Close(); err != nil {
		writerFinished = true
		namespaceChanged = namespaceChanged || filesecurity.ManagedMutationChanged(err)
		return result, err
	}
	writerFinished = true
	namespaceChanged = true
	assemblyIdentity, err := out.PublishedIdentity()
	if err != nil {
		return result, err
	}
	if len(beforeCommit) > 0 && beforeCommit[0] != nil {
		if err := beforeCommit[0](); err != nil {
			return result, err
		}
	}
	identity, err := roots.CommitNoReplaceWithExpectedIdentityAndDigest(assemblyPath, targetPath, assemblyIdentity, result.Digest)
	result.Identity = identity
	if err != nil {
		result.TargetPublished = filesecurity.ManagedMutationChanged(err)
		return result, err
	}
	result.TargetPublished = true
	return result, nil
}

func changedV1UploadErrorIf(changed bool, operation string, err error) error {
	if !changed {
		return err
	}
	return changedV1UploadError(operation, err)
}

// @Summary copy or move file
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param body body model.FileOperate true "type:move,copy"
// @Success 200 {string} string "ok"
// @Router /file/operate [post]
func PostOperateFileOrDir(ctx echo.Context) error {
	list := model.FileOperate{}
	if err := bindBoundedFileJSON(ctx, &list, maxFileOperationRequestBodySize); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if err := service.ValidateFileOperationShape(list); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	list, err = service.PrepareFileOperation(roots, list)
	if err != nil {
		if errors.Is(err, service.ErrInvalidFileOperation) {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	for i := range list.Item {
		if list.Type == "move" {
			mounted := service.IsMounted(list.Item[i].From)
			if mounted {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
			}
		}
	}

	uid := uuid.NewString()
	if err := service.EnqueueFileOperation(uid, list); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	service.StartFileOperationNotifications()

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// @Summary delete file
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param body body string true "paths eg ["/a/b/c","/d/e/f"]"
// @Success 200 {string} string "ok"
// @Router /file/delete [delete]
func DeleteFile(ctx echo.Context) error {
	paths := []string{}
	if err := bindBoundedFileJSON(ctx, &paths, maxFileOperationRequestBodySize); err != nil {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if len(paths) == 0 || len(paths) > maxFileDeleteItems {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	cleanedInputs := make([]string, 0, len(paths))
	for _, path := range paths {
		if !validManagedRequestPath(path) {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		cleaned := filepath.Clean(path)
		for _, previous := range cleanedInputs {
			if managedRoutePathsOverlap(previous, cleaned) {
				return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
			}
		}
		cleanedInputs = append(cleanedInputs, cleaned)
	}
	//	path := ctx.QueryParam("path")

	//	paths := strings.Split(path, ",")
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	canonicalPaths := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range cleanedInputs {
		location, err := roots.Match(path)
		if err != nil || location.Relative == "." {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		if _, exists := seen[location.Canonical]; exists {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
		}
		for _, previous := range canonicalPaths {
			if managedRoutePathsOverlap(previous, location.Canonical) {
				return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
			}
		}
		mounted := service.IsMounted(location.Canonical)
		if mounted {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
		}
		seen[location.Canonical] = struct{}{}
		canonicalPaths = append(canonicalPaths, location.Canonical)
	}

	result, err := roots.RemoveAllBatch(canonicalPaths)
	if err != nil {
		status := managedDeleteFailureStatus(result, err)
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_DELETE_ERROR, Message: status, Data: managedDeleteFailureData(result, err)})
	}

	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// @Summary update file
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path body string true "path"
// @Param content body string true "content"
// @Success 200 {string} string "ok"
// @Router /file/update [put]
func PutFileContent(ctx echo.Context) error {
	fi := model.FileUpdate{}
	if err := bindBoundedFileJSON(ctx, &fi, maxManagedTextUpdateRequestBodySize); err != nil || !validManagedRequestPath(fi.FilePath) || len(fi.FileContent) > int(maxManagedTextFileSize) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	err = roots.RewriteRegular(fi.FilePath, []byte(fi.FileContent))
	if err != nil {
		return respondManagedMutationFailure(ctx, err)
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

// @Summary image thumbnail/original image
// @Produce  application/json
// @Accept  application/json
// @Tags file
// @Security ApiKeyAuth
// @Param path query string true "path"
// @Param type query string false "original,thumbnail" Enums(original,thumbnail)
// @Success 200 {string} string "ok"
// @Router /file/image [get]
func GetFileImage(ctx echo.Context) error {
	t := ctx.QueryParam("type")
	path := ctx.QueryParam("path")
	if strings.TrimSpace(path) == "" {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	ctx.Response().Header().Set("X-Content-Type-Options", "nosniff")
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	imageFile, err := roots.OpenRegular(path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	defer imageFile.Close()
	if t == "thumbnail" {
		thumbnail, err := file.GetImageFromFile(imageFile, path, 100, 0)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
		}
		contentType := http.DetectContentType(thumbnail)
		return ctx.Blob(http.StatusOK, contentType, thumbnail)
	}
	if t != "" && t != "original" {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	info, err := imageFile.Stat()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if !info.Mode().IsRegular() {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	header := make([]byte, 512)
	n, readErr := imageFile.Read(header)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_READ_ERROR, Message: common_err.GetMsg(common_err.FILE_READ_ERROR), Data: readErr.Error()})
	}
	if _, err := imageFile.Seek(0, io.SeekStart); err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_READ_ERROR, Message: common_err.GetMsg(common_err.FILE_READ_ERROR), Data: err.Error()})
	}
	ctx.Response().Header().Set("Content-Type", http.DetectContentType(header[:n]))
	http.ServeContent(ctx.Response().Writer, ctx.Request(), filepath.Base(path), info.ModTime(), imageFile)
	return nil
}

func DeleteOperateFileOrDir(ctx echo.Context) error {
	id := ctx.Param("id")
	if err := service.DeleteFileOperation(id); err != nil {
		if errors.Is(err, service.ErrFileOperationRunning) {
			return ctx.JSON(http.StatusConflict, model.Result{Success: common_err.SERVICE_ERROR, Message: "running file operation cannot be cancelled", Data: err.Error()})
		}
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	service.StartFileOperationNotifications()
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

func GetSize(ctx echo.Context) error {
	request := filePathRequest{}
	if err := bindBoundedFileJSON(ctx, &request, maxSmallFileJSONRequestBodySize); err != nil || !validManagedRequestPath(request.Path) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	size, err := roots.TreeSize(request.Path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: size})
}

func GetFileCount(ctx echo.Context) error {
	request := filePathRequest{}
	if err := bindBoundedFileJSON(ctx, &request, maxSmallFileJSONRequestBodySize); err != nil || !validManagedRequestPath(request.Path) {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR)})
	}
	count, err := roots.DirectoryCount(request.Path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: count})
}

type CenterHandler struct {
	mu sync.RWMutex
	// 广播通道，有数据则循环每个用户广播出去
	broadcast chan []byte
	// 用户集合，每个用户本身也在跑两个协程，监听用户的读、写的状态
	clients map[string]*Client
}

type Client struct {
	handler *CenterHandler
	conn    *websocket.Conn
	done    chan struct{}
	stop    sync.Once
	// 每个用户自己的循环跑起来的状态监控
	send         chan []byte
	ID           string       `json:"id"`
	IP           string       `json:"ip"`
	Name         service.Name `json:"name"`
	RtcSupported bool         `json:"rtcSupported"`
	TimerId      int          `json:"timerId"`
	LastBeat     time.Time    `json:"lastBeat"`
}

type PeerModel struct {
	ID           string       `json:"id"`
	Name         service.Name `json:"name"`
	RtcSupported bool         `json:"rtcSupported"`
}

const (
	fileWebSocketReadTimeout = 90 * time.Second
	fileWebSocketWriteWait   = 10 * time.Second
	fileWebSocketMaxLifetime = 12 * time.Hour
)

func ConnectWebSocket(ctx echo.Context) error {
	writer := ctx.Response().Writer
	request := ctx.Request()

	key := uuid.NewString()
	peerModel := model2.PeerDriveDBModel{}
	name := service.GetName(request)
	client := &Client{handler: &handler, send: make(chan []byte, 64), done: make(chan struct{}), ID: key, IP: service.GetIP(request), Name: name, RtcSupported: true, LastBeat: time.Now()}

	wsConn, err := upgraderFile.Upgrade(writer, request, nil)
	if err != nil {
		return nil
	}
	wsConn.SetReadLimit(64 << 10)
	_ = wsConn.SetReadDeadline(time.Now().Add(fileWebSocketReadTimeout))
	wsConn.SetPongHandler(func(string) error {
		return wsConn.SetReadDeadline(time.Now().Add(fileWebSocketReadTimeout))
	})
	client.conn = wsConn
	if !handler.tryAdd(client, 32) {
		_ = wsConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "too many active file WebSocket connections"), time.Now().Add(time.Second))
		_ = wsConn.Close()
		return nil
	}

	// Peer IDs are connection-scoped. A reusable unsigned cookie allowed a
	// client with a matching User-Agent to claim another offline peer identity.
	peerModel.ID = key
	peerModel.DisplayName = name.DisplayName
	peerModel.DeviceName = name.DeviceName
	peerModel.Model = name.Model
	peerModel.OS = name.OS
	peerModel.Browser = name.Browser
	peerModel.UserAgent = ctx.Request().UserAgent()
	peerModel.IP = client.IP
	service.MyService.Peer().CreatePeer(&peerModel)
	list := service.MyService.Peer().GetPeers()
	if len(list) > 10 {
		count := len(list) - 10
		for i := len(list) - 1; count > 0 && i > -1; i-- {
			if !handler.has(list[i].ID) {
				count--
				service.MyService.Peer().DeletePeer(list[i].ID)
			}
		}
	}

	currentPeer := PeerModel{ID: client.ID, Name: client.Name, RtcSupported: client.RtcSupported}
	pby, err := json.Marshal(map[string]interface{}{"type": "peer-joined", "peer": currentPeer})
	if err == nil {
		handler.broadcast <- pby
	}

	clients := []PeerModel{}
	for _, connected := range client.handler.snapshot() {
		clients = append(clients, PeerModel{ID: connected.ID, Name: connected.Name, RtcSupported: connected.RtcSupported})
	}

	if otherBy, err := json.Marshal(map[string]interface{}{"type": "peers", "peers": clients}); err == nil {
		client.send <- otherBy
	}

	client.send <- []byte(`{"type":"ping"}`)

	data := make(map[string]string)
	data["displayName"] = client.Name.DisplayName
	data["deviceName"] = client.Name.DeviceName
	data["id"] = client.ID
	msg := make(map[string]interface{})
	msg["type"] = "display-name"
	msg["message"] = data
	if by, err := json.Marshal(msg); err == nil {
		client.send <- by
	}

	// 每个 client 都挂起 2 个新的协程，监控读、写状态
	go client.writePump()
	go client.readPump()
	return nil
}

var handler = CenterHandler{
	broadcast: make(chan []byte, 64),
	clients:   make(map[string]*Client),
}

func (ch *CenterHandler) has(id string) bool {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	_, ok := ch.clients[id]
	return ok
}

func (ch *CenterHandler) count() int {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return len(ch.clients)
}

func (ch *CenterHandler) tryAdd(client *Client, maximum int) bool {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if maximum < 1 || len(ch.clients) >= maximum {
		return false
	}
	if _, exists := ch.clients[client.ID]; exists {
		return false
	}
	ch.clients[client.ID] = client
	return true
}

func (ch *CenterHandler) remove(client *Client) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if current := ch.clients[client.ID]; current == client {
		delete(ch.clients, client.ID)
	}
}

func (ch *CenterHandler) get(id string) *Client {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.clients[id]
}

func (ch *CenterHandler) snapshot() []*Client {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	clients := make([]*Client, 0, len(ch.clients))
	for _, client := range ch.clients {
		clients = append(clients, client)
	}
	return clients
}

func init() {
	// 起个协程跑起来，监听注册、注销、消息 3 个 channel
	go handler.monitoring()

	crontab := cron.New(cron.WithSeconds()) // 精确到秒
	// 定义定时器调用的任务函数

	task := func() {
		handler.broadcast <- []byte(`{"type":"ping"}`)
	}
	// 定时任务
	spec := "*/30 * * * * ?" // cron表达式，每五秒一次
	// 添加定时任务,
	crontab.AddFunc(spec, task)
	// 启动定时器
	crontab.Start()
}

func (c *Client) writePump() {
	defer c.shutdown()
	lifetime := time.NewTimer(fileWebSocketMaxLifetime)
	defer lifetime.Stop()
	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.send:
			if !ok {
				return
			}
			if err := c.conn.SetWriteDeadline(time.Now().Add(fileWebSocketWriteWait)); err != nil {
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-lifetime.C:
			_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "connection lifetime reached"), time.Now().Add(fileWebSocketWriteWait))
			return
		}
	}
}

// 读，监听客户端是否有推送内容过来服务端
func (c *Client) readPump() {
	defer c.shutdown()
	for {
		// 循环监听是否该用户是否要发言
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			// 异常关闭的处理
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			c.handler.broadcast <- []byte(`{"type":"peer-left","peerId":"` + c.ID + `"}`)
			break
		}
		// 要的话，推给广播中心，广播中心再推给每个用户

		messageType, target, normalized, err := normalizeClientPeerMessage(message, c.ID)
		if err != nil {
			continue
		}
		if messageType == "disconnect" {
			// clients := []Client{}
			// list := service.MyService.Peer().GetPeers()
			// for _, v := range list {
			// 	if _, ok := handler.clients[v.ID]; ok {
			// 		clients = append(clients, *handler.clients[v.ID])
			// 	} else {
			// 		clients = append(clients, Client{ID: v.ID, Name: service.GetNameByDB(v), IP: v.IP, Offline: true})
			// 	}
			// }
			// other := make(map[string]interface{})
			// other["type"] = "peers"
			// other["peers"] = clients
			// otherBy, err := json.Marshal(other)
			// fmt.Println(err)
			c.handler.broadcast <- []byte(`{"type":"peer-left","peerId":"` + c.ID + `"}`)
			// c.handler.broadcast <- otherBy
			break
		} else if messageType == "pong" {
			c.LastBeat = time.Now()
			_ = c.conn.SetReadDeadline(time.Now().Add(fileWebSocketReadTimeout))
			continue
		}

		if target != "" {
			toC := c.handler.get(target)
			if toC == nil {
				continue
			}
			select {
			case toC.send <- normalized:
			default:
			}
			continue
		}

		c.handler.broadcast <- normalized
	}
}

func (c *Client) shutdown() {
	c.stop.Do(func() {
		if c.handler != nil {
			c.handler.remove(c)
		}
		if c.done != nil {
			close(c.done)
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

func normalizeClientPeerMessage(message []byte, sender string) (messageType, target string, normalized []byte, err error) {
	data := make(map[string]interface{})
	if err := json.Unmarshal(message, &data); err != nil {
		return "", "", nil, err
	}
	messageType, ok := data["type"].(string)
	if !ok || len(messageType) == 0 || len(messageType) > 64 {
		return "", "", nil, errors.New("invalid peer message type")
	}
	if messageType == "disconnect" || messageType == "pong" {
		return messageType, "", nil, nil
	}
	switch messageType {
	case "peer-left", "peer-joined", "peers", "ping", "display-name":
		return "", "", nil, errors.New("client cannot send a server control message")
	}
	if rawTarget, exists := data["to"]; exists {
		var ok bool
		target, ok = rawTarget.(string)
		if !ok || len(target) == 0 || len(target) > 128 {
			return "", "", nil, errors.New("invalid peer message target")
		}
	}
	data["sender"] = sender
	delete(data, "to")
	normalized, err = json.Marshal(data)
	if err != nil {
		return "", "", nil, err
	}
	return messageType, target, normalized, nil
}

func (ch *CenterHandler) monitoring() {
	for {
		select {
		// 消息，监听到有新消息到来
		case message := <-ch.broadcast:
			// 推送给每个用户的通道，每个用户都有跑协程起了writePump的监听
			for _, client := range ch.snapshot() {
				select {
				case client.send <- message:
				default:
				}
			}
		}
	}
}

func GetPeers(ctx echo.Context) error {
	peers := service.MyService.Peer().GetPeers()
	for i := 0; i < len(peers); i++ {
		if handler.has(peers[i].ID) {
			peers[i].Online = true
		}
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: peers})
}
