package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	url2 "net/url"
	"os"
	"path"
	"path/filepath"
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
	if !file.Exists(filePath) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_DOES_NOT_EXIST,
			Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
		})
	}
	// 文件读取任务是将文件内容读取到内存中。
	info, err := ioutil.ReadFile(filePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{
			Success: common_err.FILE_READ_ERROR,
			Message: common_err.GetMsg(common_err.FILE_READ_ERROR),
			Data:    err.Error(),
		})
	}
	result := string(info)

	return ctx.JSON(common_err.SUCCESS, model.Result{
		Success: common_err.SUCCESS,
		Message: common_err.GetMsg(common_err.SUCCESS),
		Data:    result,
	})
}

func GetLocalFile(ctx echo.Context) error {
	path := ctx.QueryParam("path")
	if len(path) == 0 {
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.INVALID_PARAMS,
			Message: common_err.GetMsg(common_err.INVALID_PARAMS),
		})
	}
	if !file.Exists(path) {
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.FILE_DOES_NOT_EXIST,
			Message: common_err.GetMsg(common_err.FILE_DOES_NOT_EXIST),
		})
	}
	return ctx.File(path)
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
	for _, v := range list {
		if strings.TrimSpace(v) == "" {
			return ctx.JSON(common_err.CLIENT_ERROR, model.Result{
				Success: common_err.INVALID_PARAMS,
				Message: common_err.GetMsg(common_err.INVALID_PARAMS),
			})
		}
		info, err := os.Stat(v)
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
		fileHandle, err := os.Open(filePath)
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
		if !info.IsDir() {
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
		err = file.AddFile(ar, fname, commonDir)
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

	fi, err := os.Open(filePath)
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
	path := ctx.QueryParam("path")
	req.Path = path
	req.Validate()
	info, err := service.MyService.System().GetDirPath(req.Path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	shares := service.MyService.Shares().GetSharesList()
	sharesMap := make(map[string]string)
	for _, v := range shares {
		sharesMap[v.Path] = fmt.Sprint(v.ID)
	}
	// if len(info) <= (req.Page-1)*req.Size {
	// 	return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: "page out of range"})
	// 	return
	// }
	forEnd := req.Index * req.Size
	if forEnd > len(info) {
		forEnd = len(info)
	}
	for i := (req.Index - 1) * req.Size; i < forEnd; i++ {
		if v, ok := sharesMap[info[i].Path]; ok {
			ex := make(map[string]interface{})
			shareEx := make(map[string]string)
			shareEx["shared"] = "true"
			shareEx["id"] = v
			ex["share"] = shareEx
			ex["mounted"] = false
			info[i].Extensions = ex
		}
	}
	if strings.HasPrefix(req.Path, "/mnt") || strings.HasPrefix(req.Path, "/media") {
		for i := (req.Index - 1) * req.Size; i < forEnd; i++ {
			ex := info[i].Extensions
			if ex == nil {
				ex = make(map[string]interface{})
			}
			mounted := service.IsMounted(info[i].Path)
			ex["mounted"] = mounted
			info[i].Extensions = ex
		}
	}
	// Hide the files or folders in operation
	fileQueue := make(map[string]string)
	if len(service.OpStrArr) > 0 {
		for _, v := range service.OpStrArr {
			v, ok := service.FileQueue.Load(v)
			if !ok {
				continue
			}
			vt := v.(model.FileOperate)
			for _, i := range vt.Item {
				lastPath := i.From[strings.LastIndex(i.From, "/")+1:]
				fileQueue[vt.To+"/"+lastPath] = i.From
			}
		}
	}

	pathList := []ObjResp{}
	for i := (req.Index - 1) * req.Size; i < forEnd; i++ {
		if info[i].Name == ".temp" && info[i].IsDir {
			continue
		}
		if _, ok := fileQueue[info[i].Path]; !ok {
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
	}
	flist := FsListResp{
		Content: pathList,
		Total:   int64(len(info)),
		// Readme:   "",
		// Write:    true,
		// Provider: "local",
		Index: req.Index,
		Size:  req.Size,
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: flist})
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
	json := make(map[string]string)
	ctx.Bind(&json)
	op := json["old_path"]
	np := json["new_path"]
	if len(op) == 0 || len(np) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	mounted := service.IsMounted(op)
	if mounted {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
	}

	success, err := service.MyService.System().RenameFile(op, np)
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
	json := make(map[string]string)
	ctx.Bind(&json)
	path := json["path"]
	var code int
	if len(path) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	// decodedPath, err := url.QueryUnescape(path)
	// if err != nil {
	// 	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	// 	return
	// }
	code, _ = service.MyService.System().MkdirAll(path)
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
	json := make(map[string]string)
	ctx.Bind(&json)
	path := json["path"]
	var code int
	if len(path) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	// decodedPath, err := url.QueryUnescape(path)
	// if err != nil {
	// 	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	// 	return
	// }
	code, _ = service.MyService.System().CreateFile(path)
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

	paths, err := buildV1UploadPaths(ctx.QueryParam("path"), relative, fileName, totalChunks, chunkNumber)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	if _, err := os.Lstat(paths.target); err == nil {
		return ctx.JSON(http.StatusConflict, model.Result{Success: http.StatusConflict, Message: common_err.GetMsg(common_err.FILE_ALREADY_EXISTS)})
	} else if !os.IsNotExist(err) {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if _, err := os.Stat(paths.chunk); err == nil {
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
	paths, err := buildV1UploadPaths(base, relative, fileName, totalChunks, chunkNumber)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}
	uploadSession, err := v1UploadSessions.acquire(paths, totalChunks)
	if err != nil {
		return ctx.JSON(http.StatusTooManyRequests, model.Result{Success: http.StatusTooManyRequests, Message: err.Error()})
	}
	sessionFinished := false
	defer func() {
		if !sessionFinished {
			uploadSession.lock.Unlock()
		}
	}()

	if err := os.MkdirAll(filepath.Dir(paths.target), 0o750); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if err := os.MkdirAll(paths.tempDir, 0o750); err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	// Recheck after creating parents so a pre-existing symlink cannot turn a
	// previously missing prefix into an escape.
	if checked, err := filesecurity.JoinWithinBase(base, relative); err != nil || checked != paths.target {
		if err == nil {
			err = filesecurity.ErrUnsafePath
		}
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS), Data: err.Error()})
	}

	if err := writeUploadChunk(paths.chunk, f); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errUploadTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		return ctx.JSON(status, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}

	complete, err := allV1ChunksPresent(base, paths.tempRelative, totalChunks)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	if complete {
		if err := assembleV1Upload(base, relative, paths.tempRelative, paths.assembly, paths.target, totalChunks); err != nil {
			v1UploadSessions.finish(paths.tempDir, uploadSession)
			sessionFinished = true
			return ctx.JSON(http.StatusInternalServerError, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
		}
		v1UploadSessions.finish(paths.tempDir, uploadSession)
		sessionFinished = true
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
	maxActiveV1UploadSessions = 16
	v1UploadSessionTTL        = 6 * time.Hour
)

type v1UploadSession struct {
	lock         sync.Mutex
	closed       bool
	target       string
	tempDir      string
	totalChunks  int64
	lastActivity time.Time
}

type v1UploadSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*v1UploadSession
}

var v1UploadSessions = v1UploadSessionRegistry{sessions: make(map[string]*v1UploadSession)}

func (r *v1UploadSessionRegistry) acquire(paths v1UploadPaths, totalChunks int64) (*v1UploadSession, error) {
	now := time.Now()
	r.cleanup(now)
	r.mu.Lock()
	session := r.sessions[paths.tempDir]
	if session == nil {
		if len(r.sessions) >= maxActiveV1UploadSessions {
			r.mu.Unlock()
			return nil, errors.New("too many active upload sessions")
		}
		session = &v1UploadSession{target: paths.target, tempDir: paths.tempDir, totalChunks: totalChunks, lastActivity: now}
		r.sessions[paths.tempDir] = session
	}
	r.mu.Unlock()

	session.lock.Lock()
	if session.closed || session.target != paths.target || session.tempDir != paths.tempDir || session.totalChunks != totalChunks {
		session.lock.Unlock()
		return nil, errors.New("upload session is closing or metadata changed")
	}
	session.lastActivity = now
	return session, nil
}

func (r *v1UploadSessionRegistry) finish(key string, session *v1UploadSession) {
	session.closed = true
	session.lock.Unlock()
	r.mu.Lock()
	if r.sessions[key] == session {
		_ = os.RemoveAll(session.tempDir)
		delete(r.sessions, key)
	}
	r.mu.Unlock()
}

func (r *v1UploadSessionRegistry) cleanup(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, session := range r.sessions {
		if session == nil || !session.lock.TryLock() {
			continue
		}
		expired := !session.closed && now.Sub(session.lastActivity) > v1UploadSessionTTL
		if expired {
			session.closed = true
		}
		session.lock.Unlock()
		if expired && r.sessions[key] == session {
			_ = os.RemoveAll(session.tempDir)
			delete(r.sessions, key)
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

func buildV1UploadPaths(base, relative, fileName string, totalChunks, chunkNumber int64) (v1UploadPaths, error) {
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

	target, err := filesecurity.JoinWithinBase(base, cleanRelative)
	if err != nil {
		return v1UploadPaths{}, err
	}
	uploadHash := file.GetHashByContent([]byte(cleanRelative + "\x00" + fileName))
	tempRelative := filepath.Join(".temp", "upload-"+uploadHash+"-"+strconv.FormatInt(totalChunks, 10), filepath.Dir(cleanRelative))
	tempDir, err := filesecurity.JoinWithinBase(base, tempRelative)
	if err != nil {
		return v1UploadPaths{}, err
	}
	chunk, err := filesecurity.JoinWithinBase(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
	if err != nil {
		return v1UploadPaths{}, err
	}
	assembly, err := filesecurity.JoinWithinBase(base, filepath.Join(tempRelative, ".complete"))
	if err != nil {
		return v1UploadPaths{}, err
	}

	return v1UploadPaths{target: target, tempDir: tempDir, tempRelative: tempRelative, chunk: chunk, assembly: assembly}, nil
}

func writeUploadChunk(destination string, source io.Reader) error {
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		_ = os.Remove(destination)
		return err
	}
	written, copyErr := io.Copy(out, io.LimitReader(source, filesecurity.MaxUploadChunkSize+1))
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return closeErr
	}
	if written > filesecurity.MaxUploadChunkSize {
		_ = os.Remove(destination)
		return errUploadTooLarge
	}
	return nil
}

func allV1ChunksPresent(base, tempRelative string, totalChunks int64) (bool, error) {
	for chunkNumber := int64(1); chunkNumber <= totalChunks; chunkNumber++ {
		chunkPath, err := filesecurity.JoinWithinBase(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			return false, err
		}
		info, err := os.Stat(chunkPath)
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

func assembleV1Upload(base, targetRelative, tempRelative, assemblyPath, targetPath string, totalChunks int64) error {
	out, err := os.OpenFile(assemblyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		return err
	}

	for chunkNumber := int64(1); chunkNumber <= totalChunks; chunkNumber++ {
		chunkPath, err := filesecurity.JoinWithinBase(base, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			_ = out.Close()
			return err
		}
		chunk, err := os.Open(chunkPath)
		if err != nil {
			_ = out.Close()
			return err
		}
		written, copyErr := io.Copy(out, io.LimitReader(chunk, filesecurity.MaxUploadChunkSize+1))
		closeErr := chunk.Close()
		if copyErr != nil {
			_ = out.Close()
			return copyErr
		}
		if closeErr != nil {
			_ = out.Close()
			return closeErr
		}
		if written > filesecurity.MaxUploadChunkSize {
			_ = out.Close()
			return fmt.Errorf("upload chunk %d exceeds 256 MiB", chunkNumber)
		}
	}
	if err := out.Close(); err != nil {
		return err
	}

	checkedTarget, err := filesecurity.JoinWithinBase(base, targetRelative)
	if err != nil {
		return err
	}
	if checkedTarget != targetPath {
		return filesecurity.ErrUnsafePath
	}
	return filesecurity.CommitNoReplace(assemblyPath, targetPath)
}

func PostFileOctet(ctx echo.Context) error {
	content_length := ctx.Request().ContentLength
	if content_length <= 0 || content_length > 1024*1024*1024*2*1024 {
		log.Printf("content_length error\n")
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: "content_length error"})
	}
	content_type_, has_key := ctx.Request().Header["Content-Type"]
	if !has_key {
		log.Printf("Content-Type error\n")
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: "Content-Type error"})
	}
	if len(content_type_) != 1 {
		log.Printf("Content-Type count error\n")
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: "Content-Type count error"})
	}
	content_type := content_type_[0]
	const BOUNDARY string = "; boundary="
	loc := strings.Index(content_type, BOUNDARY)
	if loc == -1 {
		log.Printf("Content-Type error, no boundary\n")
		return ctx.JSON(http.StatusBadRequest, model.Result{Success: common_err.CLIENT_ERROR, Message: common_err.GetMsg(common_err.CLIENT_ERROR), Data: "Content-Type error, no boundary"})
	}
	boundary := []byte(content_type[(loc + len(BOUNDARY)):])
	log.Printf("[%s]\n\n", boundary)
	read_data := make([]byte, 1024*24)
	var read_total int = 0
	for {
		file_header, file_data, err := file.ParseFromHead(read_data, read_total, append(boundary, []byte("\r\n")...), ctx.Request().Body)
		if err != nil {
			log.Printf("%v", err)
		}
		log.Printf("file :%s\n", file_header)
		//
		//os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
		f, err := os.OpenFile(file_header["path"]+"/"+file_header["filename"], os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			log.Printf("create file fail:%v\n", err)
		}
		f.Write(file_data)
		file_data = nil

		temp_data, reach_end, err := file.ReadToBoundary(boundary, ctx.Request().Body, f)
		f.Close()
		if err != nil {
			log.Printf("%v\n", err)
		}
		if reach_end {
			break
		} else {
			copy(read_data[0:], temp_data)
			read_total = len(temp_data)
			continue
		}
	}
	return ctx.JSON(http.StatusOK, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
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
	ctx.Bind(&list)

	if len(list.Item) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	if list.To == list.Item[0].From[:strings.LastIndex(list.Item[0].From, "/")] {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SOURCE_DES_SAME, Message: common_err.GetMsg(common_err.SOURCE_DES_SAME)})
	}

	var total int64 = 0
	for i := 0; i < len(list.Item); i++ {

		size, err := file.GetFileOrDirSize(list.Item[i].From)
		if err != nil {
			continue
		}
		list.Item[i].Size = size
		total += size
		if list.Type == "move" {
			mounted := service.IsMounted(list.Item[i].From)
			if mounted {
				return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
			}
		}
	}

	list.TotalSize = total
	list.ProcessedSize = 0

	uid := uuid.NewString()
	service.FileQueue.Store(uid, list)
	service.OpStrArr = append(service.OpStrArr, uid)
	if len(service.OpStrArr) == 1 {
		go service.ExecOpFile()
		go service.CheckFileStatus()

		go service.MyService.Notify().SendFileOperateNotify(false)

	}

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
	ctx.Bind(&paths)
	if len(paths) == 0 {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}
	//	path := ctx.QueryParam("path")

	//	paths := strings.Split(path, ",")
	for _, v := range paths {
		mounted := service.IsMounted(v)
		if mounted {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.MOUNTED_DIRECTIORIES, Message: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES), Data: common_err.GetMsg(common_err.MOUNTED_DIRECTIORIES)})
		}
	}

	for _, v := range paths {
		err := os.RemoveAll(v)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_DELETE_ERROR, Message: common_err.GetMsg(common_err.FILE_DELETE_ERROR), Data: err})
		}
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
	ctx.Bind(&fi)

	// path := ctx.FormValue("path")
	// content := ctx.FormValue("content")
	if !file.Exists(fi.FilePath) {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.FILE_ALREADY_EXISTS)})
	}
	// err := os.Remove(path)
	f, err := os.Stat(fi.FilePath)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_ALREADY_EXISTS, Message: common_err.GetMsg(common_err.FILE_ALREADY_EXISTS)})
	}
	fm := f.Mode()
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.FILE_DELETE_ERROR, Message: common_err.GetMsg(common_err.FILE_DELETE_ERROR), Data: err})
	}
	err = file.WriteToFullPath([]byte(fi.FileContent), fi.FilePath, fm)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
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
	if t == "thumbnail" {
		thumbnail, err := file.GetImage(path, 100, 0)
		if err != nil {
			return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
		}
		contentType := http.DetectContentType(thumbnail)
		return ctx.Blob(http.StatusOK, contentType, thumbnail)
	}
	if t != "" && t != "original" {
		return ctx.JSON(common_err.CLIENT_ERROR, model.Result{Success: common_err.INVALID_PARAMS, Message: common_err.GetMsg(common_err.INVALID_PARAMS)})
	}

	imageFile, err := os.Open(path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	defer imageFile.Close()
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
	if id == "0" {
		service.FileQueue = sync.Map{}
		service.OpStrArr = []string{}
	} else {

		service.FileQueue.Delete(id)
		tempList := []string{}
		for _, v := range service.OpStrArr {
			if v != id {
				tempList = append(tempList, v)
			}
		}
		service.OpStrArr = tempList

	}

	go service.MyService.Notify().SendFileOperateNotify(true)
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS)})
}

func GetSize(ctx echo.Context) error {
	json := make(map[string]string)
	ctx.Bind(&json)
	path := json["path"]
	size, err := file.GetFileOrDirSize(path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: size})
}

func GetFileCount(ctx echo.Context) error {
	json := make(map[string]string)
	ctx.Bind(&json)
	path := json["path"]
	list, err := ioutil.ReadDir(path)
	if err != nil {
		return ctx.JSON(common_err.SERVICE_ERROR, model.Result{Success: common_err.SERVICE_ERROR, Message: common_err.GetMsg(common_err.SERVICE_ERROR), Data: err.Error()})
	}
	return ctx.JSON(common_err.SUCCESS, model.Result{Success: common_err.SUCCESS, Message: common_err.GetMsg(common_err.SUCCESS), Data: len(list)})
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
