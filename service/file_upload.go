package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

type FileInfo struct {
	lock             sync.Mutex
	init             bool
	uploaded         []bool
	uploadedChunkNum int64
	base             string
	targetPath       string
	targetRelative   string
	tempRelative     string
	tempDir          string
	assemblyPath     string
	totalChunks      int64
	totalSize        int64
	chunkSize        int64
	lastActivity     time.Time
	roots            *filesecurity.ManagedRoots
}

type FileUploadService struct {
	sessionsMu   sync.Mutex
	uploadStatus map[string]*FileInfo
	removeTree   func(string) error
}

func NewFileUploadService() *FileUploadService {
	return &FileUploadService{uploadStatus: make(map[string]*FileInfo), removeTree: filesecurity.RemoveManagementTree}
}

const (
	maxActiveUploadSessions = int64(16)
	uploadSessionTTL        = 6 * time.Hour
)

func (s *FileUploadService) TestChunk(
	c echo.Context,
	identifier string,
	chunkNumber int64,
) error {
	s.cleanupExpiredUploads(time.Now())
	if err := validateUploadIdentifier(identifier); err != nil {
		return err
	}
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return err
	}
	targetLocation, err := roots.MatchChild(c.QueryParam("path"), c.QueryParam("relativePath"))
	if err != nil {
		return err
	}
	targetPath := targetLocation.Canonical

	key := boundUploadIdentifier(identifier, targetPath)
	s.sessionsMu.Lock()
	fileInfo, ok := s.uploadStatus[key]
	s.sessionsMu.Unlock()
	if !ok {
		return fmt.Errorf("file not found")
	}
	if fileInfo == nil {
		return fmt.Errorf("invalid upload state")
	}

	fileInfo.lock.Lock()
	defer fileInfo.lock.Unlock()
	if !fileInfo.init || fileInfo.targetPath != targetPath {
		return fmt.Errorf("file not initialized")
	}
	fileInfo.lastActivity = time.Now()
	if err := filesecurity.ValidateChunk(fileInfo.totalChunks, chunkNumber); err != nil {
		return err
	}
	if !fileInfo.uploaded[chunkNumber-1] {
		return fmt.Errorf("file not found")
	}

	return nil
}

func (s *FileUploadService) UploadFile(
	c echo.Context,
	path string,
	chunkNumber int64,
	chunkSize int64,
	currentChunkSize int64,
	totalChunks int64,
	totalSize int64,
	identifier string,
	relativePath string,
	fileName string,
	bin *multipart.FileHeader,
) error {
	_ = c
	s.cleanupExpiredUploads(time.Now())
	if err := filesecurity.ValidateChunk(totalChunks, chunkNumber); err != nil {
		return err
	}
	if err := filesecurity.ValidateUploadSizes(chunkSize, currentChunkSize, totalSize, totalChunks); err != nil {
		return err
	}
	if err := validateChunkShape(chunkNumber, chunkSize, currentChunkSize, totalChunks, totalSize); err != nil {
		return err
	}
	if err := validateUploadIdentifier(identifier); err != nil {
		return err
	}
	if err := validateUploadName(relativePath, fileName); err != nil {
		return err
	}
	if bin == nil {
		return fmt.Errorf("file is required")
	}
	if bin.Size < 0 || bin.Size > filesecurity.MaxUploadChunkSize || bin.Size != currentChunkSize {
		return fmt.Errorf("uploaded chunk size does not match currentChunkSize")
	}

	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return err
	}
	targetLocation, err := roots.MatchChild(path, relativePath)
	if err != nil {
		return err
	}
	targetPath := targetLocation.Canonical
	uploadHash := boundUploadIdentifier(identifier, targetPath)
	tempRelative := filepath.Join(".temp", "v2-upload-"+uploadHash)
	tempLocation, err := roots.MatchChild(path, tempRelative)
	if err != nil {
		return err
	}
	tempDir := tempLocation.Canonical
	chunkLocation, err := roots.MatchChild(path, filepath.Join(tempRelative, strconv.FormatInt(chunkNumber, 10)))
	if err != nil {
		return err
	}
	chunkPath := chunkLocation.Canonical
	assemblyLocation, err := roots.MatchChild(path, filepath.Join(tempRelative, ".complete"))
	if err != nil {
		return err
	}
	assemblyPath := assemblyLocation.Canonical

	if err := roots.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		return err
	}
	if err := roots.MkdirAll(tempDir, 0o700); err != nil {
		return err
	}
	checkedTarget, err := roots.MatchChild(path, relativePath)
	if err != nil {
		return err
	}
	if checkedTarget.Canonical != targetPath {
		return filesecurity.ErrUnsafePath
	}

	key := boundUploadIdentifier(identifier, targetPath)
	candidate := &FileInfo{
		init:           true,
		uploaded:       make([]bool, int(totalChunks)),
		base:           path,
		targetPath:     targetPath,
		targetRelative: filepath.Clean(relativePath),
		tempRelative:   tempRelative,
		tempDir:        tempDir,
		assemblyPath:   assemblyPath,
		totalChunks:    totalChunks,
		totalSize:      totalSize,
		chunkSize:      chunkSize,
		lastActivity:   time.Now(),
		roots:          roots,
	}
	fileInfo, err := s.getOrCreateUploadSession(key, candidate)
	if err != nil {
		if s.removeTree != nil {
			_ = s.removeTree(candidate.tempDir)
		}
		return err
	}

	fileInfo.lock.Lock()
	if !fileInfo.init || fileInfo.targetPath != targetPath || fileInfo.totalChunks != totalChunks || fileInfo.totalSize != totalSize || fileInfo.chunkSize != chunkSize {
		fileInfo.lock.Unlock()
		return fmt.Errorf("identifier is already bound to different upload metadata")
	}
	fileInfo.lastActivity = time.Now()

	source, err := bin.Open()
	if err != nil {
		fileInfo.lock.Unlock()
		return err
	}
	written, writeErr := writeServiceChunk(roots, chunkPath, source)
	closeErr := source.Close()
	if writeErr != nil {
		fileInfo.lock.Unlock()
		return writeErr
	}
	if closeErr != nil {
		fileInfo.lock.Unlock()
		return closeErr
	}
	if written != currentChunkSize {
		_ = roots.Remove(chunkPath)
		fileInfo.lock.Unlock()
		return fmt.Errorf("uploaded chunk contains %d bytes, expected %d", written, currentChunkSize)
	}

	if !fileInfo.uploaded[chunkNumber-1] {
		fileInfo.uploadedChunkNum++
		fileInfo.uploaded[chunkNumber-1] = true
	}
	if fileInfo.uploadedChunkNum != totalChunks {
		fileInfo.lock.Unlock()
		return nil
	}

	if err := assembleServiceUpload(fileInfo); err != nil {
		fileInfo.init = false
		fileInfo.lock.Unlock()
		s.deleteUploadSession(key, fileInfo)
		return err
	}
	fileInfo.init = false
	fileInfo.lock.Unlock()
	s.deleteUploadSession(key, fileInfo)
	// The final rename already committed the upload. Cleanup failure must not
	// report a false upload failure and prompt the client to resend it.
	return nil
}

func (s *FileUploadService) cleanupExpiredUploads(now time.Time) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for key, fileInfo := range s.uploadStatus {
		if fileInfo == nil || !fileInfo.lock.TryLock() {
			continue
		}
		expired := !fileInfo.lastActivity.IsZero() && now.Sub(fileInfo.lastActivity) > uploadSessionTTL
		if expired {
			fileInfo.init = false
		}
		fileInfo.lock.Unlock()
		if expired && s.uploadStatus[key] == fileInfo {
			delete(s.uploadStatus, key)
			if s.removeTree != nil {
				_ = s.removeTree(fileInfo.tempDir)
			}
		}
	}
}

func (s *FileUploadService) getOrCreateUploadSession(key string, candidate *FileInfo) (*FileInfo, error) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if fileInfo := s.uploadStatus[key]; fileInfo != nil {
		return fileInfo, nil
	}
	if len(s.uploadStatus) >= int(maxActiveUploadSessions) {
		return nil, fmt.Errorf("too many active upload sessions")
	}
	s.uploadStatus[key] = candidate
	return candidate, nil
}

func (s *FileUploadService) deleteUploadSession(key string, fileInfo *FileInfo) {
	s.sessionsMu.Lock()
	if s.uploadStatus[key] == fileInfo {
		// Remove the generation's staging directory before making the key
		// available to a new session. Otherwise late cleanup could delete the
		// replacement session's chunks.
		if s.removeTree != nil {
			_ = s.removeTree(fileInfo.tempDir)
		}
		delete(s.uploadStatus, key)
	}
	s.sessionsMu.Unlock()
}

func validateUploadIdentifier(identifier string) error {
	if strings.TrimSpace(identifier) == "" || strings.IndexByte(identifier, 0) >= 0 {
		return fmt.Errorf("identifier is required")
	}
	if len(identifier) > 512 {
		return fmt.Errorf("identifier is too long")
	}
	return nil
}

func validateUploadName(relativePath, fileName string) error {
	if err := filesecurity.ValidateRelativePath(relativePath); err != nil {
		return err
	}
	if fileName == "" || fileName == "." || fileName == ".." || filepath.Base(fileName) != fileName {
		return fmt.Errorf("invalid filename")
	}
	if filepath.Base(filepath.Clean(relativePath)) != fileName {
		return fmt.Errorf("filename does not match relativePath")
	}
	return nil
}

func validateChunkShape(chunkNumber, chunkSize, currentChunkSize, totalChunks, totalSize int64) error {
	if totalSize == 0 {
		return nil
	}
	minimumSize := (totalChunks - 1) * chunkSize
	if totalSize <= minimumSize {
		return fmt.Errorf("totalSize is inconsistent with totalChunks and chunkSize")
	}
	expectedCurrentSize := chunkSize
	if chunkNumber == totalChunks {
		expectedCurrentSize = totalSize - minimumSize
	}
	if currentChunkSize != expectedCurrentSize {
		return fmt.Errorf("currentChunkSize is inconsistent with chunk position")
	}
	return nil
}

func boundUploadIdentifier(identifier, targetPath string) string {
	digest := sha256.Sum256([]byte(identifier + "\x00" + targetPath))
	return hex.EncodeToString(digest[:])
}

func writeServiceChunk(roots *filesecurity.ManagedRoots, destination string, source io.Reader) (int64, error) {
	out, err := roots.CreateExclusive(destination, 0o600)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(out, io.LimitReader(source, filesecurity.MaxUploadChunkSize+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		_ = roots.Remove(destination)
		return written, copyErr
	}
	if syncErr != nil {
		_ = roots.Remove(destination)
		return written, syncErr
	}
	if closeErr != nil {
		_ = roots.Remove(destination)
		return written, closeErr
	}
	if written > filesecurity.MaxUploadChunkSize {
		_ = roots.Remove(destination)
		return written, fmt.Errorf("upload chunk exceeds %d bytes", filesecurity.MaxUploadChunkSize)
	}
	return written, nil
}

func assembleServiceUpload(fileInfo *FileInfo) error {
	if fileInfo.roots == nil {
		return errors.New("management file roots are unavailable")
	}
	_ = fileInfo.roots.Remove(fileInfo.assemblyPath)
	out, err := fileInfo.roots.CreateExclusive(fileInfo.assemblyPath, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = out.Close()
		if !committed {
			_ = fileInfo.roots.Remove(fileInfo.assemblyPath)
		}
	}()

	var totalWritten int64
	for chunkNumber := int64(1); chunkNumber <= fileInfo.totalChunks; chunkNumber++ {
		chunkLocation, err := fileInfo.roots.MatchChild(fileInfo.base, filepath.Join(fileInfo.tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			_ = out.Close()
			return err
		}
		info, err := fileInfo.roots.Stat(chunkLocation.Canonical)
		if err != nil {
			_ = out.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > filesecurity.MaxUploadChunkSize {
			_ = out.Close()
			return fmt.Errorf("invalid upload chunk %d", chunkNumber)
		}

		chunk, err := fileInfo.roots.OpenRegular(chunkLocation.Canonical)
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
			return fmt.Errorf("upload chunk %d exceeds %d bytes", chunkNumber, filesecurity.MaxUploadChunkSize)
		}
		totalWritten += written
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if totalWritten != fileInfo.totalSize {
		return fmt.Errorf("assembled file contains %d bytes, expected %d", totalWritten, fileInfo.totalSize)
	}

	checkedTarget, err := fileInfo.roots.MatchChild(fileInfo.base, fileInfo.targetRelative)
	if err != nil {
		return err
	}
	if checkedTarget.Canonical != fileInfo.targetPath {
		return filesecurity.ErrUnsafePath
	}
	if err := fileInfo.roots.CommitNoReplace(fileInfo.assemblyPath, fileInfo.targetPath); err != nil {
		return err
	}
	committed = true
	return nil
}
