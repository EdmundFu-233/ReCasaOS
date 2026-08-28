package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/labstack/echo/v4"
)

type FileInfo struct {
	lock                 sync.Mutex
	init                 bool
	uploaded             []bool
	chunkDigests         [][sha256.Size]byte
	uploadedChunkNum     int64
	base                 string
	targetPath           string
	targetRelative       string
	tempRelative         string
	tempDir              string
	assemblyPath         string
	totalChunks          int64
	totalSize            int64
	chunkSize            int64
	lastActivity         time.Time
	roots                *filesecurity.ManagedRoots
	cleanupErr           error
	completed            bool
	completedAt          time.Time
	completionDigest     [sha256.Size]byte
	completionSize       int64
	completionIdentity   filesecurity.ManagedFileIdentity
	completionErr        error
	stagingClean         bool
	assemblyBeforeCommit func() error
}

type serviceChunkWriteResult struct {
	Written   int64
	Published bool
	Digest    [sha256.Size]byte
}

type serviceAssemblyResult struct {
	TargetPublished bool
	Digest          [sha256.Size]byte
	Size            int64
	Identity        filesecurity.ManagedFileIdentity
}

type completedUploadIdentityVerifier interface {
	VerifyRegularIdentity(string, filesecurity.ManagedFileIdentity) error
}

type serviceChunkWriter interface {
	io.Writer
	Sync() error
	Close() error
	Abort() error
}

type FileUploadService struct {
	sessionsMu      sync.Mutex
	uploadStatus    map[string]*FileInfo
	removeTree      func(string) error
	managementRoots func() (*filesecurity.ManagedRoots, error)
	mkdirAll        func(*filesecurity.ManagedRoots, string, fs.FileMode) error
}

func NewFileUploadService() *FileUploadService {
	return &FileUploadService{
		uploadStatus:    make(map[string]*FileInfo),
		removeTree:      filesecurity.RemoveManagementTree,
		managementRoots: filesecurity.ManagementFileRoots,
		mkdirAll: func(roots *filesecurity.ManagedRoots, path string, mode fs.FileMode) error {
			return roots.MkdirAll(path, mode)
		},
	}
}

const (
	maxActiveUploadSessions      = int64(16)
	maxCompletedUploadTombstones = 128
	uploadSessionTTL             = 6 * time.Hour
	uploadCompletionTTL          = 10 * time.Minute
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
	roots, err := s.managementFileRoots()
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
	if fileInfo.targetPath != targetPath || (!fileInfo.init && !fileInfo.completed) {
		return fmt.Errorf("file not initialized")
	}
	fileInfo.lastActivity = time.Now()
	if err := filesecurity.ValidateChunk(fileInfo.totalChunks, chunkNumber); err != nil {
		return err
	}
	if fileInfo.completed {
		if err := verifyCompletedServiceUpload(fileInfo, fileInfo.roots); err != nil {
			return err
		}
		return fileInfo.completionErr
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

	roots, err := s.managementFileRoots()
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

	key := boundUploadIdentifier(identifier, targetPath)
	candidate := &FileInfo{
		init:           true,
		uploaded:       make([]bool, int(totalChunks)),
		chunkDigests:   make([][sha256.Size]byte, int(totalChunks)),
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
	fileInfo, _, err := s.getOrCreateUploadSession(key, candidate)
	if err != nil {
		return err
	}

	fileInfo.lock.Lock()
	if fileInfo.completed {
		if fileInfo.targetPath != targetPath || fileInfo.totalChunks != totalChunks || fileInfo.totalSize != totalSize || fileInfo.chunkSize != chunkSize {
			fileInfo.lock.Unlock()
			return fmt.Errorf("identifier is already bound to a completed upload with different metadata")
		}
		if err := verifyCompletedServiceUpload(fileInfo, roots); err != nil {
			fileInfo.lock.Unlock()
			return err
		}
		completionErr := fileInfo.completionErr
		fileInfo.lastActivity = time.Now()
		fileInfo.lock.Unlock()
		return completionErr
	}
	if !fileInfo.init {
		cleanupErr := fileInfo.cleanupErr
		fileInfo.lock.Unlock()
		if cleanupErr != nil {
			return cleanupErr
		}
		return errors.New("upload session cleanup is pending")
	}
	if fileInfo.targetPath != targetPath || fileInfo.totalChunks != totalChunks || fileInfo.totalSize != totalSize || fileInfo.chunkSize != chunkSize {
		fileInfo.lock.Unlock()
		return fmt.Errorf("identifier is already bound to different upload metadata")
	}
	if len(fileInfo.chunkDigests) != len(fileInfo.uploaded) {
		fileInfo.lock.Unlock()
		return fmt.Errorf("invalid upload digest state")
	}
	hadPublishedChunks := fileInfo.uploadedChunkNum > 0
	if err := s.makeUploadDirectory(roots, filepath.Dir(targetPath), 0o750); err != nil {
		fileInfo.init = false
		fileInfo.lock.Unlock()
		requestChanged := hadPublishedChunks || filesecurity.ManagedMutationChanged(err)
		cleanupErr := s.deleteUploadSession(key, fileInfo, requestChanged)
		return errors.Join(changedServiceUploadErrorIf(requestChanged, "upload session changed before target parent creation failed", err), cleanupErr)
	}
	// MkdirAll does not expose whether it created a prefix. Once it succeeds,
	// any later failure is conservatively treated as changed.
	namespaceMayHaveChanged := true
	checkedTarget, err := roots.MatchChild(path, relativePath)
	if err != nil || checkedTarget.Canonical != targetPath {
		if err == nil {
			err = filesecurity.ErrUnsafePath
		}
		fileInfo.init = false
		fileInfo.lock.Unlock()
		cleanupErr := s.deleteUploadSession(key, fileInfo, true)
		return errors.Join(changedServiceUploadErrorIf(namespaceMayHaveChanged, "target path changed after parent creation", err), cleanupErr)
	}
	if err := s.makeUploadDirectory(roots, tempDir, 0o700); err != nil {
		fileInfo.init = false
		fileInfo.lock.Unlock()
		cleanupErr := s.deleteUploadSession(key, fileInfo, true)
		return errors.Join(changedServiceUploadErrorIf(namespaceMayHaveChanged, "target parent created before upload staging creation failed", err), cleanupErr)
	}
	fileInfo.stagingClean = false
	fileInfo.lastActivity = time.Now()
	chunkIndex := int(chunkNumber - 1)
	if fileInfo.uploaded[chunkIndex] {
		reconciled, err := reconcileRecordedServiceChunk(fileInfo, chunkIndex, roots, chunkPath, currentChunkSize)
		if err != nil {
			fileInfo.lock.Unlock()
			return changedServiceUploadErrorIf(namespaceMayHaveChanged || hadPublishedChunks, "upload namespace changed before recorded chunk reconciliation failed", err)
		}
		if reconciled {
			fileInfo.lock.Unlock()
			return nil
		}
	}

	source, err := bin.Open()
	if err != nil {
		fileInfo.lock.Unlock()
		return changedServiceUploadErrorIf(namespaceMayHaveChanged || hadPublishedChunks, "upload namespace changed before multipart chunk open failed", err)
	}
	chunkSpaceRelease, spaceErr := filesecurity.ReserveUploadSpace(roots, filepath.Dir(targetPath), uint64(currentChunkSize))
	if spaceErr != nil {
		_ = source.Close()
		fileInfo.lock.Unlock()
		return spaceErr
	}
	writeResult, writeErr := func() (serviceChunkWriteResult, error) {
		defer chunkSpaceRelease()
		return writeValidatedServiceChunk(roots, chunkPath, source, currentChunkSize)
	}()
	if writeErr != nil && !writeResult.Published {
		fileInfo.lock.Unlock()
		return changedServiceUploadErrorIf(namespaceMayHaveChanged || hadPublishedChunks, "upload namespace changed before chunk publication failed", writeErr)
	}
	if !writeResult.Published {
		fileInfo.lock.Unlock()
		return changedServiceUploadErrorIf(namespaceMayHaveChanged || hadPublishedChunks, "upload namespace changed before chunk publication was confirmed", errors.New("validated upload chunk was not published"))
	}

	if !fileInfo.uploaded[chunkIndex] {
		fileInfo.uploadedChunkNum++
		fileInfo.uploaded[chunkIndex] = true
	}
	fileInfo.chunkDigests[chunkIndex] = writeResult.Digest
	if fileInfo.uploadedChunkNum != totalChunks {
		fileInfo.lock.Unlock()
		return writeErr
	}

	assemblySpaceRelease, spaceErr := filesecurity.ReserveUploadSpace(roots, filepath.Dir(targetPath), uint64(fileInfo.totalSize))
	if spaceErr != nil {
		fileInfo.lock.Unlock()
		return changedServiceUploadError("upload chunks published before assembly space admission failed", spaceErr)
	}
	assemblyResult, assemblyErr := func() (serviceAssemblyResult, error) {
		defer assemblySpaceRelease()
		return assembleServiceUpload(fileInfo)
	}()
	if assemblyResult.TargetPublished {
		fileInfo.completed = true
		fileInfo.completedAt = time.Now()
		fileInfo.completionDigest = assemblyResult.Digest
		fileInfo.completionSize = assemblyResult.Size
		fileInfo.completionIdentity = assemblyResult.Identity
		fileInfo.completionErr = assemblyErr
		// Completed tombstones need only immutable request metadata and the
		// target identity. Release per-chunk state so replay protection cannot
		// retain attacker-sized slices for the tombstone TTL.
		fileInfo.uploaded = nil
		fileInfo.chunkDigests = nil
		fileInfo.uploadedChunkNum = 0
	}
	if assemblyErr != nil {
		fileInfo.init = false
		fileInfo.lock.Unlock()
		operationErr := changedServiceUploadError("upload chunk published before assembly failed", errors.Join(writeErr, assemblyErr))
		cleanupErr := s.deleteUploadSession(key, fileInfo, true)
		return errors.Join(operationErr, cleanupErr)
	}
	if !assemblyResult.TargetPublished {
		fileInfo.init = false
		fileInfo.lock.Unlock()
		cleanupErr := s.deleteUploadSession(key, fileInfo, true)
		return errors.Join(errors.New("upload assembly completed without publishing its target"), cleanupErr)
	}
	fileInfo.init = false
	fileInfo.lock.Unlock()
	// Target publication succeeded durably. Cleanup failures retain a
	// completed tombstone for background retry but do not make clients resend
	// an already committed upload.
	if cleanupErr := s.deleteUploadSession(key, fileInfo, true); cleanupErr != nil {
		// The completed tombstone owns this cleanup error and retries it on the
		// next request. Returning failure here would make the client resend a
		// target that CommitNoReplace already published durably.
		return nil
	}
	return nil
}

func (s *FileUploadService) managementFileRoots() (*filesecurity.ManagedRoots, error) {
	if s.managementRoots == nil {
		return nil, errors.New("management file roots are unavailable")
	}
	return s.managementRoots()
}

func (s *FileUploadService) makeUploadDirectory(roots *filesecurity.ManagedRoots, path string, mode fs.FileMode) error {
	if s.mkdirAll == nil {
		return errors.New("upload directory creation is unavailable")
	}
	return s.mkdirAll(roots, path, mode)
}

func changedServiceUploadError(operation string, err error) error {
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

func (s *FileUploadService) cleanupExpiredUploads(now time.Time) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for key, fileInfo := range s.uploadStatus {
		if fileInfo == nil {
			delete(s.uploadStatus, key)
			continue
		}
		if !fileInfo.lock.TryLock() {
			continue
		}
		if fileInfo.completed && fileInfo.stagingClean {
			completionExpired := !fileInfo.completedAt.IsZero() && now.Sub(fileInfo.completedAt) > uploadCompletionTTL
			fileInfo.lock.Unlock()
			if completionExpired && s.uploadStatus[key] == fileInfo {
				delete(s.uploadStatus, key)
			}
			continue
		}
		expired := !fileInfo.lastActivity.IsZero() && now.Sub(fileInfo.lastActivity) > uploadSessionTTL
		if expired {
			fileInfo.init = false
		}
		terminal := !fileInfo.init
		requestChanged := fileInfo.uploadedChunkNum > 0 || filesecurity.ManagedMutationChanged(fileInfo.cleanupErr)
		completed := fileInfo.completed
		fileInfo.lock.Unlock()
		if terminal && s.uploadStatus[key] == fileInfo {
			cleanupErr := s.removeUploadTree(fileInfo.tempDir)
			if cleanupErr != nil {
				if requestChanged {
					cleanupErr = changedServiceUploadError("upload staging cleanup remains incomplete", cleanupErr)
				}
				if fileInfo.lock.TryLock() {
					fileInfo.cleanupErr = cleanupErr
					fileInfo.lock.Unlock()
				}
				continue
			}
			if completed {
				if fileInfo.lock.TryLock() {
					fileInfo.stagingClean = true
					fileInfo.cleanupErr = nil
					fileInfo.lock.Unlock()
				}
			} else {
				delete(s.uploadStatus, key)
			}
		}
	}
	s.pruneCompletedUploadTombstonesLocked(now)
}

func (s *FileUploadService) getOrCreateUploadSession(key string, candidate *FileInfo) (*FileInfo, bool, error) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.pruneCompletedUploadTombstonesLocked(time.Now())
	if fileInfo := s.uploadStatus[key]; fileInfo != nil {
		return fileInfo, false, nil
	}
	active := 0
	for _, fileInfo := range s.uploadStatus {
		if fileInfo == nil {
			continue
		}
		if !fileInfo.lock.TryLock() {
			// An in-flight generation is conservatively active. Never let a slow
			// upload make capacity accounting wait or undercount the cap.
			active++
			continue
		}
		completed := fileInfo.completed
		fileInfo.lock.Unlock()
		if !completed {
			active++
		}
	}
	if active >= int(maxActiveUploadSessions) {
		return nil, false, fmt.Errorf("too many active upload sessions")
	}
	if len(s.uploadStatus) >= int(maxActiveUploadSessions)+maxCompletedUploadTombstones {
		return nil, false, fmt.Errorf("too many retained upload sessions")
	}
	s.uploadStatus[key] = candidate
	if cleanupErr := s.removeUploadTree(candidate.tempDir); cleanupErr != nil {
		candidate.init = false
		candidate.cleanupErr = cleanupErr
		return candidate, true, cleanupErr
	}
	candidate.stagingClean = true
	return candidate, true, nil
}

func (s *FileUploadService) deleteUploadSession(key string, fileInfo *FileInfo, requestChanged bool) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.uploadStatus[key] == fileInfo {
		// Remove the generation's staging directory before making the key
		// available to a new session. Otherwise late cleanup could delete the
		// replacement session's chunks.
		cleanupErr := s.removeUploadTree(fileInfo.tempDir)
		if cleanupErr != nil {
			if requestChanged {
				cleanupErr = changedServiceUploadError("upload completed but staging cleanup remains incomplete", cleanupErr)
			}
			if fileInfo.lock.TryLock() {
				fileInfo.init = false
				fileInfo.cleanupErr = cleanupErr
				fileInfo.lock.Unlock()
			}
			return cleanupErr
		}
		completed := true
		stateKnown := false
		if fileInfo.lock.TryLock() {
			fileInfo.stagingClean = true
			fileInfo.cleanupErr = nil
			completed = fileInfo.completed
			stateKnown = true
			fileInfo.lock.Unlock()
		}
		if stateKnown && !completed {
			delete(s.uploadStatus, key)
		}
		s.pruneCompletedUploadTombstonesLocked(time.Now())
	}
	return nil
}

// pruneCompletedUploadTombstonesLocked enforces both TTL and a bounded replay
// cache. Only fully cleaned completed records are eligible for eviction;
// active sessions and cleanup-pending tombstones remain owned by their key so
// late cleanup can never race a replacement generation.
func (s *FileUploadService) pruneCompletedUploadTombstonesLocked(now time.Time) {
	type cleanCompleted struct {
		key         string
		completedAt time.Time
	}
	clean := make([]cleanCompleted, 0)
	completedCount := 0
	for key, fileInfo := range s.uploadStatus {
		if fileInfo == nil {
			delete(s.uploadStatus, key)
			continue
		}
		if !fileInfo.lock.TryLock() {
			// A request owns this generation. It is neither safe nor necessary
			// to wait while holding sessionsMu; a later cleanup pass can prune it.
			continue
		}
		completed := fileInfo.completed
		stagingClean := fileInfo.stagingClean
		completedAt := fileInfo.completedAt
		fileInfo.lock.Unlock()
		if !completed {
			continue
		}
		if stagingClean && !completedAt.IsZero() && now.Sub(completedAt) > uploadCompletionTTL {
			delete(s.uploadStatus, key)
			continue
		}
		completedCount++
		if stagingClean {
			clean = append(clean, cleanCompleted{key: key, completedAt: completedAt})
		}
	}
	if completedCount <= maxCompletedUploadTombstones {
		return
	}
	sort.Slice(clean, func(i, j int) bool {
		return clean[i].completedAt.Before(clean[j].completedAt)
	})
	for _, candidate := range clean {
		if completedCount <= maxCompletedUploadTombstones {
			break
		}
		fileInfo := s.uploadStatus[candidate.key]
		if fileInfo == nil {
			continue
		}
		if !fileInfo.lock.TryLock() {
			continue
		}
		eligible := fileInfo.completed && fileInfo.stagingClean
		fileInfo.lock.Unlock()
		if eligible {
			delete(s.uploadStatus, candidate.key)
			completedCount--
		}
	}
}

func (s *FileUploadService) removeUploadTree(path string) error {
	if s.removeTree == nil {
		return errors.New("upload staging cleanup is unavailable")
	}
	err := s.removeTree(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
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
	return writeServiceChunkWithLimit(roots, destination, source, filesecurity.MaxUploadChunkSize)
}

// writeValidatedServiceChunk keeps the destination hidden until the multipart
// source has closed cleanly and the exact declared size has been observed.
// A failed source close or size mismatch therefore cannot leave a published
// chunk that makes a retry fail with EEXIST.
func writeValidatedServiceChunk(roots *filesecurity.ManagedRoots, destination string, source io.ReadCloser, expectedSize int64) (serviceChunkWriteResult, error) {
	out, err := roots.CreateExclusive(destination, 0o600)
	if err != nil {
		return serviceChunkWriteResult{}, errors.Join(err, source.Close())
	}
	return writeValidatedServiceChunkTo(out, source, expectedSize, filesecurity.MaxUploadChunkSize)
}

func writeValidatedServiceChunkTo(out serviceChunkWriter, source io.ReadCloser, expectedSize, limit int64) (result serviceChunkWriteResult, resultErr error) {
	writerFinished := false
	defer func() {
		if !writerFinished {
			resultErr = errors.Join(resultErr, out.Abort())
		}
	}()

	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, digest), io.LimitReader(source, limit+1))
	result.Written = written
	copy(result.Digest[:], digest.Sum(nil))
	closeErr := source.Close()
	if copyErr != nil || closeErr != nil {
		return result, errors.Join(copyErr, closeErr)
	}
	if written > limit {
		return result, fmt.Errorf("upload chunk exceeds %d bytes", limit)
	}
	if written != expectedSize {
		return result, fmt.Errorf("uploaded chunk contains %d bytes, expected %d", written, expectedSize)
	}
	if err := out.Sync(); err != nil {
		return result, err
	}
	if err := out.Close(); err != nil {
		writerFinished = true
		result.Published = filesecurity.ManagedMutationChanged(err)
		return result, err
	}
	writerFinished = true
	result.Published = true
	return result, nil
}

func reconcileRecordedServiceChunk(fileInfo *FileInfo, chunkIndex int, roots *filesecurity.ManagedRoots, chunkPath string, expectedSize int64) (bool, error) {
	if fileInfo == nil || chunkIndex < 0 || chunkIndex >= len(fileInfo.uploaded) || !fileInfo.uploaded[chunkIndex] {
		return false, nil
	}
	if len(fileInfo.chunkDigests) != len(fileInfo.uploaded) {
		return false, fmt.Errorf("invalid upload digest state")
	}
	release, err := roots.AcquireMutation()
	if err != nil {
		return false, err
	}
	defer release()
	chunk, err := roots.OpenRegular(chunkPath)
	if errors.Is(err, fs.ErrNotExist) {
		fileInfo.uploaded[chunkIndex] = false
		fileInfo.chunkDigests[chunkIndex] = [sha256.Size]byte{}
		if fileInfo.uploadedChunkNum > 0 {
			fileInfo.uploadedChunkNum--
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	info, statErr := chunk.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != expectedSize {
		_ = chunk.Close()
		if statErr != nil {
			return false, statErr
		}
		return false, fmt.Errorf("%w: recorded upload chunk changed before retry", filesecurity.ErrUnsafePath)
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, io.LimitReader(chunk, expectedSize+1))
	closeErr := chunk.Close()
	var actualDigest [sha256.Size]byte
	copy(actualDigest[:], digest.Sum(nil))
	if err := errors.Join(copyErr, closeErr); err != nil {
		return false, err
	}
	if written != expectedSize || actualDigest != fileInfo.chunkDigests[chunkIndex] {
		return false, fmt.Errorf("%w: recorded upload chunk content changed before retry", filesecurity.ErrUnsafePath)
	}
	return true, nil
}

func verifyCompletedServiceUpload(fileInfo *FileInfo, roots completedUploadIdentityVerifier) error {
	if fileInfo == nil || !fileInfo.completed || fileInfo.completionSize < 0 {
		return errors.New("invalid completed upload state")
	}
	if roots == nil {
		return errors.New("management file roots are unavailable")
	}
	return roots.VerifyRegularIdentity(fileInfo.targetPath, fileInfo.completionIdentity)
}

func writeServiceChunkWithLimit(roots *filesecurity.ManagedRoots, destination string, source io.Reader, limit int64) (int64, error) {
	out, err := roots.CreateExclusive(destination, 0o600)
	if err != nil {
		return 0, err
	}
	defer out.Abort()
	written, copyErr := io.Copy(out, io.LimitReader(source, limit+1))
	if copyErr != nil {
		return written, errors.Join(copyErr, out.Abort())
	}
	if written > limit {
		return written, errors.Join(fmt.Errorf("upload chunk exceeds %d bytes", limit), out.Abort())
	}
	if err := out.Sync(); err != nil {
		return written, errors.Join(err, out.Abort())
	}
	if err := out.Close(); err != nil {
		return written, err
	}
	return written, nil
}

func assembleServiceUpload(fileInfo *FileInfo) (result serviceAssemblyResult, resultErr error) {
	if fileInfo.roots == nil {
		return result, errors.New("management file roots are unavailable")
	}
	if len(fileInfo.chunkDigests) != len(fileInfo.uploaded) {
		return result, errors.New("invalid upload digest state")
	}
	namespaceChanged := false
	if err := fileInfo.roots.Remove(fileInfo.assemblyPath); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return result, err
		}
	} else {
		namespaceChanged = true
	}
	out, err := fileInfo.roots.CreateExclusive(fileInfo.assemblyPath, 0o600)
	if err != nil {
		return result, changedServiceUploadErrorIf(namespaceChanged, "old upload assembly removed before recreation failed", err)
	}
	writerFinished := false
	defer func() {
		if !writerFinished {
			resultErr = errors.Join(resultErr, out.Abort())
		}
		resultErr = changedServiceUploadErrorIf(namespaceChanged, "upload assembly namespace changed before failure", resultErr)
	}()

	var totalWritten int64
	completionDigest := sha256.New()
	for chunkNumber := int64(1); chunkNumber <= fileInfo.totalChunks; chunkNumber++ {
		chunkLocation, err := fileInfo.roots.MatchChild(fileInfo.base, filepath.Join(fileInfo.tempRelative, strconv.FormatInt(chunkNumber, 10)))
		if err != nil {
			return result, err
		}
		info, err := fileInfo.roots.Stat(chunkLocation.Canonical)
		if err != nil {
			return result, err
		}
		if !info.Mode().IsRegular() || info.Size() > filesecurity.MaxUploadChunkSize {
			return result, fmt.Errorf("invalid upload chunk %d", chunkNumber)
		}

		chunk, err := fileInfo.roots.OpenRegular(chunkLocation.Canonical)
		if err != nil {
			return result, err
		}
		digest := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(out, digest, completionDigest), io.LimitReader(chunk, filesecurity.MaxUploadChunkSize+1))
		closeErr := chunk.Close()
		if copyErr != nil {
			return result, copyErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		if written > filesecurity.MaxUploadChunkSize {
			return result, fmt.Errorf("upload chunk %d exceeds %d bytes", chunkNumber, filesecurity.MaxUploadChunkSize)
		}
		var actualDigest [sha256.Size]byte
		copy(actualDigest[:], digest.Sum(nil))
		if actualDigest != fileInfo.chunkDigests[chunkNumber-1] {
			return result, fmt.Errorf("%w: upload chunk %d changed before assembly", filesecurity.ErrUnsafePath, chunkNumber)
		}
		totalWritten += written
	}
	if totalWritten != fileInfo.totalSize {
		return result, fmt.Errorf("assembled file contains %d bytes, expected %d", totalWritten, fileInfo.totalSize)
	}
	result.Size = totalWritten
	copy(result.Digest[:], completionDigest.Sum(nil))
	checkedTarget, err := fileInfo.roots.MatchChild(fileInfo.base, fileInfo.targetRelative)
	if err != nil {
		return result, err
	}
	if checkedTarget.Canonical != fileInfo.targetPath {
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
	if fileInfo.assemblyBeforeCommit != nil {
		if err := fileInfo.assemblyBeforeCommit(); err != nil {
			return result, err
		}
	}
	identity, err := fileInfo.roots.CommitNoReplaceWithExpectedIdentityAndDigest(fileInfo.assemblyPath, fileInfo.targetPath, assemblyIdentity, result.Digest)
	result.Identity = identity
	if err != nil {
		result.TargetPublished = filesecurity.ManagedMutationChanged(err)
		return result, err
	}
	result.TargetPublished = true
	return result, nil
}

func changedServiceUploadErrorIf(changed bool, operation string, err error) error {
	if !changed {
		return err
	}
	return changedServiceUploadError(operation, err)
}
