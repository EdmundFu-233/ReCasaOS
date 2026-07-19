/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2021-12-20 14:15:46
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-04 16:18:23
 * @FilePath: /CasaOS/service/file.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/moby/sys/mountinfo"
)

const (
	maxManagedFileOperationItems = 16
	maxQueuedFileOperations      = 32
	maxFileOperationErrorRunes   = 512

	FileOperationPending = "PENDING"
	FileOperationRunning = "RUNNING"
	FileOperationSuccess = "SUCCESS"
	FileOperationFailed  = "FAILED"
	FileOperationPartial = "PARTIAL"
)

var (
	ErrInvalidFileOperation     = errors.New("invalid managed file operation")
	ErrFileOperationPrepareBusy = errors.New("managed file operation preparation is busy")
	ErrFileOperationQueueFull   = errors.New("managed file operation queue is full")
	ErrFileOperationNotFound    = errors.New("managed file operation was not found")
	ErrFileOperationRunning     = errors.New("running managed file operation cannot be deleted")
	fileOperationPrepareGate    = make(chan struct{}, 1)
	managedFileOperationQueue   = newFileOperationQueue(executeQueuedFileOperation)
)

type fileOperationExecutor func(model.FileOperate) model.FileOperate

type queuedFileOperation struct {
	operation model.FileOperate
}

// FileOperationSnapshot is an immutable deep copy used by routes and the
// notification publisher. Callers cannot mutate queue state without its mutex.
type FileOperationSnapshot struct {
	ID        string
	Operation model.FileOperate
}

type fileOperationQueue struct {
	mu            sync.Mutex
	tasks         map[string]*queuedFileOperation
	order         []string
	runningID     string
	workerStarted bool
	execute       fileOperationExecutor
}

func newFileOperationQueue(execute fileOperationExecutor) *fileOperationQueue {
	return &fileOperationQueue{
		tasks:   make(map[string]*queuedFileOperation),
		execute: execute,
	}
}

func (q *fileOperationQueue) enqueue(id string, operation model.FileOperate) error {
	q.mu.Lock()
	if len(q.tasks) >= maxQueuedFileOperations {
		q.mu.Unlock()
		return ErrFileOperationQueueFull
	}
	if _, exists := q.tasks[id]; exists || id == "" || id == "0" {
		q.mu.Unlock()
		return ErrInvalidFileOperation
	}
	operation = cloneFileOperation(operation)
	operation.Status = FileOperationPending
	operation.Finished = false
	operation.DurabilityUnknown = false
	for i := range operation.Item {
		operation.Item[i].Status = FileOperationPending
		operation.Item[i].Finished = false
		operation.Item[i].DurabilityUnknown = false
	}
	q.tasks[id] = &queuedFileOperation{operation: operation}
	q.order = append(q.order, id)
	startWorker := !q.workerStarted
	q.workerStarted = true
	q.mu.Unlock()
	if startWorker {
		go q.worker()
	}
	return nil
}

func (q *fileOperationQueue) worker() {
	for {
		q.mu.Lock()
		id, task := q.nextPendingLocked()
		if task == nil {
			q.workerStarted = false
			q.mu.Unlock()
			return
		}
		q.runningID = id
		task.operation.Status = FileOperationRunning
		operation := cloneFileOperation(task.operation)
		q.mu.Unlock()

		result := q.executeSafely(operation)
		q.mu.Lock()
		if current, exists := q.tasks[id]; exists {
			current.operation = cloneFileOperation(result)
		}
		q.runningID = ""
		q.mu.Unlock()
	}
}

func (q *fileOperationQueue) executeSafely(operation model.FileOperate) (result model.FileOperate) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = failQueuedFileOperation(operation, fmt.Errorf("file operation worker panic: %v", recovered))
		}
	}()
	if q.execute == nil {
		return failQueuedFileOperation(operation, errors.New("file operation executor is unavailable"))
	}
	return q.execute(operation)
}

func (q *fileOperationQueue) nextPendingLocked() (string, *queuedFileOperation) {
	for _, id := range q.order {
		task, exists := q.tasks[id]
		if exists && task.operation.Status == FileOperationPending {
			return id, task
		}
	}
	return "", nil
}

func (q *fileOperationQueue) snapshots() []FileOperationSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()
	result := make([]FileOperationSnapshot, 0, len(q.tasks))
	for _, id := range q.order {
		if task, exists := q.tasks[id]; exists {
			result = append(result, FileOperationSnapshot{ID: id, Operation: cloneFileOperation(task.operation)})
		}
	}
	return result
}

func (q *fileOperationQueue) delete(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if id == "0" {
		if q.runningID != "" {
			return ErrFileOperationRunning
		}
		q.tasks = make(map[string]*queuedFileOperation)
		q.order = nil
		return nil
	}
	task, exists := q.tasks[id]
	if !exists {
		return ErrFileOperationNotFound
	}
	if id == q.runningID || task.operation.Status == FileOperationRunning {
		return ErrFileOperationRunning
	}
	delete(q.tasks, id)
	q.compactOrderLocked()
	return nil
}

func (q *fileOperationQueue) acknowledgeTerminal(ids []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range ids {
		task, exists := q.tasks[id]
		if exists && fileOperationStatusTerminal(task.operation.Status) {
			delete(q.tasks, id)
		}
	}
	q.compactOrderLocked()
}

func (q *fileOperationQueue) compactOrderLocked() {
	compacted := q.order[:0]
	for _, id := range q.order {
		if _, exists := q.tasks[id]; exists {
			compacted = append(compacted, id)
		}
	}
	q.order = compacted
}

func (q *fileOperationQueue) hasActive() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, task := range q.tasks {
		if task.operation.Status == FileOperationPending || task.operation.Status == FileOperationRunning {
			return true
		}
	}
	return false
}

func cloneFileOperation(operation model.FileOperate) model.FileOperate {
	operation.Item = append([]model.FileItem(nil), operation.Item...)
	return operation
}

func fileOperationStatusTerminal(status string) bool {
	return status == FileOperationSuccess || status == FileOperationFailed || status == FileOperationPartial
}

// ManagedFileOperationRoots is the descriptor-relative subset used to
// validate and execute batch copy/move requests. Keeping the interface small
// makes the request validation independently testable on non-Linux hosts.
type ManagedFileOperationRoots interface {
	Match(string) (filesecurity.ManagedLocation, error)
	MatchChild(string, string) (filesecurity.ManagedLocation, error)
	Stat(string) (os.FileInfo, error)
	TreeSize(string) (int64, error)
	IsMountPoint(string) (bool, error)
	CopyInto(string, string, filesecurity.ManagedConflictStyle) (filesecurity.ManagedTransferResult, error)
	MoveInto(string, string, filesecurity.ManagedConflictStyle) (filesecurity.ManagedTransferResult, error)
}

type reader struct {
	ctx context.Context
	r   io.Reader
}

// NewReader wraps an io.Reader to handle context cancellation.
//
// Context state is checked BEFORE every Read.
func NewReader(ctx context.Context, r io.Reader) io.Reader {
	if r, ok := r.(*reader); ok && ctx == r.ctx {
		return r
	}
	return &reader{ctx: ctx, r: r}
}

func (r *reader) Read(p []byte) (n int, err error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.r.Read(p)
	}
}

type writer struct {
	ctx context.Context
	w   io.Writer
}

type copier struct {
	writer
}

func NewWriter(ctx context.Context, w io.Writer) io.Writer {
	if w, ok := w.(*copier); ok && ctx == w.ctx {
		return w
	}
	return &copier{writer{ctx: ctx, w: w}}
}

// Write implements io.Writer, but with context awareness.
func (w *writer) Write(p []byte) (n int, err error) {
	select {
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	default:
		return w.w.Write(p)
	}
}

func EnqueueFileOperation(id string, operation model.FileOperate) error {
	return managedFileOperationQueue.enqueue(id, operation)
}

func DeleteFileOperation(id string) error {
	return managedFileOperationQueue.delete(id)
}

func FileOperationSnapshots() []FileOperationSnapshot {
	return managedFileOperationQueue.snapshots()
}

func AcknowledgeTerminalFileOperations(ids []string) {
	managedFileOperationQueue.acknowledgeTerminal(ids)
}

func HasActiveFileOperations() bool {
	return managedFileOperationQueue.hasActive()
}

// ActiveFileOperationTargets returns only pending/running targets used by the
// listing route to avoid displaying a half-published operation. Terminal tasks
// remain visible to notifications but no longer hide files.
func ActiveFileOperationTargets() map[string]string {
	result := make(map[string]string)
	for _, snapshot := range managedFileOperationQueue.snapshots() {
		if snapshot.Operation.Status != FileOperationPending && snapshot.Operation.Status != FileOperationRunning {
			continue
		}
		for _, item := range snapshot.Operation.Item {
			target := item.Destination
			if target == "" {
				target = filepath.Join(snapshot.Operation.To, filepath.Base(item.From))
			}
			result[target] = item.From
		}
	}
	return result
}

// PrepareFileOperation validates every client-controlled field before the
// request is queued. It canonicalizes paths through ManagedRoots, rejects
// overlapping source/target trees, and calculates sizes through descriptor-
// relative traversal instead of the legacy pathname helpers.
func PrepareFileOperation(roots ManagedFileOperationRoots, operation model.FileOperate) (model.FileOperate, error) {
	select {
	case fileOperationPrepareGate <- struct{}{}:
		defer func() { <-fileOperationPrepareGate }()
	default:
		return model.FileOperate{}, ErrFileOperationPrepareBusy
	}
	if roots == nil {
		return model.FileOperate{}, errors.New("managed file roots are unavailable")
	}
	if err := ValidateFileOperationShape(operation); err != nil {
		return model.FileOperate{}, err
	}
	style, err := filesecurity.ParseManagedConflictStyle(operation.Style)
	if err != nil {
		return model.FileOperate{}, invalidFileOperation("%v", err)
	}

	destination, err := roots.Match(operation.To)
	if err != nil {
		return model.FileOperate{}, invalidFileOperation("unsafe destination path")
	}
	destinationInfo, err := roots.Stat(destination.Canonical)
	if err != nil {
		return model.FileOperate{}, fmt.Errorf("inspect managed destination: %w", err)
	}
	if !destinationInfo.IsDir() {
		return model.FileOperate{}, invalidFileOperation("destination must be a directory")
	}

	canonicalSources := make([]string, 0, len(operation.Item))
	plannedTargets := make([]string, 0, len(operation.Item))
	seenTargets := make(map[string]struct{}, len(operation.Item))
	var total int64
	for index := range operation.Item {
		source, err := roots.Match(operation.Item[index].From)
		if err != nil || source.Relative == "." {
			return model.FileOperate{}, invalidFileOperation("unsafe source path at item %d", index)
		}
		sourceInfo, err := roots.Stat(source.Canonical)
		if err != nil {
			return model.FileOperate{}, fmt.Errorf("inspect managed source %d: %w", index, err)
		}
		if !sourceInfo.IsDir() && !sourceInfo.Mode().IsRegular() {
			return model.FileOperate{}, invalidFileOperation("source %d has an unsupported type", index)
		}

		base := filepath.Base(source.Canonical)
		if err := filesecurity.ValidatePathComponent(base); err != nil {
			return model.FileOperate{}, invalidFileOperation("unsafe source name at item %d", index)
		}
		target, err := roots.MatchChild(destination.Canonical, base)
		if err != nil {
			return model.FileOperate{}, invalidFileOperation("unsafe target path at item %d", index)
		}
		targetAuthorization, err := roots.Match(target.Canonical)
		if err != nil || targetAuthorization.Relative == "." {
			return model.FileOperate{}, invalidFileOperation("target %d is a configured root", index)
		}
		if filepath.Dir(source.Canonical) == destination.Canonical || managedOperationPathsOverlap(source.Canonical, target.Canonical) {
			return model.FileOperate{}, invalidFileOperation("source and target overlap at item %d", index)
		}
		if sourceInfo.IsDir() && managedOperationPathContains(source.Canonical, destination.Canonical) {
			return model.FileOperate{}, invalidFileOperation("destination is inside source directory at item %d", index)
		}
		for previousIndex, previous := range canonicalSources {
			if managedOperationPathsOverlap(previous, source.Canonical) {
				return model.FileOperate{}, invalidFileOperation("source items %d and %d overlap", previousIndex, index)
			}
		}
		if _, exists := seenTargets[target.Canonical]; exists && style != filesecurity.ManagedConflictRename {
			return model.FileOperate{}, invalidFileOperation("multiple items resolve to target %q", target.Canonical)
		}
		if operation.Type == "move" {
			mounted, err := roots.IsMountPoint(source.Canonical)
			if err != nil {
				return model.FileOperate{}, fmt.Errorf("inspect managed source mount %d: %w", index, err)
			}
			if mounted {
				return model.FileOperate{}, invalidFileOperation("source %d is a mount point", index)
			}
		}

		size, err := roots.TreeSize(source.Canonical)
		if err != nil {
			return model.FileOperate{}, fmt.Errorf("measure managed source %d: %w", index, err)
		}
		if size < 0 || total > math.MaxInt64-size {
			return model.FileOperate{}, invalidFileOperation("total size overflows int64")
		}
		total += size
		operation.Item[index].From = source.Canonical
		operation.Item[index].Size = size
		operation.Item[index].ProcessedSize = 0
		operation.Item[index].Finished = false
		operation.Item[index].Destination = ""
		operation.Item[index].Status = ""
		operation.Item[index].Error = ""
		operation.Item[index].DurabilityUnknown = false
		canonicalSources = append(canonicalSources, source.Canonical)
		plannedTargets = append(plannedTargets, target.Canonical)
		seenTargets[target.Canonical] = struct{}{}
	}

	// A replace task must never delete another source before that source has
	// been copied. Reject all source/target overlap for every style so request
	// ordering cannot change the meaning of a batch.
	for targetIndex, target := range plannedTargets {
		for sourceIndex, source := range canonicalSources {
			if targetIndex != sourceIndex && managedOperationPathsOverlap(target, source) {
				return model.FileOperate{}, invalidFileOperation("target %d overlaps source %d", targetIndex, sourceIndex)
			}
		}
	}

	operation.To = destination.Canonical
	operation.Style = string(style)
	operation.TotalSize = total
	operation.ProcessedSize = 0
	operation.Finished = false
	operation.Error = ""
	operation.DurabilityUnknown = false
	return operation, nil
}

// ValidateFileOperationShape performs the platform-independent checks that
// must happen before route code accesses the installed Linux root set.
func ValidateFileOperationShape(operation model.FileOperate) error {
	if operation.Type != "copy" && operation.Type != "move" {
		return invalidFileOperation("type must be copy or move")
	}
	if _, err := filesecurity.ParseManagedConflictStyle(operation.Style); err != nil {
		return invalidFileOperation("%v", err)
	}
	if len(operation.Item) == 0 || len(operation.Item) > maxManagedFileOperationItems {
		return invalidFileOperation("item count must be between 1 and %d", maxManagedFileOperationItems)
	}
	if operation.To == "" || !filepath.IsAbs(operation.To) || strings.IndexByte(operation.To, 0) >= 0 {
		return invalidFileOperation("destination must be an absolute path")
	}
	for index := range operation.Item {
		from := operation.Item[index].From
		if from == "" || !filepath.IsAbs(from) || strings.IndexByte(from, 0) >= 0 {
			return invalidFileOperation("source %d must be an absolute path", index)
		}
	}
	return nil
}

func invalidFileOperation(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidFileOperation, fmt.Sprintf(format, arguments...))
}

func managedOperationPathsOverlap(first, second string) bool {
	return managedOperationPathContains(first, second) || managedOperationPathContains(second, first)
}

func managedOperationPathContains(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+string(filepath.Separator))
}

func executeQueuedFileOperation(temp model.FileOperate) model.FileOperate {
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return failQueuedFileOperation(temp, err)
	}
	return executePreparedFileOperation(roots, temp)
}

func executePreparedFileOperation(roots ManagedFileOperationRoots, temp model.FileOperate) model.FileOperate {
	style, err := filesecurity.ParseManagedConflictStyle(temp.Style)
	if err != nil {
		return failQueuedFileOperation(temp, err)
	}

	succeeded := 0
	partiallyChanged := 0
	temp.ProcessedSize = 0
	temp.Error = ""
	temp.DurabilityUnknown = false
	for i := 0; i < len(temp.Item); i++ {
		temp.Item[i].Status = FileOperationRunning
		temp.Item[i].DurabilityUnknown = false
		result, operationErr := executeManagedFileOperationItem(roots, temp.Type, temp.Item[i].From, temp.To, style)
		if operationErr != nil {
			temp.Item[i].Destination = result.Destination
			temp.Item[i].Error = safeFileOperationError(operationErr)
			// For transfer APIs, Changed on either the typed result or mutation
			// error means the destination was published before a durability or
			// source-cleanup failure. Only that state contributes processed bytes.
			targetPublished := result.Changed || filesecurity.ManagedMutationChanged(operationErr)
			temp.Item[i].DurabilityUnknown = filesecurity.ManagedMutationDurabilityUnknown(operationErr)
			temp.DurabilityUnknown = temp.DurabilityUnknown || temp.Item[i].DurabilityUnknown
			if targetPublished {
				temp.Item[i].Status = FileOperationPartial
				temp.Item[i].ProcessedSize = temp.Item[i].Size
				temp.ProcessedSize += temp.Item[i].Size
				partiallyChanged++
			} else {
				temp.Item[i].Status = FileOperationFailed
			}
			temp.Item[i].Finished = true
			if temp.Error == "" {
				temp.Error = temp.Item[i].Error
			} else {
				temp.Error += "; " + temp.Item[i].Error
			}
			temp.Error = safeFileOperationError(errors.New(temp.Error))
			continue
		}
		temp.Item[i].Destination = result.Destination
		temp.Item[i].ProcessedSize = temp.Item[i].Size
		temp.Item[i].Finished = true
		temp.Item[i].Status = FileOperationSuccess
		temp.Item[i].Error = ""
		temp.Item[i].DurabilityUnknown = false
		temp.ProcessedSize += temp.Item[i].Size
		succeeded++
	}
	temp.Finished = true
	switch {
	case succeeded == len(temp.Item) && partiallyChanged == 0:
		temp.Status = FileOperationSuccess
	case succeeded == 0 && partiallyChanged == 0:
		temp.Status = FileOperationFailed
	default:
		temp.Status = FileOperationPartial
	}
	return temp
}

func failQueuedFileOperation(temp model.FileOperate, operationErr error) model.FileOperate {
	errorText := safeFileOperationError(operationErr)
	durabilityUnknown := filesecurity.ManagedMutationDurabilityUnknown(operationErr)
	temp.Error = errorText
	temp.DurabilityUnknown = durabilityUnknown
	temp.Status = FileOperationFailed
	temp.Finished = true
	temp.ProcessedSize = 0
	for i := range temp.Item {
		temp.Item[i].Status = FileOperationFailed
		temp.Item[i].Error = errorText
		temp.Item[i].Finished = true
		temp.Item[i].ProcessedSize = 0
		temp.Item[i].DurabilityUnknown = durabilityUnknown
	}
	return temp
}

func safeFileOperationError(err error) string {
	if err == nil {
		return ""
	}
	cleaned := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, err.Error())
	runes := []rune(cleaned)
	if len(runes) > maxFileOperationErrorRunes {
		cleaned = string(runes[:maxFileOperationErrorRunes]) + "…"
	}
	return cleaned
}

func executeManagedFileOperationItem(roots ManagedFileOperationRoots, operationType, source, destination string, style filesecurity.ManagedConflictStyle) (filesecurity.ManagedTransferResult, error) {
	switch operationType {
	case "copy":
		return roots.CopyInto(source, destination, style)
	case "move":
		return roots.MoveInto(source, destination, style)
	default:
		return filesecurity.ManagedTransferResult{}, fmt.Errorf("%w: unsupported type %q", ErrInvalidFileOperation, operationType)
	}
}

func IsMounted(path string) bool {
	mounted, _ := mountinfo.Mounted(path)
	if mounted {
		return true
	}
	connections := MyService.Connections().GetConnectionsList()
	for _, v := range connections {
		if v.MountPoint == path {
			return true
		}
	}
	return false
}
