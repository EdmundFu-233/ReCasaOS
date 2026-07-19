package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

type blockingPrepareRoots struct {
	*fakeManagedFileOperationRoots
	started chan struct{}
	release chan struct{}
}

func (b *blockingPrepareRoots) TreeSize(path string) (int64, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-b.release
	return b.fakeManagedFileOperationRoots.TreeSize(path)
}

type fakeManagedFileOperationRoots struct {
	root               string
	copyCalls          int
	moveCalls          int
	treeSizeCalls      int
	mounted            bool
	failSource         string
	partialSource      string
	changedErrorSource string
	observedStyle      filesecurity.ManagedConflictStyle
}

func (f *fakeManagedFileOperationRoots) Match(path string) (filesecurity.ManagedLocation, error) {
	return filesecurity.MatchManagementPath([]string{f.root}, path)
}

func (f *fakeManagedFileOperationRoots) MatchChild(base, relative string) (filesecurity.ManagedLocation, error) {
	return filesecurity.MatchManagementChild([]string{f.root}, base, relative)
}

func (f *fakeManagedFileOperationRoots) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (f *fakeManagedFileOperationRoots) TreeSize(path string) (int64, error) {
	f.treeSizeCalls++
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode().IsRegular() {
		return info.Size(), nil
	}
	var total int64
	err = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func (f *fakeManagedFileOperationRoots) IsMountPoint(string) (bool, error) {
	return f.mounted, nil
}

func TestPrepareMoveRejectsMountBeforeTreeTraversal(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "mounted")
	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root, mounted: true}
	_, err := PrepareFileOperation(roots, model.FileOperate{
		Type:  "move",
		Style: "skip",
		To:    destination,
		Item:  []model.FileItem{{From: source}},
	})
	if !errors.Is(err, ErrInvalidFileOperation) {
		t.Fatalf("mount move error = %v", err)
	}
	if roots.treeSizeCalls != 0 {
		t.Fatalf("mounted source traversed %d times", roots.treeSizeCalls)
	}
}

func (f *fakeManagedFileOperationRoots) CopyInto(source, destination string, style filesecurity.ManagedConflictStyle) (filesecurity.ManagedTransferResult, error) {
	f.copyCalls++
	f.observedStyle = style
	if source == f.failSource {
		return filesecurity.ManagedTransferResult{}, errors.New("copy\nfailed")
	}
	if source == f.changedErrorSource {
		return filesecurity.ManagedTransferResult{Destination: filepath.Join(destination, filepath.Base(source))}, &filesecurity.ManagedMutationError{
			Operation:         "sync private transfer transaction",
			Changed:           true,
			DurabilityUnknown: true,
			Err:               errors.New("injected sync failure"),
		}
	}
	return filesecurity.ManagedTransferResult{Destination: filepath.Join(destination, filepath.Base(source)), Changed: true}, nil
}

func (f *fakeManagedFileOperationRoots) MoveInto(source, destination string, style filesecurity.ManagedConflictStyle) (filesecurity.ManagedTransferResult, error) {
	f.moveCalls++
	f.observedStyle = style
	if source == f.partialSource {
		return filesecurity.ManagedTransferResult{Destination: filepath.Join(destination, filepath.Base(source)), Changed: true}, &filesecurity.ManagedMutationError{
			Operation:         "copy-first managed move retained source",
			Changed:           true,
			DurabilityUnknown: false,
			Err:               filesecurity.ErrManagedMoveSourceRetained,
		}
	}
	return filesecurity.ManagedTransferResult{Destination: filepath.Join(destination, filepath.Base(source)), Changed: true}, nil
}

func TestPrepareFileOperationCanonicalizesAndNormalizesLegacyOverwrite(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root}
	prepared, err := PrepareFileOperation(roots, model.FileOperate{
		Type:  "copy",
		Style: "overwrite",
		To:    destination + string(filepath.Separator),
		Item:  []model.FileItem{{From: source, Size: 999, ProcessedSize: 999, Finished: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Style != string(filesecurity.ManagedConflictReplace) {
		t.Fatalf("style = %q", prepared.Style)
	}
	if prepared.To != destination || prepared.Item[0].From != source {
		t.Fatalf("canonical paths = %q, %q", prepared.To, prepared.Item[0].From)
	}
	if prepared.TotalSize != int64(len("content")) || prepared.Item[0].Size != int64(len("content")) {
		t.Fatalf("sizes = total %d item %d", prepared.TotalSize, prepared.Item[0].Size)
	}
	if prepared.ProcessedSize != 0 || prepared.Item[0].ProcessedSize != 0 || prepared.Finished || prepared.Item[0].Finished {
		t.Fatalf("client progress fields were trusted: %+v", prepared)
	}
}

func TestPrepareFileOperationRejectsInvalidAndOverlappingRequests(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	nestedDestination := filepath.Join(source, "nested")
	if err := os.MkdirAll(nestedDestination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root}

	requests := []model.FileOperate{
		{Type: "delete", Style: "skip", To: root, Item: []model.FileItem{{From: source}}},
		{Type: "copy", Style: "unknown", To: root, Item: []model.FileItem{{From: source}}},
		{Type: "copy", Style: "skip", To: nestedDestination, Item: []model.FileItem{{From: source}}},
		{Type: "copy", Style: "skip", To: root, Item: []model.FileItem{{From: "no-slash"}}},
	}
	for index, request := range requests {
		if _, err := PrepareFileOperation(roots, request); !errors.Is(err, ErrInvalidFileOperation) {
			t.Fatalf("request %d error = %v", index, err)
		}
	}
}

func TestValidateFileOperationShapeCapsBatchItems(t *testing.T) {
	items := make([]model.FileItem, maxManagedFileOperationItems+1)
	for index := range items {
		items[index].From = filepath.Join("/DATA", "item", fmt.Sprint(index))
	}
	err := ValidateFileOperationShape(model.FileOperate{Type: "copy", Style: "skip", To: "/DATA/destination", Item: items})
	if !errors.Is(err, ErrInvalidFileOperation) {
		t.Fatalf("oversized batch error = %v", err)
	}
}

func TestExecuteManagedFileOperationItemDispatchesTypedOperation(t *testing.T) {
	root := t.TempDir()
	roots := &fakeManagedFileOperationRoots{root: root}
	result, err := executeManagedFileOperationItem(roots, "copy", filepath.Join(root, "source"), root, filesecurity.ManagedConflictRename)
	if err != nil || !result.Changed || roots.copyCalls != 1 || roots.moveCalls != 0 || roots.observedStyle != filesecurity.ManagedConflictRename {
		t.Fatalf("copy dispatch result = %+v, %v, roots = %+v", result, err, roots)
	}
	if _, err := executeManagedFileOperationItem(roots, "remove", filepath.Join(root, "source"), root, filesecurity.ManagedConflictSkip); !errors.Is(err, ErrInvalidFileOperation) {
		t.Fatalf("invalid dispatch error = %v", err)
	}
}

func TestPrepareFileOperationSerializesExpensiveTraversal(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &blockingPrepareRoots{
		fakeManagedFileOperationRoots: &fakeManagedFileOperationRoots{root: root},
		started:                       make(chan struct{}, 1),
		release:                       make(chan struct{}),
	}
	request := model.FileOperate{Type: "copy", Style: "skip", To: destination, Item: []model.FileItem{{From: source}}}
	firstResult := make(chan error, 1)
	go func() {
		_, err := PrepareFileOperation(roots, request)
		firstResult <- err
	}()
	select {
	case <-roots.started:
	case <-time.After(time.Second):
		t.Fatal("first preparation did not enter traversal")
	}
	if _, err := PrepareFileOperation(roots, request); !errors.Is(err, ErrFileOperationPrepareBusy) {
		t.Fatalf("concurrent preparation error = %v", err)
	}
	close(roots.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first preparation failed: %v", err)
	}
}

func TestFileOperationQueueUsesOneWorkerAndRejectsRunningDeletion(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	queue := newFileOperationQueue(func(operation model.FileOperate) model.FileOperate {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- operation.To
		<-release
		active.Add(-1)
		operation.Status = FileOperationSuccess
		operation.Finished = true
		return operation
	})
	operation := model.FileOperate{Type: "copy", Style: "skip", Item: []model.FileItem{{From: "/root/source"}}}
	first := operation
	first.To = "/root/first"
	second := operation
	second.To = "/root/second"
	if err := queue.enqueue("first", first); err != nil {
		t.Fatal(err)
	}
	if err := queue.enqueue("second", second); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-started:
		if id != first.To {
			t.Fatalf("first execution = %q", id)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if err := queue.delete("first"); !errors.Is(err, ErrFileOperationRunning) {
		t.Fatalf("running delete error = %v", err)
	}
	if err := queue.delete("0"); !errors.Is(err, ErrFileOperationRunning) {
		t.Fatalf("delete-all running error = %v", err)
	}
	if err := queue.delete("second"); err != nil {
		t.Fatalf("pending delete error = %v", err)
	}
	close(release)
	waitForQueuedOperationStatus(t, queue, "first", FileOperationSuccess)
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent workers = %d", maximum.Load())
	}
	select {
	case unexpected := <-started:
		t.Fatalf("deleted pending operation executed: %q", unexpected)
	default:
	}
}

func TestExecutePreparedFileOperationReportsZeroByteSuccessAndPartialFailure(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	failing := filepath.Join(root, "failing")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failing, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root, failSource: failing}
	prepared, err := PrepareFileOperation(roots, model.FileOperate{
		Type:  "copy",
		Style: "skip",
		To:    destination,
		Item:  []model.FileItem{{From: empty}, {From: failing}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := executePreparedFileOperation(roots, prepared)
	if !result.Finished || result.Status != FileOperationPartial {
		t.Fatalf("task result = %+v", result)
	}
	if !result.Item[0].Finished || result.Item[0].Status != FileOperationSuccess || result.Item[0].ProcessedSize != 0 {
		t.Fatalf("zero-byte item = %+v", result.Item[0])
	}
	if !result.Item[1].Finished || result.Item[1].Status != FileOperationFailed || result.Item[1].Error != "copy failed" {
		t.Fatalf("failed item = %+v", result.Item[1])
	}
	files, terminal := buildFileOperationNotifications([]FileOperationSnapshot{{ID: "task", Operation: result}})
	if len(files) != 1 || files[0].Status != FileOperationPartial || !files[0].Finished || files[0].Error == "" || len(files[0].Items) != 2 || files[0].Items[1].Error != "copy failed" {
		t.Fatalf("notification = %+v", files)
	}
	if len(terminal) != 1 || terminal[0] != "task" {
		t.Fatalf("terminal IDs = %v", terminal)
	}
}

func TestExecutePreparedFileOperationPreservesPublishedPartialResult(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root, partialSource: source}
	prepared, err := PrepareFileOperation(roots, model.FileOperate{
		Type:  "move",
		Style: "replace",
		To:    destination,
		Item:  []model.FileItem{{From: source}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := executePreparedFileOperation(roots, prepared)
	expectedDestination := filepath.Join(destination, filepath.Base(source))
	if result.Status != FileOperationPartial || !result.Finished || result.ProcessedSize != result.TotalSize || result.DurabilityUnknown {
		t.Fatalf("partial task = %+v", result)
	}
	if item := result.Item[0]; item.Status != FileOperationPartial || !item.Finished || item.Destination != expectedDestination || item.ProcessedSize != item.Size || item.Error == "" || item.DurabilityUnknown {
		t.Fatalf("partial item = %+v", item)
	}
	files, terminal := buildFileOperationNotifications([]FileOperationSnapshot{{ID: "partial", Operation: result}})
	if len(files) != 1 || files[0].Status != FileOperationPartial || files[0].Items[0].Status != FileOperationPartial || files[0].Items[0].Destination != expectedDestination {
		t.Fatalf("partial notification = %+v", files)
	}
	if len(terminal) != 1 || terminal[0] != "partial" {
		t.Fatalf("terminal IDs = %v", terminal)
	}
}

func TestExecutePreparedFileOperationUsesChangedMutationErrorForPartialState(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "destination")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := &fakeManagedFileOperationRoots{root: root, changedErrorSource: source}
	prepared, err := PrepareFileOperation(roots, model.FileOperate{
		Type:  "copy",
		Style: "skip",
		To:    destination,
		Item:  []model.FileItem{{From: source}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := executePreparedFileOperation(roots, prepared)
	if result.Status != FileOperationPartial || result.ProcessedSize != 0 || !result.DurabilityUnknown {
		t.Fatalf("changed-error task = %+v", result)
	}
	item := result.Item[0]
	if item.Status != FileOperationPartial || !item.Finished || item.ProcessedSize != 0 || item.Destination != "" || item.Error == "" || !item.DurabilityUnknown {
		t.Fatalf("changed-error item = %+v", item)
	}
	files, _ := buildFileOperationNotifications([]FileOperationSnapshot{{ID: "durability", Operation: result}})
	if len(files) != 1 || !files[0].DurabilityUnknown || len(files[0].Items) != 1 || !files[0].Items[0].DurabilityUnknown {
		t.Fatalf("durability notification = %+v", files)
	}
	payload, err := json.Marshal(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		DurabilityUnknown bool `json:"durability_unknown"`
		Items             []struct {
			DurabilityUnknown bool `json:"durability_unknown"`
		} `json:"items"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.DurabilityUnknown || len(decoded.Items) != 1 || !decoded.Items[0].DurabilityUnknown {
		t.Fatalf("durability JSON = %s", payload)
	}
}

func TestCloneFileOperationPreservesDurabilityStateIndependently(t *testing.T) {
	original := model.FileOperate{
		DurabilityUnknown: true,
		Item:              []model.FileItem{{From: "/managed/source", DurabilityUnknown: true}},
	}
	cloned := cloneFileOperation(original)
	original.DurabilityUnknown = false
	original.Item[0].DurabilityUnknown = false
	if !cloned.DurabilityUnknown || len(cloned.Item) != 1 || !cloned.Item[0].DurabilityUnknown {
		t.Fatalf("cloned durability state = %+v", cloned)
	}
}

func waitForQueuedOperationStatus(t *testing.T, queue *fileOperationQueue, id, status string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, snapshot := range queue.snapshots() {
			if snapshot.ID == id && snapshot.Operation.Status == status {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("operation %q did not reach %s", id, status)
}
