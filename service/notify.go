package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/model/notify"
	"github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/IceWhaleTech/CasaOS/types"
	"go.uber.org/zap"
	"golang.org/x/sync/syncmap"

	socketio "github.com/googollee/go-socket.io"
	"gorm.io/gorm"
)

var (
	fileOperationNotifierMu        sync.Mutex
	fileOperationNotifierRunning   bool
	fileOperationNotifierRequested bool
)

type NotifyServer interface {
	GetLog(id string) model.AppNotify
	AddLog(log model.AppNotify)
	UpdateLog(log model.AppNotify)
	UpdateLogByCustomID(log model.AppNotify)
	DelLog(id string)
	GetList(c int) (list []model.AppNotify)
	MarkRead(id string, state int)
	//	SendText(m model.AppNotify)
	//	SendUninstallAppBySocket(app notifyCommon.Application)

	SendFileOperateNotify(nowSend bool)
	//SendInstallAppBySocket(app notifyCommon.Application)
	SendNotify(name string, message map[string]interface{})
	SettingSystemTempData(message map[string]interface{})
	GetSystemTempMap() *syncmap.Map
}

type notifyServer struct {
	db            *gorm.DB
	SystemTempMap syncmap.Map //[string]interface{}
}

func (i *notifyServer) SettingSystemTempData(message map[string]interface{}) {
	for k, v := range message {
		i.SystemTempMap.Store(k, v)
		//i.SystemTempMap[k] = v
	}
}

func (i *notifyServer) SendNotify(name string, message map[string]interface{}) {
	msg := make(map[string]string)
	for k, v := range message {
		bt, _ := json.Marshal(v)
		msg[k] = string(bt)
	}
	response, err := UnaryMessageBus().PublishEventWithResponse(context.Background(), common.SERVICENAME, name, msg)
	if err != nil {
		logger.Error("failed to publish event to message bus", zap.Error(err))
		return
	}
	if response == nil {
		logger.Error("message bus returned an empty publish response")
		return
	}
	if response.StatusCode() != http.StatusOK {
		logger.Error("failed to publish event to message bus", zap.String("status", response.Status()))
	}
	// SocketServer.BroadcastToRoom("/", "public", path, message)
}

// StartFileOperationNotifications coalesces route requests into one publisher
// loop. The queue's worker is independent; notification failures never start,
// stop, or advance file operations.
func StartFileOperationNotifications() {
	fileOperationNotifierMu.Lock()
	fileOperationNotifierRequested = true
	if fileOperationNotifierRunning {
		fileOperationNotifierMu.Unlock()
		return
	}
	fileOperationNotifierRunning = true
	fileOperationNotifierRequested = false
	fileOperationNotifierMu.Unlock()

	go func() {
		for {
			MyService.Notify().SendFileOperateNotify(false)
			fileOperationNotifierMu.Lock()
			if fileOperationNotifierRequested {
				fileOperationNotifierRequested = false
				fileOperationNotifierMu.Unlock()
				continue
			}
			fileOperationNotifierRunning = false
			fileOperationNotifierMu.Unlock()
			return
		}
	}()
}

// SendFileOperateNotify publishes immutable queue snapshots. Terminal tasks
// are acknowledged only after a successful message-bus response.
func (i *notifyServer) SendFileOperateNotify(nowSend bool) {
	publishedAtLeastOnce := false
	for {
		snapshots := FileOperationSnapshots()
		files, terminalIDs := buildFileOperationNotifications(snapshots)
		if len(snapshots) == 0 && publishedAtLeastOnce && !nowSend {
			return
		}
		if !publishFileOperationNotifications(files) {
			return
		}
		publishedAtLeastOnce = true
		AcknowledgeTerminalFileOperations(terminalIDs)
		if nowSend {
			return
		}
		if len(FileOperationSnapshots()) == 0 {
			return
		}
		if HasActiveFileOperations() {
			time.Sleep(3 * time.Second)
		}
	}
}

func buildFileOperationNotifications(snapshots []FileOperationSnapshot) ([]notify.File, []string) {
	files := make([]notify.File, 0, len(snapshots))
	terminalIDs := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		operation := snapshot.Operation
		task := notify.File{
			Id:                snapshot.ID,
			ProcessedSize:     operation.ProcessedSize,
			TotalSize:         operation.TotalSize,
			To:                operation.To,
			Type:              operation.Type,
			Status:            operation.Status,
			Error:             operation.Error,
			DurabilityUnknown: operation.DurabilityUnknown,
			Finished:          operation.Finished && fileOperationStatusTerminal(operation.Status),
			Items:             make([]notify.FileItem, 0, len(operation.Item)),
		}
		for _, item := range operation.Item {
			task.Items = append(task.Items, notify.FileItem{
				From:              item.From,
				Destination:       item.Destination,
				Status:            item.Status,
				Error:             item.Error,
				DurabilityUnknown: item.DurabilityUnknown,
			})
			if task.ProcessingPath == "" && !item.Finished {
				task.ProcessingPath = item.From
			}
		}
		if task.Finished {
			terminalIDs = append(terminalIDs, snapshot.ID)
		}
		files = append(files, task)
	}
	return files, terminalIDs
}

func publishFileOperationNotifications(files []notify.File) bool {
	payload, err := json.Marshal(notify.NotifyModel{State: "NORMAL", Data: files})
	if err != nil {
		logger.Error("failed to encode file operation notification", zap.Error(err))
		return false
	}
	response, err := UnaryMessageBus().PublishEventWithResponse(context.Background(), common.SERVICENAME, "casaos:file:operate", map[string]string{"file_operate": string(payload)})
	if err != nil {
		logger.Error("failed to publish event to message bus", zap.Error(err))
		return false
	}
	if response == nil {
		logger.Error("message bus returned an empty publish response")
		return false
	}
	if response.StatusCode() != http.StatusOK {
		logger.Error("failed to publish event to message bus", zap.String("status", response.Status()))
		return false
	}
	return true
}

// func (i *notifyServer) SendInstallAppBySocket(app notifyCommon.Application) {
// 	SocketServer.BroadcastToRoom("/", "public", "app_install", app)
// }

// func (i *notifyServer) SendUninstallAppBySocket(app notifyCommon.Application) {
// 	SocketServer.BroadcastToRoom("/", "public", "app_uninstall", app)
// }

func (i *notifyServer) SSR() {
	server := socketio.NewServer(nil)
	fmt.Println(server)
}

func (i *notifyServer) GetList(c int) (list []model.AppNotify) {
	i.db.Where("class = ?", c).Where(i.db.Where("state = ?", types.NOTIFY_DYNAMICE).Or("state = ?", types.NOTIFY_UNREAD)).Find(&list)
	return
}

func (i *notifyServer) AddLog(log model.AppNotify) {
	i.db.Create(&log)
}

func (i *notifyServer) UpdateLog(log model.AppNotify) {
	i.db.Save(&log)
}

func (i *notifyServer) UpdateLogByCustomID(log model.AppNotify) {
	if len(log.CustomId) == 0 {
		return
	}
	i.db.Model(&model.AppNotify{}).Select("*").Where("custom_id = ? ", log.CustomId).Updates(log)
}

func (i *notifyServer) GetLog(id string) model.AppNotify {
	var log model.AppNotify
	i.db.Where("custom_id = ? ", id).First(&log)
	return log
}

func (i *notifyServer) MarkRead(id string, state int) {
	if id == "0" {
		i.db.Model(&model.AppNotify{}).Where("1 = ?", 1).Update("state", state)
		return
	}
	i.db.Model(&model.AppNotify{}).Where("id = ? ", id).Update("state", state)
}

func (i *notifyServer) DelLog(id string) {
	var log model.AppNotify
	i.db.Where("custom_id = ?", id).Delete(&log)
}

// func (i notifyServer) SendText(m model.AppNotify) {
// 	list := []model.AppNotify{}
// 	list = append(list, m)
// 	json, _ := json2.Marshal(list)
// 	var temp []*websocket.Conn
// 	for _, v := range WebSocketConns {

// 		err := v.WriteMessage(1, json)
// 		if err == nil {
// 			temp = append(temp, v)
// 		}
// 	}
// 	WebSocketConns = temp

// 	if len(WebSocketConns) == 0 {
// 		SocketRun = false
// 	}

// }
func (i *notifyServer) GetSystemTempMap() *syncmap.Map {
	return &i.SystemTempMap
}

func NewNotifyService(db *gorm.DB) NotifyServer {
	return &notifyServer{db: db, SystemTempMap: syncmap.Map{}}
}
