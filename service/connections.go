/*
 * @Author: LinkLeong link@icewhale.org
 * @Date: 2022-07-26 18:13:22
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-08-04 20:10:31
 * @FilePath: /CasaOS/service/connections.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"errors"
	"os"

	"github.com/IceWhaleTech/CasaOS/service/model"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ConnectionsService interface {
	GetConnectionsList() ([]model2.ConnectionsDBModel, error)
	GetConnectionByHost(host string) ([]model2.ConnectionsDBModel, error)
	GetConnectionByID(id string) (model2.ConnectionsDBModel, error)
	CreateConnection(connection *model2.ConnectionsDBModel) error
	DeleteConnection(id string) error
	UpdateConnectionMountState(id uint, port, directories, bootID, mountIDs string) error
	MountSmaba(username, host, directory, port string, mountDirectory *os.File, password string) error
	UnmountSmaba(parentDirectory *os.File, child string) error
	InspectSambaMount(mountPoint, host, directory string) (SambaMountIdentity, bool, error)
	ValidateSambaMount(mountPoint, host, directory string, expectedMountID uint64) (bool, error)
}

type connectionsStruct struct {
	db *gorm.DB
}

var (
	ErrSambaConnectionMutationRejected = errors.New("SMB connection mutation rejected")
	ErrSambaConnectionMutationFailed   = errors.New("SMB connection mutation failed")
)

const legacyConnectionMutationPredicateSQL = `id = ? AND ` +
	model.LegacySMBCredentialRowPredicateSQL +
	` AND NOT EXISTS (SELECT 1 FROM o_security_migrations)`

func (s *connectionsStruct) GetConnectionByHost(host string) ([]model2.ConnectionsDBModel, error) {
	connections := []model2.ConnectionsDBModel{}
	err := s.db.Select("username,host,status,id").Where("host = ?", host).Find(&connections).Error
	return connections, err
}

func (s *connectionsStruct) GetConnectionByID(id string) (model2.ConnectionsDBModel, error) {
	connection := model2.ConnectionsDBModel{}
	err := s.db.Select("username,password,host,status,id,directories,mount_point,port,boot_id,mount_ids").Where("id = ?", id).First(&connection).Error
	return connection, err
}

func (s *connectionsStruct) GetConnectionsList() ([]model2.ConnectionsDBModel, error) {
	connections := []model2.ConnectionsDBModel{}
	err := s.db.Select("username,host,port,status,id,mount_point").Find(&connections).Error
	return connections, err
}

func (s *connectionsStruct) CreateConnection(connection *model2.ConnectionsDBModel) error {
	if !isLegacyConnectionMutationPayload(connection) {
		return ErrSambaConnectionMutationRejected
	}
	return runLegacyConnectionMutation(s.db, func(transaction *gorm.DB) error {
		return requireOneSambaConnectionMutation(createLegacyConnectionRecord(transaction, connection))
	})
}

func (s *connectionsStruct) UpdateConnectionMountState(id uint, port, directories, bootID, mountIDs string) error {
	if id == 0 {
		return ErrSambaConnectionMutationRejected
	}
	return runLegacyConnectionMutation(s.db, func(transaction *gorm.DB) error {
		return requireOneSambaConnectionMutation(updateLegacyConnectionMountStateRecord(
			transaction,
			id,
			port,
			directories,
			bootID,
			mountIDs,
		))
	})
}

func (s *connectionsStruct) DeleteConnection(id string) error {
	return runLegacyConnectionMutation(s.db, func(transaction *gorm.DB) error {
		return requireOneSambaConnectionMutation(deleteLegacyConnectionRecord(transaction, id))
	})
}

func createLegacyConnectionRecord(database *gorm.DB, connection *model2.ConnectionsDBModel) *gorm.DB {
	return database.Select([]string{
		"id",
		"updated",
		"created",
		"username",
		"password",
		"host",
		"port",
		"status",
		"directories",
		"mount_point",
		"boot_id",
		"mount_ids",
	}).Create(connection)
}

func updateLegacyConnectionMountStateRecord(database *gorm.DB, id uint, port, directories, bootID, mountIDs string) *gorm.DB {
	return database.Model(&model.ConnectionsDBModel{}).
		Where(legacyConnectionMutationPredicateSQL, id).
		UpdateColumns(map[string]any{
			"updated":     database.NowFunc().Unix(),
			"port":        port,
			"directories": directories,
			"boot_id":     bootID,
			"mount_ids":   mountIDs,
		})
}

func deleteLegacyConnectionRecord(database *gorm.DB, id string) *gorm.DB {
	return database.Where(legacyConnectionMutationPredicateSQL, id).
		Delete(&model.ConnectionsDBModel{})
}

func isLegacyConnectionMutationPayload(connection *model2.ConnectionsDBModel) bool {
	return connection != nil &&
		connection.CredentialID == "" &&
		connection.CredentialFormat == "" &&
		len(connection.PasswordEnvelope) == 0 &&
		connection.RowRevision == 0
}

func runLegacyConnectionMutation(database *gorm.DB, mutate func(*gorm.DB) error) error {
	if database == nil || mutate == nil {
		return ErrSambaConnectionMutationFailed
	}
	err := database.Session(&gorm.Session{Logger: logger.Discard}).Transaction(func(transaction *gorm.DB) error {
		if err := verifyLegacyConnectionMutationState(transaction); err != nil {
			return err
		}
		return mutate(transaction)
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSambaConnectionMutationRejected) {
		return ErrSambaConnectionMutationRejected
	}
	return ErrSambaConnectionMutationFailed
}

func verifyLegacyConnectionMutationState(database *gorm.DB) error {
	var nonLegacyExists bool
	if err := database.Raw(`SELECT EXISTS(
		SELECT 1 FROM o_connections
		WHERE NOT ` + model.LegacySMBCredentialRowPredicateSQL + `
		LIMIT 1
	)`).Scan(&nonLegacyExists).Error; err != nil {
		return ErrSambaConnectionMutationFailed
	}
	if nonLegacyExists {
		return ErrSambaConnectionMutationRejected
	}

	var markerExists bool
	if err := database.Raw(`SELECT EXISTS(
		SELECT 1 FROM o_security_migrations LIMIT 1
	)`).Scan(&markerExists).Error; err != nil {
		return ErrSambaConnectionMutationFailed
	}
	if markerExists {
		return ErrSambaConnectionMutationRejected
	}
	return nil
}

func requireOneSambaConnectionMutation(result *gorm.DB) error {
	if result == nil || result.Error != nil || result.RowsAffected > 1 {
		return ErrSambaConnectionMutationFailed
	}
	if result.RowsAffected != 1 {
		return ErrSambaConnectionMutationRejected
	}
	return nil
}

func NewConnectionsService(db *gorm.DB) ConnectionsService {
	return &connectionsStruct{db: db}
}
