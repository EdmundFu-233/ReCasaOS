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
	"os"

	"github.com/IceWhaleTech/CasaOS/service/model"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
)

type ConnectionsService interface {
	GetConnectionsList() ([]model2.ConnectionsDBModel, error)
	GetConnectionByHost(host string) ([]model2.ConnectionsDBModel, error)
	GetConnectionByID(id string) (model2.ConnectionsDBModel, error)
	CreateConnection(connection *model2.ConnectionsDBModel) error
	DeleteConnection(id string) error
	UpdateConnection(connection *model2.ConnectionsDBModel) error
	MountSmaba(username, host, directory, port string, mountDirectory *os.File, password string) error
	UnmountSmaba(parentDirectory *os.File, child string) error
	InspectSambaMount(mountPoint, host, directory string) (SambaMountIdentity, bool, error)
	ValidateSambaMount(mountPoint, host, directory string, expectedMountID uint64) (bool, error)
}

type connectionsStruct struct {
	db *gorm.DB
}

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
	return s.db.Create(connection).Error
}

func (s *connectionsStruct) UpdateConnection(connection *model2.ConnectionsDBModel) error {
	return s.db.Save(connection).Error
}

func (s *connectionsStruct) DeleteConnection(id string) error {
	return s.db.Where("id= ?", id).Delete(&model.ConnectionsDBModel{}).Error
}

func NewConnectionsService(db *gorm.DB) ConnectionsService {
	return &connectionsStruct{db: db}
}
