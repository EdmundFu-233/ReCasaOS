/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-07-12 09:48:56
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-09-02 22:10:05
 * @FilePath: /CasaOS/service/service.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package service

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS/codegen/message_bus"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/patrickmn/go-cache"
	"gorm.io/gorm"
)

var Cache *cache.Cache

const messageBusRequestTimeout = 3 * time.Second

var (
	MyService Repository

	messageBusDialer = &net.Dialer{
		Timeout:   messageBusRequestTimeout,
		KeepAlive: 30 * time.Second,
	}
	messageBusHTTPClient = &http.Client{Transport: newMessageBusTransport(messageBusDialer)}
)

// UnaryMessageBusClient deliberately excludes MessageBus streaming APIs. Those
// need lifetime semantics that are different from bounded request/response work.
type UnaryMessageBusClient interface {
	PublishEventWithResponse(ctx context.Context, sourceID message_bus.SourceID, name message_bus.EventName, body message_bus.PublishEventJSONRequestBody, reqEditors ...message_bus.RequestEditorFn) (*message_bus.PublishEventResponse, error)
	RegisterEventTypesWithResponse(ctx context.Context, body message_bus.RegisterEventTypesJSONRequestBody, reqEditors ...message_bus.RequestEditorFn) (*message_bus.RegisterEventTypesResponse, error)
}

func newMessageBusTransport(dialer *net.Dialer) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return transport
}

type Repository interface {
	Casa() CasaService
	Connections() ConnectionsService
	Gateway() external.ManagementService
	Health() HealthService
	Notify() NotifyServer
	Rely() RelyService
	Shares() SharesService
	System() SystemService
	Storage() StorageService
	MessageBus() *message_bus.ClientWithResponses
	Peer() PeerService
	Other() OtherService
}

func NewService(db *gorm.DB, RuntimePath string) Repository {
	gatewayManagement, err := external.NewManagementService(RuntimePath)
	if err != nil && len(RuntimePath) > 0 {
		panic(err)
	}

	return &store{
		casa:        NewCasaService(),
		connections: NewConnectionsService(db),
		gateway:     gatewayManagement,
		notify:      NewNotifyService(db),
		rely:        NewRelyService(db),
		system:      NewSystemService(),
		health:      NewHealthService(),
		shares:      NewSharesService(db),
		storage:     NewStorageService(),
		other:       NewOtherService(),

		peer: NewPeerService(db),
	}
}

type store struct {
	peer        PeerService
	db          *gorm.DB
	casa        CasaService
	notify      NotifyServer
	rely        RelyService
	system      SystemService
	shares      SharesService
	connections ConnectionsService
	gateway     external.ManagementService
	storage     StorageService
	health      HealthService
	other       OtherService
}

func (c *store) Storage() StorageService {
	return c.storage
}

func (c *store) Peer() PeerService {
	return c.peer
}

func (c *store) Other() OtherService {
	return c.other
}

func (c *store) Gateway() external.ManagementService {
	return c.gateway
}

func (s *store) Connections() ConnectionsService {
	return s.connections
}

func (s *store) Shares() SharesService {
	return s.shares
}

func (c *store) Rely() RelyService {
	return c.rely
}

func (c *store) System() SystemService {
	return c.system
}

func (c *store) Notify() NotifyServer {
	return c.notify
}

func (c *store) Casa() CasaService {
	return c.casa
}

func (c *store) Health() HealthService {
	return c.health
}

type boundedUnaryMessageBusClient struct {
	delegate       UnaryMessageBusClient
	requestTimeout time.Duration
}

var _ UnaryMessageBusClient = (*boundedUnaryMessageBusClient)(nil)

func newBoundedUnaryMessageBusClient(delegate UnaryMessageBusClient, timeout time.Duration) *boundedUnaryMessageBusClient {
	return &boundedUnaryMessageBusClient{
		delegate:       delegate,
		requestTimeout: timeout,
	}
}

func (c *boundedUnaryMessageBusClient) PublishEventWithResponse(ctx context.Context, sourceID message_bus.SourceID, name message_bus.EventName, body message_bus.PublishEventJSONRequestBody, reqEditors ...message_bus.RequestEditorFn) (*message_bus.PublishEventResponse, error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	return c.delegate.PublishEventWithResponse(requestContext, sourceID, name, body, reqEditors...)
}

func (c *boundedUnaryMessageBusClient) RegisterEventTypesWithResponse(ctx context.Context, body message_bus.RegisterEventTypesJSONRequestBody, reqEditors ...message_bus.RequestEditorFn) (*message_bus.RegisterEventTypesResponse, error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	return c.delegate.RegisterEventTypesWithResponse(requestContext, body, reqEditors...)
}

// UnaryMessageBus returns the bounded request/response capability used by the
// main service. The raw Repository accessor remains available for separately
// designed streaming lifetimes.
func UnaryMessageBus() UnaryMessageBusClient {
	return unaryMessageBusFor(MyService)
}

func unaryMessageBusFor(repository Repository) UnaryMessageBusClient {
	return newBoundedUnaryMessageBusClient(repository.MessageBus(), messageBusRequestTimeout)
}

func (c *store) MessageBus() *message_bus.ClientWithResponses {
	client, _ := message_bus.NewClientWithResponses("", message_bus.WithHTTPClient(messageBusHTTPClient), func(c *message_bus.Client) error {
		// error will never be returned, as we always want to return a client, even with wrong address,
		// in order to avoid panic.
		//
		// If we don't avoid panic, message bus becomes a hard dependency, which is not what we want.

		messageBusAddress, err := external.GetMessageBusAddress(config.CommonInfo.RuntimePath)
		if err != nil {
			c.Server = "message bus address not found"
			return nil
		}

		c.Server = messageBusAddress
		return nil
	})

	return client
}
